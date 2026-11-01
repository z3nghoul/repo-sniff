mod clone;
mod fail_on;
mod redact;
mod report;
mod target;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use repo_sniff_core::{Limits, Report, builtin_rules};

use crate::fail_on::FailOn;
use crate::redact::{redact_credentials, redact_path};
use crate::target::Target;

/// Exit status when the scan found something at or above `--fail-on`.
const EXIT_FINDINGS: u8 = 1;
/// Exit status when the scan could not run (bad target, clone failure, ...).
/// clap also uses 2 for command-line mistakes.
const EXIT_ERROR: u8 = 2;
/// Exit status when nothing reached `--fail-on` but the scan was inconclusive
/// (the walk was cut short, a file was not read, or an executable was not
/// reported by any rule): not a pass.
const EXIT_INCONCLUSIVE: u8 = 3;

/// Statically scan a repository for signs of malicious or suspicious code.
///
/// Exit status: 0 when the scan was complete and nothing reaches the
/// --fail-on threshold, 1 when something does, 2 when the scan could not
/// run, 3 when nothing reaches the threshold but the scan was inconclusive
/// (the file limit was reached, a file was too large or unreadable, or an
/// executable binary was not reported by any rule), so that a clean-looking
/// result is never a pass. Other binary files, such as images and archives, are listed
/// but do not change the status.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a local directory or a remote git repository.
    Scan {
        /// Path to a local directory or an https:// URL of a git repository.
        target: String,

        /// Exit with status 1 if any finding is at least this severe
        /// (info, low, medium, high, critical), or `none` to never fail
        /// because of findings.
        #[arg(
            long,
            value_name = "SEVERITY",
            default_value = "high",
            value_parser = fail_on::parse
        )]
        fail_on: FailOn,

        /// Branch or tag to scan. Only for remote repositories; by default
        /// the repository's default branch is scanned.
        #[arg(long = "ref", value_name = "REF")]
        git_ref: Option<String>,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            // The error chain can quote a URL (a failed clone, git's own
            // message), so it is cleaned as a whole before it is printed.
            eprintln!("Error: {}", redact_credentials(&format!("{err:?}")));
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan {
            target,
            fail_on,
            git_ref,
        } => scan(&target, git_ref.as_deref(), fail_on),
    }
}

fn scan(raw_target: &str, git_ref: Option<&str>, fail_on: FailOn) -> Result<ExitCode> {
    match Target::parse(raw_target) {
        Target::Local(path) => {
            if git_ref.is_some() {
                bail!(
                    "--ref selects what to clone, so it only works with a remote repository; \
                     check out the branch or tag yourself before scanning a local directory"
                );
            }
            // A URL with credentials that did not look like one (no scheme,
            // a typo in it) ends up here, so the path is shown redacted.
            let root = path.canonicalize().with_context(|| {
                format!("cannot access {}", redact_path(&path.to_string_lossy()))
            })?;
            if !root.is_dir() {
                bail!(
                    "{} is not a directory",
                    redact_path(&root.to_string_lossy())
                );
            }
            scan_dir(&root, &HashSet::new(), raw_target, fail_on)
        }
        Target::Remote(url) => {
            clone::validate(&url, git_ref)?;
            eprintln!("Cloning {}", redact_credentials(&url));
            // `checkout` must stay alive until the scan ends: dropping it
            // deletes the cloned files.
            let checkout = clone::shallow_clone(&url, git_ref)?;
            let label = match git_ref {
                Some(git_ref) => format!("{} (ref {git_ref})", redact_credentials(raw_target)),
                None => redact_credentials(raw_target),
            };
            scan_dir(checkout.path(), &checkout.symlinks, &label, fail_on)
        }
    }
}

/// Scans `root`. `links` lists files that the repository records as symbolic
/// links although they are plain files on disk (a clone, see
/// `clone::Checkout`); it is empty for a local folder, whose links are real.
fn scan_dir(
    root: &Path,
    links: &HashSet<PathBuf>,
    label: &str,
    fail_on: FailOn,
) -> Result<ExitCode> {
    let rules = builtin_rules().context("failed to load built-in rules")?;
    let report = repo_sniff_core::scan_with_links(root, &rules, Limits::default(), links);
    print!("{}", report::render(&report, label));

    Ok(ExitCode::from(exit_status(&report, fail_on)))
}

/// The exit status for a finished scan: findings at the threshold come first,
/// then an inconclusive scan, otherwise success.
fn exit_status(report: &Report, fail_on: FailOn) -> u8 {
    if fail_on.is_triggered_by(report) {
        EXIT_FINDINGS
    } else if !report.is_complete() {
        EXIT_INCONCLUSIVE
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use repo_sniff_core::{Finding, Severity, SkipReason, Skipped, Stage};

    use super::*;

    fn finding(severity: Severity) -> Finding {
        Finding {
            rule_id: "test.rule".to_string(),
            severity,
            stage: Stage::Run,
            attack: vec![],
            file: PathBuf::from("a"),
            line: 1,
            column: None,
            span: None,
            snippet: None,
            explanation: String::new(),
        }
    }

    fn with_skip(reason: SkipReason) -> Report {
        Report {
            skipped: vec![Skipped {
                path: PathBuf::from("x"),
                reason,
            }],
            ..Report::default()
        }
    }

    #[test]
    fn a_clean_complete_scan_exits_zero() {
        assert_eq!(
            exit_status(&Report::default(), FailOn::AtLeast(Severity::High)),
            0
        );
    }

    #[test]
    fn findings_at_the_threshold_exit_one_even_when_the_scan_is_incomplete() {
        let report = Report {
            findings: vec![finding(Severity::High)],
            truncated: true,
            ..Report::default()
        };
        assert_eq!(exit_status(&report, FailOn::AtLeast(Severity::High)), 1);
    }

    #[test]
    fn a_walk_cut_short_is_inconclusive_even_with_fail_on_none() {
        // A payload padded past the file limit leaves no findings at all.
        let report = Report {
            truncated: true,
            ..Report::default()
        };
        assert_eq!(exit_status(&report, FailOn::AtLeast(Severity::High)), 3);
        assert_eq!(exit_status(&report, FailOn::Never), 3);
    }

    #[test]
    fn only_unread_or_executable_skips_are_inconclusive() {
        let status = |reason| exit_status(&with_skip(reason), FailOn::AtLeast(Severity::High));
        assert_eq!(status(SkipReason::TooLarge { size: 9 }), 3);
        assert_eq!(
            status(SkipReason::Unreadable {
                error: "denied".to_string()
            }),
            3
        );
        assert_eq!(
            status(SkipReason::Executable {
                format: "ELF",
                reported: false,
            }),
            3
        );
        assert_eq!(status(SkipReason::Binary), 0);
        assert_eq!(status(SkipReason::Symlink { target: None }), 0);
    }
}
