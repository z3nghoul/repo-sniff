mod clone;
mod fail_on;
mod report;
mod target;

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use repo_sniff_core::{Limits, builtin_rules};

use crate::fail_on::FailOn;
use crate::target::Target;

/// Exit status when the scan found something at or above `--fail-on`.
const EXIT_FINDINGS: u8 = 1;
/// Exit status when the scan could not run (bad target, clone failure, ...).
/// clap also uses 2 for command-line mistakes.
const EXIT_ERROR: u8 = 2;

/// Statically scan a repository for signs of malicious or suspicious code.
///
/// Exit status: 0 when nothing reaches the --fail-on threshold, 1 when
/// something does, 2 when the scan could not run.
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
        /// Path to a local directory or a git URL (https://, ssh://, git@...).
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
            eprintln!("Error: {err:?}");
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
            let root = path
                .canonicalize()
                .with_context(|| format!("cannot access {}", path.display()))?;
            if !root.is_dir() {
                bail!("{} is not a directory", root.display());
            }
            scan_dir(&root, raw_target, fail_on)
        }
        Target::Remote(url) => {
            eprintln!("Cloning {url}");
            // `checkout` must stay alive until the scan ends: dropping it
            // deletes the cloned files.
            let checkout = clone::shallow_clone(&url, git_ref)?;
            let label = match git_ref {
                Some(git_ref) => format!("{raw_target} (ref {git_ref})"),
                None => raw_target.to_string(),
            };
            scan_dir(checkout.path(), &label, fail_on)
        }
    }
}

fn scan_dir(root: &Path, label: &str, fail_on: FailOn) -> Result<ExitCode> {
    let rules = builtin_rules().context("failed to load built-in rules")?;
    let report = repo_sniff_core::scan(root, &rules, Limits::default());
    print!("{}", report::render(&report, label));

    Ok(if fail_on.is_triggered_by(&report) {
        ExitCode::from(EXIT_FINDINGS)
    } else {
        ExitCode::SUCCESS
    })
}
