//! Plain-text report for the terminal and CI logs.

use std::fmt::Write;

use repo_sniff_core::{Report, Severity, SkipReason, display_path, display_safe};

use crate::redact::redact_credentials;

/// Severity levels from most to least serious, the order the report uses.
const SEVERITIES_DESC: [Severity; 5] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Info,
];

/// Skip reasons can quote OS error text that contains file names.
const MAX_REASON_CHARS: usize = 300;

/// Renders `report` as plain text. `target` is what the user asked to scan
/// (a path or URL), shown instead of a temporary clone directory.
pub fn render(report: &Report, target: &str) -> String {
    let mut out = String::new();
    // Writing to a String cannot fail, so the `fmt::Result`s are ignored.
    // The label is what the user typed, so it may hold a token in the URL.
    let target = redact_credentials(target);
    let _ = writeln!(out, "Scanned {} files in {target}\n", report.files_scanned);

    let mut findings: Vec<_> = report.findings.iter().collect();
    // Most severe first; the core already sorted by file and line, and a
    // stable sort keeps that order within each severity.
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));

    if findings.is_empty() {
        let _ = writeln!(out, "No findings.\n");
    }
    for finding in findings {
        let _ = writeln!(
            out,
            "{:<8}  {}:{}  {}  [{}]",
            finding.severity.code(),
            display_path(&finding.file),
            finding.line,
            finding.rule_id,
            finding.stage,
        );
        let _ = writeln!(out, "          {}", finding.explanation);
        if !finding.attack.is_empty() {
            let _ = writeln!(out, "          ATT&CK: {}", finding.attack.join(", "));
        }
        let _ = writeln!(out);
    }

    // Findings cut by the per-file limit, one line per file with the levels.
    let mut files: Vec<&std::path::Path> = Vec::new();
    for unlisted in &report.unlisted {
        if !files.contains(&unlisted.file.as_path()) {
            files.push(&unlisted.file);
        }
    }
    for file in files {
        let of_file = || report.unlisted.iter().filter(|u| u.file == file);
        let total: usize = of_file().map(|u| u.count).sum();
        let levels: Vec<String> = SEVERITIES_DESC
            .iter()
            .filter_map(|&severity| {
                let n: usize = of_file()
                    .filter(|u| u.severity == severity)
                    .map(|u| u.count)
                    .sum();
                (n > 0).then(|| format!("{n} {}", severity.code()))
            })
            .collect();
        let _ = writeln!(
            out,
            "{}  {total} more findings in this file not shown ({})\n",
            display_path(file),
            levels.join(", ")
        );
    }

    if !report.skipped.is_empty() {
        let _ = writeln!(
            out,
            "Not fully analyzed ({}): {}",
            report.skipped.len(),
            skip_breakdown(report)
        );
        // Every entry is listed, never a prefix. The ones that make the scan
        // inconclusive come first, so the reader sees what to deal with.
        let mut skipped: Vec<_> = report.skipped.iter().collect();
        skipped
            .sort_by(|a, b| (skip_rank(&a.reason), &a.path).cmp(&(skip_rank(&b.reason), &b.path)));
        let causes = skipped
            .iter()
            .filter(|s| s.reason.makes_scan_inconclusive())
            .count();
        for (index, entry) in skipped.iter().enumerate() {
            if causes > 0 && index == 0 {
                let _ = writeln!(out, "Make the scan INCONCLUSIVE ({causes}):");
            }
            if causes > 0 && index == causes {
                let others = skipped.len() - causes;
                let _ = writeln!(out, "Do not change the result ({others}):");
            }
            let _ = writeln!(
                out,
                "  {}  {}",
                display_path(&entry.path),
                display_safe(&skip_text(&entry.reason), MAX_REASON_CHARS)
            );
        }
        let _ = writeln!(out);
    }
    if report.truncated {
        let _ = writeln!(
            out,
            "Warning: file limit reached, the scan is incomplete.\n"
        );
    }

    let counts: Vec<String> = SEVERITIES_DESC
        .iter()
        .map(|&severity| {
            let n = report
                .findings
                .iter()
                .filter(|f| f.severity == severity)
                .count();
            format!("{n} {}", severity.code().to_lowercase())
        })
        .collect();
    let _ = writeln!(out, "Summary: {}", counts.join(", "));
    let _ = writeln!(out, "{}", completeness(report));
    out
}

/// Sort key for the list of skipped files: the reasons that make the scan
/// inconclusive first, then the rest, each kind together.
fn skip_rank(reason: &SkipReason) -> u8 {
    match reason {
        SkipReason::Executable { .. } => 0,
        SkipReason::TooLarge { .. } => 1,
        SkipReason::Unreadable { .. } => 2,
        SkipReason::GitMetadata { nested: true } => 3,
        SkipReason::Binary => 4,
        SkipReason::Symlink { .. } => 5,
        SkipReason::GitMetadata { nested: false } => 6,
    }
}

fn skip_text(reason: &SkipReason) -> String {
    match reason {
        SkipReason::TooLarge { size } => format!("too large ({size} bytes)"),
        SkipReason::Symlink { .. } => "symlink, not followed".to_string(),
        SkipReason::Binary => "binary format, ASCII rules only".to_string(),
        SkipReason::Executable { format } => {
            format!("executable binary ({format}), not analyzed")
        }
        SkipReason::Unreadable { error } => format!("unreadable: {error}"),
        SkipReason::GitMetadata { nested: false } => "git metadata, not analyzed".to_string(),
        SkipReason::GitMetadata { nested: true } => {
            "nested git repository, not analyzed".to_string()
        }
    }
}

/// A short count of what was skipped, by reason.
fn skip_breakdown(report: &Report) -> String {
    let count = |wanted: fn(&SkipReason) -> bool| {
        report.skipped.iter().filter(|s| wanted(&s.reason)).count()
    };
    let parts = [
        (count(|r| matches!(r, SkipReason::Binary)), "binary"),
        (
            count(|r| matches!(r, SkipReason::Executable { .. })),
            "executable",
        ),
        (
            count(|r| matches!(r, SkipReason::TooLarge { .. })),
            "too large",
        ),
        (
            count(|r| matches!(r, SkipReason::Unreadable { .. })),
            "unreadable",
        ),
        (
            count(|r| matches!(r, SkipReason::Symlink { .. })),
            "symlink",
        ),
        (
            count(|r| matches!(r, SkipReason::GitMetadata { .. })),
            "git metadata",
        ),
    ];
    parts
        .iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, what)| format!("{n} {what}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The last line of the report: says whether "no findings" can be trusted.
fn completeness(report: &Report) -> String {
    let count = |wanted: fn(&SkipReason) -> bool| {
        report.skipped.iter().filter(|s| wanted(&s.reason)).count()
    };
    if report.is_complete() {
        let binaries = count(|r| matches!(r, SkipReason::Binary));
        let git = count(|r| matches!(r, SkipReason::GitMetadata { .. }));
        let mut notes = Vec::new();
        if binaries > 0 {
            notes.push(format!("{binaries} binary files were read as ASCII only"));
        }
        if git > 0 {
            notes.push("git metadata was not analyzed".to_string());
        }
        return if notes.is_empty() {
            "Scan: complete (every file was read)".to_string()
        } else {
            format!("Scan: complete (every file was read; {})", notes.join("; "))
        };
    }
    let mut reasons = Vec::new();
    if report.truncated {
        reasons.push("the file limit was reached".to_string());
    }
    let unread = count(|r| {
        matches!(
            r,
            SkipReason::TooLarge { .. } | SkipReason::Unreadable { .. }
        )
    });
    if unread > 0 {
        reasons.push(format!(
            "{unread} files could not be read (too large or unreadable)"
        ));
    }
    let executables = count(|r| matches!(r, SkipReason::Executable { .. }));
    if executables > 0 {
        reasons.push(format!(
            "{executables} executable binaries were not analyzed"
        ));
    }
    let nested = count(|r| matches!(r, SkipReason::GitMetadata { nested: true }));
    if nested > 0 {
        reasons.push(format!("{nested} nested git repositories were not read"));
    }
    format!(
        "Scan: INCONCLUSIVE ({}). Findings above may be incomplete, and a result without \
         findings does not mean the repository is clean.",
        reasons.join("; ")
    )
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use repo_sniff_core::{Finding, Skipped, Stage};

    use super::*;

    fn finding(file: PathBuf) -> Finding {
        Finding {
            rule_id: "test.rule".to_string(),
            severity: Severity::High,
            stage: Stage::Run,
            attack: vec![],
            file,
            line: 3,
            explanation: "because".to_string(),
        }
    }

    #[test]
    fn paths_are_relative_with_forward_slashes() {
        let report = Report {
            findings: vec![finding(Path::new("src").join("lib.rs"))],
            files_scanned: 1,
            ..Report::default()
        };
        let text = render(&report, "repo");
        assert!(
            text.contains("HIGH      src/lib.rs:3  test.rule  [run]"),
            "{text}"
        );
    }

    #[test]
    fn a_complete_scan_says_so() {
        let text = render(&Report::default(), "repo");

        assert!(text.contains("Scan: complete"), "{text}");
        assert!(!text.contains("INCONCLUSIVE"), "{text}");
    }

    #[test]
    fn an_incomplete_scan_says_why_and_warns_that_no_findings_is_not_clean() {
        let report = Report {
            truncated: true,
            skipped: vec![Skipped {
                path: PathBuf::from("tool"),
                reason: SkipReason::Executable { format: "ELF" },
            }],
            ..Report::default()
        };

        let text = render(&report, "repo");

        assert!(text.contains("Scan: INCONCLUSIVE"), "{text}");
        assert!(text.contains("the file limit was reached"), "{text}");
        assert!(
            text.contains("1 executable binaries were not analyzed"),
            "{text}"
        );
        assert!(
            text.contains("does not mean the repository is clean"),
            "{text}"
        );
    }

    #[test]
    fn unread_files_are_named_in_the_reasons() {
        let report = Report {
            skipped: vec![Skipped {
                path: PathBuf::from("big.txt"),
                reason: SkipReason::TooLarge { size: 9 },
            }],
            ..Report::default()
        };

        let text = render(&report, "repo");

        assert!(
            text.contains(
                "Scan: INCONCLUSIVE (1 files could not be read (too large or unreadable))"
            ),
            "{text}"
        );
    }

    #[test]
    fn binary_files_without_rules_are_listed_but_the_scan_stays_complete() {
        let skip = |name: &str| Skipped {
            path: PathBuf::from(name),
            reason: SkipReason::Binary,
        };
        let report = Report {
            skipped: vec![skip("a.gz"), skip("b.png")],
            ..Report::default()
        };

        let text = render(&report, "repo");

        assert!(text.contains("Not fully analyzed (2): 2 binary"), "{text}");
        assert!(
            text.contains(
                "Scan: complete (every file was read; 2 binary files were read as ASCII only)"
            ),
            "{text}"
        );
        assert!(!text.contains("INCONCLUSIVE"), "{text}");
    }

    #[test]
    fn findings_cut_by_the_per_file_limit_are_counted_in_the_report() {
        let report = Report {
            unlisted: vec![repo_sniff_core::Unlisted {
                file: PathBuf::from("src/big.js"),
                rule_id: "test.rule".to_string(),
                severity: Severity::Low,
                count: 42,
            }],
            ..Report::default()
        };

        let text = render(&report, "repo");

        assert!(
            text.contains("src/big.js  42 more findings in this file not shown (42 LOW)"),
            "{text}"
        );
    }

    #[test]
    fn a_lone_symlink_does_not_make_the_report_inconclusive() {
        let report = Report {
            skipped: vec![Skipped {
                path: PathBuf::from("link"),
                reason: SkipReason::Symlink { target: None },
            }],
            ..Report::default()
        };

        assert!(render(&report, "repo").contains("Scan: complete"));
    }

    #[test]
    fn credentials_in_the_target_label_are_hidden() {
        let report = Report::default();

        let text = render(&report, "https://TOKEN@github.com/owner/repo (ref v1)");

        assert!(!text.contains("TOKEN"), "{text}");
        assert!(
            text.contains("Scanned 0 files in https://***@github.com/owner/repo (ref v1)"),
            "{text}"
        );
    }

    #[test]
    fn every_kind_of_skipped_file_is_listed_with_its_reason() {
        let skip = |name: &str, reason| Skipped {
            path: PathBuf::from(name),
            reason,
        };
        let report = Report {
            skipped: vec![
                skip("a.bin", SkipReason::Binary),
                skip("tool", SkipReason::Executable { format: "ELF" }),
                skip("big.txt", SkipReason::TooLarge { size: 99 }),
                skip("link", SkipReason::Symlink { target: None }),
                skip(
                    "locked",
                    SkipReason::Unreadable {
                        error: "denied".to_string(),
                    },
                ),
            ],
            ..Report::default()
        };

        let text = render(&report, "repo");

        assert!(
            text.contains(
                "Not fully analyzed (5): 1 binary, 1 executable, 1 too large, 1 unreadable, 1 symlink"
            ),
            "{text}"
        );
        assert!(
            text.contains("a.bin  binary format, ASCII rules only"),
            "{text}"
        );
        assert!(
            text.contains("tool  executable binary (ELF), not analyzed"),
            "{text}"
        );
        assert!(text.contains("big.txt  too large (99 bytes)"), "{text}");
        assert!(text.contains("link  symlink, not followed"), "{text}");
        assert!(text.contains("locked  unreadable: denied"), "{text}");
    }

    #[test]
    fn every_skipped_file_is_listed_and_the_ones_behind_inconclusive_come_first() {
        let mut skipped: Vec<Skipped> = (0..30)
            .map(|n| Skipped {
                path: PathBuf::from(format!("img/{n:02}.png")),
                reason: SkipReason::Binary,
            })
            .collect();
        for name in ["vendor/z.dll", "a.exe"] {
            skipped.push(Skipped {
                path: PathBuf::from(name),
                reason: SkipReason::Executable { format: "PE" },
            });
        }
        let report = Report {
            skipped,
            ..Report::default()
        };

        let text = render(&report, "repo");

        assert!(!text.contains("more"), "{text}");
        for n in 0..30 {
            assert!(text.contains(&format!("img/{n:02}.png")), "{n}: {text}");
        }
        let position = |needle: &str| {
            text.find(needle)
                .unwrap_or_else(|| panic!("{needle}: {text}"))
        };
        assert!(position("Make the scan INCONCLUSIVE (2):") < position("a.exe"));
        assert!(position("a.exe") < position("vendor/z.dll"));
        assert!(position("vendor/z.dll") < position("Do not change the result (30):"));
        assert!(position("Do not change the result (30):") < position("img/00.png"));
    }

    #[test]
    fn without_a_cause_of_inconclusive_the_list_has_no_headings() {
        let report = Report {
            skipped: vec![Skipped {
                path: PathBuf::from("a.png"),
                reason: SkipReason::Binary,
            }],
            ..Report::default()
        };

        let text = render(&report, "repo");

        assert!(
            text.contains("  a.png  binary format, ASCII rules only"),
            "{text}"
        );
        assert!(!text.contains("Make the scan"), "{text}");
    }

    #[test]
    fn hostile_file_names_cannot_inject_terminal_escapes() {
        let hostile = PathBuf::from("a\u{1b}[2Jb\nHIGH      forged.rs:1");
        let report = Report {
            findings: vec![finding(hostile.clone())],
            skipped: vec![Skipped {
                path: hostile,
                reason: SkipReason::Symlink { target: None },
            }],
            files_scanned: 1,
            ..Report::default()
        };
        let text = render(&report, "repo");
        assert!(!text.contains('\u{1b}'), "{text:?}");
        // The newline in the name must not start a line that looks like a finding.
        assert!(
            text.lines()
                .all(|line| !line.starts_with("HIGH      forged")),
            "{text}"
        );
    }
}
