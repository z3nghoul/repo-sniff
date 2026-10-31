//! Plain-text report for the terminal and CI logs.

use std::fmt::Write;

use repo_sniff_core::{Report, Severity, SkipReason};

/// Severity levels from most to least serious, the order the report uses.
const SEVERITIES_DESC: [Severity; 5] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Info,
];

/// At most this many skipped paths are listed; the rest are only counted.
const MAX_SKIPPED_SHOWN: usize = 10;

/// Renders `report` as plain text. `target` is what the user asked to scan
/// (a path or URL), shown instead of a temporary clone directory.
pub fn render(report: &Report, target: &str) -> String {
    let mut out = String::new();
    // Writing to a String cannot fail, so the `fmt::Result`s are ignored.
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
            finding.file.display(),
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

    if !report.skipped.is_empty() {
        let _ = writeln!(out, "Not scanned ({}):", report.skipped.len());
        for skipped in report.skipped.iter().take(MAX_SKIPPED_SHOWN) {
            let reason = match &skipped.reason {
                SkipReason::TooLarge { size } => format!("too large ({size} bytes)"),
                SkipReason::Symlink => "symlink, not followed".to_string(),
                SkipReason::Unreadable { error } => format!("unreadable: {error}"),
            };
            let _ = writeln!(out, "  {}  {reason}", skipped.path.display());
        }
        if report.skipped.len() > MAX_SKIPPED_SHOWN {
            let hidden = report.skipped.len() - MAX_SKIPPED_SHOWN;
            let _ = writeln!(out, "  ... and {hidden} more");
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
    out
}
