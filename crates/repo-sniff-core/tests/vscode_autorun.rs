//! The `ide.vscode-folder-open-task` rule against its fixtures.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use repo_sniff_core::{Finding, Limits, Severity, Stage, builtin_rules, scan};

const RULE_ID: &str = "ide.vscode-folder-open-task";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vscode-autorun")
}

/// Reports use `/` on every OS, so compare paths the same way.
fn slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn scan_fixtures() -> (Vec<Finding>, usize) {
    let rules = builtin_rules().unwrap();
    let report = scan(&fixtures(), &rules, Limits::default());
    let findings = report
        .findings
        .into_iter()
        .filter(|f| f.rule_id == RULE_ID)
        .collect();
    (findings, report.files_scanned)
}

#[test]
fn positive_fixtures_are_flagged_and_negative_ones_are_not() {
    let (findings, files_scanned) = scan_fixtures();

    let found: BTreeMap<String, (usize, Severity)> = findings
        .iter()
        .map(|f| (slash(&f.file), (f.line, f.severity)))
        .collect();

    // (line, severity) per file. The marker comment is line 1 of each fixture.
    let expected: BTreeMap<String, (usize, Severity)> = [
        ("positive/crlf/.vscode/tasks.json", 4, Severity::High),
        (
            "positive/download-critical/.vscode/tasks.json",
            6,
            Severity::Critical,
        ),
        ("positive/escaped-key/.vscode/tasks.json", 2, Severity::High),
        ("positive/plain/.vscode/tasks.json", 8, Severity::High),
        ("positive/split-lines/.vscode/tasks.json", 6, Severity::High),
        ("positive/unparseable/.vscode/tasks.json", 2, Severity::High),
        (
            "positive/windows-override/.vscode/tasks.json",
            7,
            Severity::Critical,
        ),
        ("positive/workspace/app.code-workspace", 6, Severity::High),
    ]
    .into_iter()
    .map(|(file, line, severity)| (file.to_string(), (line, severity)))
    .collect();

    assert_eq!(found, expected);
    assert_eq!(findings.len(), expected.len(), "one finding per fixture");
    assert_eq!(files_scanned, 14, "every fixture should have been read");
}

#[test]
fn findings_carry_rule_metadata_and_a_specific_explanation() {
    let (findings, _) = scan_fixtures();

    let plain = findings
        .iter()
        .find(|f| slash(&f.file) == "positive/plain/.vscode/tasks.json")
        .unwrap();
    assert_eq!(plain.stage, Stage::Ide);
    assert!(
        plain.explanation.contains("\"build\""),
        "{}",
        plain.explanation
    );

    let download = findings
        .iter()
        .find(|f| slash(&f.file) == "positive/download-critical/.vscode/tasks.json")
        .unwrap();
    assert!(
        download.explanation.contains("\"curl\""),
        "{}",
        download.explanation
    );

    let windows = findings
        .iter()
        .find(|f| slash(&f.file) == "positive/windows-override/.vscode/tasks.json")
        .unwrap();
    assert!(
        windows.explanation.contains("\"powershell\""),
        "{}",
        windows.explanation
    );

    let broken = findings
        .iter()
        .find(|f| slash(&f.file) == "positive/unparseable/.vscode/tasks.json")
        .unwrap();
    assert!(
        broken.explanation.contains("could not be parsed"),
        "{}",
        broken.explanation
    );
}
