//! The `ide.vscode-folder-open-task` rule against its fixtures.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use repo_sniff_core::{Finding, Limits, Report, Severity, SkipReason, Stage, builtin_rules, scan};

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

/// Scans a repository whose only file is `.vscode/tasks.json`.
fn scan_tasks(contents: &[u8], limits: Limits) -> Report {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".vscode").join("tasks.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, contents).unwrap();
    scan(dir.path(), &builtin_rules().unwrap(), limits)
}

#[test]
fn a_tasks_file_the_jsonc_rule_cannot_read_whole_is_listed_not_judged() {
    // Pins today's behaviour: the jsonc rule only sees files read whole, and
    // the file is listed instead, so the scan is never reported as clean.
    let autorun = br#"{"tasks": [{"label": "x", "runOptions": {"runOn": "folderOpen"}}]}"#;
    let size = autorun.len() as u64;
    let reasons = |report: &Report| -> Vec<SkipReason> {
        report.skipped.iter().map(|s| s.reason.clone()).collect()
    };

    // Over the hard limit: not read at all.
    let tiny = Limits {
        max_file_size: 10,
        ..Limits::default()
    };
    let report = scan_tasks(autorun, tiny);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(report.files_scanned, 0);
    assert_eq!(reasons(&report), [SkipReason::TooLarge { size }]);

    // Over the in-memory limit: the line rules read it as a stream, and it is
    // listed as too large for the jsonc rule.
    let streamed = Limits {
        max_buffered_size: 10,
        ..Limits::default()
    };
    let report = scan_tasks(autorun, streamed);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(report.files_scanned, 1);
    assert_eq!(reasons(&report), [SkipReason::TooLarge { size }]);
    assert!(!report.is_complete());

    // An executable under that name: listed as one, never parsed or counted.
    let mut elf = b"\x7fELF\x02\x01\x01\0".to_vec();
    elf.extend_from_slice(autorun);
    let report = scan_tasks(&elf, Limits::default());
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(report.files_scanned, 0);
    assert_eq!(
        reasons(&report),
        [SkipReason::Executable {
            format: "ELF",
            reported: false
        }]
    );
}

#[test]
fn many_auto_run_tasks_are_all_listed_in_linear_time() {
    // Counting lines from the start of the file for every task made this
    // quadratic: 20 000 tasks took minutes. Each task is on its own line, and
    // every task must still be listed (the jsonc rule has no cap).
    let count = 20_000;
    let mut text = String::from("{\"tasks\": [\n");
    for index in 0..count {
        let comma = if index + 1 < count { "," } else { "" };
        text.push_str(&format!(
            "{{\"label\": \"t{index}\", \"runOptions\": {{\"runOn\": \"folderOpen\"}}}}{comma}\n"
        ));
    }
    text.push_str("]}\n");

    let started = std::time::Instant::now();
    let report = scan_tasks(text.as_bytes(), Limits::default());
    let elapsed = started.elapsed();

    let lines: Vec<usize> = report.findings.iter().map(|f| f.line).collect();
    assert_eq!(lines, (2..2 + count).collect::<Vec<_>>());
    assert!(
        elapsed < std::time::Duration::from_secs(20),
        "took {elapsed:?}"
    );
}
