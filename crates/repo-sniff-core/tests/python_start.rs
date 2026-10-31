//! The `deps.python-start-entrypoint` rule: the fixture table, and cases that
//! need raw bytes a text fixture cannot carry.

use std::fs;
use std::path::{Path, PathBuf};

use repo_sniff_core::{Limits, Report, Severity, SkipReason, builtin_rules, scan};

const RULE_ID: &str = "deps.python-start-entrypoint";
const PTH_RULE_ID: &str = "deps.python-pth-exec";
const MARKER: &str = "# SYNTHETIC TEST FIXTURE \u{2014} not functional";
const ENTRY: &str = "demo.mod:run";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/python-start")
}

fn slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

type Row = (String, usize, Severity);

fn rows_of(report: &Report, rule_id: &str) -> Vec<Row> {
    let mut rows: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.rule_id == rule_id)
        .map(|f| (slash(&f.file), f.line, f.severity))
        .collect();
    rows.sort();
    rows
}

fn rows(report: &Report) -> Vec<Row> {
    rows_of(report, RULE_ID)
}

fn scan_dir(dir: &Path, limits: Limits) -> Report {
    scan(dir, &builtin_rules().unwrap(), limits)
}

fn row(file: &str, line: usize, severity: Severity) -> Row {
    (file.to_string(), line, severity)
}

// ------------------------------------------------------------ fixture table

fn list_dirs(dir: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect();
    paths.sort();
    paths
}

/// `positive/<group>/<case>` and `negative/<case>`.
fn case_dirs() -> Vec<PathBuf> {
    let mut cases = Vec::new();
    for group in list_dirs(&fixtures().join("positive")) {
        cases.extend(list_dirs(&group));
    }
    cases.extend(list_dirs(&fixtures().join("negative")));
    cases
}

fn expected_rows() -> Vec<Row> {
    let table = fs::read_to_string(fixtures().join("expectations.tsv")).unwrap();
    let mut rows: Vec<_> = table
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let columns: Vec<&str> = line.split('\t').collect();
            assert_eq!(columns.len(), 3, "bad row `{line}`");
            (
                columns[0].to_string(),
                columns[1].parse().unwrap(),
                columns[2].parse().unwrap(),
            )
        })
        .collect();
    rows.sort();
    rows
}

#[test]
fn every_fixture_case_matches_the_expectation_table() {
    let mut found = Vec::new();
    let cases = case_dirs();
    for case in &cases {
        let report = scan_dir(case, Limits::default());
        let prefix = slash(case.strip_prefix(fixtures()).unwrap());
        for (file, line, severity) in rows(&report) {
            found.push((format!("{prefix}/{file}"), line, severity));
        }
    }
    found.sort();

    assert_eq!(found, expected_rows());
    assert!(cases.len() >= 15, "only {} cases were found", cases.len());
}

#[test]
fn a_matching_start_file_never_lowers_the_pth_finding() {
    // In Python 3.15 a foo.start next to foo.pth suppresses the .pth's import
    // lines, but older versions still run them, so the .pth stays HIGH.
    let report = scan_dir(
        &fixtures().join("positive/pairs/with-pth"),
        Limits::default(),
    );

    assert_eq!(rows(&report), [row("foo.start", 2, Severity::High)]);
    assert_eq!(
        rows_of(&report, PTH_RULE_ID),
        [row("foo.pth", 2, Severity::High)]
    );
}

#[test]
fn findings_name_the_entry_point_and_whether_the_module_is_in_the_repository() {
    let report = scan_dir(
        &fixtures().join("positive/entry-points/plain"),
        Limits::default(),
    );
    let finding = report
        .findings
        .iter()
        .find(|f| f.rule_id == RULE_ID)
        .unwrap();

    assert_eq!(finding.attack, ["T1546.018"]);
    assert!(
        finding.explanation.contains("`demo.mod:run`"),
        "{}",
        finding.explanation
    );
    assert!(
        finding
            .explanation
            .contains("module `demo` is not in this repository"),
        "{}",
        finding.explanation
    );

    let (report, _dir) = scan_files(
        &[
            ("a.start", format!("{ENTRY}\n").into_bytes()),
            ("demo/__init__.py", Vec::new()),
        ],
        Limits::default(),
    );
    let finding = report
        .findings
        .iter()
        .find(|f| f.rule_id == RULE_ID)
        .unwrap();
    assert!(
        finding
            .explanation
            .contains("module `demo` is in this repository"),
        "{}",
        finding.explanation
    );
}

// ------------------------------------------------------ cases built from bytes

fn scan_files(files: &[(&str, Vec<u8>)], limits: Limits) -> (Report, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    for (name, bytes) in files {
        let path = dir.path().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    let report = scan_dir(dir.path(), limits);
    (report, dir)
}

fn one(name: &str, bytes: Vec<u8>) -> Report {
    scan_files(&[(name, bytes)], Limits::default()).0
}

#[test]
fn a_byte_order_mark_at_the_start_is_dropped() {
    let mut bytes = b"\xEF\xBB\xBF".to_vec();
    bytes.extend(format!("{ENTRY}\n{MARKER}\n").bytes());

    assert_eq!(
        rows(&one("a.start", bytes)),
        [row("a.start", 1, Severity::High)]
    );
}

#[test]
fn empty_and_bom_only_files_produce_nothing() {
    assert_eq!(rows(&one("a.start", Vec::new())), []);
    assert_eq!(rows(&one("a.start", b"\xEF\xBB\xBF".to_vec())), []);
}

#[test]
fn a_file_that_is_not_utf8_is_ignored_because_python_ignores_it() {
    let mut bytes = b"# caf\xE9\n".to_vec();
    bytes.extend(format!("{ENTRY}\n").bytes());

    assert_eq!(rows(&one("a.start", bytes)), []);
}

#[test]
fn a_nul_byte_in_a_comment_does_not_hide_the_file() {
    let report = one("a.start", format!("# a\0b\n{ENTRY}\n").into_bytes());

    assert_eq!(rows(&report), [row("a.start", 2, Severity::High)]);
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
}

#[test]
fn an_oversized_start_file_is_a_finding_not_just_a_skip() {
    let mut bytes = vec![b'#'; 100];
    bytes.extend(format!("\n{ENTRY}\n").bytes());
    let limits = Limits {
        max_file_size: 60,
        ..Limits::default()
    };

    let (report, _dir) = scan_files(&[("big.start", bytes)], limits);

    assert_eq!(rows(&report), [row("big.start", 1, Severity::High)]);
    assert!(matches!(
        report.skipped[0].reason,
        SkipReason::TooLarge { .. }
    ));
}

#[test]
fn an_oversized_file_python_ignores_is_low() {
    let limits = Limits {
        max_file_size: 10,
        ..Limits::default()
    };

    let (report, _dir) = scan_files(&[(".big.start", vec![b'#'; 100])], limits);

    assert_eq!(rows(&report), [row(".big.start", 1, Severity::Low)]);
}

#[cfg(unix)]
#[test]
fn a_symlinked_start_file_is_a_finding_and_its_target_is_checked() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("notes.txt"), format!("{MARKER}\n{ENTRY}\n")).unwrap();
    std::os::unix::fs::symlink("notes.txt", dir.path().join("evil.start")).unwrap();

    let report = scan_dir(dir.path(), Limits::default());

    assert_eq!(
        rows(&report),
        [
            row("evil.start", 1, Severity::High),
            row("evil.start", 2, Severity::High),
        ]
    );
}

#[test]
fn a_huge_file_of_entry_points_stays_bounded() {
    let bytes = format!("{ENTRY}\n").repeat(100_000).into_bytes();

    let report = one("flood.start", bytes);

    assert_eq!(
        rows(&report).len(),
        100,
        "the engine caps findings per file"
    );
    let last = report.findings.last().unwrap();
    assert!(
        last.explanation.contains("not listed"),
        "{}",
        last.explanation
    );
}
