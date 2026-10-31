//! The `deps.python-pth-exec` rule: the fixture table, and cases that need
//! raw bytes a text fixture cannot carry.

use std::fs;
use std::path::{Path, PathBuf};

use repo_sniff_core::{Finding, Limits, Report, Severity, SkipReason, Stage, builtin_rules, scan};

const RULE_ID: &str = "deps.python-pth-exec";
const MARKER: &str = "# SYNTHETIC TEST FIXTURE \u{2014} not functional";
const PAYLOAD: &str = "import sys; print('hello')";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/python-pth")
}

fn slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn severity(name: &str) -> Severity {
    name.parse()
        .unwrap_or_else(|_| panic!("bad severity `{name}`"))
}

/// Findings of this rule in a report as `(file, line, severity)`, sorted.
fn rows(report: &Report) -> Vec<(String, usize, Severity)> {
    let mut rows: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.rule_id == RULE_ID)
        .map(|f| (slash(&f.file), f.line, f.severity))
        .collect();
    rows.sort();
    rows
}

fn scan_dir(dir: &Path, limits: Limits) -> Report {
    scan(dir, &builtin_rules().unwrap(), limits)
}

// ------------------------------------------------------------ fixture table

/// Every case directory: `positive/<group>/<case>` and `negative/<case>`.
fn case_dirs() -> Vec<PathBuf> {
    let list = |dir: &Path| -> Vec<PathBuf> {
        let mut paths: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.is_dir())
            .collect();
        paths.sort();
        paths
    };
    let mut cases = Vec::new();
    for group in list(&fixtures().join("positive")) {
        cases.extend(list(&group));
    }
    cases.extend(list(&fixtures().join("negative")));
    cases
}

fn expected_rows() -> Vec<(String, usize, Severity)> {
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
                severity(columns[2]),
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
    assert!(cases.len() >= 70, "only {} cases were found", cases.len());
}

#[test]
fn every_positive_case_has_at_least_one_expected_finding_and_no_negative_one_has() {
    let expected = expected_rows();
    for case in case_dirs() {
        let prefix = format!("{}/", slash(case.strip_prefix(fixtures()).unwrap()));
        let count = expected
            .iter()
            .filter(|(file, _, _)| file.starts_with(&prefix))
            .count();
        if prefix.starts_with("positive/") {
            assert!(count > 0, "positive case {prefix} expects nothing");
        } else {
            assert_eq!(count, 0, "negative case {prefix} expects findings");
        }
    }
}

// ------------------------------------------------------------ explanations

fn explanation_of(case: &str, file: &str) -> String {
    let dir = fixtures().join(case);
    let report = scan_dir(&dir, Limits::default());
    report
        .findings
        .iter()
        .find(|f| f.rule_id == RULE_ID && slash(&f.file) == file)
        .unwrap_or_else(|| panic!("no finding for {case}/{file}"))
        .explanation
        .clone()
}

#[test]
fn findings_carry_rule_metadata() {
    let report = scan_dir(
        &fixtures().join("positive/executes/plain"),
        Limits::default(),
    );
    let finding: &Finding = &report.findings[0];
    assert_eq!(finding.stage, Stage::Deps);
    assert_eq!(finding.attack, ["T1546.018"]);
    assert_eq!(finding.severity, Severity::High);
}

#[test]
fn honest_forms_say_whether_their_module_is_in_the_repository() {
    let absent = explanation_of(
        "positive/honest/virtualenv-without-module",
        "_virtualenv.pth",
    );
    assert!(
        absent.contains("module `_virtualenv` is not in this repository"),
        "{absent}"
    );

    let present = explanation_of("positive/honest/virtualenv-with-module", "_virtualenv.pth");
    assert!(
        present.contains("module `_virtualenv` is in this repository"),
        "{present}"
    );
}

#[test]
fn critical_findings_say_why() {
    let why = explanation_of("positive/critical/form-feed-hidden-keyword", "demo.pth");
    assert!(why.contains("uses `exec`"), "{why}");
    let why = explanation_of("positive/critical/long-line", "demo.pth");
    assert!(why.contains("characters long"), "{why}");
    let why = explanation_of("positive/critical/high-entropy-base64", "demo.pth");
    assert!(why.contains("encoded data"), "{why}");
}

#[test]
fn files_python_never_reads_say_so() {
    let why = explanation_of("positive/inert/dot-prefixed", ".hidden.pth");
    assert!(why.contains("name starts with a dot"), "{why}");
    let why = explanation_of("positive/inert/upper-extension", "UPPER.PTH");
    assert!(why.contains("not exactly lowercase"), "{why}");
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

fn text(parts: &[&str]) -> Vec<u8> {
    parts.concat().into_bytes()
}

fn row(file: &str, line: usize, severity: Severity) -> (String, usize, Severity) {
    (file.to_string(), line, severity)
}

#[test]
fn a_byte_order_mark_at_the_start_of_the_file_is_dropped() {
    let mut bytes = b"\xEF\xBB\xBF".to_vec();
    bytes.extend(format!("{PAYLOAD}\n{MARKER}\n").bytes());

    assert_eq!(
        rows(&one("a.pth", bytes)),
        [row("a.pth", 1, Severity::High)]
    );
}

#[test]
fn empty_files_and_bom_only_files_produce_nothing() {
    assert_eq!(rows(&one("a.pth", Vec::new())), []);
    assert_eq!(rows(&one("a.pth", b"\xEF\xBB\xBF".to_vec())), []);
}

#[test]
fn a_nul_byte_in_a_comment_does_not_hide_the_file() {
    let report = one("a.pth", text(&["# a\0b\n", PAYLOAD, "\n"]));

    assert_eq!(rows(&report), [row("a.pth", 2, Severity::High)]);
    // It was examined, so it is neither skipped nor a "binary file".
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
    assert_eq!(report.files_scanned, 1);
}

#[test]
fn a_zip_header_followed_by_an_import_line_still_runs() {
    let mut bytes = b"PK\x03\x04\0\0\0\0\n".to_vec();
    bytes.extend(format!("{PAYLOAD}\n").bytes());

    assert_eq!(
        rows(&one("evil.pth", bytes)),
        [row("evil.pth", 2, Severity::High)]
    );
}

#[test]
fn a_binary_model_file_is_reported_as_not_text_but_not_as_code() {
    let mut bytes = b"PK\x03\x04\xFF\xFE".to_vec();
    bytes.extend([0u8; 8]);

    assert_eq!(
        rows(&one("model.pth", bytes)),
        [
            row("model.pth", 1, Severity::Info),
            row("model.pth", 1, Severity::Medium)
        ]
    );
}

#[test]
fn invalid_utf8_is_reported_and_does_not_hide_an_import_line() {
    let mut bytes = b"# caf\xE9\n".to_vec();
    bytes.extend(format!("{PAYLOAD}\n").bytes());

    assert_eq!(
        rows(&one("a.pth", bytes)),
        [
            row("a.pth", 1, Severity::Medium),
            row("a.pth", 2, Severity::High)
        ]
    );
}

#[test]
fn a_raw_byte_before_import_may_be_whitespace_in_another_encoding() {
    // 0xA0 is a no-break space in Windows-1252, which Python 3.15 strips.
    let mut bytes = b"\xA0".to_vec();
    bytes.extend(format!("{PAYLOAD}\n").bytes());

    assert_eq!(
        rows(&one("a.pth", bytes)),
        [
            row("a.pth", 1, Severity::Medium),
            row("a.pth", 1, Severity::High)
        ]
    );
}

#[test]
fn invalid_utf8_in_a_file_python_ignores_is_not_reported() {
    let bytes = b"# caf\xE9\n".to_vec();

    assert_eq!(rows(&one(".hidden.pth", bytes)), []);
}

#[test]
fn an_oversized_pth_file_is_a_finding_not_just_a_skip() {
    let mut bytes = vec![b'#'; 100];
    bytes.extend(format!("\n{PAYLOAD}\n").bytes());
    let limits = Limits {
        max_file_size: 60,
        ..Limits::default()
    };

    let (report, _dir) = scan_files(&[("big.pth", bytes)], limits);

    assert_eq!(rows(&report), [row("big.pth", 1, Severity::High)]);
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

    let (report, _dir) = scan_files(&[(".big.pth", vec![b'#'; 100])], limits);

    assert_eq!(rows(&report), [row(".big.pth", 1, Severity::Low)]);
}

#[cfg(unix)]
#[test]
fn a_symlinked_pth_file_is_a_finding_and_its_target_is_checked() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("notes.txt"),
        format!("{MARKER}\n{PAYLOAD}\n"),
    )
    .unwrap();
    std::os::unix::fs::symlink("notes.txt", dir.path().join("evil.pth")).unwrap();
    std::os::unix::fs::symlink("../elsewhere.txt", dir.path().join("out.pth")).unwrap();

    let report = scan_dir(dir.path(), Limits::default());

    assert_eq!(
        rows(&report),
        [
            row("evil.pth", 1, Severity::High),
            row("evil.pth", 2, Severity::High),
            row("out.pth", 1, Severity::High),
        ]
    );
    let symlinks = report
        .skipped
        .iter()
        .filter(|s| matches!(s.reason, SkipReason::Symlink { .. }))
        .count();
    assert_eq!(symlinks, 2, "both links are still listed as not followed");
}

#[test]
fn a_cut_short_walk_does_not_lower_an_honest_form() {
    // `_virtualenv.pth` sorts first, so the walk reads it and then stops.
    let files = [
        ("_virtualenv.pth", b"import _virtualenv\n".to_vec()),
        ("b.txt", b"x".to_vec()),
        ("c.txt", b"x".to_vec()),
    ];
    let limits = Limits {
        max_files: 1,
        ..Limits::default()
    };

    let (report, _dir) = scan_files(&files, limits);

    assert!(report.truncated);
    assert_eq!(rows(&report), [row("_virtualenv.pth", 1, Severity::Medium)]);
    let finding = &report.findings[0];
    assert!(
        finding.explanation.contains("cut short"),
        "{}",
        finding.explanation
    );
}

#[test]
fn a_directory_named_like_a_pth_file_is_harmless() {
    let (report, _dir) = scan_files(
        &[("evil.pth/notes.txt", PAYLOAD.as_bytes().to_vec())],
        Limits::default(),
    );

    assert_eq!(rows(&report), []);
}

#[test]
fn a_huge_file_of_import_lines_stays_bounded() {
    // Many executable lines in one physical line, separated by form feeds.
    let bytes = "import x\x0C".repeat(100_000).into_bytes();

    let report = one("flood.pth", bytes);

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
