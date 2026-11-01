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

    // An executable under that name: never parsed or counted, listed as an
    // executable, and reported as one disguised as a JSON file.
    let mut elf = b"\x7fELF\x02\x01\x01\0".to_vec();
    elf.extend_from_slice(autorun);
    let report = scan_tasks(&elf, Limits::default());
    let rules: Vec<_> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert_eq!(rules, ["repo.disguised-executable"]);
    assert_eq!(report.files_scanned, 0);
    assert_eq!(
        reasons(&report),
        [SkipReason::Executable {
            format: "ELF",
            reported: true
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

/// VS Code follows a `.vscode/tasks.json` or `*.code-workspace` that is a
/// symbolic link, so the check judges the file the link points at (#63).
#[cfg(unix)]
#[test]
fn a_tasks_file_that_is_a_symlink_to_a_file_in_the_repository_is_judged() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let write = |relative: &str, contents: &str| {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    };
    // Named so that no rule reads them as tasks files on their own.
    write(
        "notes.txt",
        "{\n  \"tasks\": [\n    {\"label\": \"x\", \"command\": \"make\",\n     \"runOptions\": {\"runOn\": \"folderOpen\"}}\n  ]\n}\n",
    );
    write(
        "docs/workspace.txt",
        r#"{"tasks": {"tasks": [{"label": "x", "runOptions": {"runOn": "folderOpen"}}]}}"#,
    );
    write(
        "honest.txt",
        r#"{"tasks": [{"label": "build", "command": "make"}]}"#,
    );
    fs::create_dir_all(root.join(".vscode")).unwrap();
    fs::create_dir_all(root.join("other/.vscode")).unwrap();
    symlink("../notes.txt", root.join(".vscode/tasks.json")).unwrap();
    symlink("docs/workspace.txt", root.join("app.code-workspace")).unwrap();
    symlink("../../honest.txt", root.join("other/.vscode/tasks.json")).unwrap();

    let report = scan(root, &builtin_rules().unwrap(), Limits::default());

    let found: Vec<(String, usize, Severity)> = report
        .findings
        .iter()
        .filter(|f| f.rule_id == RULE_ID)
        .map(|f| (slash(&f.file), f.line, f.severity))
        .collect();
    assert_eq!(
        found,
        [
            (".vscode/tasks.json".to_string(), 4, Severity::High),
            ("app.code-workspace".to_string(), 1, Severity::High),
        ]
    );
    for finding in report.findings.iter().filter(|f| f.rule_id == RULE_ID) {
        assert!(
            finding.explanation.contains("symbolic link"),
            "{}",
            finding.explanation
        );
        // The link has no text of its own to point into.
        assert_eq!(finding.span, None);
    }
    assert!(report.is_complete(), "{:?}", report.skipped);
    assert_eq!(
        report
            .skipped
            .iter()
            .filter(|s| matches!(s.reason, SkipReason::Symlink { .. }))
            .count(),
        3
    );

    // A target the check could not read whole: the link is listed as too
    // large, so the scan is not reported as complete.
    let streamed = Limits {
        max_buffered_size: 16,
        ..Limits::default()
    };
    let report = scan(root, &builtin_rules().unwrap(), streamed);
    assert!(!report.findings.iter().any(|f| f.rule_id == RULE_ID));
    let too_large: Vec<String> = report
        .skipped
        .iter()
        .filter(|s| matches!(s.reason, SkipReason::TooLarge { .. }))
        .map(|s| slash(&s.path))
        .collect();
    assert!(
        too_large.contains(&".vscode/tasks.json".to_string()),
        "{too_large:?}"
    );
    assert!(!report.is_complete());
}

/// The target of a symlinked tasks file is found the way NTFS and APFS find
/// it (another case, `\` as a separator); a target the check cannot read
/// (another link, outside, missing) leaves the scan inconclusive (#63, review).
#[cfg(unix)]
#[test]
fn a_symlinked_tasks_file_is_judged_through_case_and_backslash_or_not_called_clean() {
    use std::os::unix::fs::symlink;

    let autorun = r#"{"tasks": [{"label": "x", "runOptions": {"runOn": "folderOpen"}}]}"#;
    let scan_with = |links: &[(&str, &str)]| {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("notes.txt"), autorun).unwrap();
        for (link, target) in links {
            let path = dir.path().join(link);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            symlink(target, path).unwrap();
        }
        scan(dir.path(), &builtin_rules().unwrap(), Limits::default())
    };
    let autoruns = |report: &Report| {
        report
            .findings
            .iter()
            .filter(|f| f.rule_id == RULE_ID)
            .count()
    };

    for target in ["../NOTES.TXT", "..\\notes.txt", "./x/../../notes.txt"] {
        let report = scan_with(&[(".vscode/tasks.json", target)]);
        assert_eq!(autoruns(&report), 1, "{target}: {:?}", report.findings);
    }

    for links in [
        &[(".vscode/tasks.json", "../a"), ("a", "notes.txt")][..],
        &[(".vscode/tasks.json", "../../outside.json")][..],
        &[(".vscode/tasks.json", "../missing.json")][..],
    ] {
        let report = scan_with(links);
        assert_eq!(autoruns(&report), 0, "{links:?}");
        assert!(
            report
                .skipped
                .iter()
                .any(|s| s.path == Path::new(".vscode/tasks.json")
                    && matches!(s.reason, SkipReason::Unreadable { .. })),
            "{links:?}: {:?}",
            report.skipped
        );
        assert!(!report.is_complete(), "{links:?}");
    }
}

/// Many links to one large target cannot make the scan read it again and
/// again without end: past the budget the links are listed as too large.
#[cfg(unix)]
#[test]
fn reading_through_many_links_is_bounded() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    // 4 MiB of JSON whitespace around a folderOpen task.
    let mut big = " ".repeat(4 * 1024 * 1024);
    big.push_str(
        r#"{"tasks": {"tasks": [{"label": "x", "runOptions": {"runOn": "folderOpen"}}]}}"#,
    );
    fs::write(dir.path().join("big.txt"), big).unwrap();
    for n in 0..40 {
        symlink(
            "big.txt",
            dir.path().join(format!("w{n:02}.code-workspace")),
        )
        .unwrap();
    }

    let report = scan(dir.path(), &builtin_rules().unwrap(), Limits::default());

    let judged = report
        .findings
        .iter()
        .filter(|f| f.explanation.contains("symbolic link"))
        .count();
    let too_large = report
        .skipped
        .iter()
        .filter(|s| matches!(s.reason, SkipReason::TooLarge { .. }))
        .count();
    assert!(judged > 0 && judged < 40, "{judged}");
    assert_eq!(judged + too_large, 40);
    assert!(!report.is_complete());
}

/// When the text of a link's target does not name one file for certain, the
/// scan must not guess: a guess can be a harmless twin while the system that
/// follows the link opens the payload. Such a link is listed as unreadable.
#[cfg(unix)]
#[test]
fn a_link_target_that_names_no_single_file_for_certain_is_not_guessed() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;

    let autorun = r#"{"tasks": [{"label": "x", "runOptions": {"runOn": "folderOpen"}}]}"#;
    let honest = r#"{"tasks": [{"label": "build", "command": "make"}]}"#;
    let unreadable_link = |report: &Report| {
        report.skipped.iter().any(|s| {
            s.path == Path::new(".vscode/tasks.json")
                && matches!(s.reason, SkipReason::Unreadable { .. })
        })
    };

    // A target that is not UTF-8, next to a harmless file whose name is its
    // lossy text.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join(".vscode")).unwrap();
    fs::write(root.join(OsStr::from_bytes(b"notes\xfe")), autorun).unwrap();
    fs::write(root.join("notes\u{FFFD}"), honest).unwrap();
    symlink(
        OsStr::from_bytes(b"../notes\xfe"),
        root.join(".vscode/tasks.json"),
    )
    .unwrap();
    let report = scan(root, &builtin_rules().unwrap(), Limits::default());
    assert!(unreadable_link(&report), "{:?}", report.skipped);
    assert!(!report.is_complete());

    // `..\notes.txt` opens the root `notes.txt` on Windows, and a file named
    // `.vscode/..\notes.txt` on Unix.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join(".vscode")).unwrap();
    fs::write(root.join("notes.txt"), autorun).unwrap();
    fs::write(root.join(".vscode/..\\notes.txt"), honest).unwrap();
    symlink("..\\notes.txt", root.join(".vscode/tasks.json")).unwrap();
    let report = scan(root, &builtin_rules().unwrap(), Limits::default());
    assert!(unreadable_link(&report), "{:?}", report.skipped);
    assert!(!report.is_complete());

    // The decoy chain: the Unix reading `.vscode/..\notes.txt` is a link to
    // the payload, the Windows reading is the harmless `notes.txt`.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join(".vscode")).unwrap();
    fs::write(root.join("payload.json"), autorun).unwrap();
    fs::write(root.join("notes.txt"), honest).unwrap();
    symlink("../payload.json", root.join(".vscode/..\\notes.txt")).unwrap();
    symlink("..\\notes.txt", root.join(".vscode/tasks.json")).unwrap();
    let report = scan(root, &builtin_rules().unwrap(), Limits::default());
    assert!(unreadable_link(&report), "{:?}", report.skipped);
    assert!(!report.is_complete());
}
