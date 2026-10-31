//! The process exit status: 0 clean, 1 findings at or above `--fail-on`,
//! 2 when the scan could not run.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn core_fixtures(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../repo-sniff-core/tests/fixtures")
        .join(name)
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_repo-sniff"))
        .current_dir(dir)
        .args(args)
        .output()
        .expect("failed to run repo-sniff")
}

fn code(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("process was not killed by a signal")
}

/// A directory whose only finding is HIGH: an auto-run VS Code task.
fn high_only_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let vscode = dir.path().join(".vscode");
    fs::create_dir(&vscode).unwrap();
    fs::write(
        vscode.join("tasks.json"),
        r#"{"tasks":[{"label":"x","command":"make","runOptions":{"runOn":"folderOpen"}}]}"#,
    )
    .unwrap();
    dir
}

#[test]
fn clean_directory_exits_zero() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();

    assert_eq!(code(&run(dir.path(), &["scan", "."])), 0);
}

#[test]
fn default_threshold_is_high() {
    let dir = high_only_dir();

    assert_eq!(code(&run(dir.path(), &["scan", "."])), 1);
}

#[test]
fn threshold_above_every_finding_exits_zero() {
    let dir = high_only_dir();

    assert_eq!(
        code(&run(dir.path(), &["scan", ".", "--fail-on", "critical"])),
        0
    );
}

#[test]
fn threshold_at_or_below_a_finding_exits_one() {
    let dir = high_only_dir();

    assert_eq!(
        code(&run(dir.path(), &["scan", ".", "--fail-on", "high"])),
        1
    );
    assert_eq!(
        code(&run(dir.path(), &["scan", ".", "--fail-on", "LOW"])),
        1
    );
}

#[test]
fn critical_findings_fail_at_the_critical_threshold() {
    let output = run(
        &core_fixtures("trojan-source"),
        &["scan", ".", "--fail-on", "critical"],
    );

    assert_eq!(code(&output), 1);
}

#[test]
fn none_never_fails_because_of_findings() {
    let output = run(
        &core_fixtures("trojan-source"),
        &["scan", ".", "--fail-on", "none"],
    );

    assert_eq!(code(&output), 0);
    // The report is still printed.
    assert!(String::from_utf8_lossy(&output.stdout).contains("CRITICAL"));
}

#[test]
fn unknown_threshold_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();

    let output = run(dir.path(), &["scan", ".", "--fail-on", "urgent"]);

    assert_eq!(code(&output), 2);
    assert!(String::from_utf8_lossy(&output.stderr).contains("`urgent`"));
}

#[test]
fn missing_target_is_a_runtime_error() {
    let dir = tempfile::tempdir().unwrap();

    let output = run(dir.path(), &["scan", "no-such-directory"]);

    assert_eq!(code(&output), 2);
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot access"));
}
