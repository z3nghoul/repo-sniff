//! End-to-end tests: run the real `repo-sniff` binary and compare its report
//! with a stored snapshot.
//!
//! Each scan runs from inside the directory being scanned and uses `.` as the
//! target, so the first line of the report is the same on every machine.
//!
//! To accept an intended change in the output, run
//! `INSTA_UPDATE=always cargo test -p repo-sniff --test cli_snapshots`
//! and review the diff of the `.snap` files.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn core_fixtures(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../repo-sniff-core/tests/fixtures")
        .join(name)
}

/// Runs `repo-sniff scan .` inside `dir` and returns what it printed.
fn scan_dot(dir: &Path) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_repo-sniff"))
        .current_dir(dir)
        .args(["scan", "."])
        .output()
        .expect("failed to run repo-sniff");
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("report is valid UTF-8")
}

#[test]
fn report_for_trojan_source_fixtures() {
    insta::assert_snapshot!(scan_dot(&core_fixtures("trojan-source")));
}

#[test]
fn report_for_vscode_autorun_fixtures() {
    insta::assert_snapshot!(scan_dot(&core_fixtures("vscode-autorun")));
}

#[test]
fn report_for_a_clean_directory() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();

    insta::assert_snapshot!(scan_dot(dir.path()));
}
