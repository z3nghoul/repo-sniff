//! The `--json` report: one JSON document on stdout, the same exit status as
//! the text report, and repository text bounded, escaped and marked untrusted.

use std::path::{Path, PathBuf};

// The fixtures are stored defanged; the shared helper makes the real copy.
#[path = "../../repo-sniff-core/tests/common/mod.rs"]
mod common;

/// The stored (defanged) fixtures of this test.
fn stored(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/json-report")
        .join(name)
}

#[test]
fn the_stored_fixtures_are_defanged() {
    let problems = common::storage_problems(&stored(""));
    assert!(problems.is_empty(), "\n{}\n", problems.join("\n"));
}

#[test]
fn the_fixtures_materialize_without_an_unknown_marker() {
    let golden = common::materialize(&stored("golden"));
    assert!(golden.path().join(".vscode/tasks.json").is_file());
    assert!(golden.path().join("package.json").is_file());
    let hostile = common::materialize(&stored("hostile"));
    assert!(hostile.path().join("src/notes.js").is_file());
}
