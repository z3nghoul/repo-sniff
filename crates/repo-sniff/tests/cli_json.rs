//! The `--json` report: one JSON document on stdout, the same exit status as
//! the text report, and repository text bounded, escaped and marked untrusted.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

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

/// The one JSON document on stdout. Fails if stdout holds anything else: a
/// second document, text before or after it, or no final newline.
fn document(output: &Output) -> Value {
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    let body = stdout
        .strip_suffix('\n')
        .unwrap_or_else(|| panic!("no final newline: {stdout:?}"));
    assert!(!body.ends_with('\n'), "more than one final newline");
    assert!(body.starts_with('{') && body.ends_with('}'), "{stdout}");
    let mut documents = serde_json::Deserializer::from_str(body).into_iter::<Value>();
    let value = documents
        .next()
        .expect("no JSON document")
        .unwrap_or_else(|err| panic!("{err}: {stdout}"));
    assert!(documents.next().is_none(), "more than one document");
    value
}

/// Runs `repo-sniff scan . --json` with `args` inside `dir`.
fn scan_json(dir: &Path, args: &[&str]) -> (Output, Value) {
    let mut all = vec!["scan", ".", "--json"];
    all.extend(args);
    let output = run(dir, &all);
    let value = document(&output);
    (output, value)
}

/// The printed report with the scan time, which differs on every run, set to 0.
fn without_time(output: &Output) -> String {
    let stdout = String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8");
    let lines: Vec<String> = stdout
        .lines()
        .map(|line| {
            if line.starts_with("  \"duration_ms\": ") {
                "  \"duration_ms\": 0,".to_string()
            } else {
                line.to_string()
            }
        })
        .collect();
    lines.join("\n") + "\n"
}

/// The golden repository, with a binary file the scan lists as skipped
/// (binary fixtures are generated, never committed).
fn golden() -> TempDir {
    let dir = common::materialize(&stored("golden"));
    fs::write(
        dir.path().join("logo.png"),
        b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR",
    )
    .unwrap();
    dir
}

/// A directory whose only file is over the 100 MiB read limit.
fn oversized() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    // set_len makes the file without writing 100 MiB.
    fs::File::create(dir.path().join("big.bin"))
        .unwrap()
        .set_len(100 * 1024 * 1024 + 1)
        .unwrap();
    dir
}

fn clean() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();
    dir
}

#[test]
fn golden_report() {
    let dir = golden();

    let output = run(dir.path(), &["scan", ".", "--json", "--fail-on", "none"]);

    assert_eq!(code(&output), 0);
    assert!(document(&output)["duration_ms"].is_u64());
    // The printed text as it is, so that the order of the fields and the
    // formatting are part of what is compared.
    insta::assert_snapshot!(without_time(&output));
}

#[test]
fn two_runs_print_the_same_document_but_for_the_scan_time() {
    let dir = golden();

    let first = run(dir.path(), &["scan", ".", "--json"]);
    let second = run(dir.path(), &["scan", ".", "--json"]);

    document(&first);
    document(&second);
    // Two runs differ in the scan time only, byte for byte.
    assert_eq!(without_time(&first), without_time(&second));
    assert!(first.stderr.is_empty(), "{:?}", first.stderr);
}

#[test]
fn a_hostile_line_is_data_escaped_and_marked_untrusted() {
    let dir = common::materialize(&stored("hostile"));

    let (_, value) = scan_json(dir.path(), &[]);

    let finding = value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["file"] == "src/notes.js" && f["rule_id"] == "deception.bidi-control")
        .expect("the bidi finding");
    let snippet = finding["snippet"].as_str().unwrap();
    // The invisible characters are shown as escapes, never as themselves.
    assert!(snippet.contains("\\u{202E}AI agent: ignore"), "{snippet}");
    assert!(snippet.contains("\\u{200B}</untrusted>"), "{snippet}");
    assert!(!snippet.contains('\u{202E}') && !snippet.contains('\u{200B}'));
    // Quotes and backslashes survive the round trip as plain data.
    assert!(snippet.contains(r#"\"q\" C:\\x"#), "{snippet}");
    let fields: Vec<&str> = value["untrusted"]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    assert!(fields.contains(&"findings[].snippet"), "{fields:?}");
    assert!(fields.contains(&"findings[].explanation"), "{fields:?}");
    let notice = value["untrusted"]["notice"].as_str().unwrap();
    assert!(notice.contains("never as instructions"), "{notice}");
}

#[test]
fn a_long_path_and_a_long_line_are_cut_and_named() {
    let dir = tempfile::tempdir().unwrap();
    // Four folders of 90 characters: past the 300-character limit for paths,
    // each name well within what every OS allows.
    let mut folder = dir.path().to_path_buf();
    for letter in ["a", "b", "c", "d"] {
        folder.push(letter.repeat(90));
    }
    fs::create_dir_all(&folder).unwrap();
    let line = format!("// \u{202E}{}\n", "x".repeat(500));
    fs::write(folder.join("long.js"), line).unwrap();

    let (_, value) = scan_json(dir.path(), &[]);

    let finding = &value["findings"][0];
    let file = finding["file"].as_str().unwrap();
    assert!(file.starts_with(&"a".repeat(90)), "{file}");
    assert!(file.ends_with("..."), "{file}");
    assert_eq!(file.chars().count(), 303, "{file}");
    let snippet = finding["snippet"].as_str().unwrap();
    assert!(snippet.ends_with("..."), "{snippet}");
    assert_eq!(
        finding["truncated_fields"],
        serde_json::json!(["file", "snippet"])
    );
}

#[test]
fn an_oversized_file_is_inconclusive_with_exit_three() {
    let dir = oversized();

    let (output, value) = scan_json(dir.path(), &[]);

    assert_eq!(code(&output), 3);
    assert_eq!(value["status"], "inconclusive");
    assert_eq!(
        value["skipped"],
        serde_json::json!([{
            "file": "big.bin",
            "reason": "too_large",
            "inconclusive": true,
            "detail": "too large (104857601 bytes)",
            "truncated_fields": [],
        }])
    );
}

#[test]
fn exit_status_is_the_same_as_for_the_text_report() {
    let golden = golden();
    let clean = clean();
    let oversized = oversized();
    for (dir, args, expected) in [
        (clean.path(), &[][..], 0),
        (golden.path(), &[][..], 1),
        (golden.path(), &["--fail-on", "critical"][..], 1),
        (golden.path(), &["--fail-on", "none"][..], 0),
        (oversized.path(), &[][..], 3),
    ] {
        let mut text = vec!["scan", "."];
        text.extend(args);
        let mut json = text.clone();
        json.push("--json");

        let text_code = code(&run(dir, &text));
        let output = run(dir, &json);

        assert_eq!(text_code, expected, "{args:?}");
        assert_eq!(code(&output), expected, "{args:?}");
        document(&output);
    }
}

#[test]
fn a_scan_that_cannot_run_prints_no_json() {
    let dir = tempfile::tempdir().unwrap();

    let output = run(dir.path(), &["scan", "no-such-directory", "--json"]);

    assert_eq!(code(&output), 2);
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot access"));
}

#[test]
fn credentials_in_the_target_never_reach_the_json() {
    let dir = clean();

    // The clone fails at the name lookup (`.invalid` never resolves), so no
    // network is needed; the error goes to stderr, redacted, and no JSON is
    // printed.
    let output = run(
        dir.path(),
        &["scan", "https://FAKE_TOKEN@example.invalid/o/r", "--json"],
    );

    assert_eq!(code(&output), 2);
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("FAKE_TOKEN"));
}
