//! Generic fixture harness: a file `tests/fixtures/<family>.expected.toml`
//! describes what the built-in rules must report when the folder
//! `tests/fixtures/<family>/` is scanned as one repository. A new rule family
//! adds its fixture folder and that file; it needs no test code of its own.
//!
//! The file sits beside the folder, not in it, so the folder holds nothing but
//! fixtures: inside, it would be scanned and counted like one, and a rule could
//! match its text.
//!
//! Format (every key is optional; no `[[finding]]` means nothing is reported):
//!
//! ```toml
//! # Files the scan must have read; catches a fixture that was silently skipped.
//! files_scanned = 7
//! # Files under positive/ that are there to support another fixture and are
//! # not expected to be flagged themselves.
//! unflagged = ["positive/pair/helper.py"]
//!
//! [[finding]]
//! file     = "positive/commenting_out.c"   # relative to this folder, `/`
//! line     = 3
//! rule     = "deception.bidi-control"
//! severity = "critical"
//! # Optional: the explanation must contain this text.
//! explanation_contains = "Trojan Source"
//! ```
//!
//! Besides the list being exact (a finding that is not listed fails the test,
//! so a negative fixture is simply a file without an entry), the harness checks
//! the rules from CONTRIBUTING.md: the folder has `positive/` and `negative/`
//! fixtures, every positive file is flagged, and no negative file is.
//!
//! The fixtures are stored defanged (see `common/mod.rs`): each test scans a
//! copy with the real names and the markers replaced, made in a temporary
//! folder. The paths in the expectations files are the real ones.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use repo_sniff_core::{Limits, Report, Severity, builtin_rules, scan};
use serde::Deserialize;

/// Suffix of the file beside a fixture folder that drives the harness.
const EXPECTED_SUFFIX: &str = ".expected.toml";

/// Older families scan each case on its own, describe the cases in this table
/// inside the folder and test them in their own test file. A family has one or
/// the other.
const LEGACY_TABLE: &str = "expectations.tsv";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    files_scanned: Option<usize>,
    #[serde(default)]
    unflagged: Vec<String>,
    #[serde(default)]
    finding: Vec<ExpectedFinding>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedFinding {
    file: String,
    line: usize,
    rule: String,
    severity: Severity,
    explanation_contains: Option<String>,
}

/// One finding as the harness compares it: file, line, rule, severity.
type Row = (String, usize, String, Severity);

/// The stored (defanged) fixtures in the repository.
fn stored_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Reports use `/` on every OS, so compare paths the same way.
fn slash(path: &Path) -> String {
    path.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// Every regular file under `dir`, relative to it, without following symlinks.
fn files_under(dir: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            let path = entry.path();
            if kind.is_dir() {
                walk(root, &path, out);
            } else if kind.is_file() {
                out.push(slash(path.strip_prefix(root).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// The expectations file of a fixture folder: `<folder>.expected.toml`.
fn expected_path(folder: &Path) -> PathBuf {
    let mut name = folder.file_name().unwrap().to_os_string();
    name.push(EXPECTED_SUFFIX);
    folder.with_file_name(name)
}

/// Every folder directly under `tests/fixtures/`.
fn families(root: &Path) -> Vec<PathBuf> {
    let mut families: Vec<PathBuf> = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect();
    families.sort();
    families
}

/// Every fixture folder that has an expectations file.
fn harness_folders(root: &Path) -> Vec<PathBuf> {
    families(root)
        .into_iter()
        .filter(|folder| expected_path(folder).is_file())
        .collect()
}

fn load(folder: &Path) -> Expected {
    let path = expected_path(folder);
    let text = fs::read_to_string(&path).unwrap();
    toml::from_str(&text).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

fn rows(report: &Report) -> Vec<Row> {
    let mut rows: Vec<Row> = report
        .findings
        .iter()
        .map(|f| (slash(&f.file), f.line, f.rule_id.clone(), f.severity))
        .collect();
    rows.sort();
    rows
}

/// Checks one folder and returns what is wrong with it, empty when all is well.
fn check_folder(root: &Path, folder: &Path) -> Vec<String> {
    let name = folder
        .strip_prefix(root)
        .map_or_else(|_| folder.display().to_string(), slash);
    let expected = load(folder);
    let report = scan(folder, &builtin_rules().unwrap(), Limits::default());
    let mut problems = Vec::new();

    let mut wanted: Vec<Row> = expected
        .finding
        .iter()
        .map(|f| (f.file.clone(), f.line, f.rule.clone(), f.severity))
        .collect();
    wanted.sort();
    let found = rows(&report);
    for row in found.iter().filter(|row| !wanted.contains(row)) {
        problems.push(format!("{name}: unexpected finding {row:?}"));
    }
    for row in wanted.iter().filter(|row| !found.contains(row)) {
        problems.push(format!("{name}: missing finding {row:?}"));
    }

    for want in &expected.finding {
        let Some(text) = &want.explanation_contains else {
            continue;
        };
        let matched = report.findings.iter().any(|f| {
            slash(&f.file) == want.file
                && f.line == want.line
                && f.rule_id == want.rule
                && f.explanation.contains(text.as_str())
        });
        if !matched {
            problems.push(format!(
                "{name}: no explanation for {}:{} ({}) contains {text:?}",
                want.file, want.line, want.rule
            ));
        }
    }

    if let Some(count) = expected.files_scanned
        && report.files_scanned != count
    {
        problems.push(format!(
            "{name}: {} files scanned, expected {count}",
            report.files_scanned
        ));
    }

    // Positive and negative pairs, as CONTRIBUTING.md asks.
    let files = files_under(folder);
    let flagged: BTreeSet<&str> = found.iter().map(|row| row.0.as_str()).collect();
    for side in ["positive/", "negative/"] {
        if !files.iter().any(|file| file.starts_with(side)) {
            problems.push(format!("{name}: no fixtures under {side}"));
        }
    }
    for file in files.iter().filter(|file| file.starts_with("positive/")) {
        let supporting = expected.unflagged.contains(file);
        if flagged.contains(file.as_str()) == supporting {
            problems.push(if supporting {
                format!("{name}: {file} is listed in `unflagged` but has a finding")
            } else {
                format!("{name}: positive fixture {file} has no finding")
            });
        }
    }
    for file in &expected.unflagged {
        if !files.contains(file) {
            problems.push(format!(
                "{name}: `unflagged` names {file}, which does not exist"
            ));
        }
    }
    for file in flagged.iter().filter(|file| file.starts_with("negative/")) {
        problems.push(format!("{name}: negative fixture {file} has a finding"));
    }
    problems
}

#[test]
fn every_fixture_folder_matches_its_expected_toml() {
    let fixtures = common::materialize(&stored_root());
    let root = fixtures.path();
    let folders = harness_folders(root);
    assert!(!folders.is_empty(), "no *{EXPECTED_SUFFIX} found");
    let problems: Vec<String> = folders.iter().flat_map(|f| check_folder(root, f)).collect();
    assert!(problems.is_empty(), "\n{}\n", problems.join("\n"));
}

#[test]
fn every_fixture_family_is_covered_by_exactly_one_table() {
    for family in families(&stored_root()) {
        let harness = expected_path(&family).is_file();
        let legacy = family.join(LEGACY_TABLE).is_file();
        assert!(
            harness != legacy,
            "{} needs exactly one of {} beside it or {LEGACY_TABLE} inside it",
            family.display(),
            expected_path(&family).display()
        );
    }
}

#[test]
fn every_expectations_file_belongs_to_a_fixture_folder() {
    for entry in fs::read_dir(stored_root()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if let Some(family) = name.strip_suffix(EXPECTED_SUFFIX) {
            assert!(
                stored_root().join(family).is_dir(),
                "{name} has no folder {family}/ beside it"
            );
        }
    }
}

/// The demo repository of the README is stored defanged the same way.
fn stored_demo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/demo")
}

#[test]
fn the_stored_fixtures_and_the_demo_are_defanged() {
    let mut problems = common::storage_problems(&stored_root());
    problems.extend(common::storage_problems(&stored_demo()));
    assert!(problems.is_empty(), "\n{}\n", problems.join("\n"));
}

#[test]
fn the_demo_materializes_without_an_unknown_marker() {
    // `docs/demo.tape` materializes the whole folder, README.md included.
    let real = common::materialize(&stored_demo());
    assert!(real.path().join(".vscode/tasks.json").is_file());
    assert!(real.path().join("package.json").is_file());
}

#[test]
fn the_storage_check_names_a_raw_fixture() {
    let stored = tempfile::tempdir().unwrap();
    let write = |relative: &str, contents: &str| {
        let path = stored.path().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    };
    // Built from pieces so this file stays free of the words as well.
    write(
        "positive/raw.js",
        &format!("{}(x)\n", ["ev", "al"].concat()),
    );
    write("positive/.vscode/notes.txt", "text\n");
    write("positive/tasks.json", "{}\n");
    write("positive/ok.js", "{{EVAL}}(x)\n");
    write("positive/bidi.js", "a \u{202E} b\n");
    write("positive/ok.json", "{}\n");
    write(
        "positive/ctor.js",
        &format!("a.{}(b)\n", ["construc", "tor.construc", "tor"].concat()),
    );
    write("positive/ok.json.fixture", "{}\n");

    let text = common::storage_problems(stored.path()).join("\n");
    for expected in [
        "positive/raw.js: contains {{EVAL}} written out",
        "positive/.vscode: folder starts with a dot",
        "positive/tasks.json: needs the .fixture suffix",
        "positive/ok.json: needs the .fixture suffix",
        "positive/bidi.js: contains U+202E written out, use {{RLO}}",
        "positive/ctor.js: contains {{CTOR_CHAIN}} written out",
    ] {
        assert!(text.contains(expected), "{expected:?} not in:\n{text}");
    }
    assert!(!text.contains("positive/ok.js:"), "{text}");
    assert!(!text.contains("ok.json.fixture"), "{text}");
}

#[test]
fn materializing_restores_names_and_text_and_rejects_unknown_markers() {
    let stored = tempfile::tempdir().unwrap();
    let write = |relative: &str, contents: &str| {
        let path = stored.path().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    };
    write("_vscode/tasks.json.fixture", "{{EVAL}}({{ATOB}}(x))\n");
    write("_distutils_hack/__init__.py", "plain\n");
    let real = common::materialize(stored.path());
    let text = fs::read_to_string(real.path().join(".vscode/tasks.json")).unwrap();
    assert_eq!(
        text,
        format!("{}({}(x))\n", ["ev", "al"].concat(), ["at", "ob"].concat())
    );
    assert!(real.path().join("_distutils_hack/__init__.py").is_file());

    write("bad.txt", "{{NO_SUCH_MARKER}}\n");
    let result = std::panic::catch_unwind(|| common::materialize(stored.path()));
    assert!(result.is_err(), "an unknown marker must fail");
}

#[test]
fn materializing_restores_invisible_characters_new_words_and_generated_lines() {
    let stored = tempfile::tempdir().unwrap();
    let write = |relative: &str, contents: &str| {
        let path = stored.path().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    };
    for (name, character) in common::CHAR_MARKERS {
        write(
            &format!("chars/{name}.txt"),
            &format!("a{{{{{name}}}}}b\r\n"),
        );
        let real = common::materialize(stored.path());
        let text = fs::read_to_string(real.path().join(format!("chars/{name}.txt"))).unwrap();
        assert_eq!(text, format!("a{character}b\r\n"), "{name}");
    }
    write(
        "words.txt",
        "x.{{CTOR_CHAIN}}(y); z.{{RUN_IN_NEW_CONTEXT}}(c)\n",
    );
    write("gen.js", "{{MIN_FUNCS_2}}\n");
    let real = common::materialize(stored.path());
    let words = fs::read_to_string(real.path().join("words.txt")).unwrap();
    assert_eq!(
        words,
        format!(
            "x.{}(y); z.{}(c)\n",
            ["construc", "tor.construc", "tor"].concat(),
            ["run", "InNew", "Context"].concat()
        )
    );
    let line = fs::read_to_string(real.path().join("gen.js")).unwrap();
    assert_eq!(
        line,
        "function f0(a){if(a>0){return a-0;}return a+0;}var v0=f0(0);\
         function f1(a){if(a>1){return a-1;}return a+1;}var v1=f1(1);\n"
    );
}

#[test]
fn the_harness_reports_what_is_wrong() {
    let parent = tempfile::tempdir().unwrap();
    let dir = parent.path().join("family");
    let write = |relative: &str, contents: &str| {
        let path = parent.path().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    };
    // A bidi control character, written as an escape so this file has none.
    write("family/positive/flagged.txt", "x \u{202E} y\n");
    write("family/positive/quiet.txt", "nothing here\n");
    write("family/negative/loud.txt", "z \u{202E}\n");
    write(
        "family.expected.toml",
        r#"
        files_scanned = 9
        unflagged = ["positive/missing.txt"]

        [[finding]]
        file = "positive/flagged.txt"
        line = 1
        rule = "deception.bidi-control"
        severity = "critical"
        explanation_contains = "not in the text"

        [[finding]]
        file = "positive/gone.txt"
        line = 2
        rule = "deception.bidi-control"
        severity = "critical"
        "#,
    );

    let problems = check_folder(parent.path(), &dir);
    let text = problems.join("\n");
    for expected in [
        "unexpected finding (\"negative/loud.txt\"",
        "missing finding (\"positive/gone.txt\"",
        "contains \"not in the text\"",
        "3 files scanned, expected 9",
        // The expectations file beside the folder is not scanned.
        "positive fixture positive/quiet.txt has no finding",
        "`unflagged` names positive/missing.txt",
        "negative fixture negative/loud.txt has a finding",
    ] {
        assert!(text.contains(expected), "{expected:?} not in:\n{text}");
    }
}

/// Not a check: `docs/demo.tape` runs it (`cargo test ... -- --ignored`) to
/// get the README demo with real names and text in the folder named by
/// `REPO_SNIFF_DEMO_DIR`, so the demo can be scanned without being committed
/// in that form.
#[test]
#[ignore = "run by docs/demo.tape"]
fn materialize_demo() {
    let dest = std::env::var_os("REPO_SNIFF_DEMO_DIR").expect("REPO_SNIFF_DEMO_DIR is not set");
    common::copy_real(&stored_demo(), Path::new(&dest));
}
