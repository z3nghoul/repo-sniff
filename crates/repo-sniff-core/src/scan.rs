//! Running rules over a repository.

use std::fs;
use std::path::Path;

use crate::finding::Finding;
use crate::rule::Rule;
use crate::walk::{self, Limits, SkipReason, Skipped};

/// How many leading bytes are checked to tell text from binary files.
const BINARY_SNIFF_LEN: usize = 8 * 1024;

/// Everything one scan produced. Front ends decide how to show it.
#[derive(Debug, Default)]
pub struct Report {
    /// Sorted by file, then line, then rule ID.
    pub findings: Vec<Finding>,
    /// Number of text files the line rules ran on.
    pub files_scanned: usize,
    /// Files that were not scanned at all, with the reason.
    pub skipped: Vec<Skipped>,
    /// True if the file-count limit cut the scan short.
    pub truncated: bool,
}

/// Scans every file under `root` with every rule.
///
/// All rules always run; hiding findings by severity, stage or family is
/// left to the front end, so filters can change without rescanning.
pub fn scan(root: &Path, rules: &[Rule], limits: Limits) -> Report {
    let walked = walk::walk(root, limits);
    let mut report = Report {
        skipped: walked.skipped,
        truncated: walked.truncated,
        ..Report::default()
    };

    for relative in walked.files {
        let bytes = match fs::read(root.join(&relative)) {
            Ok(bytes) => bytes,
            Err(err) => {
                report.skipped.push(Skipped {
                    path: relative,
                    reason: SkipReason::Unreadable {
                        error: err.to_string(),
                    },
                });
                continue;
            }
        };
        if looks_binary(&bytes) {
            // Binary files get their own (non-line) rules in a later milestone.
            continue;
        }

        report.files_scanned += 1;
        let text = String::from_utf8_lossy(&bytes);
        report.findings.extend(scan_text(&relative, &text, rules));
    }

    report
        .findings
        .sort_by(|a, b| (&a.file, a.line, &a.rule_id).cmp(&(&b.file, b.line, &b.rule_id)));
    report
}

/// Runs line rules over one file's text. `relative` is the path shown in
/// findings and matched against each rule's `files` globs.
fn scan_text(relative: &Path, text: &str, rules: &[Rule]) -> Vec<Finding> {
    let slash_path = to_slash(relative);
    let applicable: Vec<&Rule> = rules
        .iter()
        .filter(|rule| rule.applies_to(&slash_path))
        .collect();
    if applicable.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    for (index, line) in text.lines().enumerate() {
        for rule in &applicable {
            if rule.pattern.is_match(line) {
                findings.push(Finding {
                    rule_id: rule.id.clone(),
                    severity: rule.severity,
                    stage: rule.stage,
                    attack: rule.attack.clone(),
                    file: relative.to_path_buf(),
                    line: index + 1,
                    explanation: rule.description.clone(),
                });
            }
        }
    }
    findings
}

/// Same heuristic as git and ripgrep: a NUL byte near the start means binary.
fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(BINARY_SNIFF_LEN).any(|&b| b == 0)
}

/// Joins path components with `/` so globs behave the same on Windows.
fn to_slash(path: &Path) -> String {
    path.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::rule::parse_rules;

    const RULES: &str = r#"
        [[rule]]
        id = "test.everywhere"
        family = "test"
        stage = "run"
        severity = "low"
        description = "Matches TODO anywhere"
        example = "a.txt:1"
        pattern = 'TODO'

        [[rule]]
        id = "test.only-json"
        family = "test"
        stage = "ide"
        severity = "high"
        description = "Matches TODO in JSON under .vscode"
        example = ".vscode/tasks.json:1"
        pattern = 'TODO'
        files = [".vscode/*.json"]
    "#;

    fn write(root: &Path, relative: &str, contents: &[u8]) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn findings_have_file_line_and_rule_metadata() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.txt", b"fine\nTODO here\n");
        let rules = parse_rules(RULES, "test.toml").unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        assert_eq!(report.files_scanned, 1);
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.rule_id, "test.everywhere");
        assert_eq!(finding.file, PathBuf::from("a.txt"));
        assert_eq!(finding.line, 2);
    }

    #[test]
    fn file_globs_limit_where_a_rule_runs() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".vscode/tasks.json", b"TODO\n");
        write(dir.path(), "notes.json", b"TODO\n");
        let rules = parse_rules(RULES, "test.toml").unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        let ids: Vec<_> = report
            .findings
            .iter()
            .map(|f| (to_slash(&f.file), f.rule_id.as_str()))
            .collect();
        assert_eq!(
            ids,
            [
                (".vscode/tasks.json".to_string(), "test.everywhere"),
                (".vscode/tasks.json".to_string(), "test.only-json"),
                ("notes.json".to_string(), "test.everywhere"),
            ]
        );
    }

    #[test]
    fn binary_files_are_not_line_scanned() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "blob.bin", b"\0\0TODO");
        let rules = parse_rules(RULES, "test.toml").unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        assert_eq!(report.files_scanned, 0);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn crlf_line_endings_count_lines_correctly() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.txt", b"one\r\ntwo\r\nTODO\r\n");
        let rules = parse_rules(RULES, "test.toml").unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        assert_eq!(report.findings[0].line, 3);
    }
}
