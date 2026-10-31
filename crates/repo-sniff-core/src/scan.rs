//! Running rules over a repository.

use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::checks::{FileCheck, FileCtx, FileIssue, RepoIndex};
use crate::finding::Finding;
use crate::rule::{Matcher, Rule};
use crate::sanitize::{display_safe, to_slash};
use crate::walk::{self, Limits, SkipReason, Skipped};

/// Explanations built from text in the scanned repository are cut to this.
const MAX_EXPLANATION_CHARS: usize = 300;

/// How many leading bytes are checked to tell text from binary files.
const BINARY_SNIFF_LEN: usize = 8 * 1024;

/// One file check may list at most this many findings for one file; the rest
/// are summarized on the last one, so a hostile file cannot flood the report.
const MAX_FINDINGS_PER_FILE_CHECK: usize = 100;

/// Everything one scan produced. Front ends decide how to show it.
#[derive(Debug, Default)]
pub struct Report {
    /// Sorted by file, then line, then rule ID.
    pub findings: Vec<Finding>,
    /// Number of files that were read and analysed: text files, and binary
    /// files that a file-level rule examined.
    pub files_scanned: usize,
    /// Files that were not (fully) analysed, with the reason. Nothing is left
    /// out silently: binary, oversized, symlinked and unreadable files are all
    /// listed here.
    pub skipped: Vec<Skipped>,
    /// True if the file-count limit cut the scan short.
    pub truncated: bool,
}

impl Report {
    /// Whether the scan can vouch for what it looked at. A report with no
    /// findings is only a clean bill of health when this is true: a payload
    /// may sit past the file limit, in a file that was too large or could not
    /// be opened, or in an executable nobody analyzes yet.
    pub fn is_complete(&self) -> bool {
        !self.truncated && self.inconclusive_count() == 0
    }

    /// Number of skipped files that make the scan inconclusive, see
    /// `SkipReason::makes_scan_inconclusive`.
    pub fn inconclusive_count(&self) -> usize {
        self.skipped
            .iter()
            .filter(|skipped| skipped.reason.makes_scan_inconclusive())
            .count()
    }
}

/// Scans every file under `root` with every rule.
///
/// All rules always run; hiding findings by severity, stage or family is
/// left to the front end, so filters can change without rescanning.
pub fn scan(root: &Path, rules: &[Rule], limits: Limits) -> Report {
    let walked = walk::walk(root, limits);

    // Where files are allowed to be looked up: everything the walk saw,
    // including files it did not hand over because of the size limit or
    // because they are symlinks.
    let index = RepoIndex::new(
        walked
            .files
            .iter()
            .map(|path| to_slash(path))
            .chain(
                walked
                    .skipped
                    .iter()
                    .filter_map(|skipped| match skipped.reason {
                        SkipReason::TooLarge { .. } | SkipReason::Symlink { .. } => {
                            Some(to_slash(&skipped.path))
                        }
                        _ => None,
                    }),
            ),
    );
    let regular_files: HashSet<String> = walked.files.iter().map(|path| to_slash(path)).collect();
    let file_rules: Vec<(&Rule, FileCheck)> = rules
        .iter()
        .filter_map(|rule| match rule.matcher {
            Matcher::File(check) => Some((rule, check)),
            _ => None,
        })
        .collect();
    let env = Env {
        index: &index,
        truncated: walked.truncated,
        file_rules: &file_rules,
    };

    let mut report = Report {
        truncated: walked.truncated,
        ..Report::default()
    };
    let mut skipped = walked.skipped;

    for relative in &walked.files {
        let slash_path = to_slash(relative);
        let bytes = match fs::read(root.join(relative)) {
            Ok(bytes) => bytes,
            Err(err) => {
                skipped.push(Skipped {
                    path: relative.clone(),
                    reason: SkipReason::Unreadable {
                        error: err.to_string(),
                    },
                });
                continue;
            }
        };

        // File-level rules go first and see the raw bytes, so a file is judged
        // the way its consumer reads it, even if it looks like a binary here.
        let checked = env.run_file_checks(relative, &slash_path, &bytes, None);
        report.findings.extend(checked.findings);

        if looks_binary(&bytes) {
            // An executable is listed even when a file rule looked at it: the
            // rule saw the bytes of a `.pth` or `.start` file, not the code
            // of the program.
            let executable = executable_format(&bytes);
            if let Some(format) = executable {
                skipped.push(Skipped {
                    path: relative.clone(),
                    reason: SkipReason::Executable { format },
                });
            } else if !checked.examined {
                skipped.push(Skipped {
                    path: relative.clone(),
                    reason: SkipReason::Binary,
                });
            }
            if checked.examined {
                report.files_scanned += 1;
            }
            continue;
        }

        report.files_scanned += 1;
        let text = String::from_utf8_lossy(&bytes);
        report
            .findings
            .extend(scan_text(relative, &slash_path, &text, rules));
    }

    // Entries the walk did not hand over still matter to a rule that asks for
    // that file by name: an oversized file or a symlink is not a way around it.
    let walk_skips: Vec<Skipped> = skipped.clone();
    for entry in &walk_skips {
        let slash_path = to_slash(&entry.path);
        let checked = match &entry.reason {
            SkipReason::TooLarge { size } => env.run_file_checks(
                &entry.path,
                &slash_path,
                &[],
                Some(FileIssue::TooLarge { size: *size }),
            ),
            SkipReason::Symlink { target } => {
                let bytes =
                    symlink_target_bytes(root, &entry.path, target.as_deref(), &regular_files);
                let issue = FileIssue::Symlink {
                    target: target.as_deref().map(to_slash),
                };
                env.run_file_checks(&entry.path, &slash_path, &bytes, Some(issue))
            }
            _ => continue,
        };
        report.findings.extend(checked.findings);
    }

    report.skipped = skipped;
    report
        .findings
        .sort_by(|a, b| (&a.file, a.line, &a.rule_id).cmp(&(&b.file, b.line, &b.rule_id)));
    report
}

/// What a scan shares between files.
struct Env<'a> {
    index: &'a RepoIndex,
    truncated: bool,
    file_rules: &'a [(&'a Rule, FileCheck)],
}

/// The outcome of offering one file to the file-level rules.
struct Checked {
    /// True if at least one file-level rule applies to this path.
    examined: bool,
    findings: Vec<Finding>,
}

impl Env<'_> {
    fn run_file_checks(
        &self,
        relative: &Path,
        slash_path: &str,
        bytes: &[u8],
        issue: Option<FileIssue>,
    ) -> Checked {
        let mut checked = Checked {
            examined: false,
            findings: Vec::new(),
        };
        for (rule, check) in self.file_rules {
            if !rule.applies_to(slash_path) {
                continue;
            }
            checked.examined = true;
            let ctx = FileCtx {
                path: slash_path,
                bytes,
                issue: issue.clone(),
                repo: self.index,
                truncated: self.truncated,
                base: rule.severity,
            };
            let mut hits = check(&ctx);
            let unlisted = hits.len().saturating_sub(MAX_FINDINGS_PER_FILE_CHECK);
            hits.truncate(MAX_FINDINGS_PER_FILE_CHECK);

            let start = checked.findings.len();
            for hit in hits {
                checked.findings.push(Finding {
                    rule_id: rule.id.clone(),
                    severity: hit.severity,
                    stage: rule.stage,
                    attack: rule.attack.clone(),
                    file: relative.to_path_buf(),
                    line: hit.line,
                    // The reason may quote the scanned file, so it is cleaned
                    // before it can reach a terminal.
                    explanation: display_safe(&hit.reason, MAX_EXPLANATION_CHARS),
                });
            }
            if unlisted > 0
                && let Some(last) = checked.findings[start..].last_mut()
            {
                last.explanation.push_str(&format!(
                    " [{unlisted} more from this rule in this file not listed]"
                ));
            }
        }
        checked
    }
}

/// The content of the file a symlink points at, if that is a regular file
/// inside the repository; empty otherwise. The target is resolved as text, so
/// nothing outside the scanned directory is ever opened.
fn symlink_target_bytes(
    root: &Path,
    link: &Path,
    target: Option<&Path>,
    regular_files: &HashSet<String>,
) -> Vec<u8> {
    let Some(resolved) = target.and_then(|target| resolve_inside(link, target)) else {
        return Vec::new();
    };
    if !regular_files.contains(&to_slash(&resolved)) {
        return Vec::new();
    }
    fs::read(root.join(resolved)).unwrap_or_default()
}

/// Resolves `target` relative to the directory of `link`, purely lexically.
/// Returns `None` for absolute targets and for targets that leave the root.
fn resolve_inside(link: &Path, target: &Path) -> Option<PathBuf> {
    let mut resolved: Vec<_> = link.parent()?.components().collect();
    for component in target.components() {
        match component {
            Component::Normal(_) => resolved.push(component),
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop()?;
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(resolved.into_iter().collect())
}

/// Runs line, JSONC and other text rules over one file's text. `relative` is
/// the path shown in findings; `slash_path` is matched against each rule's
/// `files` globs.
fn scan_text(relative: &Path, slash_path: &str, text: &str, rules: &[Rule]) -> Vec<Finding> {
    let applicable: Vec<&Rule> = rules
        .iter()
        .filter(|rule| rule.applies_to(slash_path))
        .collect();
    if applicable.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    for rule in applicable {
        match &rule.matcher {
            Matcher::LineRegex(pattern) => {
                for (index, line) in text.lines().enumerate() {
                    if pattern.is_match(line) {
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
            Matcher::Jsonc(check) => {
                for hit in check(slash_path, text, rule.severity) {
                    findings.push(Finding {
                        rule_id: rule.id.clone(),
                        severity: hit.severity,
                        stage: rule.stage,
                        attack: rule.attack.clone(),
                        file: relative.to_path_buf(),
                        line: hit.line,
                        // The reason may quote the scanned file, so it is
                        // cleaned before it can reach a terminal.
                        explanation: display_safe(&hit.reason, MAX_EXPLANATION_CHARS),
                    });
                }
            }
            // File-level rules already ran on the raw bytes.
            Matcher::File(_) => {}
        }
    }
    findings
}

/// Names the executable format a file starts with, by its magic bytes:
/// ELF, PE (the `MZ` header), Mach-O in all four byte orders, and fat Mach-O
/// binaries (32 and 64 bit; fat headers are always big-endian on disk). The fat header `CAFEBABE` is also the header of a Java class
/// file; both are code that runs, so both count.
fn executable_format(bytes: &[u8]) -> Option<&'static str> {
    match bytes {
        [0x7F, b'E', b'L', b'F', ..] => Some("ELF"),
        [b'M', b'Z', ..] => Some("PE"),
        [0xFE, 0xED, 0xFA, 0xCE | 0xCF, ..] | [0xCE | 0xCF, 0xFA, 0xED, 0xFE, ..] => Some("Mach-O"),
        [0xCA, 0xFE, 0xBA, 0xBE | 0xBF, ..] => Some("Mach-O fat (or Java class)"),
        _ => None,
    }
}

/// Same heuristic as git and ripgrep: a NUL byte near the start means binary.
fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(BINARY_SNIFF_LEN).any(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use globset::{GlobBuilder, GlobSetBuilder};

    use super::*;
    use crate::checks::Hit;
    use crate::finding::{Severity, Stage};
    use crate::rule::parse_rules;

    const RULES: &str = r#"
        [[rule]]
        id = "test.everywhere"
        engine = "line-regex"
        family = "test"
        stage = "run"
        severity = "low"
        description = "Matches TODO anywhere"
        example = "a.txt:1"
        pattern = 'TODO'

        [[rule]]
        id = "test.only-json"
        engine = "line-regex"
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

    /// A file-level rule that reports what the engine handed to its check.
    fn probe(ctx: &FileCtx<'_>) -> Vec<Hit> {
        vec![Hit {
            line: 1,
            severity: ctx.base,
            reason: format!(
                "path={} bytes={} issue={:?} helper={} truncated={}",
                ctx.path,
                ctx.bytes.len(),
                ctx.issue,
                ctx.repo.has_module("helper"),
                ctx.truncated
            ),
        }]
    }

    fn file_rule(glob: &str, check: FileCheck) -> Rule {
        let mut globs = GlobSetBuilder::new();
        globs.add(
            GlobBuilder::new(glob)
                .case_insensitive(true)
                .build()
                .unwrap(),
        );
        Rule {
            id: "test.file".to_string(),
            family: "test".to_string(),
            stage: Stage::Deps,
            severity: Severity::High,
            attack: vec![],
            description: "test".to_string(),
            example: "x".to_string(),
            matcher: Matcher::File(check),
            files: Some(globs.build().unwrap()),
        }
    }

    fn explanations(report: &Report) -> Vec<(String, String)> {
        report
            .findings
            .iter()
            .map(|f| (to_slash(&f.file), f.explanation.clone()))
            .collect()
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
    fn binary_files_are_not_line_scanned_but_are_reported_as_skipped() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "blob.bin", b"\0\0TODO");
        let rules = parse_rules(RULES, "test.toml").unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        assert_eq!(report.files_scanned, 0);
        assert!(report.findings.is_empty());
        assert_eq!(
            report.skipped,
            [Skipped {
                path: PathBuf::from("blob.bin"),
                reason: SkipReason::Binary,
            }]
        );
    }

    #[test]
    fn crlf_line_endings_count_lines_correctly() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.txt", b"one\r\ntwo\r\nTODO\r\n");
        let rules = parse_rules(RULES, "test.toml").unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        assert_eq!(report.findings[0].line, 3);
    }

    #[test]
    fn a_scan_that_read_everything_is_complete() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.txt", b"fine\n");
        let rules = parse_rules(RULES, "test.toml").unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        assert!(report.is_complete());
        assert_eq!(report.inconclusive_count(), 0);
    }

    #[test]
    fn unread_and_executable_files_make_the_scan_incomplete() {
        let skip = |reason| Skipped {
            path: PathBuf::from("x"),
            reason,
        };
        for reason in [
            SkipReason::TooLarge { size: 9 },
            SkipReason::Unreadable {
                error: "denied".to_string(),
            },
            SkipReason::Executable { format: "ELF" },
        ] {
            let report = Report {
                skipped: vec![skip(reason.clone())],
                ..Report::default()
            };
            assert!(!report.is_complete(), "{reason:?}");
            assert_eq!(report.inconclusive_count(), 1);
        }
    }

    #[test]
    fn a_binary_that_was_read_but_has_no_rules_does_not_make_the_scan_incomplete() {
        let report = Report {
            skipped: vec![Skipped {
                path: PathBuf::from("data.gz"),
                reason: SkipReason::Binary,
            }],
            ..Report::default()
        };

        assert!(report.is_complete());
        assert_eq!(report.inconclusive_count(), 0);
    }

    #[test]
    fn executable_formats_are_recognised_by_their_magic_bytes() {
        let cases: [(&[u8], Option<&str>); 12] = [
            (b"\x7fELF\x02\x01\x01\0", Some("ELF")),
            (b"MZ\x90\0\x03\0", Some("PE")),
            (&[0xFE, 0xED, 0xFA, 0xCE, 0, 0], Some("Mach-O")),
            (&[0xFE, 0xED, 0xFA, 0xCF, 0, 0], Some("Mach-O")),
            (&[0xCE, 0xFA, 0xED, 0xFE, 0, 0], Some("Mach-O")),
            (&[0xCF, 0xFA, 0xED, 0xFE, 0, 0], Some("Mach-O")),
            (
                &[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2],
                Some("Mach-O fat (or Java class)"),
            ),
            (
                &[0xCA, 0xFE, 0xBA, 0xBF, 0, 0, 0, 2],
                Some("Mach-O fat (or Java class)"),
            ),
            (&[0x1F, 0x8B, 8, 0, 0], None),
            (&[0x28, 0xB5, 0x2F, 0xFD, 0], None),
            (b"\x89PNG\r\n\x1a\n\0", None),
            (b"", None),
        ];
        for (bytes, expected) in cases {
            assert_eq!(executable_format(bytes), expected, "{bytes:?}");
        }
    }

    #[test]
    fn an_executable_that_a_file_rule_examined_is_still_listed() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "helper.start", b"\x7fELF\x02\x01\x01\0\0\0\0\0");
        let rules = vec![file_rule("*.start", probe)];

        let report = scan(dir.path(), &rules, Limits::default());

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.inconclusive_count(), 1);
        assert!(!report.is_complete());
    }

    #[test]
    fn an_elf_binary_is_listed_as_an_executable_and_a_gzip_file_as_plain_binary() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "tool", b"\x7fELF\x02\x01\x01\0\0\0\0\0");
        write(dir.path(), "data.gz", &[0x1F, 0x8B, 8, 0, 0, 0, 0, 0]);
        let rules = parse_rules(RULES, "test.toml").unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        let reasons: Vec<_> = report
            .skipped
            .iter()
            .map(|s| (to_slash(&s.path), s.reason.clone()))
            .collect();
        assert_eq!(
            reasons,
            [
                ("data.gz".to_string(), SkipReason::Binary),
                ("tool".to_string(), SkipReason::Executable { format: "ELF" }),
            ]
        );
        assert!(
            !report.is_complete(),
            "the executable makes it inconclusive"
        );
        assert_eq!(report.inconclusive_count(), 1);
    }

    #[test]
    fn a_symlink_alone_does_not_make_the_scan_incomplete() {
        let report = Report {
            skipped: vec![Skipped {
                path: PathBuf::from("link"),
                reason: SkipReason::Symlink { target: None },
            }],
            ..Report::default()
        };

        assert!(report.is_complete());
    }

    #[test]
    fn a_payload_past_the_file_limit_is_missed_and_the_scan_is_not_complete() {
        let dir = tempfile::tempdir().unwrap();
        // Padding sorts before the payload, so the limit cuts the payload off.
        for name in ["a1.txt", "a2.txt", "a3.txt", "a4.txt"] {
            write(dir.path(), name, b"padding\n");
        }
        write(dir.path(), "z-payload.txt", b"TODO payload\n");
        let rules = parse_rules(RULES, "test.toml").unwrap();
        let limits = Limits {
            max_files: 4,
            ..Limits::default()
        };

        let report = scan(dir.path(), &rules, limits);

        assert!(report.findings.is_empty(), "the payload was never read");
        assert!(report.truncated);
        assert!(
            !report.is_complete(),
            "no findings must not mean clean here"
        );
    }

    #[test]
    fn file_rules_see_raw_bytes_of_binary_looking_files() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "x.pth", b"# \0 comment\nimport os\n");
        write(dir.path(), "other.bin", b"\0\0");
        let rules = [file_rule("**/*.pth", probe)];

        let report = scan(dir.path(), &rules, Limits::default());

        let found = explanations(&report);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, "x.pth");
        assert!(found[0].1.contains("bytes=22 issue=None"), "{}", found[0].1);
        // The file a rule examined counts as scanned and is not listed as a
        // binary skip; the file nobody examined is listed.
        assert_eq!(report.files_scanned, 1);
        assert_eq!(
            report.skipped,
            [Skipped {
                path: PathBuf::from("other.bin"),
                reason: SkipReason::Binary,
            }]
        );
    }

    #[test]
    fn file_rules_only_run_on_files_their_globs_select() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.pth", b"x");
        write(dir.path(), "a.txt", b"x");
        write(dir.path(), "UPPER.PTH", b"x");
        let rules = [file_rule("**/*.pth", probe)];

        let report = scan(dir.path(), &rules, Limits::default());

        let files: Vec<_> = explanations(&report)
            .into_iter()
            .map(|(file, _)| file)
            .collect();
        assert_eq!(files, ["UPPER.PTH", "a.pth"]);
    }

    #[test]
    fn oversized_files_reach_file_rules_with_an_issue_and_stay_in_skipped() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "big.pth", &[b'#'; 100]);
        let limits = Limits {
            max_file_size: 10,
            ..Limits::default()
        };
        let rules = [file_rule("**/*.pth", probe)];

        let report = scan(dir.path(), &rules, limits);

        let found = explanations(&report);
        assert_eq!(found.len(), 1);
        assert!(
            found[0]
                .1
                .contains("bytes=0 issue=Some(TooLarge { size: 100 })"),
            "{}",
            found[0].1
        );
        assert_eq!(report.skipped.len(), 1);
        assert!(matches!(
            report.skipped[0].reason,
            SkipReason::TooLarge { size: 100 }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_reach_file_rules_with_the_target_content_when_it_is_inside() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "docs/notes.txt", b"12345");
        std::os::unix::fs::symlink("docs/notes.txt", dir.path().join("inside.pth")).unwrap();
        std::os::unix::fs::symlink("../../etc/passwd", dir.path().join("outside.pth")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", dir.path().join("absolute.pth")).unwrap();
        let rules = [file_rule("**/*.pth", probe)];

        let report = scan(dir.path(), &rules, Limits::default());

        let found = explanations(&report);
        let get = |name: &str| {
            found
                .iter()
                .find(|(file, _)| file == name)
                .unwrap()
                .1
                .clone()
        };
        assert!(
            get("inside.pth").contains("bytes=5 issue=Some(Symlink"),
            "{}",
            get("inside.pth")
        );
        assert!(get("outside.pth").contains("bytes=0 issue=Some(Symlink"));
        assert!(get("absolute.pth").contains("bytes=0 issue=Some(Symlink"));
        // All three are still listed as not followed.
        assert_eq!(
            report
                .skipped
                .iter()
                .filter(|s| matches!(s.reason, SkipReason::Symlink { .. }))
                .count(),
            3
        );
    }

    #[test]
    fn symlink_targets_are_resolved_without_touching_anything_outside() {
        let link = Path::new("a/b/link.pth");
        assert_eq!(
            resolve_inside(link, Path::new("../c.txt")),
            Some(PathBuf::from("a/c.txt"))
        );
        assert_eq!(
            resolve_inside(link, Path::new("./d/e.txt")),
            Some(PathBuf::from("a/b/d/e.txt"))
        );
        assert_eq!(resolve_inside(link, Path::new("../../../x")), None);
        assert_eq!(resolve_inside(link, Path::new("/etc/passwd")), None);
        assert_eq!(
            resolve_inside(Path::new("top.pth"), Path::new("../x")),
            None
        );
    }

    #[test]
    fn file_rules_can_ask_whether_a_module_is_in_the_repository() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.pth", b"x");
        write(dir.path(), "lib/helper.py", b"x");
        let rules = [file_rule("**/*.pth", probe)];

        let report = scan(dir.path(), &rules, Limits::default());

        assert!(explanations(&report)[0].1.contains("helper=true"));
    }

    #[test]
    fn file_rules_are_told_when_the_walk_was_cut_short() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["a.pth", "b.txt", "c.txt"] {
            write(dir.path(), name, b"x");
        }
        let limits = Limits {
            max_files: 2,
            ..Limits::default()
        };
        let rules = [file_rule("**/*.pth", probe)];

        let report = scan(dir.path(), &rules, limits);

        assert!(report.truncated);
        assert!(explanations(&report)[0].1.contains("truncated=true"));
    }

    #[test]
    fn file_rule_explanations_are_cleaned_and_long_lists_are_capped() {
        fn noisy(_: &FileCtx<'_>) -> Vec<Hit> {
            (1..=150)
                .map(|line| Hit {
                    line,
                    severity: Severity::High,
                    reason: "bad \u{1b}[2J text".to_string(),
                })
                .collect()
        }
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.pth", b"x");
        let rules = [file_rule("**/*.pth", noisy)];

        let report = scan(dir.path(), &rules, Limits::default());

        assert_eq!(report.findings.len(), MAX_FINDINGS_PER_FILE_CHECK);
        assert!(
            report
                .findings
                .iter()
                .all(|f| !f.explanation.contains('\u{1b}'))
        );
        let last = report.findings.last().unwrap();
        assert!(last.explanation.contains("50 more"), "{}", last.explanation);
    }
}
