//! Rules whose logic is written in Rust rather than as a pattern.
//!
//! A rule with `engine = "jsonc"` or `engine = "file"` in its TOML file only
//! carries metadata (id, stage, severity, ATT&CK IDs, descriptions). The code
//! that decides what to report lives here and is looked up by the rule's id.
//!
//! Every check has the same signature (`Check`) and reads the file through
//! `Ctx`, whose views are computed on demand. The engine only decides when a
//! check runs: an `engine = "file"` check sees the raw bytes of every file its
//! globs select, before binary detection, including files that are too large or
//! are symbolic links (see `FileIssue`); an `engine = "jsonc"` check runs on
//! files the line rules read, after the scanner has classified them, and on a
//! symbolic link to a regular file inside the repository, with that file's
//! content and `FileIssue::Symlink`, because the tool that opens the link
//! follows it. A file or link target it cannot read whole is listed as too
//! large instead, and a link whose target is not a regular file in the
//! repository as unreadable; both make the scan inconclusive.

pub mod js_lex;
pub mod js_loaders;
pub mod js_shape;
pub mod npm_scripts;
mod pylines;
pub mod python_pth;
pub mod python_start;
pub mod repo_contents;
pub mod vscode_autorun;
pub mod win_loaders;

use std::borrow::Cow;
use std::cell::{Cell, OnceCell};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::ops::Range;

use crate::finding::Severity;
use crate::jsonc::{self, Node, ParseError};

/// One thing a check wants to report in a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// 1-based line number.
    pub line: usize,
    pub severity: Severity,
    /// What is wrong, shown to the user. May contain text from the scanned
    /// file; the scanner cleans it with `display_safe` before reporting.
    pub reason: String,
    /// Where in `Ctx::text` the hit is, if the check knows. The scanner turns
    /// it into the finding's column and snippet, and into a byte range of the
    /// file when the text is the file byte for byte. A span that is out of
    /// bounds, splits a character or is not on `line` is ignored. A check that
    /// works on `Ctx::bytes` leaves it `None`.
    pub span: Option<TextSpan>,
}

/// A byte range in `Ctx::text`, which is not always the file's bytes (UTF-16
/// is decoded, NUL bytes are dropped, invalid UTF-8 is replaced). The type
/// keeps it apart from a range of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextSpan(pub Range<usize>);

/// Every check has this signature, whatever the format it reads: it asks the
/// context for the view it needs (`bytes`, `text`, `jsonc`) and reports hits.
pub type Check = fn(&Ctx<'_>) -> Vec<Hit>;

/// How the bytes of a file become the text the rules read. The scanner picks
/// it when it classifies the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decode {
    /// UTF-8 with the NUL bytes dropped first and invalid sequences replaced,
    /// as `dash` and `bash` read a file.
    Utf8WithoutNuls,
    /// Only the ASCII bytes; every other byte becomes U+FFFD. Used for data
    /// that does not read as text.
    AsciiOnly,
    /// UTF-16 after its byte order mark.
    Utf16Bom,
}

/// The views of one file. Each is computed the first time a check asks for
/// it and then shared by every rule that looks at the same file, so a file is
/// decoded and parsed at most once, and not at all if no check needs it.
pub(crate) struct Views<'a> {
    bytes: &'a [u8],
    decode: Decode,
    /// The native executable format the scanner found, if any.
    executable: Option<&'static str>,
    /// The size of the whole file, when `bytes` is only its head.
    size: Option<u64>,
    text: OnceCell<Cow<'a, str>>,
    jsonc: OnceCell<Result<Node, ParseError>>,
    /// What the JavaScript loader flow analysis found in `text`.
    js_flow: OnceCell<Vec<js_loaders::Found>>,
    /// What the Windows loader signatures found in the file.
    win_flow: OnceCell<Vec<win_loaders::WinFound>>,
    /// The last `line_of` answer, `(offset, line)`, to count on from.
    line_cursor: Cell<(usize, usize)>,
}

impl<'a> Views<'a> {
    pub(crate) fn new(bytes: &'a [u8], decode: Decode) -> Self {
        Views {
            bytes,
            decode,
            executable: None,
            size: None,
            text: OnceCell::new(),
            jsonc: OnceCell::new(),
            js_flow: OnceCell::new(),
            win_flow: OnceCell::new(),
            line_cursor: Cell::new((0, 1)),
        }
    }

    pub(crate) fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Records the native executable format the scanner found for the file.
    pub(crate) fn with_executable(mut self, executable: Option<&'static str>) -> Self {
        self.executable = executable;
        self
    }

    /// Records the size of the whole file.
    pub(crate) fn with_size(mut self, size: Option<u64>) -> Self {
        self.size = size;
        self
    }

    /// The file as the line rules read it.
    pub(crate) fn text(&self) -> &str {
        self.text
            .get_or_init(|| crate::scan::decode(self.decode, self.bytes))
    }

    /// The 1-based line of a byte offset in `text`, counting `\n`, so LF and
    /// CRLF files agree; an offset past the end counts as the end. It counts on
    /// from the previous answer, so offsets asked in document order, as a
    /// parser hands them out, cost one pass over the text in total instead of
    /// one pass each.
    pub(crate) fn line_of(&self, offset: usize) -> usize {
        let text = self.text().as_bytes();
        let offset = offset.min(text.len());
        let newlines = |range: &[u8]| range.iter().filter(|&&b| b == b'\n').count();
        let (from, line) = self.line_cursor.get();
        let line = if offset >= from {
            line + newlines(&text[from..offset])
        } else {
            line - newlines(&text[offset..from])
        };
        self.line_cursor.set((offset, line));
        line
    }

    /// Whether `text` is the file byte for byte, so an offset in one is the
    /// same offset in the other. False until `text` has been computed, and
    /// for decoded UTF-16, dropped NUL bytes, replaced invalid UTF-8 and the
    /// ASCII-only view.
    pub(crate) fn text_is_bytes(&self) -> bool {
        matches!(
            self.text.get(),
            Some(Cow::Borrowed(text))
                if text.as_ptr() == self.bytes.as_ptr() && text.len() == self.bytes.len()
        )
    }

    /// Whether a count of characters in `text` is a column an editor would
    /// show: the text is the file itself, or the file decoded from UTF-16.
    /// Dropped NUL bytes, replaced invalid UTF-8 and the ASCII-only view shift
    /// or split characters, so they give no column. Like `text_is_bytes`, it
    /// is meant to be asked once `text` has been computed.
    pub(crate) fn columns_are_exact(&self) -> bool {
        self.text_is_bytes() || self.decode == Decode::Utf16Bom
    }

    /// The loader findings of `text` read as JavaScript (see `js_loaders`),
    /// found once for all the rules that ask.
    pub(crate) fn js_flow(&self) -> &[js_loaders::Found] {
        self.js_flow.get_or_init(|| js_loaders::flow(self.text()))
    }

    /// `text` parsed as JSONC.
    pub(crate) fn jsonc(&self) -> &Result<Node, ParseError> {
        self.jsonc.get_or_init(|| jsonc::parse(self.text()))
    }
}

/// What a check is given: where the file is, what the repository around it
/// holds, and lazily computed views of the file's content.
pub struct Ctx<'a> {
    /// Path relative to the repository root, with `/` separators.
    pub path: &'a str,
    /// Why the file is not an ordinary readable file, if it is not.
    /// `engine = "file"` checks are offered every such file; `engine = "jsonc"`
    /// checks only symbolic links whose target was read.
    pub issue: Option<FileIssue>,
    pub repo: &'a RepoIndex,
    /// True if the walk stopped early, so `repo` may be missing files.
    pub truncated: bool,
    /// The severity from the rule's TOML file: the check reports it for the
    /// ordinary case and may go higher or lower when the file gives a reason.
    pub base: Severity,
    views: &'a Views<'a>,
}

impl<'a> Ctx<'a> {
    pub(crate) fn new(
        path: &'a str,
        issue: Option<FileIssue>,
        repo: &'a RepoIndex,
        truncated: bool,
        base: Severity,
        views: &'a Views<'a>,
    ) -> Self {
        Ctx {
            path,
            issue,
            repo,
            truncated,
            base,
            views,
        }
    }

    /// The raw bytes of the file, so a file is judged the way the tool that
    /// consumes it reads it, even when it would not pass for a text file. Empty
    /// for a file that was too large to read.
    pub fn bytes(&self) -> &'a [u8] {
        self.views.bytes()
    }

    /// The file as the line rules read it (see `Decode`). For a file that is
    /// too large it is empty; for a symbolic link it is the text of the target
    /// that `bytes` holds; for an executable it is its ASCII only.
    pub fn text(&self) -> &'a str {
        self.views.text()
    }

    /// The native executable format the scanner found for the file (`ELF`,
    /// `PE`, `Mach-O`, ...), or `None`. A check that asks this and the
    /// scanner's own "executable" listing always agree. It is found from the
    /// first bytes, and for a PE from the `PE\0\0` signature where `e_lfanew`
    /// points, read from the file even past the bytes a head check sees. Set
    /// for head checks; `None` for other engines.
    pub fn executable(&self) -> Option<&'static str> {
        self.views.executable
    }

    /// The size of the whole file in bytes, for a head check, whose `bytes`
    /// are only the first ones; `None` when unknown and for other engines.
    pub fn file_size(&self) -> Option<u64> {
        self.views.size
    }

    /// The 1-based line of a byte offset in `text` (see `Views::line_of`).
    /// Use it instead of counting lines from the start for every hit, which is
    /// quadratic on a file with many hits.
    pub fn line_of(&self, offset: usize) -> usize {
        self.views.line_of(offset)
    }

    /// What the Windows loader signatures found in the file, computed once
    /// for the three rules.
    pub(crate) fn win_flow(&self) -> &'a [win_loaders::WinFound] {
        self.views
            .win_flow
            .get_or_init(|| win_loaders::analyze(self))
    }

    /// What the JavaScript loader analysis found in the file's text.
    pub(crate) fn js_flow(&self) -> &'a [js_loaders::Found] {
        self.views.js_flow()
    }

    /// The file parsed as JSONC, or the parse error.
    pub fn jsonc(&self) -> &'a Result<Node, ParseError> {
        self.views.jsonc()
    }
}

impl std::fmt::Debug for Ctx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ctx")
            .field("path", &self.path)
            .field("bytes", &self.views.bytes().len())
            .field("issue", &self.issue)
            .field("truncated", &self.truncated)
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

/// Everything a file check may want to know about the repository.
#[derive(Debug, Default, Clone)]
pub struct RepoIndex {
    paths: BTreeSet<String>,
    names: HashSet<String>,
    /// The bytes of every `package.json` the scan read (see
    /// `with_manifests`), by path, so a check can follow `cd a && npm install`
    /// into another manifest without touching the disk.
    manifests: HashMap<String, Vec<u8>>,
    /// Files that a script of some `package.json` starts with `node`.
    run_files: HashSet<String>,
}

impl RepoIndex {
    /// Builds the index from repository-relative paths with `/` separators.
    pub fn new<I, S>(paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut index = RepoIndex::default();
        for path in paths {
            let path = path.as_ref();
            for component in path.split('/') {
                index.names.insert(component.to_string());
            }
            index.paths.insert(path.to_string());
        }
        index
    }

    /// Records the contents of the `package.json` files, by repository path.
    pub fn with_manifests(mut self, manifests: HashMap<String, Vec<u8>>) -> Self {
        self.manifests = manifests;
        self
    }

    /// Records the files that npm scripts start (see
    /// `npm_scripts::started_files`).
    pub fn with_run_files(mut self, files: HashSet<String>) -> Self {
        self.run_files = files;
        self
    }

    /// Whether a script of some `package.json` in the repository starts this
    /// file with `node` or a similar program.
    pub fn runs_file(&self, path: &str) -> bool {
        self.run_files.contains(path)
    }

    /// The paths of the `package.json` files the scan read.
    pub(crate) fn manifest_paths(&self) -> impl Iterator<Item = &String> {
        self.manifests.keys()
    }

    /// The bytes of the `package.json` at this exact path, if the scan read it
    /// (a regular file within the size limit).
    pub fn manifest(&self, path: &str) -> Option<&[u8]> {
        self.manifests.get(path).map(Vec::as_slice)
    }

    /// Whether this exact path exists in the repository.
    pub fn contains_path(&self, path: &str) -> bool {
        self.paths.contains(path)
    }

    /// Whether any file or directory in the repository has this name.
    pub fn has_name(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    /// Whether a Python module with this name is in the repository, as a
    /// `name.py` file or as a `name/` directory anywhere.
    pub fn has_module(&self, module: &str) -> bool {
        self.has_name(module) || self.has_name(&format!("{module}.py"))
    }
}

/// Why a file reaches a file check without being an ordinary readable file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileIssue {
    /// Larger than the scan's file size limit; `bytes` is empty.
    TooLarge { size: u64 },
    /// A symbolic link. `target` is where it points (as text). `resolved` is
    /// the repository path it points at when, resolved as text from the link's
    /// folder, it stays inside the repository; `None` when the target is
    /// absolute, leaves the repository or could not be read. `bytes` holds the
    /// target's content when that is a regular file inside the repository, and
    /// is empty otherwise.
    Symlink {
        target: Option<String>,
        resolved: Option<String>,
    },
}

/// How many leading bytes an `engine = "head"` check is given: the same
/// window the scanner reads to tell text from binary data.
pub const HEAD_LEN: usize = 8 * 1024;

/// Every file check, keyed by the id of the rule it implements.
const FILE_CHECKS: &[(&str, Check)] = &[
    ("deps.npm-lifecycle-hook", npm_scripts::lifecycle_hook),
    ("run.npm-script-local-server", npm_scripts::run_script),
    ("run.js-fetch-eval", js_loaders::fetch_eval),
    ("run.js-function-require", js_loaders::function_require),
    (
        "obfuscation.encoded-payload-sink",
        js_loaders::encoded_payload,
    ),
    ("obfuscation.obfuscator-io", js_shape::obfuscator),
    ("obfuscation.minified-source", js_shape::minified),
    ("run.windows-remote-code", win_loaders::remote_code),
    (
        "obfuscation.windows-encoded-payload",
        win_loaders::encoded_payload,
    ),
    (
        "run.windows-defender-exclusion",
        win_loaders::defender_exclusion,
    ),
    ("deps.python-pth-exec", python_pth::check),
    ("deps.python-start-entrypoint", python_start::check),
];

/// Finds the file check registered for a rule id.
pub fn file_check(rule_id: &str) -> Option<Check> {
    FILE_CHECKS
        .iter()
        .find(|(id, _)| *id == rule_id)
        .map(|(_, check)| *check)
}

/// Every head check, keyed by the id of the rule it implements.
const HEAD_CHECKS: &[(&str, Check)] = &[
    ("repo.committed-binary", repo_contents::committed_binary),
    (
        "repo.disguised-executable",
        repo_contents::disguised_executable,
    ),
    ("repo.symlink-outside", repo_contents::symlink_outside),
    ("repo.windows-dropper", repo_contents::windows_dropper),
    ("repo.windows-script", repo_contents::windows_script),
];

/// Finds the head check registered for a rule id.
pub fn head_check(rule_id: &str) -> Option<Check> {
    HEAD_CHECKS
        .iter()
        .find(|(id, _)| *id == rule_id)
        .map(|(_, check)| *check)
}

/// Every jsonc check, keyed by the id of the rule it implements.
const JSONC_CHECKS: &[(&str, Check)] = &[("ide.vscode-folder-open-task", vscode_autorun::check)];

/// Finds the check registered for a rule id.
pub fn jsonc_check(rule_id: &str) -> Option<Check> {
    JSONC_CHECKS
        .iter()
        .find(|(id, _)| *id == rule_id)
        .map(|(_, check)| *check)
}

/// Runs a check on a text file with an empty repository around it.
#[cfg(test)]
pub(crate) fn run_on_text(check: Check, path: &str, text: &str, base: Severity) -> Vec<Hit> {
    let views = Views::new(text.as_bytes(), Decode::Utf8WithoutNuls);
    let repo = RepoIndex::default();
    check(&Ctx::new(path, None, &repo, false, base, &views))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::{Matcher, builtin_rules};

    #[test]
    fn every_registered_check_has_a_builtin_rule() {
        let rules = builtin_rules().unwrap();
        for (id, _) in JSONC_CHECKS {
            let rule = rules
                .iter()
                .find(|rule| rule.id == *id)
                .unwrap_or_else(|| panic!("check `{id}` has no rule in rules/*.toml"));
            assert!(
                matches!(rule.matcher, Matcher::Jsonc(_)),
                "rule `{id}` must use engine = \"jsonc\""
            );
        }
    }

    #[test]
    fn every_registered_head_check_has_a_builtin_rule() {
        let rules = builtin_rules().unwrap();
        for (id, _) in HEAD_CHECKS {
            let rule = rules
                .iter()
                .find(|rule| rule.id == *id)
                .unwrap_or_else(|| panic!("check `{id}` has no rule in rules/*.toml"));
            assert!(
                matches!(rule.matcher, Matcher::Head(_)),
                "rule `{id}` must use engine = \"head\""
            );
        }
    }

    #[test]
    fn every_registered_file_check_has_a_builtin_rule() {
        let rules = builtin_rules().unwrap();
        for (id, _) in FILE_CHECKS {
            let rule = rules
                .iter()
                .find(|rule| rule.id == *id)
                .unwrap_or_else(|| panic!("check `{id}` has no rule in rules/*.toml"));
            assert!(
                matches!(rule.matcher, Matcher::File(_)),
                "rule `{id}` must use engine = \"file\""
            );
        }
    }

    #[test]
    fn views_are_computed_once_and_shared() {
        let bytes = b"{\"a\": 1}\0";
        let views = Views::new(bytes, Decode::Utf8WithoutNuls);
        assert!(views.text.get().is_none(), "nothing is decoded up front");
        let repo = RepoIndex::default();
        let first = Ctx::new("x.json", None, &repo, false, Severity::Low, &views);
        let second = Ctx::new("x.json", None, &repo, false, Severity::High, &views);

        assert!(
            first.jsonc().is_ok(),
            "parsed from the text without the NUL"
        );
        assert!(std::ptr::eq(first.jsonc(), second.jsonc()));
        assert!(std::ptr::eq(first.text(), second.text()));
        assert_eq!(second.bytes(), bytes);
    }

    #[test]
    fn line_of_agrees_with_counting_from_the_start_in_any_order() {
        let text = "a\nbb\r\n\nccc\r\nd";
        let views = Views::new(text.as_bytes(), Decode::Utf8WithoutNuls);
        let offsets = [0, 5, 2, 3, 15, 999, 7, 1, 8, 4, 0, 14, 6, 13];
        for offset in offsets {
            assert_eq!(
                views.line_of(offset),
                jsonc::line_of(text, offset),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn repo_index_answers_questions_about_paths_and_modules() {
        let index = RepoIndex::new([
            "a/b/c.txt",
            "pkg/_helper.py",
            "pkg/tools/__init__.py",
            "README.md",
        ]);
        assert!(index.contains_path("a/b/c.txt"));
        assert!(!index.contains_path("a/b"));
        assert!(index.has_name("b"));
        assert!(index.has_name("README.md"));
        assert!(index.has_module("_helper"));
        assert!(index.has_module("tools"));
        assert!(!index.has_module("c"));
        assert!(!index.has_module("missing"));
    }

    #[test]
    fn every_jsonc_rule_has_a_registered_check() {
        // Loading already fails for an unknown check; this documents the
        // other direction of the pairing.
        let rules = builtin_rules().unwrap();
        for rule in rules
            .iter()
            .filter(|r| matches!(r.matcher, Matcher::Jsonc(_)))
        {
            assert!(jsonc_check(&rule.id).is_some(), "{}", rule.id);
        }
    }
}
