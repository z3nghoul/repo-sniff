//! Rules whose logic is written in Rust rather than as a pattern.
//!
//! A rule with `engine = "jsonc"` or `engine = "file"` in its TOML file only
//! carries metadata (id, stage, severity, ATT&CK IDs, descriptions). The code
//! that decides what to report lives here and is looked up by the rule's id.

mod pylines;
pub mod python_pth;
pub mod vscode_autorun;

use std::collections::{BTreeSet, HashSet};

use crate::finding::Severity;

/// One thing a check wants to report in a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// 1-based line number.
    pub line: usize,
    pub severity: Severity,
    /// What is wrong, shown to the user. May contain text from the scanned
    /// file; the scanner cleans it with `display_safe` before reporting.
    pub reason: String,
}

/// A check for structured (JSONC) files.
///
/// `path` is relative to the repository root with `/` separators, `text` is
/// the whole file, and `base` is the severity from the rule's TOML file: the
/// check reports it for the ordinary case and may go higher or lower when the
/// file gives a reason to.
pub type JsoncCheck = fn(path: &str, text: &str, base: Severity) -> Vec<Hit>;

/// Everything a file check may want to know about the repository.
#[derive(Debug, Default, Clone)]
pub struct RepoIndex {
    paths: BTreeSet<String>,
    names: HashSet<String>,
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
    /// A symbolic link. `target` is where it points (as text). `bytes` holds
    /// the target's content when that is a regular file inside the repository,
    /// and is empty otherwise.
    Symlink { target: Option<String> },
}

/// What a file check is given. It sees the raw bytes, so a file is judged the
/// way the tool that will consume it sees it, even when it would not pass for
/// a text file.
#[derive(Debug)]
pub struct FileCtx<'a> {
    /// Path relative to the repository root, with `/` separators.
    pub path: &'a str,
    pub bytes: &'a [u8],
    pub issue: Option<FileIssue>,
    pub repo: &'a RepoIndex,
    /// True if the walk stopped early, so `repo` may be missing files.
    pub truncated: bool,
    /// The severity from the rule's TOML file.
    pub base: Severity,
}

/// A check that works on one whole file, selected by the rule's `files` globs.
pub type FileCheck = fn(&FileCtx<'_>) -> Vec<Hit>;

/// Every file check, keyed by the id of the rule it implements.
const FILE_CHECKS: &[(&str, FileCheck)] = &[("deps.python-pth-exec", python_pth::check)];

/// Finds the file check registered for a rule id.
pub fn file_check(rule_id: &str) -> Option<FileCheck> {
    FILE_CHECKS
        .iter()
        .find(|(id, _)| *id == rule_id)
        .map(|(_, check)| *check)
}

/// Every jsonc check, keyed by the id of the rule it implements.
const JSONC_CHECKS: &[(&str, JsoncCheck)] =
    &[("ide.vscode-folder-open-task", vscode_autorun::check)];

/// Finds the check registered for a rule id.
pub fn jsonc_check(rule_id: &str) -> Option<JsoncCheck> {
    JSONC_CHECKS
        .iter()
        .find(|(id, _)| *id == rule_id)
        .map(|(_, check)| *check)
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
