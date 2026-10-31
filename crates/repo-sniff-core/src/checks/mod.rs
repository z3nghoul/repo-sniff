//! Rules whose logic is written in Rust rather than as a pattern.
//!
//! A rule with `engine = "jsonc"` in its TOML file only carries metadata (id,
//! stage, severity, ATT&CK IDs, descriptions). The code that decides what to
//! report lives here and is looked up by the rule's id.

pub mod vscode_autorun;

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
