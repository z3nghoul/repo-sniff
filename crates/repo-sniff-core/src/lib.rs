//! Scanning engine of repo-sniff.
//!
//! This crate knows nothing about how results are shown: it never prints
//! and has no terminal or UI dependencies. The CLI, the TUI and the GitHub
//! Action all build on top of it.

pub mod checks;
pub mod finding;
pub mod jsonc;
pub mod rule;
pub mod sanitize;
pub mod scan;
pub mod walk;

pub use checks::{FileCheck, FileCtx, FileIssue, Hit, JsoncCheck, RepoIndex};
pub use finding::{Finding, Severity, Stage, UnknownSeverity};
pub use rule::{Engine, Matcher, Rule, RuleError, builtin_rules, parse_rules};
pub use sanitize::{display_path, display_safe};
pub use scan::{Report, Unlisted, scan};
pub use walk::{Limits, SkipReason, Skipped, WalkResult, walk};
