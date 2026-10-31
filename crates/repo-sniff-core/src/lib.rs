//! Scanning engine of repo-sniff.
//!
//! This crate knows nothing about how results are shown: it never prints
//! and has no terminal or UI dependencies. The CLI, the TUI and the GitHub
//! Action all build on top of it.

pub mod finding;
pub mod rule;
pub mod scan;
pub mod walk;

pub use finding::{Finding, Severity, Stage};
pub use rule::{Engine, Matcher, Rule, RuleError, builtin_rules, parse_rules};
pub use scan::{Report, scan};
pub use walk::{Limits, SkipReason, Skipped, WalkResult, walk};
