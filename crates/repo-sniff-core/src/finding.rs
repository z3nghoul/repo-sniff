//! What the scanner reports: one `Finding` per suspicious spot.

use std::fmt;
use std::path::PathBuf;

use serde::Deserialize;

/// How serious a finding is.
///
/// Variants are declared from least to most severe, so the derived `Ord`
/// lets us compare levels directly: `Severity::High > Severity::Low`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// The untranslatable code shown in every report and UI.
    pub fn code(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// The step on a developer's machine at which the flagged code would run.
/// Mirrors the stages in `docs/DETECTIONS.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    /// The repository contents themselves, right after cloning.
    Repo,
    /// Opening the project in an IDE.
    Ide,
    /// Installing dependencies.
    Deps,
    /// Building.
    Build,
    /// Running tests.
    Tests,
    /// Running the program.
    Run,
    /// Tricks aimed at the human reading the code.
    Deception,
    /// Hiding what code does.
    Obfuscation,
}

impl Stage {
    pub fn name(self) -> &'static str {
        match self {
            Stage::Repo => "repo",
            Stage::Ide => "ide",
            Stage::Deps => "deps",
            Stage::Build => "build",
            Stage::Tests => "tests",
            Stage::Run => "run",
            Stage::Deception => "deception",
            Stage::Obfuscation => "obfuscation",
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A single suspicious spot found by a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub stage: Stage,
    /// MITRE ATT&CK technique IDs, e.g. `T1547.001`. May be empty.
    pub attack: Vec<String>,
    /// Path relative to the scanned repository root.
    pub file: PathBuf,
    /// 1-based line number.
    pub line: usize,
    /// Why this is suspicious, in plain words.
    pub explanation: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severities_are_ordered_from_info_to_critical() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn severity_displays_as_untranslatable_code() {
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
        assert_eq!(Severity::Info.to_string(), "INFO");
    }
}
