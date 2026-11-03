//! What the scanner reports: one `Finding` per suspicious spot.

use std::fmt;
use std::ops::Range;
use std::path::PathBuf;
use std::str::FromStr;

use serde::Deserialize;
use thiserror::Error;

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

/// The text is not the name of a severity level.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unknown severity `{0}`; expected one of: info, low, medium, high, critical")]
pub struct UnknownSeverity(pub String);

impl FromStr for Severity {
    type Err = UnknownSeverity;

    /// Accepts the level names in any letter case: `high`, `HIGH`, `High`.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.to_ascii_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            _ => Err(UnknownSeverity(text.to_string())),
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
    /// 1-based column where the match starts, in Unicode scalar values of the
    /// line (a byte order mark on the first line is not counted). Given only
    /// when the text the rule read is the file itself or the file decoded from
    /// UTF-16; with NUL bytes dropped, invalid UTF-8 replaced or binary data
    /// read as ASCII only, a count would not be the column an editor shows, so
    /// it is `None`, as it is when the rule points at a whole line or file.
    pub column: Option<usize>,
    /// Byte range of the match in the file. `None` when it is not known, and
    /// also when the text the rule read is not the file byte for byte (decoded
    /// UTF-16, dropped NUL bytes, replaced invalid UTF-8, the ASCII-only view
    /// of binary data), so a range that is given is never wrong.
    pub span: Option<Range<usize>>,
    /// The line of the match as the rule read it, cut to a short window around
    /// the match and escaped with `snippet_safe`. It is still text from the
    /// scanned file. `None` when the rule points at a whole line or file.
    pub snippet: Option<String>,
    /// True when the line was longer than the window of `snippet`, so `...`
    /// marks text left out before or after it.
    pub snippet_truncated: bool,
    /// Why this is suspicious, in plain words. A check may quote the scanned
    /// file in it; such an explanation is escaped with `display_safe` and cut
    /// to a limit.
    pub explanation: String,
    /// True when `explanation` was cut to its limit.
    pub explanation_truncated: bool,
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
    fn severity_parses_names_in_any_case() {
        assert_eq!("high".parse(), Ok(Severity::High));
        assert_eq!("CRITICAL".parse(), Ok(Severity::Critical));
        assert_eq!("Info".parse(), Ok(Severity::Info));
        // The code shown in reports can be fed back as input.
        for severity in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert_eq!(severity.code().parse(), Ok(severity));
        }
    }

    #[test]
    fn unknown_severity_is_an_error_naming_the_input() {
        let err = "urgent".parse::<Severity>().unwrap_err();
        assert_eq!(err, UnknownSeverity("urgent".to_string()));
        assert!(err.to_string().contains("`urgent`"));
        assert!("".parse::<Severity>().is_err());
    }

    #[test]
    fn severity_displays_as_untranslatable_code() {
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
        assert_eq!(Severity::Info.to_string(), "INFO");
    }
}
