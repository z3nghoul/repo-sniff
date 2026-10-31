//! The `--fail-on` threshold: when a scan should make the command fail.

use repo_sniff_core::{Report, Severity};

/// What to do about findings when choosing the process exit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailOn {
    /// Findings never change the exit status (`--fail-on none`).
    Never,
    /// Fail if any finding is at least this severe.
    AtLeast(Severity),
}

impl FailOn {
    /// Whether `report` contains a finding that crosses the threshold.
    pub fn is_triggered_by(self, report: &Report) -> bool {
        match self {
            FailOn::Never => false,
            FailOn::AtLeast(threshold) => report.findings.iter().any(|f| f.severity >= threshold),
        }
    }
}

/// Parses the value of `--fail-on`: a severity name or `none`.
pub fn parse(text: &str) -> Result<FailOn, String> {
    if text.eq_ignore_ascii_case("none") {
        return Ok(FailOn::Never);
    }
    text.parse::<Severity>()
        .map(FailOn::AtLeast)
        .map_err(|err| format!("{err}, or `none`"))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use repo_sniff_core::{Finding, Stage};

    use super::*;

    fn report_with(severities: &[Severity]) -> Report {
        Report {
            findings: severities
                .iter()
                .map(|&severity| Finding {
                    rule_id: "test.rule".to_string(),
                    severity,
                    stage: Stage::Run,
                    attack: vec![],
                    file: PathBuf::from("a.txt"),
                    line: 1,
                    explanation: String::new(),
                })
                .collect(),
            ..Report::default()
        }
    }

    #[test]
    fn parses_severities_and_none() {
        assert_eq!(parse("high"), Ok(FailOn::AtLeast(Severity::High)));
        assert_eq!(parse("CRITICAL"), Ok(FailOn::AtLeast(Severity::Critical)));
        assert_eq!(parse("none"), Ok(FailOn::Never));
        assert_eq!(parse("None"), Ok(FailOn::Never));
    }

    #[test]
    fn rejects_unknown_values_with_a_helpful_message() {
        let message = parse("urgent").unwrap_err();
        assert!(message.contains("`urgent`"), "{message}");
        assert!(message.contains("none"), "{message}");
    }

    #[test]
    fn threshold_is_inclusive() {
        let report = report_with(&[Severity::Medium]);
        assert!(FailOn::AtLeast(Severity::Medium).is_triggered_by(&report));
        assert!(FailOn::AtLeast(Severity::Low).is_triggered_by(&report));
        assert!(!FailOn::AtLeast(Severity::High).is_triggered_by(&report));
    }

    #[test]
    fn never_ignores_every_finding() {
        assert!(!FailOn::Never.is_triggered_by(&report_with(&[Severity::Critical])));
    }

    #[test]
    fn a_report_without_findings_never_triggers() {
        assert!(!FailOn::AtLeast(Severity::Info).is_triggered_by(&report_with(&[])));
    }
}
