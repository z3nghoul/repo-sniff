//! The Trojan Source rule against its fixtures and every character it covers.

use std::fs;
use std::path::{Path, PathBuf};

use repo_sniff_core::{Limits, Severity, Stage, builtin_rules, scan};

const RULE_ID: &str = "deception.bidi-control";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/trojan-source")
}

/// Reports use `/` on every OS, so compare paths the same way.
fn slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[test]
fn only_the_positive_and_unchanged_fixtures_are_flagged() {
    let rules = builtin_rules().unwrap();

    let report = scan(&fixtures(), &rules, Limits::default());

    let found: Vec<_> = report
        .findings
        .iter()
        .map(|f| (slash(&f.file), f.line, f.rule_id.as_str(), f.severity))
        .collect();
    assert_eq!(
        found,
        [
            (
                "positive/commenting_out.c".to_string(),
                3,
                RULE_ID,
                Severity::Critical
            ),
            (
                "positive/early_return.py".to_string(),
                3,
                RULE_ID,
                Severity::Critical
            ),
            (
                "positive/invisible_padding.js".to_string(),
                3,
                RULE_ID,
                Severity::Critical
            ),
            (
                "positive/isolate_reorders_call.js".to_string(),
                2,
                RULE_ID,
                Severity::Critical
            ),
            (
                "positive/line_separator_inside_override.js".to_string(),
                3,
                RULE_ID,
                Severity::Critical
            ),
            (
                "positive/next_line_inside_override.js".to_string(),
                3,
                RULE_ID,
                Severity::Critical
            ),
            (
                "positive/rlm_beside_controls.js".to_string(),
                3,
                RULE_ID,
                Severity::Critical
            ),
            (
                "positive/rtl_base_only.js".to_string(),
                3,
                RULE_ID,
                Severity::Critical
            ),
            (
                "positive/rtl_helper_longer.js".to_string(),
                3,
                RULE_ID,
                Severity::Critical
            ),
            (
                "positive/stretched_string.js".to_string(),
                3,
                RULE_ID,
                Severity::Critical
            ),
            (
                "positive/trailing_space_in_override.py".to_string(),
                3,
                RULE_ID,
                Severity::Critical
            ),
            (
                "positive/unclosed_embedding.js".to_string(),
                2,
                RULE_ID,
                Severity::Critical
            ),
            (
                "unchanged/arabic_label.py".to_string(),
                3,
                RULE_ID,
                Severity::Low
            ),
            (
                "unchanged/arabic_label.py".to_string(),
                4,
                RULE_ID,
                Severity::Low
            ),
            (
                "unchanged/lrm_beside_controls.js".to_string(),
                3,
                RULE_ID,
                Severity::Low
            ),
            (
                "unchanged/rtl_helper.js".to_string(),
                3,
                RULE_ID,
                Severity::Low
            ),
            (
                "unchanged/rtl_helper.js".to_string(),
                5,
                RULE_ID,
                Severity::Low
            ),
            (
                "unchanged/rtl_helper.js".to_string(),
                6,
                RULE_ID,
                Severity::Low
            ),
            (
                "unchanged/rtl_helper.js".to_string(),
                7,
                RULE_ID,
                Severity::Low
            ),
        ]
    );
    assert_eq!(
        report.files_scanned, 20,
        "every fixture should have been read"
    );
}

#[test]
fn finding_carries_rule_metadata() {
    let rules = builtin_rules().unwrap();

    let report = scan(&fixtures(), &rules, Limits::default());

    let finding = &report.findings[0];
    assert_eq!(finding.stage, Stage::Deception);
    assert!(finding.explanation.contains("CVE-2021-42574"));
}

#[test]
fn every_bidi_control_character_is_detected() {
    let rules = builtin_rules().unwrap();
    let dir = tempfile::tempdir().unwrap();

    for code in (0x202A..=0x202E).chain(0x2066..=0x2069) {
        let ch = char::from_u32(code).unwrap();
        fs::write(dir.path().join("a.txt"), format!("before{ch}after\n")).unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        assert_eq!(report.findings.len(), 1, "U+{code:04X} was not detected");
    }
}

#[test]
fn neighbouring_code_points_are_not_detected() {
    let rules = builtin_rules().unwrap();
    let dir = tempfile::tempdir().unwrap();

    // Just outside both ranges: paragraph separator, narrow no-break space,
    // an unassigned code point, and inhibit-symmetric-swapping.
    for code in [0x2029, 0x202F, 0x2065, 0x206A] {
        let ch = char::from_u32(code).unwrap();
        fs::write(dir.path().join("a.txt"), format!("before{ch}after\n")).unwrap();

        let report = scan(dir.path(), &rules, Limits::default());

        assert!(
            report.findings.is_empty(),
            "U+{code:04X} must not be flagged"
        );
    }
}
