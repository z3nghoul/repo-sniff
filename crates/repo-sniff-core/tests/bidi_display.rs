//! The Trojan Source rule judges a line by how it is displayed: LOW when its
//! bidi controls change nothing, the rule's level when they do or when that
//! cannot be known. Cases generated here; the fixture folder holds the rest.

use std::fs;

use repo_sniff_core::{Finding, Limits, Report, Severity, builtin_rules, scan};

const RULE_ID: &str = "deception.bidi-control";
const LRE: char = '\u{202A}';
const RLE: char = '\u{202B}';
const PDF: char = '\u{202C}';
const RLO: char = '\u{202E}';

/// A direction helper in the shape of a vendored bundle: the controls change
/// nothing.
fn honest() -> String {
    format!("function a(e){{return\"{LRE}\"+e+\"{PDF}\"}}")
}

/// The same helper with one call more between the controls: shown reordered.
fn deceptive() -> String {
    format!("function a(e){{return\"{RLE}\"+e.trim()+\"{PDF}\"}}")
}

fn scan_files(files: &[(&str, Vec<u8>)], limits: Limits) -> Report {
    let dir = tempfile::tempdir().unwrap();
    for (name, contents) in files {
        fs::write(dir.path().join(name), contents).unwrap();
    }
    scan(dir.path(), &builtin_rules().unwrap(), limits)
}

fn scan_text(name: &str, lines: &[String]) -> Report {
    let text = lines.join("\n") + "\n";
    scan_files(&[(name, text.into_bytes())], Limits::default())
}

fn bidi(report: &Report) -> Vec<&Finding> {
    report
        .findings
        .iter()
        .filter(|f| f.rule_id == RULE_ID)
        .collect()
}

fn levels(report: &Report) -> Vec<(usize, Severity)> {
    bidi(report).iter().map(|f| (f.line, f.severity)).collect()
}

#[test]
fn a_helper_whose_controls_change_nothing_is_low_and_complete() {
    let report = scan_text("a.js", &[honest(), deceptive()]);

    assert_eq!(
        levels(&report),
        [(1, Severity::Low), (2, Severity::Critical)]
    );
    let low = bidi(&report)[0];
    assert_eq!(low.explanation, "bidi controls present, display unchanged");
    assert_eq!(low.column, Some(22));
    assert!(report.is_complete());
}

#[test]
fn a_file_with_only_harmless_controls_has_no_finding_above_low() {
    let report = scan_text("a.js", &vec![honest(); 3]);

    assert!(report.findings.iter().all(|f| f.severity == Severity::Low));
    assert_eq!(report.findings.len(), 3);
}

#[test]
fn a_flood_of_harmless_lines_does_not_hide_a_deceptive_one() {
    let mut lines = vec![honest(); 150];
    lines.push(deceptive());

    let report = scan_text("a.js", &lines);

    let critical: Vec<_> = levels(&report)
        .into_iter()
        .filter(|(_, severity)| *severity == Severity::Critical)
        .collect();
    assert_eq!(critical, [(151, Severity::Critical)]);
    let low = bidi(&report)
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();
    assert_eq!(low, 100);
    let hidden: Vec<_> = report
        .unlisted
        .iter()
        .map(|u| (u.severity, u.count))
        .collect();
    assert_eq!(hidden, [(Severity::Low, 50)]);
}

#[test]
fn deceptive_lines_past_the_list_are_counted_at_the_rules_level() {
    let report = scan_text("a.js", &vec![deceptive(); 130]);

    assert_eq!(bidi(&report).len(), 100);
    let hidden: Vec<_> = report
        .unlisted
        .iter()
        .map(|u| (u.severity, u.count))
        .collect();
    assert_eq!(hidden, [(Severity::Critical, 30)]);
}

#[test]
fn a_line_that_may_be_shown_on_two_lines_stays_critical_with_the_reason() {
    // Equal over the whole line; drawn as "ba" over "ab" where U+2028 breaks.
    for separator in ["\r", "\u{2028}", "\u{85}", "\u{B}"] {
        let line = format!("x = \"{RLO}ab{separator}ba{PDF}\";");

        let report = scan_text("a.js", &[line]);

        let found = bidi(&report);
        assert_eq!(found.len(), 1, "{separator:?}");
        assert_eq!(found[0].severity, Severity::Critical);
        assert!(found[0].explanation.contains("line break"), "{separator:?}");
    }
}

#[test]
fn a_line_over_the_length_limit_stays_critical_with_the_reason() {
    let long = format!("{LRE} {}", "a".repeat(64 * 1024));

    let report = scan_text("min.js", &[long]);

    let found = bidi(&report);
    assert_eq!(found[0].severity, Severity::Critical);
    assert!(found[0].explanation.contains("too long"));
}

#[test]
fn a_streamed_file_is_judged_like_one_read_whole() {
    let text = [honest(), deceptive()].join("\n") + "\n";
    let limits = Limits {
        max_buffered_size: 16,
        ..Limits::default()
    };

    let report = scan_files(&[("big.js", text.into_bytes())], limits);

    assert_eq!(
        levels(&report),
        [(1, Severity::Low), (2, Severity::Critical)]
    );
    assert!(report.is_complete());
}

fn utf16_le(text: &str) -> Vec<u8> {
    let mut bytes = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        bytes.extend(unit.to_le_bytes());
    }
    bytes
}

#[test]
fn a_utf16_script_is_judged_after_decoding() {
    let text = [honest(), deceptive()].join("\n") + "\n";

    for limits in [
        Limits::default(),
        Limits {
            max_buffered_size: 16,
            ..Limits::default()
        },
    ] {
        let report = scan_files(&[("run.ps1", utf16_le(&text))], limits);

        assert_eq!(
            levels(&report),
            [(1, Severity::Low), (2, Severity::Critical)]
        );
    }
}

#[test]
fn an_invalid_byte_does_not_change_the_judgement() {
    let mut harmless = honest().into_bytes();
    harmless.insert(0, 0xFF);
    let mut deceiving = deceptive().into_bytes();
    deceiving.insert(0, 0xFF);
    let bytes = [harmless, deceiving].join(&b'\n');

    let report = scan_files(&[("a.js", bytes)], Limits::default());

    assert_eq!(
        levels(&report),
        [(1, Severity::Low), (2, Severity::Critical)]
    );
}

#[test]
fn a_control_inside_a_name_stays_critical_whatever_the_layout() {
    // The display does not change, but the name does: another file, another
    // module, a comparison that never matches.
    let lines = [
        "bash ./setup\u{2066}.sh".to_string(),
        format!("const util = require(\"./util{LRE}\");"),
        format!("if host == \"example.com{PDF}\":"),
        format!("run(\"a\u{200E}{LRE}b\");"),
    ];

    let report = scan_text("a.js", &lines);

    assert_eq!(
        levels(&report),
        [
            (1, Severity::Critical),
            (2, Severity::Critical),
            (3, Severity::Critical),
            (4, Severity::Critical)
        ]
    );
    assert!(bidi(&report)[0].explanation.contains("what a name is"));
}

#[test]
fn crlf_endings_do_not_turn_a_harmless_line_critical() {
    let text = [honest(), honest()].join("\r\n") + "\r\n";
    let streamed = Limits {
        max_buffered_size: 16,
        ..Limits::default()
    };

    for limits in [Limits::default(), streamed] {
        let report = scan_files(&[("a.js", text.clone().into_bytes())], limits);

        assert_eq!(levels(&report), [(1, Severity::Low), (2, Severity::Low)]);
    }
}
