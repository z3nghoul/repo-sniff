//! Detection rules: loaded from TOML, validated and compiled once.
//!
//! A rule file is a list of `[[rule]]` tables:
//!
//! ```toml
//! [[rule]]
//! id          = "deception.bidi-control"
//! family      = "trojan-source"
//! stage       = "deception"
//! severity    = "critical"
//! attack      = []
//! description = "Unicode bidi control characters reorder how code is displayed"
//! example     = "src/auth.rs:12 contains U+202E"
//! pattern     = '[\u{202A}-\u{202E}]'
//! files       = ["*.rs"]   # optional; omitted means every file
//! ```

use std::collections::HashSet;
use std::sync::LazyLock;

use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde::Deserialize;
use thiserror::Error;

use crate::finding::{Severity, Stage};

/// Rule files shipped inside the binary, as `(file name, contents)`.
const BUILTIN_RULE_FILES: &[(&str, &str)] = &[];

/// A rule as written in TOML, before validation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    family: String,
    stage: Stage,
    severity: Severity,
    #[serde(default)]
    attack: Vec<String>,
    description: String,
    example: String,
    pattern: String,
    #[serde(default)]
    files: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    #[serde(default)]
    rule: Vec<RawRule>,
}

/// A validated rule, ready to run.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    /// Groups related rules; a row in the TUI rules grid.
    pub family: String,
    pub stage: Stage,
    pub severity: Severity,
    pub attack: Vec<String>,
    pub description: String,
    pub example: String,
    pub pattern: Regex,
    /// Which files the rule applies to; `None` means every file.
    pub files: Option<GlobSet>,
}

impl Rule {
    /// Whether this rule should look at a file with the given path
    /// (relative to the repository root, `/`-separated).
    pub fn applies_to(&self, relative_path: &str) -> bool {
        self.files
            .as_ref()
            .is_none_or(|globs| globs.is_match(relative_path))
    }
}

#[derive(Debug, Error)]
pub enum RuleError {
    #[error("{origin}: invalid rule file: {source}")]
    Parse {
        origin: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("rule `{id}`: invalid pattern: {source}")]
    Pattern {
        id: String,
        #[source]
        source: regex::Error,
    },
    #[error("rule `{id}`: invalid file glob: {source}")]
    Glob {
        id: String,
        #[source]
        source: globset::Error,
    },
    #[error(
        "rule `{id}`: `{value}` is not a MITRE ATT&CK technique ID (expected e.g. T1547 or T1547.001)"
    )]
    Attack { id: String, value: String },
    #[error("rule `{id}` is defined more than once")]
    DuplicateId { id: String },
}

/// Loads every rule shipped with repo-sniff.
pub fn builtin_rules() -> Result<Vec<Rule>, RuleError> {
    let mut rules = Vec::new();
    for (origin, source) in BUILTIN_RULE_FILES {
        rules.extend(parse_rules(source, origin)?);
    }
    check_unique_ids(&rules)?;
    Ok(rules)
}

/// Parses and validates one rule file. `origin` names the file in errors.
pub fn parse_rules(source: &str, origin: &str) -> Result<Vec<Rule>, RuleError> {
    let file: RuleFile = toml::from_str(source).map_err(|source| RuleError::Parse {
        origin: origin.to_string(),
        source,
    })?;
    let rules = file
        .rule
        .into_iter()
        .map(compile)
        .collect::<Result<Vec<_>, _>>()?;
    check_unique_ids(&rules)?;
    Ok(rules)
}

fn compile(raw: RawRule) -> Result<Rule, RuleError> {
    static ATTACK_ID: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^T\d{4}(\.\d{3})?$").expect("valid regex"));

    if let Some(bad) = raw.attack.iter().find(|a| !ATTACK_ID.is_match(a)) {
        return Err(RuleError::Attack {
            id: raw.id,
            value: bad.clone(),
        });
    }

    let pattern = Regex::new(&raw.pattern).map_err(|source| RuleError::Pattern {
        id: raw.id.clone(),
        source,
    })?;

    let files = if raw.files.is_empty() {
        None
    } else {
        let mut builder = GlobSetBuilder::new();
        for glob in &raw.files {
            builder.add(Glob::new(glob).map_err(|source| RuleError::Glob {
                id: raw.id.clone(),
                source,
            })?);
        }
        Some(builder.build().map_err(|source| RuleError::Glob {
            id: raw.id.clone(),
            source,
        })?)
    };

    Ok(Rule {
        id: raw.id,
        family: raw.family,
        stage: raw.stage,
        severity: raw.severity,
        attack: raw.attack,
        description: raw.description,
        example: raw.example,
        pattern,
        files,
    })
}

fn check_unique_ids(rules: &[Rule]) -> Result<(), RuleError> {
    let mut seen = HashSet::new();
    for rule in rules {
        if !seen.insert(rule.id.as_str()) {
            return Err(RuleError::DuplicateId {
                id: rule.id.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
        [[rule]]
        id = "test.example"
        family = "example"
        stage = "build"
        severity = "high"
        attack = ["T1059", "T1547.001"]
        description = "Example rule"
        example = "build.rs:1"
        pattern = 'Command::new'
        files = ["build.rs"]
    "#;

    #[test]
    fn valid_rule_is_loaded() {
        let rules = parse_rules(VALID, "test.toml").unwrap();
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        assert_eq!(rule.id, "test.example");
        assert_eq!(rule.stage, Stage::Build);
        assert_eq!(rule.severity, Severity::High);
        assert!(rule.pattern.is_match(r#"Command::new("sh")"#));
        assert!(rule.applies_to("build.rs"));
        assert!(!rule.applies_to("src/main.rs"));
    }

    #[test]
    fn rule_without_files_applies_everywhere() {
        let source = VALID.replace(r#"files = ["build.rs"]"#, "");
        let rules = parse_rules(&source, "test.toml").unwrap();
        assert!(rules[0].applies_to("any/file.txt"));
    }

    #[test]
    fn unknown_field_is_rejected() {
        // A typo like `severty` must fail loudly instead of being ignored.
        let source = VALID.replace("severity", "severty");
        assert!(matches!(
            parse_rules(&source, "test.toml"),
            Err(RuleError::Parse { .. })
        ));
    }

    #[test]
    fn unknown_stage_is_rejected() {
        let source = VALID.replace(r#"stage = "build""#, r#"stage = "compile""#);
        assert!(matches!(
            parse_rules(&source, "test.toml"),
            Err(RuleError::Parse { .. })
        ));
    }

    #[test]
    fn invalid_pattern_names_the_rule() {
        let source = VALID.replace("'Command::new'", "'(unclosed'");
        let err = parse_rules(&source, "test.toml").unwrap_err();
        assert!(matches!(err, RuleError::Pattern { .. }));
        assert!(err.to_string().contains("test.example"));
    }

    #[test]
    fn invalid_attack_id_is_rejected() {
        let source = VALID.replace(r#""T1059""#, r#""T59""#);
        assert!(matches!(
            parse_rules(&source, "test.toml"),
            Err(RuleError::Attack { .. })
        ));
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let source = format!("{VALID}\n{VALID}");
        assert!(matches!(
            parse_rules(&source, "test.toml"),
            Err(RuleError::DuplicateId { .. })
        ));
    }

    #[test]
    fn builtin_rules_load() {
        builtin_rules().unwrap();
    }
}
