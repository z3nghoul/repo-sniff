//! Detection rules: loaded from TOML, validated and compiled once.
//!
//! A rule file is a list of `[[rule]]` tables:
//!
//! ```toml
//! [[rule]]
//! id          = "deception.bidi-control"
//! engine      = "line-regex"
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

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde::Deserialize;
use thiserror::Error;

use crate::checks::{self, Check};
use crate::finding::{Severity, Stage};

/// Rule files shipped inside the binary, as `(file name, contents)`.
const BUILTIN_RULE_FILES: &[(&str, &str)] = &[
    ("deception.toml", include_str!("../rules/deception.toml")),
    ("ide.toml", include_str!("../rules/ide.toml")),
    ("deps.toml", include_str!("../rules/deps.toml")),
    ("repo.toml", include_str!("../rules/repo.toml")),
];

/// How a rule looks for its target. Every rule names its engine explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Engine {
    /// A regular expression matched against each line of a text file.
    LineRegex,
    /// Rust code that parses a structured (JSONC) file. The code is looked up
    /// by the rule's id; the TOML only supplies its metadata.
    Jsonc,
    /// Rust code that inspects one whole file as raw bytes, with knowledge of
    /// the rest of the repository. Looked up by the rule's id like `Jsonc`;
    /// `files` is required and selects the candidate files.
    File,
    /// Reports a NUL byte inside a file that is meant to be read as a script
    /// (by extension or shebang). The scanner itself decides what a script is.
    NulByte,
    /// Rust code that judges a file by its name and its first bytes (at most
    /// `checks::HEAD_LEN`). Looked up by the rule's id like `File`; `files` is
    /// optional. It is offered every entry of the repository: files read
    /// whole, files read as a stream, files over the size limit (name only)
    /// and symbolic links, so neither size nor a link is a way around it.
    Head,
}

/// A rule as written in TOML, before validation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    engine: Engine,
    family: String,
    stage: Stage,
    severity: Severity,
    #[serde(default)]
    attack: Vec<String>,
    description: String,
    example: String,
    pattern: Option<String>,
    #[serde(default)]
    files: Vec<String>,
    #[serde(default)]
    names_executables: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    #[serde(default)]
    rule: Vec<RawRule>,
}

/// The compiled, ready-to-run form of a rule's engine.
#[derive(Debug, Clone)]
pub enum Matcher {
    LineRegex(Regex),
    Jsonc(Check),
    File(Check),
    NulByte,
    Head(Check),
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
    pub matcher: Matcher,
    /// Which files the rule applies to; `None` means every file.
    pub files: Option<GlobSet>,
    /// Only for `engine = "head"`: the rule's findings on a native executable
    /// name it as one. Such a finding stands for the executable in the
    /// report, so the file no longer makes the scan inconclusive; a finding
    /// of any other rule does not.
    pub names_executables: bool,
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
    #[error("rule `{id}`: engine `line-regex` requires a `pattern`")]
    MissingPattern { id: String },
    #[error("rule `{id}`: this engine does not take a `pattern`")]
    UnexpectedPattern { id: String },
    #[error("rule `{id}`: this engine needs a check registered in the code under this id")]
    UnknownCheck { id: String },
    #[error("rule `{id}`: engine `file` requires `files` globs to select the files to check")]
    MissingFiles { id: String },
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
    #[error("rule `{id}`: only an `engine = \"head\"` rule can set `names_executables`")]
    NamesExecutablesNeedsHead { id: String },
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

    let matcher = match raw.engine {
        Engine::LineRegex => {
            let pattern = raw
                .pattern
                .ok_or_else(|| RuleError::MissingPattern { id: raw.id.clone() })?;
            let regex = Regex::new(&pattern).map_err(|source| RuleError::Pattern {
                id: raw.id.clone(),
                source,
            })?;
            Matcher::LineRegex(regex)
        }
        Engine::Jsonc => {
            if raw.pattern.is_some() {
                return Err(RuleError::UnexpectedPattern { id: raw.id });
            }
            let check = checks::jsonc_check(&raw.id)
                .ok_or_else(|| RuleError::UnknownCheck { id: raw.id.clone() })?;
            Matcher::Jsonc(check)
        }
        Engine::NulByte => {
            if raw.pattern.is_some() {
                return Err(RuleError::UnexpectedPattern { id: raw.id });
            }
            Matcher::NulByte
        }
        Engine::Head => {
            if raw.pattern.is_some() {
                return Err(RuleError::UnexpectedPattern { id: raw.id });
            }
            let check = checks::head_check(&raw.id)
                .ok_or_else(|| RuleError::UnknownCheck { id: raw.id.clone() })?;
            Matcher::Head(check)
        }
        Engine::File => {
            if raw.pattern.is_some() {
                return Err(RuleError::UnexpectedPattern { id: raw.id });
            }
            if raw.files.is_empty() {
                return Err(RuleError::MissingFiles { id: raw.id });
            }
            let check = checks::file_check(&raw.id)
                .ok_or_else(|| RuleError::UnknownCheck { id: raw.id.clone() })?;
            Matcher::File(check)
        }
    };

    let files = if raw.files.is_empty() {
        None
    } else {
        let mut builder = GlobSetBuilder::new();
        for glob in &raw.files {
            // Case-insensitive on purpose: on Windows and macOS the file system
            // is, so `.vscode/Tasks.json` is still the file VS Code reads.
            let glob = GlobBuilder::new(glob)
                .case_insensitive(true)
                .build()
                .map_err(|source| RuleError::Glob {
                    id: raw.id.clone(),
                    source,
                })?;
            builder.add(glob);
        }
        Some(builder.build().map_err(|source| RuleError::Glob {
            id: raw.id.clone(),
            source,
        })?)
    };

    if raw.names_executables && !matches!(matcher, Matcher::Head(_)) {
        return Err(RuleError::NamesExecutablesNeedsHead { id: raw.id });
    }

    Ok(Rule {
        id: raw.id,
        family: raw.family,
        stage: raw.stage,
        severity: raw.severity,
        attack: raw.attack,
        description: raw.description,
        example: raw.example,
        matcher,
        files,
        names_executables: raw.names_executables,
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
        engine = "line-regex"
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
        let Matcher::LineRegex(pattern) = &rule.matcher else {
            panic!("expected a line-regex matcher");
        };
        assert!(pattern.is_match(r#"Command::new("sh")"#));
        assert!(rule.applies_to("build.rs"));
        assert!(!rule.applies_to("src/main.rs"));
    }

    #[test]
    fn file_globs_ignore_case() {
        let source = VALID.replace(
            r#"files = ["build.rs"]"#,
            r#"files = ["**/.vscode/tasks.json"]"#,
        );
        let rules = parse_rules(&source, "test.toml").unwrap();
        assert!(rules[0].applies_to(".vscode/tasks.json"));
        assert!(rules[0].applies_to("sub/.VSCode/Tasks.JSON"));
        assert!(!rules[0].applies_to("sub/tasks.json"));
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
    fn engine_is_required() {
        let source = VALID.replace(r#"engine = "line-regex""#, "");
        assert!(matches!(
            parse_rules(&source, "test.toml"),
            Err(RuleError::Parse { .. })
        ));
    }

    #[test]
    fn unknown_engine_is_rejected() {
        let source = VALID.replace("line-regex", "magic");
        assert!(matches!(
            parse_rules(&source, "test.toml"),
            Err(RuleError::Parse { .. })
        ));
    }

    #[test]
    fn line_regex_rule_without_pattern_is_rejected() {
        let source = VALID.replace("pattern = 'Command::new'", "");
        assert!(matches!(
            parse_rules(&source, "test.toml"),
            Err(RuleError::MissingPattern { .. })
        ));
    }

    const JSONC_RULE: &str = r#"
        [[rule]]
        id = "ide.vscode-folder-open-task"
        engine = "jsonc"
        family = "vscode-autorun"
        stage = "ide"
        severity = "high"
        description = "Example"
        example = ".vscode/tasks.json:1"
    "#;

    #[test]
    fn jsonc_rule_with_a_registered_check_is_loaded() {
        let rules = parse_rules(JSONC_RULE, "test.toml").unwrap();
        assert!(matches!(rules[0].matcher, Matcher::Jsonc(_)));
    }

    #[test]
    fn jsonc_rule_without_a_registered_check_is_rejected() {
        let source = JSONC_RULE.replace("ide.vscode-folder-open-task", "ide.no-such-check");
        assert!(matches!(
            parse_rules(&source, "test.toml"),
            Err(RuleError::UnknownCheck { .. })
        ));
    }

    #[test]
    fn jsonc_rule_with_a_pattern_is_rejected() {
        let source = format!("{JSONC_RULE}\npattern = 'x'");
        assert!(matches!(
            parse_rules(&source, "test.toml"),
            Err(RuleError::UnexpectedPattern { .. })
        ));
    }

    const FILE_RULE: &str = r#"
        [[rule]]
        id = "test.no-such-file-check"
        engine = "file"
        family = "test"
        stage = "deps"
        severity = "high"
        description = "Example"
        example = "x.pth:1"
        files = ["**/*.pth"]
    "#;

    #[test]
    fn file_rule_without_a_registered_check_is_rejected() {
        assert!(matches!(
            parse_rules(FILE_RULE, "test.toml"),
            Err(RuleError::UnknownCheck { .. })
        ));
    }

    #[test]
    fn file_rule_must_say_which_files_it_wants() {
        let source = FILE_RULE.replace(r#"files = ["**/*.pth"]"#, "");
        assert!(matches!(
            parse_rules(&source, "test.toml"),
            Err(RuleError::MissingFiles { .. })
        ));
    }

    #[test]
    fn nul_byte_rule_needs_no_pattern_and_no_files() {
        let source = r#"
            [[rule]]
            id = "test.nul"
            engine = "nul-byte"
            family = "test"
            stage = "deception"
            severity = "high"
            description = "Example"
            example = "a.sh:1"
        "#;
        let rules = parse_rules(source, "test.toml").unwrap();
        assert!(matches!(rules[0].matcher, Matcher::NulByte));

        let with_pattern = format!("{source}\npattern = 'x'");
        assert!(matches!(
            parse_rules(&with_pattern, "test.toml"),
            Err(RuleError::UnexpectedPattern { .. })
        ));
    }

    #[test]
    fn file_rule_with_a_pattern_is_rejected() {
        let source = format!("{FILE_RULE}\npattern = 'x'");
        assert!(matches!(
            parse_rules(&source, "test.toml"),
            Err(RuleError::UnexpectedPattern { .. })
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
