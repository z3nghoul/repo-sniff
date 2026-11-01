//! Rule `deps.python-start-entrypoint`: Python 3.15 `.start` files.
//!
//! PEP 829 added `*.start` files next to `*.pth` files. Every non-comment line
//! of a `.start` file is an entry point written `package.module:callable`.
//! At interpreter start-up `site.py` resolves it with
//! `pkgutil.resolve_name(strict=True)` and **calls it**, so like a `.pth` file
//! a `.start` file is code that runs without being imported.
//!
//! Sources read: `Lib/site.py` and `Lib/pkgutil.py` of CPython 3.15.
//!
//! - The file is decoded as UTF-8 only (a leading BOM is dropped); a `.start`
//!   file that is not valid UTF-8 is ignored, so it gets no finding.
//! - Lines are split like `str.splitlines()` and stripped, as for `.pth`.
//! - Only a line in the strict entry-point form is acted on; anything else
//!   just makes Python print an error, so it is not reported.
//! - The name must end in exactly lowercase `.start` and must not start with a
//!   dot, otherwise `site` never reads the file.

use super::pylines::{is_python_space, python_lines};
use super::{Ctx, FileIssue, Hit};
use crate::finding::Severity;

/// At most this many entry points are recorded; the rest are counted.
const MAX_TRACKED_ENTRY_POINTS: usize = 500;

pub fn check(ctx: &Ctx<'_>) -> Vec<Hit> {
    let name = ctx.path.rsplit('/').next().unwrap_or(ctx.path);
    let inert = inert_reason(name);
    let mut hits = Vec::new();

    if let Some(issue) = &ctx.issue {
        hits.push(issue_hit(issue, inert.is_some()));
    }
    // An oversized file was not read; a symlink may have brought its target.
    if ctx.bytes().is_empty() {
        return hits;
    }

    let raw = ctx.bytes();
    let bytes = raw.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(raw);
    let Ok(text) = std::str::from_utf8(bytes) else {
        return hits; // Python 3.15 ignores a .start file that is not UTF-8
    };

    let mut entries: Vec<(usize, &str)> = Vec::new();
    let mut total = 0usize;
    for line in python_lines(text) {
        let stripped = line.body.trim_matches(is_python_space);
        if stripped.is_empty() || stripped.starts_with('#') || !is_entry_point(stripped) {
            continue;
        }
        total += 1;
        if entries.len() < MAX_TRACKED_ENTRY_POINTS {
            entries.push((line.number, stripped));
        }
    }

    for &(number, entry) in &entries {
        hits.push(match inert {
            Some(why) => Hit {
                line: number,
                span: None,
                severity: Severity::Low,
                reason: format!(
                    "Python's site module ignores this file because {why}, but this line is an \
                     entry point (`{entry}`) that would be called if the file were loaded"
                ),
            },
            None => Hit {
                line: number,
                span: None,
                severity: ctx.base,
                reason: format!(
                    "Python 3.15 and later calls the entry point `{entry}` every time the \
                     interpreter starts{}",
                    module_note(ctx, entry)
                ),
            },
        });
    }
    if total > entries.len() {
        hits.push(Hit {
            line: entries.last().map_or(1, |&(number, _)| number),
            span: None,
            severity: ctx.base,
            reason: format!(
                "{} more entry points in this file are not listed",
                total - entries.len()
            ),
        });
    }
    hits
}

/// Why Python's `site` module would never read a file with this name.
fn inert_reason(name: &str) -> Option<&'static str> {
    if name.starts_with('.') {
        Some("its name starts with a dot")
    } else if !name.ends_with(".start") {
        Some("its extension is not exactly lowercase `.start`")
    } else {
        None
    }
}

fn issue_hit(issue: &FileIssue, inert: bool) -> Hit {
    let severity = if inert { Severity::Low } else { Severity::High };
    let reason = match issue {
        FileIssue::TooLarge { size } => format!(
            "this .start file is larger than the scan limit ({size} bytes) and was not read; \
             Python reads it in full, and honest .start files are tiny"
        ),
        FileIssue::Symlink { .. } => "this .start file is a symbolic link; Python follows it and \
             processes the target as the .start file"
            .to_string(),
    };
    Hit {
        line: 1,
        span: None,
        severity,
        reason,
    }
}

/// Says whether the code the entry point names is in the repository.
fn module_note(ctx: &Ctx<'_>, entry: &str) -> String {
    let top = entry
        .split([':', '.'])
        .next()
        .filter(|top| !top.is_empty())
        .unwrap_or(entry);
    if ctx.repo.has_module(top) {
        format!("; module `{top}` is in this repository")
    } else {
        format!("; module `{top}` is not in this repository")
    }
}

/// The strict form accepted by `pkgutil.resolve_name`: `dotted:dotted`, where
/// each dotted name is non-empty words (letters, digits, underscore) separated
/// by single dots, and no word starts with a digit.
pub(super) fn is_entry_point(line: &str) -> bool {
    let Some((module, object)) = line.split_once(':') else {
        return false;
    };
    is_dotted_name(module) && is_dotted_name(object)
}

fn is_dotted_name(name: &str) -> bool {
    !name.is_empty()
        && name.split('.').all(|word| {
            let mut chars = word.chars();
            chars.next().is_some_and(|first| {
                !first.is_ascii_digit() && (first.is_alphanumeric() || first == '_')
            }) && chars.all(|c| c.is_alphanumeric() || c == '_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_entry_points() {
        for line in [
            "demo.mod:run",
            "pkg:main",
            "pkg.sub.mod:Class.method",
            "_private.mod:_run",
            "a1.b2:c3",
            "d\u{e9}mo.mod:run",
        ] {
            assert!(is_entry_point(line), "{line}");
        }
    }

    #[test]
    fn invalid_entry_points() {
        for line in [
            "",
            "demo.mod",
            ":run",
            "demo.mod:",
            "1demo.mod:run",
            "demo.1mod:run",
            "demo.mod:1run",
            "demo mod:run",
            "demo.mod:run extra",
            "demo.mod:ru-n",
            "demo::mod:run",
            "demo.:run",
            "demo.mod:run.",
            ".demo:run",
            "demo..mod:run",
            "demo.mod:run  # note",
            "demo.mod:run;",
            "This is not an entry point",
        ] {
            assert!(!is_entry_point(line), "{line:?}");
        }
    }
}
