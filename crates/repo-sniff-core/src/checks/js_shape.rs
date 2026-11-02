//! The shape rules for JavaScript files: output of the obfuscator.io tool and
//! minified code in a source folder.
//!
//! - `obfuscation.obfuscator-io`: `_0x...` names (their number, their share of
//!   the file) with a loop `while(!![])` or a string array rotated with `push`
//!   and `shift`. CRITICAL when a tool runs the file (a configuration file such
//!   as `next.config.js`, or a file an npm script starts), HIGH in other
//!   source, MEDIUM where built bundles belong (`dist`, `build`, `public`,
//!   `vendor`, `*.min.js`). Some `_0x` names without the structure are one
//!   level lower, not silence.
//! - `obfuscation.minified-source`: a line of 2000 characters or more with
//!   little whitespace and a statement or block every 80 characters or so.
//!   MEDIUM in source, INFO where bundles belong, HIGH when a tool runs the
//!   file. The folder name does not remove the finding: whoever writes the
//!   repository chooses it.
//!
//! Both read the text of the file with regular expressions and counts, so a
//! file the lexer cannot read (an unterminated string, say) is still judged.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;

use super::js_loaders::hit;
use super::{Ctx, Hit};
use crate::finding::Severity;

static HEX_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b_0x[0-9a-fA-F]{3,8}\b").expect("valid pattern"));
static ROTATE_LOOP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"while\s*\(\s*!\s*!\s*\[\s*\]\s*\)").expect("valid pattern"));
static ROTATE_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?:\[\s*['"]push['"]\s*\]|\.\s*push)\s*\(\s*\w+\s*(?:\[\s*['"]shift['"]\s*\]|\.\s*shift)\s*\("#,
    )
    .expect("valid pattern")
});

/// Names of configuration files that a tool runs when it starts: bundlers,
/// frameworks, linters, test runners, formatters.
pub(crate) fn is_tool_config(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    let (stem, ext) = name.rsplit_once('.').unwrap_or((name.as_str(), ""));
    if !matches!(ext, "js" | "cjs" | "mjs" | "ts" | "cts" | "mts") {
        return false;
    }
    stem.ends_with(".config")
        || stem.ends_with(".conf")
        || (stem.starts_with('.') && stem.ends_with("rc"))
        || stem == "gulpfile"
        || stem == "gruntfile"
        || stem == "config-overrides"
        || stem == "babel.config"
        || stem == "webpack.common"
        || stem.starts_with("webpack.")
        || stem.starts_with("rollup.")
        || stem.starts_with("vite.")
}

/// Folders and names where bundles and vendored builds are expected, so a
/// minified or obfuscated file there is less surprising (never silent: the
/// folder name is chosen by whoever wrote the repository).
pub(crate) fn expected_bundle_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let mut parts: Vec<&str> = lower.split('/').collect();
    let name = parts.pop().unwrap_or("");
    parts.iter().any(|dir| {
        matches!(
            *dir,
            "dist"
                | "build"
                | "out"
                | "public"
                | "vendor"
                | "vendors"
                | "node_modules"
                | "third_party"
                | ".next"
                | "_next"
                | "static"
                | "assets"
                | "bundles"
        )
    }) || name.contains(".min.")
        || name.contains(".bundle.")
        || name.contains(".chunk.")
}

/// Rule `obfuscation.obfuscator-io`.
pub fn obfuscator(ctx: &Ctx<'_>) -> Vec<Hit> {
    let text = ctx.text();
    if !(text.contains("_0x") || text.contains("!![]")) {
        return Vec::new();
    }
    let mut count = 0usize;
    let mut distinct: HashSet<&str> = HashSet::new();
    let mut first: Option<usize> = None;
    for found in HEX_NAME.find_iter(text) {
        count += 1;
        first.get_or_insert(found.start());
        if distinct.len() < 8 {
            distinct.insert(found.as_str());
        }
    }
    let looped = ROTATE_LOOP.find(text);
    let rotated = ROTATE_CALL.is_match(text);
    let density = count as f64 * 1000.0 / text.len().max(1) as f64;
    let strong =
        (count >= 12 && distinct.len() >= 4 && (density >= 5.0 || looped.is_some() || rotated))
            || (count >= 1 && looped.is_some() && rotated);
    let weak = !strong && count >= 12 && distinct.len() >= 4;
    if !(strong || weak) {
        return Vec::new();
    }
    let at = first.or(looped.map(|m| m.start())).unwrap_or(0);
    let tool_config = is_tool_config(ctx.path);
    let script = ctx.repo.runs_file(ctx.path);
    let (severity, place) =
        if tool_config || script {
            let who = if tool_config {
                "a configuration file that a tool runs when it starts"
            } else {
                "a file that an npm script starts"
            };
            (
                if strong {
                    Severity::Critical
                } else {
                    Severity::High
                },
                format!("; this is {who}, so it runs"),
            )
        } else if expected_bundle_path(ctx.path) {
            (
            if strong { Severity::Medium } else { Severity::Low },
            "; it sits in a folder for built bundles (dist, build, public, vendor), which lowers \
             the level but does not remove the finding"
                .to_string(),
        )
        } else {
            (
                if strong {
                    Severity::High
                } else {
                    Severity::Medium
                },
                String::new(),
            )
        };
    let what = if strong {
        "output of the obfuscator.io tool"
    } else {
        "some names in the style of the obfuscator.io tool"
    };
    let mut signs = vec![format!("{count} `_0x...` names")];
    if looped.is_some() {
        signs.push("a `while(!![])` loop".to_string());
    }
    if rotated {
        signs.push("a string array rotated with push and shift".to_string());
    }
    vec![hit(
        ctx,
        at,
        at + 3,
        severity,
        format!(
            "{what} ({}): code that is written to be unreadable{place}",
            signs.join(", ")
        ),
    )]
}

/// A line this long is looked at for being minified code.
const MINIFIED_LINE: usize = 2000;

/// Rule `obfuscation.minified-source`.
pub fn minified(ctx: &Ctx<'_>) -> Vec<Hit> {
    let text = ctx.text();
    if text.len() < MINIFIED_LINE {
        return Vec::new();
    }
    let mut offset = 0usize;
    let mut hits = Vec::new();
    for line in text.split('\n') {
        let start = offset;
        offset += line.len() + 1;
        if line.len() < MINIFIED_LINE {
            continue;
        }
        let bytes = line.as_bytes();
        let blanks = bytes.iter().filter(|&&b| b == b' ' || b == b'\t').count();
        let code = bytes
            .iter()
            .filter(|&&b| matches!(b, b';' | b'{' | b'}'))
            .count();
        // Little whitespace and a statement or block every 80 characters or
        // so: code, not data (a table of numbers or a base64 blob has none).
        if blanks * 8 < line.len() && code * 80 >= line.len() {
            hits.push((start, line.len()));
            break;
        }
    }
    let Some((start, len)) = hits.pop() else {
        return Vec::new();
    };
    let runs = ctx.repo.runs_file(ctx.path) || is_tool_config(ctx.path);
    let (severity, place) = if runs {
        (
            Severity::High,
            "; a tool or an npm script runs this file".to_string(),
        )
    } else if expected_bundle_path(ctx.path) {
        (
            Severity::Info,
            "; built bundles are minified on purpose, so the level is low here, but the folder \
             name is chosen by whoever wrote the repository"
                .to_string(),
        )
    } else {
        (ctx.base, String::new())
    };
    let mut end = (start + 80).min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    vec![hit(
        ctx,
        start,
        end,
        severity,
        format!(
            "a line of {len} characters with almost no whitespace: minified code in a place where \
             people read and review source{place}"
        ),
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_configuration_files_are_recognised_by_name() {
        for yes in [
            "next.config.js",
            "a/b/vite.config.ts",
            ".eslintrc.js",
            "babel.config.cjs",
            "gulpfile.js",
            "webpack.prod.js",
            "tailwind.config.mjs",
        ] {
            assert!(is_tool_config(yes), "{yes}");
        }
        for no in [
            "server.js",
            "config.js",
            "app/config.json",
            "next.config.json",
            "index.ts",
        ] {
            assert!(!is_tool_config(no), "{no}");
        }
    }

    #[test]
    fn bundle_folders_and_names_are_recognised() {
        assert!(expected_bundle_path("dist/app.js"));
        assert!(expected_bundle_path("a/Public/x.js"));
        assert!(expected_bundle_path("lib/app.min.js"));
        assert!(!expected_bundle_path("src/lib/app.js"));
        assert!(!expected_bundle_path("distance/app.js"));
    }

    fn run(check: super::super::Check, path: &str, text: &str, base: Severity) -> Vec<Hit> {
        super::super::run_on_text(check, path, text, base)
    }

    fn obfuscated() -> String {
        let names: String = (0..20)
            .map(|i| format!("_0x{:04x}", 0x1a00 + i))
            .collect::<Vec<_>>()
            .join(",");
        format!("var {names};\nwhile(!![]){{try{{break;}}catch(e){{}}}}\n")
    }

    #[test]
    fn many_hex_names_with_the_loop_are_obfuscator_output() {
        let hits = run(obfuscator, "src/a.js", &obfuscated(), Severity::High);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].line, 1);
    }

    #[test]
    fn the_place_sets_the_level() {
        let text = obfuscated();
        let level = |path: &str| run(obfuscator, path, &text, Severity::High)[0].severity;
        assert_eq!(level("next.config.js"), Severity::Critical);
        assert_eq!(level("web/tailwind.config.ts"), Severity::Critical);
        assert_eq!(level("public/app.js"), Severity::Medium);
        assert_eq!(level("lib/app.min.js"), Severity::Medium);
        assert_eq!(level("src/app.js"), Severity::High);
    }

    #[test]
    fn a_few_hex_names_are_not_a_finding() {
        let text = "const _0xdeadbeef = 1; module.exports = _0xdeadbeef + _0xdeadbeef;";
        assert!(run(obfuscator, "a.js", text, Severity::High).is_empty());
        assert!(run(obfuscator, "a.js", "while(!![]){break;}", Severity::High).is_empty());
    }

    #[test]
    fn many_names_without_the_structure_are_one_level_lower() {
        let names: String = (0..20)
            .map(|i| {
                format!(
                    "var _0x{:04x} = {i};\n{}",
                    0x1a00 + i,
                    "// padding line to keep the share of names low\n".repeat(30)
                )
            })
            .collect();
        let hits = run(obfuscator, "src/a.js", &names, Severity::High);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
    }

    fn minified_line(len: usize) -> String {
        "function f(a){if(a>1){return a-1;}return a+1;}".repeat(len / 46 + 1)
    }

    #[test]
    fn a_long_line_of_code_is_minified_source() {
        let text = format!("// header\n{}\n", minified_line(2500));
        let hits = run(minified, "src/lib/bundle.js", &text, Severity::Medium);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].line, 2);
        assert_eq!(
            run(minified, "dist/app.js", &text, Severity::Medium)[0].severity,
            Severity::Info
        );
        assert_eq!(
            run(minified, "vite.config.js", &text, Severity::Medium)[0].severity,
            Severity::High
        );
    }

    #[test]
    fn long_lines_of_data_and_short_lines_of_code_are_not() {
        let numbers = (0..800)
            .map(|i| (i * 7).to_string())
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            run(
                minified,
                "a.js",
                &format!("x = [{numbers}];\n"),
                Severity::Medium
            )
            .is_empty()
        );
        let spaced = "const value = compute(argument) + other(argument2);\n".repeat(60);
        assert!(run(minified, "a.js", &spaced, Severity::Medium).is_empty());
        let one_blob = format!("const logo = \"{}\";\n", "QUJD".repeat(800));
        assert!(run(minified, "a.js", &one_blob, Severity::Medium).is_empty());
    }
}
