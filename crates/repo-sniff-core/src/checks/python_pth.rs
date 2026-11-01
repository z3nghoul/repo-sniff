//! Rule `deps.python-pth-exec`: `.pth` files with lines that Python executes
//! every time it starts.
//!
//! Python's `site` module reads every `*.pth` file in a site directory. A line
//! that starts with `import` followed by a space or a tab is passed to
//! `exec()`; any other line is added to `sys.path`. So a `.pth` file is code
//! that runs at start-up, and a malicious package can use it for persistence.
//!
//! Sources read for this check: `Lib/site.py` of CPython 3.10 to 3.15. The
//! versions differ, and the principle is to flag a line when **any** supported
//! version would run it:
//!
//! - lines are split like `str.splitlines()` (3.12 and later) which breaks on
//!   more than `\n`: `\r`, `\v`, `\f`, `\x1c`-`\x1e`, U+0085, U+2028, U+2029;
//! - a leading UTF-8 byte order mark is dropped (3.12 and later), but only at
//!   the start of the file;
//! - Python 3.15 strips whitespace from each line before testing it, so a line
//!   with leading whitespace runs there;
//! - the file name must end in exactly lowercase `.pth` and must not start
//!   with a dot, otherwise `site` never reads the file.
//!
//! The file is read as raw bytes and never as "text or binary": a NUL byte in
//! a comment does not stop Python.

use std::borrow::Cow;

use super::pylines::{is_python_space, python_lines};
use super::{Ctx, FileIssue, Hit};
use crate::finding::Severity;

/// A recorded executable line is at most this many; the rest are counted.
const MAX_TRACKED_EXEC_LINES: usize = 500;

/// A line this long (in characters) is treated as hiding something.
const LONG_LINE_CHARS: usize = 200;

/// A line is never analysed beyond this many bytes: a longer one is CRITICAL
/// by itself. It bounds the work per line, so a hostile file made of thousands
/// of executable pieces in one huge line cannot make the scan quadratic.
const MAX_ANALYSED_BYTES: usize = 4096;

/// A run of hex digits this long is treated as an encoded payload.
const HEX_RUN_CHARS: usize = 32;

/// A run of base64-like characters this long is examined for entropy.
const BLOB_RUN_CHARS: usize = 40;

/// Bits per character at or above which such a run counts as encoded data.
const BLOB_ENTROPY_BITS: f64 = 4.2;

/// Identifiers that make an executable line CRITICAL. Matched as whole words.
const DANGEROUS_WORDS: &[&str] = &[
    "__import__",
    "base64",
    "binascii",
    "codecs",
    "compile",
    "ctypes",
    "eval",
    "exec",
    "execl",
    "execle",
    "execlp",
    "execlpe",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "fromhex",
    "ftplib",
    "getattr",
    "http",
    "importlib",
    "marshal",
    "pickle",
    "popen",
    "pty",
    "requests",
    "runpy",
    "socket",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "subprocess",
    "system",
    "urllib",
    "zlib",
];

/// The lines of the `distutils-precedence.pth` file of each setuptools
/// version. See `data/honest-pth/README.md` for where they come from.
const SETUPTOOLS_LINES: &str =
    include_str!("../../data/honest-pth/setuptools-distutils-precedence.txt");

/// The line of `pytest-cov.pth` (pytest-cov up to 6.2.1).
const PYTEST_COV_LINE: &str = include_str!("../../data/honest-pth/pytest-cov.txt");

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
    hits.extend(analyse(ctx, name, inert));
    hits
}

/// Why Python's `site` module would never read a file with this name.
fn inert_reason(name: &str) -> Option<&'static str> {
    if name.starts_with('.') {
        Some("its name starts with a dot")
    } else if !name.ends_with(".pth") {
        Some("its extension is not exactly lowercase `.pth`")
    } else {
        None
    }
}

fn issue_hit(issue: &FileIssue, inert: bool) -> Hit {
    let severity = if inert { Severity::Low } else { Severity::High };
    let reason = match issue {
        FileIssue::TooLarge { size } => format!(
            "this .pth file is larger than the scan limit ({size} bytes) and was not read; \
             Python reads it in full, and honest .pth files are tiny"
        ),
        FileIssue::Symlink { .. } => "this .pth file is a symbolic link; Python follows it and \
             processes the target as the .pth file"
            .to_string(),
    };
    Hit {
        line: 1,
        severity,
        reason,
    }
}

/// What was learned about one executable line while reading the file.
struct ExecLine {
    number: usize,
    critical: Option<String>,
    /// Set when the line is a known honest form; the module it imports.
    honest_module: Option<Option<String>>,
}

fn analyse(ctx: &Ctx<'_>, name: &str, inert: Option<&'static str>) -> Vec<Hit> {
    let mut hits = Vec::new();

    // A byte order mark is dropped only at the very start of the file.
    let raw = ctx.bytes();
    let bytes = raw.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(raw);
    let (text, lossy): (Cow<'_, str>, bool) = match std::str::from_utf8(bytes) {
        Ok(text) => (Cow::Borrowed(text), false),
        Err(_) => (String::from_utf8_lossy(bytes), true),
    };
    if lossy && inert.is_none() {
        hits.push(Hit {
            line: 1,
            severity: Severity::Medium,
            reason: "this .pth file is not valid UTF-8; honest ones are plain ASCII, and Python \
                     may decode it with the system's locale encoding"
                .to_string(),
        });
    }
    // Invalid bytes may be whitespace in the encoding Python falls back to.
    let is_space = move |c: char| is_python_space(c) || (lossy && c == '\u{FFFD}');

    let mut first_effective = None;
    let mut all_honest = true;
    let mut execs: Vec<ExecLine> = Vec::new();
    let mut exec_total = 0usize;

    for line in python_lines(&text) {
        let stripped = line.body.trim_matches(is_space);
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        first_effective.get_or_insert(line.number);

        let honest = if all_honest {
            honest_form(name, stripped)
        } else {
            None
        };
        if honest.is_none() {
            all_honest = false;
        }

        if is_exec_line(stripped) {
            exec_total += 1;
            if execs.len() < MAX_TRACKED_EXEC_LINES {
                execs.push(ExecLine {
                    number: line.number,
                    critical: critical_reason(line.physical, is_space),
                    honest_module: honest,
                });
            }
        }
    }

    if let Some(why) = inert {
        // Never processed by Python's `site`, but worth a look: the name was
        // chosen by someone and the line would run if the file were loaded.
        for exec in &execs {
            hits.push(Hit {
                line: exec.number,
                severity: Severity::Low,
                reason: format!(
                    "Python's site module ignores this file because {why}, but this line starts \
                     with `import` and would run if the file were loaded"
                ),
            });
        }
        return hits;
    }

    let Some(first) = first_effective else {
        return hits; // nothing but comments and blank lines
    };
    if exec_total == 0 {
        hits.push(Hit {
            line: first,
            severity: Severity::Info,
            reason: "only adds paths to sys.path; it has no executable line".to_string(),
        });
        return hits;
    }

    let honest_file = all_honest;
    for exec in &execs {
        hits.push(if honest_file {
            honest_hit(ctx, exec)
        } else {
            ordinary_hit(ctx.base, exec)
        });
    }
    if exec_total > execs.len() {
        hits.push(Hit {
            line: execs.last().map_or(1, |exec| exec.number),
            severity: ctx.base,
            reason: format!(
                "{} more executable lines in this file are not listed",
                exec_total - execs.len()
            ),
        });
    }
    hits
}

fn ordinary_hit(base: Severity, exec: &ExecLine) -> Hit {
    match &exec.critical {
        Some(why) => Hit {
            line: exec.number,
            severity: Severity::Critical,
            reason: format!(
                "this line starts with `import`, so Python runs it every time it starts, and it {why}"
            ),
        },
        None => Hit {
            line: exec.number,
            severity: base,
            reason: "this line starts with `import`, so Python runs it every time it starts"
                .to_string(),
        },
    }
}

/// A line of a file whose name and every line are known honest forms.
fn honest_hit(ctx: &Ctx<'_>, exec: &ExecLine) -> Hit {
    let module = exec.honest_module.clone().flatten();
    let (severity, detail) = match module {
        None => (Severity::Low, "it imports no module of its own".to_string()),
        Some(module) if ctx.truncated => (
            Severity::Medium,
            format!(
                "the scan was cut short, so it could not check whether module `{module}` is in \
                 this repository"
            ),
        ),
        Some(module) if ctx.repo.has_module(&module) => (
            Severity::Medium,
            format!(
                "module `{module}` is in this repository, and honest repositories do not commit \
                 the module this file imports"
            ),
        ),
        Some(module) => (
            Severity::Low,
            format!("module `{module}` is not in this repository"),
        ),
    };
    Hit {
        line: exec.number,
        severity,
        reason: format!(
            "this is a line that a known tool writes into .pth files (setuptools, virtualenv, an \
             editable install, a legacy namespace package or pytest-cov); {detail}"
        ),
    }
}

/// Python runs a line when it starts with `import` and a space or a tab.
fn is_exec_line(stripped: &str) -> bool {
    stripped.starts_with("import ") || stripped.starts_with("import\t")
}

// ------------------------------------------------------------ escalation

/// Why an executable line is CRITICAL, if it is. `physical` is the line as
/// Python 3.10 and 3.11 see it, from its start to the next `\n` or `\r`.
fn critical_reason(physical: &str, is_space: impl Fn(char) -> bool + Copy) -> Option<String> {
    let text = physical.trim_start_matches(is_space);
    if text.len() >= MAX_ANALYSED_BYTES {
        return Some(format!("is longer than {MAX_ANALYSED_BYTES} bytes"));
    }
    let text = text.trim_end_matches(is_space);
    if let Some(word) = text
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .find(|word| DANGEROUS_WORDS.contains(word))
    {
        return Some(format!("uses `{word}`"));
    }
    if !text.is_ascii() {
        return Some(
            "contains non-ASCII characters, which Python may read as other names".to_string(),
        );
    }
    if has_escape(text) {
        return Some("contains an escape sequence that can hide what it runs".to_string());
    }
    if text.chars().count() >= LONG_LINE_CHARS {
        return Some(format!("is {} characters long", text.chars().count()));
    }
    if has_hex_run(text) {
        return Some("contains a long run of hexadecimal digits".to_string());
    }
    if has_blob(text)
        || string_literal_groups(text)
            .iter()
            .any(|group| has_blob(group))
    {
        return Some("contains what looks like encoded data".to_string());
    }
    None
}

/// A backslash followed by `x`, `u`, `U` or `N`: a `\x68`-style escape.
fn has_escape(text: &str) -> bool {
    text.as_bytes()
        .windows(2)
        .any(|pair| pair[0] == b'\\' && matches!(pair[1], b'x' | b'u' | b'U' | b'N'))
}

fn has_hex_run(text: &str) -> bool {
    let mut run = 0;
    for byte in text.bytes() {
        if byte.is_ascii_hexdigit() {
            run += 1;
            if run >= HEX_RUN_CHARS {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// A long run of base64-style characters with high entropy, letters and digits.
fn has_blob(text: &str) -> bool {
    let is_blob_char =
        |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'_' | b'=' | b'-');
    text.as_bytes()
        .split(|&b| !is_blob_char(b))
        .filter(|run| run.len() >= BLOB_RUN_CHARS)
        .any(|run| {
            run.iter().any(u8::is_ascii_alphabetic)
                && run.iter().any(u8::is_ascii_digit)
                && shannon_entropy(run) >= BLOB_ENTROPY_BITS
        })
}

/// Bits of entropy per byte.
fn shannon_entropy(bytes: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&n| n > 0)
        .map(|&n| {
            let p = n as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// The contents of string literals, with neighbours separated only by
/// whitespace joined, because `'aGVs' 'bG8='` is one string to Python.
fn string_literal_groups(text: &str) -> Vec<String> {
    let mut groups: Vec<String> = Vec::new();
    let mut last_end: Option<usize> = None;
    let mut i = 0;
    while i < text.len() {
        let rest = &text[i..];
        let quote = match rest.chars().next() {
            Some(q @ ('\'' | '"')) => q,
            Some(c) => {
                i += c.len_utf8();
                continue;
            }
            None => break,
        };
        let body = &rest[1..];
        match body.find(quote) {
            Some(close) if !body[..close].contains(['\\', '\n']) => {
                let content = &body[..close];
                let joins = last_end
                    .is_some_and(|end| text[end..i].trim_matches(is_python_space).is_empty());
                match groups.last_mut() {
                    Some(group) if joins => group.push_str(content),
                    _ => groups.push(content.to_string()),
                }
                i += close + 2;
                last_end = Some(i);
            }
            _ => i += 1,
        }
    }
    groups
}

// -------------------------------------------------------------- honest forms

/// If `line` is a known honest form for a file called `name`, returns the
/// module it imports (if it imports one of its own).
fn honest_form(name: &str, line: &str) -> Option<Option<String>> {
    if name == "distutils-precedence.pth" {
        return SETUPTOOLS_LINES
            .lines()
            .any(|known| known.trim() == line)
            .then(|| Some("_distutils_hack".to_string()));
    }
    if name == "_virtualenv.pth" {
        return (line == "import _virtualenv").then(|| Some("_virtualenv".to_string()));
    }
    if name == "pytest-cov.pth" {
        return (line == PYTEST_COV_LINE.trim()).then(|| Some("pytest_cov".to_string()));
    }
    if name.starts_with("__editable__.") && name.ends_with(".pth") {
        return editable_finder(line).map(|module| Some(module.to_string()));
    }
    if name.ends_with("-nspkg.pth") {
        return is_nspkg_line(line).then_some(None);
    }
    None
}

/// `import X; X.install()` where X is `__editable___<name>_finder`.
fn editable_finder(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("import ")?;
    let (module, call) = rest.split_once("; ")?;
    let valid = module.starts_with("__editable___")
        && module.ends_with("_finder")
        && module
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_');
    (valid && call.strip_suffix(".install()") == Some(module)).then_some(module)
}

/// A line generated by setuptools' namespace-package installer for some
/// package name, in either of the two texts it has had.
fn is_nspkg_line(line: &str) -> bool {
    const MARKER: &str = "sys.modules.setdefault('";
    let Some(start) = line.find(MARKER).map(|i| i + MARKER.len()) else {
        return false;
    };
    let Some(len) = line[start..].find('\'') else {
        return false;
    };
    let package = &line[start..start + len];
    let valid = !package.is_empty()
        && package.split('.').all(|part| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        });
    valid && (line == nspkg_line(package, true) || line == nspkg_line(package, false))
}

/// The text setuptools writes for a namespace package (`setuptools/namespaces.py`).
fn nspkg_line(package: &str, with_has_mfs: bool) -> String {
    let (parent, child) = match package.rsplit_once('.') {
        Some((parent, child)) => (Some(parent), child),
        None => (None, package),
    };
    let tuple = {
        let items: Vec<String> = package.split('.').map(|part| format!("'{part}'")).collect();
        if items.len() == 1 {
            format!("({},)", items[0])
        } else {
            format!("({})", items.join(", "))
        }
    };
    let root = "sys._getframe(1).f_locals['sitedir']";
    let pkg = format!("'{package}'");

    let mut parts: Vec<String> = vec!["import sys, types, os".to_string()];
    if with_has_mfs {
        parts.push("has_mfs = sys.version_info > (3, 5)".to_string());
    }
    parts.push(format!("p = os.path.join({root}, *{tuple})"));
    if with_has_mfs {
        parts.push("importlib = has_mfs and __import__('importlib.util')".to_string());
        parts.push("has_mfs and __import__('importlib.machinery')".to_string());
    } else {
        parts.push("importlib = __import__('importlib.util')".to_string());
        parts.push("__import__('importlib.machinery')".to_string());
    }
    let guard = if with_has_mfs { "has_mfs and " } else { "" };
    parts.push(format!(
        "m = {guard}sys.modules.setdefault({pkg}, importlib.util.module_from_spec(\
         importlib.machinery.PathFinder.find_spec({pkg}, [os.path.dirname(p)])))"
    ));
    parts.push(format!(
        "m = m or sys.modules.setdefault({pkg}, types.ModuleType({pkg}))"
    ));
    parts.push("mp = (m or []) and m.__dict__.setdefault('__path__',[])".to_string());
    parts.push("(p not in mp) and mp.append(p)".to_string());
    if let Some(parent) = parent {
        parts.push(format!(
            "m and setattr(sys.modules['{parent}'], '{child}', m)"
        ));
    }
    parts.join(";")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn critical(physical: &str) -> Option<String> {
        critical_reason(physical, is_python_space)
    }

    #[test]
    fn exec_lines_need_a_space_or_tab_after_import() {
        assert!(is_exec_line("import os"));
        assert!(is_exec_line("import\tos"));
        assert!(!is_exec_line("import"));
        assert!(!is_exec_line("importlib.x"));
        assert!(!is_exec_line("Import os"));
    }

    #[test]
    fn dangerous_words_match_whole_words_only() {
        assert_eq!(
            critical("import sys; exec('x')"),
            Some("uses `exec`".to_string())
        );
        assert!(
            critical("import os; os . system('x')")
                .unwrap()
                .contains("`system`")
        );
        assert_eq!(
            critical("import sys; print('executable evaluate compiled')"),
            None
        );
        assert_eq!(
            critical("import sys; print('https://example.invalid/')"),
            None
        );
    }

    #[test]
    fn very_long_lines_are_critical_without_being_analysed() {
        let huge = format!("import x;{}", " ".repeat(1_000_000));
        assert!(critical(&huge).unwrap().contains("longer than"));
        // Surrounding whitespace does not count towards the length.
        let padded = format!("   import sys; print('hi'){}", " ".repeat(150));
        assert_eq!(critical(&padded), None);
    }

    #[test]
    fn non_ascii_and_escapes_are_critical() {
        assert!(
            critical("import sys; print('caf\u{e9}')")
                .unwrap()
                .contains("non-ASCII")
        );
        assert!(
            critical("import sys; print('\\x68')")
                .unwrap()
                .contains("escape")
        );
        assert!(
            critical("import sys; print('\\u0068')")
                .unwrap()
                .contains("escape")
        );
        assert_eq!(critical("import sys; print('a\\nb')"), None);
    }

    #[test]
    fn long_lines_and_hex_runs_are_critical() {
        let long = format!("import sys; x = '{}'", "q".repeat(300));
        assert!(critical(&long).unwrap().contains("characters long"));
        let hex = format!("import sys; x = '{}'", "0123456789abcdef".repeat(2));
        assert!(critical(&hex).unwrap().contains("hexadecimal"));
        let short_hex = format!("import sys; x = '{}'", "0123456789abcdef01234567");
        assert_eq!(critical(&short_hex), None);
    }

    #[test]
    fn encoded_data_needs_length_entropy_letters_and_digits() {
        let blob = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIGZha2UgcGF5bG9hZA5x2z9Q7w";
        assert!(has_blob(blob), "{}", shannon_entropy(blob.as_bytes()));
        // Long but a single repeated pattern: low entropy.
        assert!(!has_blob(&"x1".repeat(30)));
        // Long and varied but without a digit.
        assert!(!has_blob(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV"
        ));
        // Too short.
        assert!(!has_blob("aGVsbG8gd29ybGQ5"));
    }

    #[test]
    fn adjacent_literals_are_joined_before_measuring() {
        let groups = string_literal_groups("x = ('aGVs' 'bG8g' 'd29y') + 'other'");
        assert_eq!(groups, ["aGVsbG8gd29y", "other"]);
        // A '+' between them is not adjacency.
        let apart = string_literal_groups("'a' + 'b'");
        assert_eq!(apart, ["a", "b"]);
        // A literal that contains a backslash is not measured at all.
        assert_eq!(string_literal_groups(r"'a\nb'"), Vec::<String>::new());
    }

    #[test]
    fn entropy_of_known_strings() {
        assert_eq!(shannon_entropy(b"aaaa"), 0.0);
        assert!((shannon_entropy(b"abab") - 1.0).abs() < 1e-9);
    }

    #[test]
    fn editable_finder_needs_the_same_module_twice() {
        let ok = "import __editable___demo_1_0_finder; __editable___demo_1_0_finder.install()";
        assert_eq!(editable_finder(ok), Some("__editable___demo_1_0_finder"));
        let mismatch = "import __editable___a_finder; __editable___b_finder.install()";
        assert_eq!(editable_finder(mismatch), None);
        assert_eq!(editable_finder("import os; os.install()"), None);
    }

    #[test]
    fn nspkg_lines_are_regenerated_not_pattern_matched() {
        for with_mfs in [true, false] {
            for package in ["zope", "a.b"] {
                let line = nspkg_line(package, with_mfs);
                assert!(is_nspkg_line(&line), "{line}");
                // Any change at all stops it being the honest text.
                assert!(!is_nspkg_line(&format!("{line};print('x')")));
                assert!(!is_nspkg_line(&line.replacen(
                    "mp.append(p)",
                    "mp.append(q)",
                    1
                )));
            }
        }
        assert!(nspkg_line("a.b", false).ends_with("m and setattr(sys.modules['a'], 'b', m)"));
        assert!(!is_nspkg_line("import sys; sys.modules.setdefault('x', 1)"));
    }

    #[test]
    fn honest_forms_need_the_right_file_name() {
        let setuptools = SETUPTOOLS_LINES.lines().next().unwrap();
        assert!(honest_form("distutils-precedence.pth", setuptools).is_some());
        assert!(honest_form("other.pth", setuptools).is_none());
        assert!(honest_form("_virtualenv.pth", "import _virtualenv").is_some());
        assert!(honest_form("x.pth", "import _virtualenv").is_none());
        assert!(honest_form("pytest-cov.pth", PYTEST_COV_LINE.trim()).is_some());
        assert!(honest_form("pytest-cov.pth", "import os").is_none());
    }
}
