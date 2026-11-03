//! Fixtures are stored defanged and become real only in a temporary folder.
//!
//! The fixtures imitate attacks on purpose, so a grep-based scanner that reads
//! this repository would take it for malware. Three conventions keep the
//! committed files harmless (the details are in CONTRIBUTING.md):
//!
//! - words such scanners react to are written as `{{NAME}}` markers, listed in
//!   [`MARKERS`];
//! - a folder whose real name starts with a dot is stored with `_` instead
//!   (`.vscode` as `_vscode`), see [`DOT_DIRS`];
//! - a file that a scanner or an editor might run is stored with the suffix
//!   `.fixture`, see [`needs_suffix`].
//!
//! [`materialize`] copies a fixture tree to a temporary folder with the real
//! names and the markers replaced, and the tests scan that copy. A marker that
//! is not in the table is an error, so a typo cannot silently weaken a fixture.

#![allow(dead_code)]

use std::fs;
use std::path::Path;

use tempfile::TempDir;

/// Marker names and the text they stand for. The text is given in pieces so
/// this file does not contain the words either.
pub const MARKERS: &[(&str, &[&str])] = &[
    ("INVOKE_EXPRESSION", &["Invoke-", "Expression"]),
    ("ADD_MPPREFERENCE", &["Add-Mp", "Preference"]),
    ("DOWNLOAD_STRING", &["Download", "String"]),
    ("ENCODED_COMMAND", &["Encoded", "Command"]),
    ("ENC_FLAG", &["-", "enc"]),
    ("CHILD_PROCESS", &["child", "_process"]),
    ("FOLDER_OPEN", &["folder", "Open"]),
    ("RUN_ON", &["run", "On"]),
    ("HEX_PREFIX", &["_0", "x"]),
    ("ATOB", &["at", "ob"]),
    ("EVAL", &["ev", "al"]),
    ("FUNCTION", &["Func", "tion"]),
    ("IEX", &["i", "ex"]),
    ("CURL", &["cu", "rl"]),
    ("WGET", &["w", "get"]),
    ("EXEC_SYNC", &["exec", "Sync"]),
    ("IMPORT_DUNDER", &["__im", "port__"]),
    ("OS_SYSTEM", &["os.", "system"]),
    ("CERTUTIL", &["cert", "util"]),
    ("MSHTA", &["ms", "hta"]),
    ("REGSVR32", &["regs", "vr32"]),
    ("RUNDLL32", &["run", "dll32"]),
    ("BITSADMIN", &["bits", "admin"]),
    ("WSCRIPT", &["W", "Script"]),
    ("ACTIVEX", &["Active", "XObject"]),
    ("WEBCLIENT", &["Net.", "WebClient"]),
    ("POWERSHELL", &["power", "shell"]),
    ("MARSHAL", &["mar", "shal"]),
];

/// Folders whose real name is `.<name>`; stored as `_<name>`. A list, not a
/// rule, because real fixture folders such as `_distutils_hack` start with `_`.
pub const DOT_DIRS: &[&str] = &["devcontainer", "projen", "roo", "vscode", "bin"];

/// Suffix of a stored file whose real name is the name without it.
pub const SUFFIX: &str = ".fixture";

/// Extensions of files that a scanner or an editor may run or open on its own.
const EXEC_EXTENSIONS: &[&str] = &[
    "pth",
    "start",
    "bat",
    "cmd",
    "ps1",
    "psm1",
    "vbs",
    "wsf",
    "hta",
    "jse",
    "sh",
    "exe",
    "code-workspace",
];

/// Names (lowercase) of files that tools run or read as configuration.
const EXEC_NAMES: &[&str] = &[
    "package.json",
    "tasks.json",
    "launch.json",
    "mcp.json",
    "devcontainer.json",
    ".devcontainer.json",
    "next.config.js",
    ".eslintrc.js",
    ".release-it.json",
    "husky",
];

/// True if a fixture file with this real name is stored with [`SUFFIX`].
pub fn needs_suffix(real_name: &str) -> bool {
    let lower = real_name.to_lowercase();
    EXEC_NAMES.contains(&lower.as_str())
        || lower
            .rsplit_once('.')
            .is_some_and(|(_, extension)| EXEC_EXTENSIONS.contains(&extension))
}

fn marker_text(pieces: &[&str]) -> String {
    pieces.concat()
}

fn real_dir_name(stored: &str) -> String {
    match stored.strip_prefix('_') {
        Some(rest) if DOT_DIRS.contains(&rest) => format!(".{rest}"),
        _ => stored.to_string(),
    }
}

fn real_file_name(stored: &str) -> String {
    stored.strip_suffix(SUFFIX).unwrap_or(stored).to_string()
}

fn replace_all(data: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut rest = data;
    while let Some(at) = rest.windows(from.len()).position(|w| w == from) {
        out.extend_from_slice(&rest[..at]);
        out.extend_from_slice(to);
        rest = &rest[at + from.len()..];
    }
    out.extend_from_slice(rest);
    out
}

/// The text of `data` with every marker replaced. Panics, naming the file, on
/// a `{{NAME}}` that is not in [`MARKERS`].
fn substitute(data: &[u8], file: &Path) -> Vec<u8> {
    let mut out = data.to_vec();
    for (name, pieces) in MARKERS {
        let marker = format!("{{{{{name}}}}}");
        out = replace_all(&out, marker.as_bytes(), marker_text(pieces).as_bytes());
    }
    if let Some(left) = leftover_marker(&out) {
        panic!("{}: marker {left} is not in MARKERS", file.display());
    }
    out
}

/// The first `{{NAME}}`-shaped text in `data`, if any.
fn leftover_marker(data: &[u8]) -> Option<String> {
    let mut at = 0;
    while let Some(open) = data[at..].windows(2).position(|w| w == b"{{") {
        let start = at + open;
        let name_len = data[start + 2..]
            .iter()
            .take_while(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || **b == b'_')
            .count();
        let end = start + 2 + name_len;
        if name_len > 0 && data[end..].starts_with(b"}}") {
            return Some(String::from_utf8_lossy(&data[start..end + 2]).into_owned());
        }
        at = start + 2;
    }
    None
}

/// Copies the stored fixture tree `src` to a new temporary folder with real
/// names and the markers replaced. Symlinks are not followed or copied.
pub fn materialize(src: &Path) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    copy_real(src, dir.path());
    dir
}

/// Same as [`materialize`] into an existing folder.
pub fn copy_real(src: &Path, dest: &Path) {
    fs::create_dir_all(dest).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        let stored = entry.file_name().to_string_lossy().into_owned();
        if kind.is_dir() {
            copy_real(&entry.path(), &dest.join(real_dir_name(&stored)));
        } else if kind.is_file() {
            let data = fs::read(entry.path()).unwrap();
            let real = dest.join(real_file_name(&stored));
            fs::write(&real, substitute(&data, &entry.path())).unwrap();
        }
    }
}

/// Where in `data` the text of a marker stands raw, as a word of its own.
fn raw_marker_text(data: &[u8]) -> Option<&'static str> {
    let word = |b: u8| b.is_ascii_alphanumeric();
    for (name, pieces) in MARKERS {
        let text = marker_text(pieces);
        let text = text.as_bytes();
        for at in data
            .windows(text.len())
            .enumerate()
            .filter(|(_, w)| *w == text)
            .map(|(at, _)| at)
        {
            let before = at.checked_sub(1).map(|i| data[i]);
            let after = data.get(at + text.len()).copied();
            let ends_ok = !before.is_some_and(word)
                && if *name == "HEX_PREFIX" {
                    data[at + text.len()..]
                        .iter()
                        .take(4)
                        .filter(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                        .count()
                        == 4
                } else {
                    !after.is_some_and(word)
                };
            if ends_ok {
                return Some(name);
            }
        }
    }
    None
}

/// What breaks the storage conventions in the stored tree `src`: a folder
/// that starts with a dot, a file that needs [`SUFFIX`] and lacks it, or a
/// word that should be a marker.
pub fn storage_problems(src: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, problems: &mut Vec<String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let shown = path.strip_prefix(root).unwrap().display().to_string();
            if kind.is_dir() {
                if name.starts_with('.') {
                    problems.push(format!("{shown}: folder starts with a dot"));
                }
                walk(root, &path, problems);
            } else if kind.is_file() {
                if !name.ends_with(SUFFIX) && needs_suffix(&name) {
                    problems.push(format!("{shown}: needs the {SUFFIX} suffix"));
                }
                let data = fs::read(&path).unwrap();
                if !data.contains(&0)
                    && !name.ends_with(".expected.toml")
                    && let Some(raw) = raw_marker_text(&data)
                {
                    problems.push(format!("{shown}: contains {{{{{raw}}}}} written out"));
                }
            }
        }
    }
    let mut problems = Vec::new();
    walk(src, src, &mut problems);
    problems
}
