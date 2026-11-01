//! Rule `ide.vscode-folder-open-task`: VS Code tasks that run automatically
//! when the folder is opened (`"runOptions": { "runOn": "folderOpen" }`).
//!
//! VS Code reads tasks from two places, so both are checked:
//! - `.vscode/tasks.json`, where `tasks` is at the top level;
//! - `*.code-workspace`, where they live under `"tasks": { "tasks": [...] }`.
//!
//! The file is parsed as JSONC instead of being matched line by line, so
//! comments, line breaks between key and value, and `\uXXXX` escapes in keys
//! cannot hide the setting.

use super::{Ctx, Hit, TextSpan};
use crate::finding::Severity;
use crate::jsonc::{self, Node};
use crate::sanitize::display_safe;

/// A task label is shown in the report, so it is cut to this many characters.
const MAX_LABEL_CHARS: usize = 60;

/// Fragments that make an auto-run task much worse: downloading, shells that
/// run strings as code, and well-known Windows "living off the land" tools.
/// Matched case-insensitively against the task's command and arguments. This
/// is a deliberate over-approximation: a few harmless commands will match too.
const SUSPICIOUS: &[&str] = &[
    "curl",
    "wget",
    "http://",
    "https://",
    "powershell",
    "pwsh",
    "invoke-webrequest",
    "iwr ",
    "invoke-expression",
    "iex ",
    "-enc",
    "base64",
    "bash -c",
    "sh -c",
    "cmd /c",
    "mshta",
    "certutil",
    "rundll32",
    "regsvr32",
    "bitsadmin",
];

/// Which kind of file is being checked; decided from the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    TasksJson,
    CodeWorkspace,
}

impl FileKind {
    /// Returns the kind for a repository-relative path with `/` separators.
    pub fn from_path(path: &str) -> Option<Self> {
        let lower = path.to_ascii_lowercase();
        if lower == ".vscode/tasks.json" || lower.ends_with("/.vscode/tasks.json") {
            Some(Self::TasksJson)
        } else if lower.ends_with(".code-workspace") {
            Some(Self::CodeWorkspace)
        } else {
            None
        }
    }
}

/// Reports every task in the file that runs on folder open.
pub fn check(ctx: &Ctx<'_>) -> Vec<Hit> {
    // Decided from the path alone, so other files are never parsed.
    let Some(kind) = FileKind::from_path(ctx.path) else {
        return Vec::new();
    };
    let root = match ctx.jsonc() {
        Ok(root) => root,
        Err(err) => return unparseable(ctx, err),
    };

    let tasks = match kind {
        FileKind::TasksJson => root.get("tasks"),
        FileKind::CodeWorkspace => root.get("tasks").and_then(|t| t.get("tasks")),
    };
    let Some(tasks) = tasks.and_then(Node::as_array) else {
        return Vec::new();
    };

    tasks
        .iter()
        .filter_map(|task| check_task(task, ctx))
        .collect()
}

fn check_task(task: &Node, ctx: &Ctx<'_>) -> Option<Hit> {
    let run_on = task.get("runOptions")?.get("runOn")?;
    // VS Code itself only accepts the exact value; comparing without case is
    // a deliberate over-approximation that costs nothing.
    if !run_on.as_str()?.eq_ignore_ascii_case("folderOpen") {
        return None;
    }

    let line = ctx.line_of(run_on.offset);
    let span = Some(TextSpan(run_on.offset..run_on.end));
    let label = display_safe(
        task.get("label")
            .and_then(Node::as_str)
            .unwrap_or("<no label>"),
        MAX_LABEL_CHARS,
    );
    let commands = command_text(task);
    let lower = commands.to_ascii_lowercase();

    match SUSPICIOUS.iter().find(|s| lower.contains(*s)) {
        Some(fragment) => Some(Hit {
            line,
            span,
            severity: Severity::Critical,
            reason: format!(
                "task \"{label}\" runs automatically when the folder is opened, \
                 and its command contains \"{}\"",
                fragment.trim()
            ),
        }),
        None => Some(Hit {
            line,
            span,
            severity: ctx.base,
            reason: format!("task \"{label}\" runs automatically when the folder is opened"),
        }),
    }
}

/// Collects `command` and `args` of a task, including the per-OS overrides
/// (`windows`, `linux`, `osx`), because an attacker can hide the real command
/// in the block for the OS they target.
fn command_text(task: &Node) -> String {
    let mut parts = Vec::new();
    for scope in [
        Some(task),
        task.get("windows"),
        task.get("linux"),
        task.get("osx"),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(cmd) = scope.get("command").and_then(Node::as_str) {
            parts.push(cmd.to_string());
        }
        for arg in scope
            .get("args")
            .and_then(Node::as_array)
            .unwrap_or_default()
        {
            if let Some(s) = arg.as_str() {
                parts.push(s.to_string());
            }
        }
    }
    parts.join(" ")
}

/// VS Code's own parser is forgiving, so a file we cannot parse may still run.
/// Instead of silently skipping it, report it for a manual look: at the rule's
/// base severity if the key words appear in the text, otherwise at MEDIUM
/// (they may still be hidden behind escapes).
fn unparseable(ctx: &Ctx<'_>, err: &jsonc::ParseError) -> Vec<Hit> {
    let line = ctx.line_of(err.offset);
    let text = ctx.text();
    let mentions = text.contains("runOn") && text.contains("folderOpen");
    vec![Hit {
        line,
        span: None,
        severity: if mentions { ctx.base } else { Severity::Medium },
        reason: format!(
            "file could not be parsed ({}); VS Code may still accept it, review it by hand",
            err.message
        ),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    const TASKS: &str = ".vscode/tasks.json";

    fn check(path: &str, text: &str, base: Severity) -> Vec<Hit> {
        crate::checks::run_on_text(super::check, path, text, base)
    }

    #[test]
    fn file_kind_from_path() {
        assert_eq!(
            FileKind::from_path(".vscode/tasks.json"),
            Some(FileKind::TasksJson)
        );
        assert_eq!(
            FileKind::from_path("sub/.VSCode/Tasks.json"),
            Some(FileKind::TasksJson)
        );
        assert_eq!(
            FileKind::from_path("app.code-workspace"),
            Some(FileKind::CodeWorkspace)
        );
        assert_eq!(FileKind::from_path("docs/tasks.json"), None);
    }

    #[test]
    fn other_paths_are_ignored_without_parsing() {
        let text = r#"{"tasks":[{"runOptions":{"runOn":"folderOpen"}}]}"#;
        assert!(check("docs/tasks.json", text, Severity::High).is_empty());
    }

    #[test]
    fn base_severity_comes_from_the_caller() {
        let text = r#"{"tasks":[{"label":"x","runOptions":{"runOn":"folderOpen"}}]}"#;
        let hits = check(TASKS, text, Severity::Medium);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
    }

    #[test]
    fn hostile_label_cannot_inject_terminal_escapes() {
        let text = r#"{"tasks":[{"label":"ok\u001b[2J\u202eevil\nFAKE","runOptions":{"runOn":"folderOpen"}}]}"#;
        let hits = check(TASKS, text, Severity::High);
        let reason = &hits[0].reason;
        assert!(!reason.chars().any(|c| c.is_control()), "{reason:?}");
        assert!(reason.contains("\\u{001B}"));
        assert!(reason.contains("\\u{202E}"));
    }

    #[test]
    fn very_long_label_is_cut() {
        let label = "x".repeat(500);
        let text =
            format!(r#"{{"tasks":[{{"label":"{label}","runOptions":{{"runOn":"folderOpen"}}}}]}}"#);
        let hits = check(TASKS, &text, Severity::High);
        assert!(hits[0].reason.len() < 200, "{}", hits[0].reason.len());
    }

    #[test]
    fn unparseable_file_without_the_key_words_is_medium() {
        let hits = check(TASKS, r#"{"tasks": [ }"#, Severity::High);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
    }
}
