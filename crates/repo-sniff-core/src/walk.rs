//! Collecting the files to scan, with limits that protect the scanner.
//!
//! The scanned repository is untrusted, so the walk is deliberately
//! paranoid:
//! - symlinks are never followed (a link could point at `/etc` or `~/.ssh`);
//! - `.gitignore` and similar files are NOT honored: a file that is in the
//!   checkout is scanned even if the repository asks us to ignore it,
//!   otherwise an attacker could hide a payload by listing it there;
//! - hidden files are scanned (`.vscode/`, `.github/` matter a lot);
//! - oversized files and anything past the file-count limit are skipped,
//!   and every skip is reported so nothing disappears silently.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ignore::WalkBuilder;

/// Upper bounds for one scan.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Files larger than this many bytes are skipped.
    pub max_file_size: u64,
    /// The walk stops after this many files.
    pub max_files: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_file_size: 5 * 1024 * 1024,
            max_files: 100_000,
        }
    }
}

/// Why a path was not scanned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    TooLarge {
        size: u64,
    },
    /// A symbolic link; `target` is where it points, when that can be read.
    Symlink {
        target: Option<PathBuf>,
    },
    /// The file has a known binary header, or NUL bytes and contents that do
    /// not read as text. The line rules ran on its ASCII only, with the NUL
    /// bytes removed, because a shell can still source such a file; nothing
    /// looked inside the binary format itself.
    Binary,
    /// The magic bytes say it is an executable format (ELF, PE, Mach-O,
    /// including fat binaries). It is code that runs, and nothing analyzes it
    /// yet.
    Executable {
        format: &'static str,
    },
    Unreadable {
        error: String,
    },
    /// A `.git` folder (or a `.git` file of a worktree or submodule). Its
    /// contents are not scanned. The one at the root is the repository's own
    /// metadata; a nested one belongs to a vendored repository whose files
    /// and hooks nobody looked at.
    GitMetadata {
        nested: bool,
    },
}

impl SkipReason {
    /// Whether this skip means the scan cannot vouch for the repository, so a
    /// result without findings must not be called clean.
    ///
    /// - A file that was too large or could not be opened: its bytes were
    ///   not read.
    /// - An executable binary: it was read, but it is code that runs and
    ///   nothing analyzes it yet. This goes away when the "committed
    ///   binaries" rule exists, because then such a file is a finding.
    ///
    /// - A nested `.git` folder: a whole repository inside the one that was
    ///   scanned, and none of it was read. The root `.git` is not counted.
    ///
    /// Not counted: other binary data (images, archives, compressed files)
    /// that was read but has no rules, and symlinks, which are not content
    /// (their target is scanned when it is inside the repository).
    pub fn makes_scan_inconclusive(&self) -> bool {
        matches!(
            self,
            SkipReason::TooLarge { .. }
                | SkipReason::Unreadable { .. }
                | SkipReason::Executable { .. }
                | SkipReason::GitMetadata { nested: true }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// Path relative to the repository root.
    pub path: PathBuf,
    pub reason: SkipReason,
}

/// The outcome of walking a repository.
#[derive(Debug, Default)]
pub struct WalkResult {
    /// Files to scan, relative to the root, in a stable (sorted) order.
    pub files: Vec<PathBuf>,
    pub skipped: Vec<Skipped>,
    /// True if the walk stopped early because of `Limits::max_files`.
    pub truncated: bool,
}

/// Lists the files under `root` that should be scanned.
pub fn walk(root: &Path, limits: Limits) -> WalkResult {
    // `.git` entries are not walked into, but each one is remembered so the
    // report can list it instead of dropping it.
    let git_entries = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&git_entries);
    let walker = WalkBuilder::new(root)
        .standard_filters(false) // no .gitignore, .ignore, hidden-file filtering
        .follow_links(false)
        .sort_by_file_name(|a, b| a.cmp(b))
        .filter_entry(move |entry| {
            if entry.file_name() != ".git" {
                return true;
            }
            if let Ok(mut list) = seen.lock() {
                list.push((entry.path().to_path_buf(), entry.depth() > 1));
            }
            false
        })
        .build();

    let mut result = WalkResult::default();

    for entry in walker {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                let path = err_path(&err).unwrap_or_default();
                result.skipped.push(Skipped {
                    path: relative(root, &path),
                    reason: SkipReason::Unreadable {
                        error: err.to_string(),
                    },
                });
                continue;
            }
        };

        let Some(file_type) = entry.file_type() else {
            continue; // stdin; never happens for a directory walk
        };
        let path = relative(root, entry.path());

        if file_type.is_symlink() {
            result.skipped.push(Skipped {
                path,
                reason: SkipReason::Symlink {
                    target: std::fs::read_link(entry.path()).ok(),
                },
            });
            continue;
        }
        if !file_type.is_file() {
            continue; // directories are walked into, not scanned
        }

        let size = match entry.metadata() {
            Ok(metadata) => metadata.len(),
            Err(err) => {
                result.skipped.push(Skipped {
                    path,
                    reason: SkipReason::Unreadable {
                        error: err.to_string(),
                    },
                });
                continue;
            }
        };
        if size > limits.max_file_size {
            result.skipped.push(Skipped {
                path,
                reason: SkipReason::TooLarge { size },
            });
            continue;
        }

        if result.files.len() == limits.max_files {
            result.truncated = true;
            break;
        }
        result.files.push(path);
    }

    let git_entries = git_entries
        .lock()
        .map(|list| list.clone())
        .unwrap_or_default();
    for (path, nested) in git_entries {
        result.skipped.push(Skipped {
            path: relative(root, &path),
            reason: SkipReason::GitMetadata { nested },
        });
    }

    result
}

fn relative(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

fn err_path(err: &ignore::Error) -> Option<PathBuf> {
    match err {
        ignore::Error::WithPath { path, .. } => Some(path.clone()),
        ignore::Error::WithDepth { err, .. } | ignore::Error::WithLineNumber { err, .. } => {
            err_path(err)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn hidden_and_gitignored_files_are_scanned() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".gitignore", "payload.bin\n");
        write(dir.path(), "payload.bin", "x");
        write(dir.path(), ".vscode/tasks.json", "{}");

        let result = walk(dir.path(), Limits::default());

        assert_eq!(
            result.files,
            [".gitignore", ".vscode/tasks.json", "payload.bin"].map(PathBuf::from)
        );
    }

    #[test]
    fn git_directories_are_not_scanned_but_are_listed() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".git/config", "[core]");
        write(dir.path(), "vendor/lib/.git/hooks/post-checkout", "x");
        write(dir.path(), "main.rs", "fn main() {}");

        let result = walk(dir.path(), Limits::default());

        assert_eq!(result.files, [PathBuf::from("main.rs")]);
        let mut skipped: Vec<_> = result
            .skipped
            .iter()
            .map(|s| (s.path.clone(), s.reason.clone()))
            .collect();
        skipped.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            skipped,
            [
                (
                    PathBuf::from(".git"),
                    SkipReason::GitMetadata { nested: false }
                ),
                (
                    PathBuf::from("vendor/lib/.git"),
                    SkipReason::GitMetadata { nested: true }
                ),
            ]
        );
        assert!(
            result.skipped[0].reason.makes_scan_inconclusive()
                || result.skipped[1].reason.makes_scan_inconclusive()
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_reported_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/etc", dir.path().join("etc-link")).unwrap();

        let result = walk(dir.path(), Limits::default());

        assert!(result.files.is_empty());
        assert_eq!(
            result.skipped,
            [Skipped {
                path: PathBuf::from("etc-link"),
                reason: SkipReason::Symlink {
                    target: Some(PathBuf::from("/etc")),
                },
            }]
        );
    }

    #[test]
    fn oversized_files_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "big.txt", "0123456789");
        let limits = Limits {
            max_file_size: 5,
            ..Limits::default()
        };

        let result = walk(dir.path(), limits);

        assert!(result.files.is_empty());
        assert_eq!(result.skipped[0].reason, SkipReason::TooLarge { size: 10 });
    }

    #[test]
    fn walk_stops_at_file_limit() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["a", "b", "c"] {
            write(dir.path(), name, "");
        }
        let limits = Limits {
            max_files: 2,
            ..Limits::default()
        };

        let result = walk(dir.path(), limits);

        assert_eq!(result.files.len(), 2);
        assert!(result.truncated);
    }
}
