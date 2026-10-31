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
    /// The file contains NUL bytes, so line rules do not apply to it.
    Binary,
    Unreadable {
        error: String,
    },
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
    let walker = WalkBuilder::new(root)
        .standard_filters(false) // no .gitignore, .ignore, hidden-file filtering
        .follow_links(false)
        .sort_by_file_name(|a, b| a.cmp(b))
        .filter_entry(|entry| entry.file_name() != ".git")
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
    fn git_directory_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".git/config", "[core]");
        write(dir.path(), "main.rs", "fn main() {}");

        let result = walk(dir.path(), Limits::default());

        assert_eq!(result.files, [PathBuf::from("main.rs")]);
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
