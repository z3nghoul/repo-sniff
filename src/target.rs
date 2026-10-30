//! Resolving what the user asked us to scan: a local directory or a remote repo URL.

use std::path::PathBuf;

/// The thing passed to `repo-sniff scan <target>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A directory that already exists on disk.
    Local(PathBuf),
    /// A git URL that has to be cloned before scanning.
    Remote(String),
}

/// Prefixes that mark an argument as a git URL rather than a filesystem path.
const REMOTE_PREFIXES: &[&str] = &["https://", "http://", "ssh://", "git@"];

impl Target {
    /// Classifies a raw CLI argument. This never touches the filesystem or
    /// network, so it is cheap and easy to unit test.
    pub fn parse(raw: &str) -> Self {
        if REMOTE_PREFIXES.iter().any(|prefix| raw.starts_with(prefix)) {
            Target::Remote(raw.to_string())
        } else {
            Target::Local(PathBuf::from(raw))
        }
    }
}
