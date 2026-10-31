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
///
/// `http://` and `git://` are recognized on purpose: they are classified as
/// remote so that cloning can refuse them with a clear message, instead of
/// the argument being mistaken for a missing local directory.
const REMOTE_PREFIXES: &[&str] = &["https://", "http://", "git://", "ssh://", "git@"];

impl Target {
    /// Classifies a raw CLI argument. This never touches the filesystem or
    /// network, so it is cheap and easy to unit test.
    pub fn parse(raw: &str) -> Self {
        let lower = raw.to_ascii_lowercase();
        if REMOTE_PREFIXES
            .iter()
            .any(|prefix| lower.starts_with(prefix))
        {
            Target::Remote(raw.to_string())
        } else {
            Target::Local(PathBuf::from(raw))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_url_is_remote() {
        let raw = "https://github.com/z3nghoul/repo-sniff";
        assert_eq!(Target::parse(raw), Target::Remote(raw.to_string()));
    }

    #[test]
    fn ssh_style_urls_are_remote() {
        for raw in [
            "git@github.com:z3nghoul/repo-sniff.git",
            "ssh://git@github.com/z3nghoul/repo-sniff.git",
        ] {
            assert_eq!(Target::parse(raw), Target::Remote(raw.to_string()));
        }
    }

    #[test]
    fn unencrypted_urls_are_still_remote() {
        // They must reach the clone step, which refuses them with a clear error.
        for raw in ["http://example.com/repo", "git://example.com/repo.git"] {
            assert_eq!(Target::parse(raw), Target::Remote(raw.to_string()));
        }
    }

    #[test]
    fn scheme_matching_ignores_case() {
        let raw = "HTTPS://example.com/repo";
        assert_eq!(Target::parse(raw), Target::Remote(raw.to_string()));
    }

    #[test]
    fn plain_paths_are_local() {
        for raw in [".", "../other-repo", "/home/user/project"] {
            assert_eq!(Target::parse(raw), Target::Local(PathBuf::from(raw)));
        }
    }

    #[test]
    fn path_that_merely_contains_a_scheme_is_local() {
        // Only a prefix counts; a directory named like this is still a path.
        let raw = "./https://not-a-url";
        assert_eq!(Target::parse(raw), Target::Local(PathBuf::from(raw)));
    }
}
