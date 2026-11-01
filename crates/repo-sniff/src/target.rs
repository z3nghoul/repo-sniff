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
/// `http://`, `git://`, `ssh://` and `git@host:path` are recognized on purpose:
/// they are classified as remote so that cloning can refuse them with a clear
/// message (and, for ssh, advice to clone the repository and scan the
/// folder), instead of the argument being mistaken for a missing directory.
const REMOTE_PREFIXES: &[&str] = &["https://", "http://", "git://", "ssh://", "git@"];

impl Target {
    /// Classifies a raw CLI argument. This never touches the filesystem or
    /// network, so it is cheap and easy to unit test.
    pub fn parse(raw: &str) -> Self {
        let lower = raw.to_ascii_lowercase();
        if REMOTE_PREFIXES
            .iter()
            .any(|prefix| lower.starts_with(prefix))
            || is_scp_like(raw)
        {
            Target::Remote(raw.to_string())
        } else {
            Target::Local(PathBuf::from(raw))
        }
    }
}

/// Whether `raw` is an scp-like ssh address, `user@host:path`, with any user
/// (`deploy:TOKEN@host:owner/repo` included), which git would fetch over ssh:
/// the part before the first `/` or `\` holds an `@`, and the text after its
/// last `@` is a host followed by `:`. The host may be empty when the user part
/// holds a `:` (`deploy:TOKEN@:x`), which is a password, not a folder name. Such an argument is not a path, and
/// taking it for one would print it, user information and all, in a "cannot
/// access" error. A local folder with a name like that can still be scanned
/// as `./user@host:path`.
pub fn is_scp_like(raw: &str) -> bool {
    if raw.contains("://") {
        return false;
    }
    let prefix = raw.split(['/', '\\']).next().unwrap_or_default();
    let Some(at) = prefix.rfind('@') else {
        return false;
    };
    let user = &prefix[..at];
    let after = &prefix[at + 1..];
    !user.is_empty()
        && after
            .find(':')
            .is_some_and(|colon| colon > 0 || user.contains(':'))
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
    fn scp_like_addresses_with_any_user_are_remote() {
        for raw in [
            "deploy:FAKE_TOKEN@example.invalid:o/r.git",
            "deploy@example.invalid:o/r.git",
            "u:p@ss@example.invalid:o/r",
            "git@example.invalid:o/r@v2",
            "deploy:FAKE_TOKEN@:o/r",
        ] {
            assert_eq!(Target::parse(raw), Target::Remote(raw.to_string()), "{raw}");
        }
    }

    #[test]
    fn paths_that_only_look_a_little_like_scp_are_local() {
        for raw in [
            "./deploy:FAKE_TOKEN@example.invalid:o/r.git",
            "dir/user@host:x",
            "C:\\work\\user@host:x",
            "C:\\work",
            "@host:x",
            "user@:x",
            "user@host",
            "notes@2026",
            "me@corp",
            "C:/Users/first@corp/repo",
            "\\\\server\\share\\me@x:y",
            "./alpine@sha256:abc",
        ] {
            assert_eq!(
                Target::parse(raw),
                Target::Local(PathBuf::from(raw)),
                "{raw}"
            );
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
