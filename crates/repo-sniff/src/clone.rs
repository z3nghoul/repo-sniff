//! Fetching remote repositories with the system `git` binary.

use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use repo_sniff_core::display_safe;
use tempfile::TempDir;

/// URL schemes that send the repository over the network unencrypted.
const PLAIN_TEXT_SCHEMES: &[&str] = &["http://", "git://"];

/// Error text from a git server is chosen by whoever runs the server, so it
/// is cleaned and cut before it is shown.
const MAX_GIT_ERROR_CHARS: usize = 500;

/// Shallow-clones `url` into a fresh temporary directory, at `git_ref` (a
/// branch or tag) or at the repository's default branch.
///
/// The returned `TempDir` deletes the checkout when it is dropped, so the
/// caller just has to keep it alive for as long as the scan runs.
///
/// The clone is locked down because we are fetching untrusted code:
/// - unencrypted transports are refused, so nobody on the network can swap
///   the code we are about to judge;
/// - only the `https` and `ssh` transports are allowed at all;
/// - hooks are disabled, so neither our own nor any global hooks run;
/// - Git LFS smudge filters are skipped, so no extra downloads or filters run;
/// - submodules are not fetched;
/// - credential prompts are disabled, so a private repo fails fast instead of hanging.
pub fn shallow_clone(url: &str, git_ref: Option<&str>) -> Result<TempDir> {
    ensure_encrypted_transport(url)?;
    if let Some(git_ref) = git_ref {
        validate_ref(git_ref)?;
    }

    let dir = tempfile::Builder::new()
        .prefix("repo-sniff-")
        .tempdir()
        .context("failed to create a temporary directory")?;

    // Pointing `core.hooksPath` at an empty directory means git finds no
    // hooks to run. Unlike `/dev/null` this works on every OS.
    let no_hooks = tempfile::Builder::new()
        .prefix("repo-sniff-nohooks-")
        .tempdir()
        .context("failed to create a temporary directory")?;

    let output = Command::new("git")
        .args(clone_args(url, git_ref, dir.path(), no_hooks.path()))
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_LFS_SKIP_SMUDGE", "1")
        .env("GIT_ALLOW_PROTOCOL", "https:ssh")
        .output()
        .context("failed to run `git`; is it installed and on PATH?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git clone of {url} failed: {}",
            display_safe(stderr.trim(), MAX_GIT_ERROR_CHARS)
        );
    }

    Ok(dir)
}

/// The arguments passed to `git`, in order. Kept separate from running the
/// command so that the safety-relevant parts can be tested without a network.
fn clone_args(url: &str, git_ref: Option<&str>, dest: &Path, hooks_dir: &Path) -> Vec<OsString> {
    let mut hooks_config = OsString::from("core.hooksPath=");
    hooks_config.push(hooks_dir);

    let mut args: Vec<OsString> = vec![
        "-c".into(),
        hooks_config,
        "clone".into(),
        "--depth".into(),
        "1".into(),
        "--quiet".into(),
        "--no-recurse-submodules".into(),
    ];
    if let Some(git_ref) = git_ref {
        // One argument, `--branch=<ref>`, so the value can never be read as
        // an option of its own. `--branch` accepts branches and tags.
        args.push(format!("--branch={git_ref}").into());
    }
    // `--` stops git from treating a crafted URL as an option.
    args.push("--".into());
    args.push(url.into());
    args.push(dest.into());
    args
}

/// Rejects refs that cannot be a branch or tag name or that look like options.
/// Git applies its own, stricter rules afterwards.
fn validate_ref(git_ref: &str) -> Result<()> {
    if git_ref.is_empty() {
        bail!("--ref must not be empty");
    }
    if git_ref.starts_with('-') {
        bail!("--ref must not start with `-`");
    }
    if git_ref.chars().any(|c| c.is_control() || c.is_whitespace()) {
        bail!("--ref must not contain whitespace or control characters");
    }
    Ok(())
}

/// Rejects URLs that would be fetched without encryption.
fn ensure_encrypted_transport(url: &str) -> Result<()> {
    let lower = url.to_ascii_lowercase();
    if let Some(scheme) = PLAIN_TEXT_SCHEMES
        .iter()
        .find(|scheme| lower.starts_with(**scheme))
    {
        bail!(
            "refusing to clone over unencrypted {scheme}: anyone on the network could \
             alter the code being scanned. Use an https:// URL instead"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_as_strings(git_ref: Option<&str>) -> Vec<String> {
        clone_args(
            "https://example.com/owner/repo",
            git_ref,
            Path::new("/dest"),
            Path::new("/hooks"),
        )
        .into_iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
    }

    #[test]
    fn plain_text_urls_are_rejected() {
        for url in [
            "http://github.com/owner/repo",
            "git://github.com/owner/repo.git",
            "HTTP://github.com/owner/repo",
        ] {
            let err = ensure_encrypted_transport(url).unwrap_err();
            assert!(err.to_string().contains("unencrypted"), "{url}: {err}");
        }
    }

    #[test]
    fn encrypted_urls_are_accepted() {
        for url in [
            "https://github.com/owner/repo",
            "ssh://git@github.com/owner/repo.git",
            "git@github.com:owner/repo.git",
        ] {
            ensure_encrypted_transport(url).unwrap();
        }
    }

    #[test]
    fn shallow_clone_refuses_http_before_touching_anything() {
        // Must fail on the URL check, without running git or the network.
        let err = shallow_clone("http://example.invalid/repo", None).unwrap_err();
        assert!(err.to_string().contains("unencrypted"));
    }

    #[test]
    fn default_branch_clone_has_no_branch_argument() {
        let args = args_as_strings(None);
        assert!(args.iter().all(|a| !a.starts_with("--branch")), "{args:?}");
        assert_eq!(&args[2..4], ["clone", "--depth"]);
    }

    #[test]
    fn ref_is_a_single_branch_argument_before_the_separator() {
        let args = args_as_strings(Some("v1.2.3"));
        let branch = args.iter().position(|a| a == "--branch=v1.2.3").unwrap();
        let separator = args.iter().position(|a| a == "--").unwrap();
        assert!(branch < separator, "{args:?}");
        // The URL and destination come after `--`, so they cannot be options.
        assert_eq!(args[separator + 1], "https://example.com/owner/repo");
        assert_eq!(args[separator + 2], "/dest");
    }

    #[test]
    fn hooks_are_always_redirected_to_the_empty_directory() {
        for args in [args_as_strings(None), args_as_strings(Some("main"))] {
            assert_eq!(args[0], "-c");
            assert_eq!(args[1], "core.hooksPath=/hooks");
        }
    }

    #[test]
    fn dangerous_refs_are_rejected() {
        for bad in [
            "",
            "-x",
            "--upload-pack=evil",
            "a b",
            "tag\n",
            "tab\there",
            "esc\u{1b}",
        ] {
            assert!(validate_ref(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn ordinary_refs_are_accepted() {
        for good in ["main", "v1.2.3", "release/2026-10", "feature_x", "1.0"] {
            validate_ref(good).unwrap();
        }
    }

    #[test]
    fn shallow_clone_rejects_a_bad_ref_before_running_git() {
        let err = shallow_clone("https://example.invalid/repo", Some("--evil")).unwrap_err();
        assert!(err.to_string().contains("--ref"), "{err}");
    }
}
