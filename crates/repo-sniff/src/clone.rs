//! Fetching remote repositories with the system `git` binary.

use std::ffi::OsString;
use std::process::Command;

use anyhow::{Context, Result, bail};
use tempfile::TempDir;

/// URL schemes that send the repository over the network unencrypted.
const PLAIN_TEXT_SCHEMES: &[&str] = &["http://", "git://"];

/// Shallow-clones `url` into a fresh temporary directory.
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
pub fn shallow_clone(url: &str) -> Result<TempDir> {
    ensure_encrypted_transport(url)?;

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
    let mut hooks_config = OsString::from("core.hooksPath=");
    hooks_config.push(no_hooks.path());

    let output = Command::new("git")
        .arg("-c")
        .arg(hooks_config)
        .args([
            "clone",
            "--depth",
            "1",
            "--quiet",
            "--no-recurse-submodules",
        ])
        // `--` stops git from treating a crafted URL as an option.
        .arg("--")
        .arg(url)
        .arg(dir.path())
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_LFS_SKIP_SMUDGE", "1")
        .env("GIT_ALLOW_PROTOCOL", "https:ssh")
        .output()
        .context("failed to run `git`; is it installed and on PATH?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git clone of {url} failed: {}", stderr.trim());
    }

    Ok(dir)
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
        let err = shallow_clone("http://example.invalid/repo").unwrap_err();
        assert!(err.to_string().contains("unencrypted"));
    }
}
