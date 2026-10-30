//! Fetching remote repositories with the system `git` binary.

use std::process::Command;

use anyhow::{Context, Result, bail};
use tempfile::TempDir;

/// Shallow-clones `url` into a fresh temporary directory.
///
/// The returned `TempDir` deletes the checkout when it is dropped, so the
/// caller just has to keep it alive for as long as the scan runs.
///
/// The clone is locked down because we are fetching untrusted code:
/// - hooks are disabled, so neither our own nor any global hooks run;
/// - Git LFS smudge filters are skipped, so no extra downloads or filters run;
/// - submodules are not fetched (git's default, kept explicit here);
/// - credential prompts are disabled, so a private repo fails fast instead of hanging.
pub fn shallow_clone(url: &str) -> Result<TempDir> {
    let dir = tempfile::Builder::new()
        .prefix("repo-sniff-")
        .tempdir()
        .context("failed to create a temporary directory")?;

    let output = Command::new("git")
        .args(["-c", "core.hooksPath=/dev/null"])
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
        .output()
        .context("failed to run `git`; is it installed and on PATH?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git clone of {url} failed: {}", stderr.trim());
    }

    Ok(dir)
}
