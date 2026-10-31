//! Fetching remote repositories with the system `git` binary.
//!
//! The repository being fetched is untrusted, and so is everything on the
//! machine that git would normally read to decide what to run: the user's and
//! the system's git configuration, environment variables such as
//! `GIT_CONFIG_COUNT`, and templates. A configuration that defines a smudge
//! filter, a credential helper or an fsmonitor would turn a plain checkout
//! into code execution. So git is started with an empty environment plus a
//! short list of variables it needs, with its configuration files replaced
//! by an empty one, and with the risky settings overridden on the command line.

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use repo_sniff_core::display_safe;
use tempfile::TempDir;

/// URL schemes that send the repository over the network unencrypted.
const PLAIN_TEXT_SCHEMES: &[&str] = &["http://", "git://"];

/// Transports git may use for a clone: https only. ssh would need the user's
/// keys and agent, which the isolated environment deliberately does not have.
const ALLOWED_PROTOCOLS: &str = "https";

/// Error text from a git server is chosen by whoever runs the server, so it
/// is cleaned and cut before it is shown.
const MAX_GIT_ERROR_CHARS: usize = 500;

/// The only variables copied from our environment into git's. They are what
/// git needs to find itself, a home directory, a temporary directory, to open
/// sockets on Windows, to reach the network through a proxy, and to verify
/// certificates. Everything else (`GIT_*`, `SSH_*`, tokens, ...) is dropped.
const PASS_THROUGH: &[&str] = &[
    "PATH",
    "HOME",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "TMPDIR",
    "TMP",
    "TEMP",
    "SYSTEMROOT",
    "SystemRoot",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CURL_CA_BUNDLE",
];

/// Shallow-clones `url` into a fresh temporary directory, at `git_ref` (a
/// branch or tag) or at the repository's default branch.
///
/// The returned `TempDir` deletes the checkout when it is dropped, so the
/// caller just has to keep it alive for as long as the scan runs.
///
/// What this does to keep the clone from running anything:
/// - only `https://` URLs are accepted (see `ensure_https_only`);
/// - git runs with a minimal environment and with its user and system
///   configuration replaced by an empty file, so no filter, credential
///   helper, fsmonitor or alias defined there is used, and no variable such as
///   `GIT_CONFIG_COUNT` reaches it;
/// - hooks and templates are disabled, symlinks are written as plain files,
///   submodules are not fetched, objects are checked for corruption;
/// - there are no interactive prompts.
pub fn shallow_clone(url: &str, git_ref: Option<&str>) -> Result<TempDir> {
    ensure_https_only(url)?;
    if let Some(git_ref) = git_ref {
        validate_ref(git_ref)?;
    }
    clone_unchecked(url, git_ref, ALLOWED_PROTOCOLS, |name| {
        std::env::var_os(name)
    })
}

/// The clone itself, without looking at the URL. `protocols` is the list of
/// transports git may use and `env` is where the environment is read from;
/// tests use both to clone a local repository with a made-up environment.
fn clone_unchecked(
    url: &str,
    git_ref: Option<&str>,
    protocols: &str,
    env: impl Fn(&str) -> Option<OsString>,
) -> Result<TempDir> {
    let dir = tempfile::Builder::new()
        .prefix("repo-sniff-")
        .tempdir()
        .context("failed to create a temporary directory")?;

    // Holds what git is pointed at instead of the real configuration: an
    // empty directory for hooks and an empty configuration file.
    let sandbox = tempfile::Builder::new()
        .prefix("repo-sniff-git-")
        .tempdir()
        .context("failed to create a temporary directory")?;
    let hooks_dir = sandbox.path().join("hooks");
    let global_config = sandbox.path().join("gitconfig");
    fs::create_dir(&hooks_dir).context("failed to prepare the git sandbox")?;
    fs::write(&global_config, "").context("failed to prepare the git sandbox")?;

    let output = Command::new("git")
        .env_clear()
        .envs(git_environment(env, &global_config, protocols))
        .args(clone_args(url, git_ref, dir.path(), &hooks_dir))
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

/// The environment git runs in: the allowed variables from `source`, plus the
/// settings that isolate it from the machine's configuration.
fn git_environment(
    source: impl Fn(&str) -> Option<OsString>,
    global_config: &Path,
    protocols: &str,
) -> Vec<(OsString, OsString)> {
    let mut vars: Vec<(OsString, OsString)> = PASS_THROUGH
        .iter()
        .filter_map(|&name| source(name).map(|value| (name.into(), value)))
        .collect();

    let fixed: [(&str, OsString); 6] = [
        // Skip the system-wide configuration file.
        ("GIT_CONFIG_NOSYSTEM", "1".into()),
        // Read this (empty) file instead of ~/.gitconfig and the XDG file.
        ("GIT_CONFIG_GLOBAL", global_config.into()),
        ("GIT_ALLOW_PROTOCOL", protocols.into()),
        // Never ask a question: fail instead.
        ("GIT_TERMINAL_PROMPT", "0".into()),
        ("GCM_INTERACTIVE", "never".into()),
        ("GIT_LFS_SKIP_SMUDGE", "1".into()),
    ];
    vars.extend(fixed.into_iter().map(|(name, value)| (name.into(), value)));
    vars
}

/// The arguments passed to `git`, in order. Kept separate from running the
/// command so that the safety-relevant parts can be tested without a network.
fn clone_args(url: &str, git_ref: Option<&str>, dest: &Path, hooks_dir: &Path) -> Vec<OsString> {
    let mut hooks_config = OsString::from("core.hooksPath=");
    hooks_config.push(hooks_dir);

    let mut args: Vec<OsString> = Vec::new();
    // Settings that are overridden whatever any configuration says. An empty
    // `credential.helper` clears the list of helpers.
    for setting in [
        hooks_config,
        "credential.helper=".into(),
        "core.symlinks=false".into(),
        "core.fsmonitor=false".into(),
        "transfer.fsckObjects=true".into(),
        "submodule.recurse=false".into(),
    ] {
        args.push("-c".into());
        args.push(setting);
    }
    args.extend(
        [
            "clone",
            "--depth=1",
            "--single-branch",
            "--no-tags",
            "--no-recurse-submodules",
            // An empty template directory: no hooks or info files are copied in.
            "--template=",
            "--quiet",
        ]
        .map(OsString::from),
    );
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

/// Accepts only `https://` URLs.
///
/// Plain-text transports are refused because anyone on the network could alter
/// the code being scanned. ssh is not supported at all: it would use the
/// user's keys, and a private repository is better cloned by its owner, who
/// then scans the folder. The messages say so instead of just refusing.
fn ensure_https_only(url: &str) -> Result<()> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return Ok(());
    }
    if let Some(scheme) = PLAIN_TEXT_SCHEMES
        .iter()
        .find(|scheme| lower.starts_with(**scheme))
    {
        bail!(
            "refusing to clone over unencrypted {scheme}: anyone on the network could \
             alter the code being scanned. Use an https:// URL instead"
        );
    }
    if lower.starts_with("ssh://") || lower.starts_with("git@") {
        bail!(
            "ssh targets are not supported: repo-sniff fetches over https only. To scan a \
             private or ssh-only repository, clone it yourself and scan the folder:\n  \
             git clone <url> some-folder\n  repo-sniff scan some-folder"
        );
    }
    bail!("unsupported URL: only https:// repositories can be cloned; scan a local folder instead")
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

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

    fn env_of(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let map: HashMap<String, OsString> = vars
            .iter()
            .map(|&(name, value)| (name.to_string(), value.into()))
            .collect();
        move |name| map.get(name).cloned()
    }

    fn environment(vars: &[(&str, &str)]) -> HashMap<String, String> {
        git_environment(env_of(vars), Path::new("/empty-config"), "https")
            .into_iter()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.to_string_lossy().into_owned(),
                )
            })
            .collect()
    }

    #[test]
    fn plain_text_urls_are_rejected() {
        for url in [
            "http://github.com/owner/repo",
            "git://github.com/owner/repo.git",
            "HTTP://github.com/owner/repo",
        ] {
            let err = ensure_https_only(url).unwrap_err();
            assert!(err.to_string().contains("unencrypted"), "{url}: {err}");
        }
    }

    #[test]
    fn ssh_urls_are_rejected_with_advice_to_clone_locally() {
        for url in [
            "ssh://git@github.com/owner/repo.git",
            "git@github.com:owner/repo.git",
            "SSH://git@github.com/owner/repo.git",
        ] {
            let message = ensure_https_only(url).unwrap_err().to_string();
            assert!(
                message.contains("ssh targets are not supported"),
                "{url}: {message}"
            );
            assert!(message.contains("clone it yourself"), "{url}: {message}");
            assert!(
                message.contains("repo-sniff scan some-folder"),
                "{url}: {message}"
            );
        }
    }

    #[test]
    fn only_https_urls_are_accepted() {
        for url in [
            "https://github.com/owner/repo",
            "HTTPS://github.com/owner/repo",
        ] {
            ensure_https_only(url).unwrap();
        }
        for url in [
            "ftp://example.invalid/repo",
            "file:///tmp/repo",
            "/tmp/repo",
            "owner/repo",
        ] {
            let message = ensure_https_only(url).unwrap_err().to_string();
            assert!(message.contains("only https://"), "{url}: {message}");
        }
    }

    #[test]
    fn git_may_use_https_only() {
        assert_eq!(ALLOWED_PROTOCOLS, "https");
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
    fn risky_settings_are_overridden_before_the_clone_command() {
        let args = args_as_strings(None);
        let clone = args.iter().position(|a| a == "clone").unwrap();
        let overrides: Vec<&str> = args[..clone]
            .chunks(2)
            .map(|pair| {
                assert_eq!(pair[0], "-c");
                pair[1].as_str()
            })
            .collect();
        assert_eq!(
            overrides,
            [
                "core.hooksPath=/hooks",
                "credential.helper=",
                "core.symlinks=false",
                "core.fsmonitor=false",
                "transfer.fsckObjects=true",
                "submodule.recurse=false",
            ]
        );
    }

    #[test]
    fn clone_is_shallow_single_branch_without_tags_templates_or_submodules() {
        let args = args_as_strings(None);
        for expected in [
            "--depth=1",
            "--single-branch",
            "--no-tags",
            "--no-recurse-submodules",
            "--template=",
        ] {
            assert!(
                args.iter().any(|a| a == expected),
                "{expected} missing in {args:?}"
            );
        }
    }

    #[test]
    fn only_the_listed_variables_reach_git() {
        let env = environment(&[
            ("PATH", "/usr/bin"),
            ("HOME", "/home/user"),
            ("HTTPS_PROXY", "http://proxy.invalid:3128"),
            ("SSL_CERT_FILE", "/etc/ssl/cert.pem"),
            ("SYSTEMROOT", "C:\\Windows"),
            ("GIT_CONFIG_COUNT", "1"),
            ("GIT_CONFIG_KEY_0", "filter.evil.smudge"),
            ("GIT_CONFIG_VALUE_0", "touch x"),
            ("GIT_SSH_COMMAND", "sh -c evil"),
            ("GIT_EXEC_PATH", "/tmp/evil"),
            ("GITHUB_TOKEN", "FAKE_TOKEN_FOR_TESTS"),
            ("SSH_AUTH_SOCK", "/tmp/agent"),
            ("LD_PRELOAD", "/tmp/evil.so"),
        ]);

        for kept in ["PATH", "HOME", "HTTPS_PROXY", "SSL_CERT_FILE", "SYSTEMROOT"] {
            assert!(env.contains_key(kept), "{kept} should be passed on");
        }
        for dropped in [
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_KEY_0",
            "GIT_CONFIG_VALUE_0",
            "GIT_SSH_COMMAND",
            "GIT_EXEC_PATH",
            "GITHUB_TOKEN",
            "SSH_AUTH_SOCK",
            "LD_PRELOAD",
        ] {
            assert!(!env.contains_key(dropped), "{dropped} must not reach git");
        }
    }

    #[test]
    fn isolation_variables_are_always_set() {
        let env = environment(&[]);
        assert_eq!(env["GIT_CONFIG_NOSYSTEM"], "1");
        assert_eq!(env["GIT_CONFIG_GLOBAL"], "/empty-config");
        assert_eq!(env["GIT_ALLOW_PROTOCOL"], "https");
        assert_eq!(env["GIT_TERMINAL_PROMPT"], "0");
        assert_eq!(env["GCM_INTERACTIVE"], "never");
    }

    #[test]
    fn isolation_variables_cannot_be_overridden_from_outside() {
        let env = environment(&[
            ("GIT_CONFIG_GLOBAL", "/home/user/.gitconfig"),
            ("GIT_CONFIG_NOSYSTEM", "0"),
            ("GIT_TERMINAL_PROMPT", "1"),
        ]);
        assert_eq!(env["GIT_CONFIG_GLOBAL"], "/empty-config");
        assert_eq!(env["GIT_CONFIG_NOSYSTEM"], "1");
        assert_eq!(env["GIT_TERMINAL_PROMPT"], "0");
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

    // ---- real clones of a local repository ---------------------------------
    //
    // These run the real `git`. The repository they clone declares a smudge
    // filter in `.gitattributes`; whether the filter is *defined* depends on
    // the configuration that git can see, which is exactly what must not
    // matter. Each test first shows that the filter does run when git can see
    // its definition, so a pass cannot come from a broken setup.

    const MARKER: &str = "SMUDGE_RAN";
    /// A filter that passes the content through and leaves a marker file in
    /// the working tree (filters run in its root).
    const FILTER_DEFINITION: &str = "cat; touch SMUDGE_RAN";

    /// A plain `git` command that ignores the machine's own configuration.
    fn plain_git(dir: &Path) -> Command {
        let mut command = Command::new("git");
        command
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", dir.join("nonexistent-config"))
            .args([
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.invalid",
            ]);
        command
    }

    fn run(mut command: Command) -> String {
        let output = command.output().expect("git is required for these tests");
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    /// `file:///path` for a local directory, also on Windows.
    fn file_url(path: &Path) -> String {
        let text = path.to_string_lossy().replace('\\', "/");
        if text.starts_with('/') {
            format!("file://{text}")
        } else {
            format!("file:///{text}")
        }
    }

    /// A repository with a file that has the smudge filter attribute, plus a
    /// symlink entry (written into the index directly, so it works on every OS).
    fn source_repository() -> TempDir {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        let mut init = plain_git(path);
        init.args(["init", "-q", "-b", "main"]);
        run(init);
        fs::write(path.join(".gitattributes"), "* filter=evil\n").unwrap();
        fs::write(path.join("file.txt"), "hello\n").unwrap();

        let mut hash = plain_git(path);
        hash.args(["hash-object", "-w", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped());
        let mut child = hash.spawn().unwrap();
        std::io::Write::write_all(child.stdin.as_mut().unwrap(), b"file.txt").unwrap();
        let blob = String::from_utf8(child.wait_with_output().unwrap().stdout)
            .unwrap()
            .trim()
            .to_string();
        let mut link = plain_git(path);
        link.args([
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("120000,{blob},link"),
        ]);
        run(link);

        let mut add = plain_git(path);
        add.args(["add", ".gitattributes", "file.txt"]);
        run(add);
        let mut commit = plain_git(path);
        commit.args(["commit", "-q", "-m", "fixture"]);
        run(commit);
        dir
    }

    /// Writes a global configuration that defines the filter, in a fresh
    /// "home" directory, and returns the directory.
    fn home_with_filter() -> TempDir {
        let home = tempfile::tempdir().unwrap();
        fs::write(
            home.path().join(".gitconfig"),
            // Quoted: in a git config file an unquoted `;` starts a comment.
            format!("[filter \"evil\"]\n\tsmudge = \"{FILTER_DEFINITION}\"\n"),
        )
        .unwrap();
        home
    }

    /// Clones `source` with plain git while it can see `config` as its
    /// global configuration, and says whether the filter ran.
    fn filter_runs_when_visible(source: &Path, config: &Path) -> bool {
        let target = tempfile::tempdir().unwrap();
        let mut command = Command::new("git");
        command
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", config)
            .env("GIT_ALLOW_PROTOCOL", "file")
            .args(["clone", "-q", &file_url(source)])
            .arg(target.path().join("out"));
        run(command);
        target.path().join("out").join(MARKER).exists()
    }

    fn pass_through_all() -> impl Fn(&str) -> Option<OsString> {
        |name| std::env::var_os(name)
    }

    #[test]
    fn a_global_smudge_filter_in_the_users_home_does_not_run() {
        let source = source_repository();
        let home = home_with_filter();
        assert!(
            filter_runs_when_visible(source.path(), &home.path().join(".gitconfig")),
            "setup is broken: the filter should run when git can see it"
        );

        let home_path = home.path().to_string_lossy().into_owned();
        let env = move |name: &str| match name {
            "HOME" | "USERPROFILE" => Some(OsString::from(&home_path)),
            other => std::env::var_os(other),
        };
        let checkout = clone_unchecked(&file_url(source.path()), None, "file", env).unwrap();

        assert!(checkout.path().join("file.txt").exists());
        assert!(
            !checkout.path().join(MARKER).exists(),
            "the filter from the home directory ran"
        );
    }

    #[test]
    fn a_filter_set_through_git_config_count_variables_has_no_effect() {
        let source = source_repository();
        let config = tempfile::tempdir().unwrap();
        let empty = config.path().join("gitconfig");
        fs::write(&empty, "").unwrap();

        // Control: the same three variables do define the filter for plain git.
        let control = tempfile::tempdir().unwrap();
        let mut command = Command::new("git");
        command
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", &empty)
            .env("GIT_ALLOW_PROTOCOL", "file")
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "filter.evil.smudge")
            .env("GIT_CONFIG_VALUE_0", FILTER_DEFINITION)
            .args(["clone", "-q", &file_url(source.path())])
            .arg(control.path().join("out"));
        run(command);
        assert!(
            control.path().join("out").join(MARKER).exists(),
            "setup is broken: the variables should define the filter for plain git"
        );

        let env = |name: &str| match name {
            "GIT_CONFIG_COUNT" => Some(OsString::from("1")),
            "GIT_CONFIG_KEY_0" => Some(OsString::from("filter.evil.smudge")),
            "GIT_CONFIG_VALUE_0" => Some(OsString::from(FILTER_DEFINITION)),
            other => std::env::var_os(other),
        };
        let checkout = clone_unchecked(&file_url(source.path()), None, "file", env).unwrap();

        assert!(checkout.path().join("file.txt").exists());
        assert!(
            !checkout.path().join(MARKER).exists(),
            "the filter from GIT_CONFIG_COUNT ran"
        );
    }

    #[test]
    fn a_symlink_in_the_repository_is_checked_out_as_a_plain_file() {
        let source = source_repository();

        let checkout =
            clone_unchecked(&file_url(source.path()), None, "file", pass_through_all()).unwrap();

        let link = checkout.path().join("link");
        let metadata = fs::symlink_metadata(&link).unwrap();
        assert!(metadata.is_file(), "link should be a regular file");
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(fs::read_to_string(&link).unwrap(), "file.txt");
    }

    #[test]
    fn the_checkout_has_no_hooks_or_templates() {
        let source = source_repository();

        let checkout =
            clone_unchecked(&file_url(source.path()), None, "file", pass_through_all()).unwrap();

        let hooks: PathBuf = checkout.path().join(".git").join("hooks");
        let entries = fs::read_dir(&hooks).map(|d| d.count()).unwrap_or(0);
        assert_eq!(
            entries, 0,
            "no hook or sample should be copied from a template"
        );
    }
}
