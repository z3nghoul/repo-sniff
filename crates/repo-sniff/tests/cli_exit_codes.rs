//! The process exit status: 0 clean, 1 findings at or above `--fail-on`,
//! 2 when the scan could not run.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn core_fixtures(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../repo-sniff-core/tests/fixtures")
        .join(name)
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_repo-sniff"))
        .current_dir(dir)
        .args(args)
        .output()
        .expect("failed to run repo-sniff")
}

fn code(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("process was not killed by a signal")
}

/// A directory whose only finding is HIGH: an auto-run VS Code task.
fn high_only_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let vscode = dir.path().join(".vscode");
    fs::create_dir(&vscode).unwrap();
    fs::write(
        vscode.join("tasks.json"),
        r#"{"tasks":[{"label":"x","command":"make","runOptions":{"runOn":"folderOpen"}}]}"#,
    )
    .unwrap();
    dir
}

#[test]
fn clean_directory_exits_zero() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();

    assert_eq!(code(&run(dir.path(), &["scan", "."])), 0);
}

#[test]
fn default_threshold_is_high() {
    let dir = high_only_dir();

    assert_eq!(code(&run(dir.path(), &["scan", "."])), 1);
}

#[test]
fn threshold_above_every_finding_exits_zero() {
    let dir = high_only_dir();

    assert_eq!(
        code(&run(dir.path(), &["scan", ".", "--fail-on", "critical"])),
        0
    );
}

#[test]
fn threshold_at_or_below_a_finding_exits_one() {
    let dir = high_only_dir();

    assert_eq!(
        code(&run(dir.path(), &["scan", ".", "--fail-on", "high"])),
        1
    );
    assert_eq!(
        code(&run(dir.path(), &["scan", ".", "--fail-on", "LOW"])),
        1
    );
}

#[test]
fn critical_findings_fail_at_the_critical_threshold() {
    let output = run(
        &core_fixtures("trojan-source"),
        &["scan", ".", "--fail-on", "critical"],
    );

    assert_eq!(code(&output), 1);
}

#[test]
fn none_never_fails_because_of_findings() {
    let output = run(
        &core_fixtures("trojan-source"),
        &["scan", ".", "--fail-on", "none"],
    );

    assert_eq!(code(&output), 0);
    // The report is still printed.
    assert!(String::from_utf8_lossy(&output.stdout).contains("CRITICAL"));
}

#[test]
fn unknown_threshold_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();

    let output = run(dir.path(), &["scan", ".", "--fail-on", "urgent"]);

    assert_eq!(code(&output), 2);
    assert!(String::from_utf8_lossy(&output.stderr).contains("`urgent`"));
}

#[test]
fn missing_target_is_a_runtime_error() {
    let dir = tempfile::tempdir().unwrap();

    let output = run(dir.path(), &["scan", "no-such-directory"]);

    assert_eq!(code(&output), 2);
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot access"));
}

#[test]
fn ref_with_a_local_directory_is_a_runtime_error() {
    let dir = tempfile::tempdir().unwrap();

    let output = run(dir.path(), &["scan", ".", "--ref", "main"]);

    assert_eq!(code(&output), 2);
    assert!(String::from_utf8_lossy(&output.stderr).contains("remote repository"));
}

#[test]
fn option_like_ref_is_rejected_before_any_network_access() {
    let dir = tempfile::tempdir().unwrap();

    // `=` keeps clap from reading the value as a flag of its own.
    let output = run(
        dir.path(),
        &[
            "scan",
            "https://example.invalid/repo",
            "--ref=--upload-pack=x",
        ],
    );

    assert_eq!(code(&output), 2);
    assert!(String::from_utf8_lossy(&output.stderr).contains("--ref must not start with"));
}

#[test]
fn ssh_targets_are_a_runtime_error_that_explains_how_to_scan_a_local_clone() {
    let dir = tempfile::tempdir().unwrap();

    for target in [
        "ssh://git@example.invalid/owner/repo.git",
        "git@example.invalid:owner/repo.git",
        // Any user, not only `git`, and never repeated with its token (#32).
        "deploy:FAKE_TOKEN@example.invalid:owner/repo.git",
    ] {
        let output = run(dir.path(), &["scan", target]);

        assert_eq!(code(&output), 2, "{target}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("FAKE_TOKEN"), "{stderr}");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("FAKE_TOKEN"));
        assert!(stderr.contains("ssh targets are not supported"), "{stderr}");
        assert!(stderr.contains("repo-sniff scan some-folder"), "{stderr}");
        assert!(
            !stderr.contains("Cloning"),
            "a refused target must not be announced: {stderr}"
        );
    }
}

/// A clone that fails at the name lookup (`.invalid` never resolves), so no
/// network is needed. Whatever happens, the token must not be printed.
#[test]
fn credentials_in_the_target_never_reach_stdout_or_stderr() {
    let dir = tempfile::tempdir().unwrap();

    for target in [
        "https://TOKEN123@example.invalid/owner/repo",
        "https://user:SECRET456@example.invalid/owner/repo.git",
    ] {
        let output = run(dir.path(), &["scan", target]);

        assert_eq!(code(&output), 2, "{target}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        for secret in ["TOKEN123", "SECRET456", "user:"] {
            assert!(!stdout.contains(secret), "{secret} in stdout: {stdout}");
            assert!(!stderr.contains(secret), "{secret} in stderr: {stderr}");
        }
        assert!(
            stderr.contains("Cloning https://***@example.invalid/owner/repo"),
            "{stderr}"
        );
        assert!(
            stderr.contains("git clone of https://***@example.invalid/owner/repo"),
            "{stderr}"
        );
    }
}

/// Targets that curl would read differently from the redaction, or that are
/// URLs with credentials but do not look like one. None of them may reach
/// git (no "Cloning" notice) or be printed. The proxy variables are removed so
/// that nothing could be sent anywhere if the check failed.
#[test]
fn ambiguous_and_scheme_less_credentials_never_reach_stdout_or_stderr() {
    let dir = tempfile::tempdir().unwrap();

    for target in [
        // A user name or password with an unescaped `#`, `?` or `/` (#31).
        "https://user:PART1#PART2@example.invalid/owner/repo",
        "https://FAKE_TOKEN#x@example.invalid/r",
        "https://FAKE_TOKEN?x@example.invalid/r",
        "https://FAKE_TOKEN/x@example.invalid/r",
        "https://user:FAKE TOKEN@example.invalid/r",
        "https://user:FAKE'TOKEN@example.invalid/r",
        "https://user:FAKE\"TOKEN@example.invalid/r",
        "https://user:FAKE`TOKEN@example.invalid/r",
        "https://user:FAKE<TOKEN@example.invalid/r",
        "FAKE_TOKEN@example.invalid/o/r",
        "user:FAKE_TOKEN@example.invalid/o/r",
        "deploy:FAKE_TOKEN@:o/r",
        "https:/user:FAKE_TOKEN@example.invalid/r",
        "https:\\\\user:FAKE_TOKEN@example.invalid\\r",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_repo-sniff"))
            .current_dir(dir.path())
            .args(["scan", target])
            .env_remove("HTTPS_PROXY")
            .env_remove("https_proxy")
            .env_remove("HTTP_PROXY")
            .env_remove("http_proxy")
            .env_remove("ALL_PROXY")
            .env_remove("all_proxy")
            .output()
            .expect("failed to run repo-sniff");

        assert_eq!(code(&output), 2, "{target}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        for secret in ["FAKE", "TOKEN", "PART1", "PART2"] {
            assert!(!stdout.contains(secret), "{target}: {stdout}");
            assert!(!stderr.contains(secret), "{target}: {stderr}");
        }
        assert!(!stderr.contains("Cloning"), "{target}: {stderr}");
    }
}

#[test]
fn credentials_in_a_refused_target_are_not_repeated() {
    let dir = tempfile::tempdir().unwrap();

    let output = run(
        dir.path(),
        &["scan", "http://TOKEN789@example.invalid/owner/repo"],
    );

    assert_eq!(code(&output), 2);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("TOKEN789"));
}

/// Source next to the kind of compressed and image files a normal repository
/// keeps as test data. They are binary (they contain NUL bytes), they were
/// read, and no rule looks inside them.
fn clean_dir_with_compressed_test_files() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();
    fs::create_dir(dir.path().join("data")).unwrap();
    fs::write(
        dir.path().join("data/a.gz"),
        [0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 3],
    )
    .unwrap();
    fs::write(
        dir.path().join("data/b.zst"),
        [0x28, 0xB5, 0x2F, 0xFD, 0, 0, 0, 0],
    )
    .unwrap();
    fs::write(
        dir.path().join("data/c.png"),
        b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR",
    )
    .unwrap();
    dir
}

/// Source next to a file that starts with the given executable header. It is
/// not a working program: only its first bytes are real.
fn clean_dir_with_executable(header: &[u8]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();
    let mut bytes = header.to_vec();
    bytes.extend([0u8; 16]);
    fs::write(dir.path().join("tool"), bytes).unwrap();
    dir
}

/// Source next to a vendored repository with its own `.git` folder, which the
/// scan does not read, so the scan is inconclusive.
fn clean_dir_with_nested_git() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();
    fs::create_dir_all(dir.path().join("vendor/lib/.git")).unwrap();
    fs::write(
        dir.path().join("vendor/lib/.git/HEAD"),
        "ref: refs/heads/main\n",
    )
    .unwrap();
    dir
}

#[test]
fn compressed_test_files_are_listed_but_do_not_change_the_exit_status() {
    let dir = clean_dir_with_compressed_test_files();

    let output = run(dir.path(), &["scan", "."]);

    assert_eq!(code(&output), 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Not fully analyzed (3): 3 binary"),
        "{stdout}"
    );
    assert!(
        stdout.contains("data/a.gz  binary format, ASCII rules only"),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "Scan: complete (every file was read; 3 binary files were read as ASCII only)"
        ),
        "{stdout}"
    );
    assert!(!stdout.contains("INCONCLUSIVE"), "{stdout}");
}

#[test]
fn an_elf_file_is_a_finding_and_still_listed() {
    let dir = clean_dir_with_executable(b"\x7fELF\x02\x01\x01\0");

    let output = run(dir.path(), &["scan", "."]);

    assert_eq!(code(&output), 1);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("HIGH      tool:1  repo.committed-binary"),
        "{stdout}"
    );
    assert!(
        stdout.contains("tool  executable binary (ELF), reported above, its code not analyzed"),
        "{stdout}"
    );
    assert!(
        stdout.contains("1 executable binaries are reported as findings"),
        "{stdout}"
    );
    assert!(!stdout.contains("INCONCLUSIVE"), "{stdout}");
}

#[test]
fn every_executable_format_is_a_high_finding_instead_of_an_inconclusive_scan() {
    for (name, header) in [
        ("PE", &b"MZ\x90\0\x03\0\0\0"[..]),
        ("Mach-O 32-bit", &[0xFE, 0xED, 0xFA, 0xCE][..]),
        ("Mach-O 64-bit", &[0xCF, 0xFA, 0xED, 0xFE][..]),
        ("Mach-O fat", &[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2][..]),
    ] {
        let dir = clean_dir_with_executable(header);

        // HIGH: a non-pass at the default threshold, as the inconclusive scan
        // was. Above it, the finding is shown but no longer fails the scan.
        assert_eq!(code(&run(dir.path(), &["scan", "."])), 1, "{name}");
        let above = ["scan", ".", "--fail-on", "critical"];
        assert_eq!(code(&run(dir.path(), &above)), 0, "{name}");
    }
}

#[test]
fn an_oversized_file_makes_the_scan_inconclusive() {
    let dir = tempfile::tempdir().unwrap();
    // Just over the 100 MiB limit; set_len makes the file without writing it.
    let big = fs::File::create(dir.path().join("big.txt")).unwrap();
    big.set_len(100 * 1024 * 1024 + 1).unwrap();

    let output = run(dir.path(), &["scan", "."]);

    assert_eq!(code(&output), 3);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("1 too large"), "{stdout}");
    assert!(
        stdout.contains("1 files could not be read (too large or unreadable)"),
        "{stdout}"
    );
}

#[test]
fn a_file_over_5_mib_is_read_as_a_stream_and_the_scan_stays_complete() {
    let dir = tempfile::tempdir().unwrap();
    let line = "an ordinary line of a large fixture\n";
    let text = line.repeat(6 * 1024 * 1024 / line.len() + 1);
    fs::write(dir.path().join("fixture.txt"), text).unwrap();

    let output = run(dir.path(), &["scan", "."]);

    assert_eq!(code(&output), 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Scan: complete"), "{stdout}");
}

#[test]
fn findings_at_the_threshold_win_over_an_inconclusive_scan() {
    let dir = high_only_dir();
    fs::create_dir_all(dir.path().join("vendor/lib/.git")).unwrap();

    assert_eq!(code(&run(dir.path(), &["scan", "."])), 1);
}

#[test]
fn fail_on_none_does_not_turn_an_inconclusive_scan_into_a_pass() {
    let dir = clean_dir_with_nested_git();

    assert_eq!(
        code(&run(dir.path(), &["scan", ".", "--fail-on", "none"])),
        3
    );
}

#[test]
fn fail_on_none_with_a_complete_scan_exits_zero() {
    let dir = clean_dir_with_compressed_test_files();

    assert_eq!(
        code(&run(dir.path(), &["scan", ".", "--fail-on", "none"])),
        0
    );
}

#[test]
fn a_complete_scan_says_so_and_exits_zero() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();

    let output = run(dir.path(), &["scan", "."]);

    assert_eq!(code(&output), 0);
    assert!(String::from_utf8_lossy(&output.stdout).contains("Scan: complete"));
}
