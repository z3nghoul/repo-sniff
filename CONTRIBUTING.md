# Contributing to repo-sniff

Thanks for helping. repo-sniff is a security tool that reads hostile code
for a living, so a few rules here are stricter than in a typical project.
Please read the whole page before opening a pull request.

## Ground rules

- **The scanner never executes code from the scanned repository.** No
  install, no build, no scripts, no `eval` of anything it reads. It only
  reads files.
- **No real malware in this repository.** Not in fixtures, not in
  examples, not "just for a test". See [Fixtures](#fixtures).
- **Every detection is documented.** A rule is not done until its row in
  [docs/DETECTIONS.md](docs/DETECTIONS.md) has the rule ID filled in.

## Development

Requirements: a stable Rust toolchain and `git`.

Before every commit, all three must pass:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The workspace has two crates:

- `crates/repo-sniff-core`: the scanning engine. It never prints and has no
  terminal or UI dependencies.
- `crates/repo-sniff`: the binary (CLI now, TUI later).

## Commits and pull requests

- One logical change per commit: "add the npm lifecycle rule" and "add tests
  for it" are separate commits, a feature and an unrelated refactor never
  share one.
- [Conventional Commits](https://www.conventionalcommits.org/): `feat:`,
  `fix:`, `test:`, `docs:`, `refactor:`, `ci:`, `chore:`.
- The commit body explains **why** the change is needed, not only what it
  does.
- No empty or cosmetic-only commits.
- New detections come in **families** of 3 to 6 related rules: one family,
  one branch, one pull request.
- Tick the matching task in [ROADMAP.md](ROADMAP.md) in the commit that
  completes it.

## Review findings

A design or code review of a pull request can raise more than the pull
request needs. Findings that block the change are fixed in it. New, smaller
findings (hardening ideas, extra evasion cases, nits) are not folded into
the same pull request: file each as a GitHub issue with the `hardening`
label instead (`gh issue create --label hardening`), so the pull request
stays reviewable and nothing is lost.

## Adding a rule

Rules are TOML files in `crates/repo-sniff-core/rules/`:

```toml
[[rule]]
id          = "deception.bidi-control"   # <stage>.<short-name>, unique
engine      = "line-regex"               # how the rule matches (see below)
family      = "trojan-source"            # groups related rules
stage       = "deception"                # repo, ide, deps, build, tests, run, deception, obfuscation
severity    = "critical"                 # info, low, medium, high, critical
attack      = []                         # MITRE ATT&CK IDs, e.g. ["T1547.001"]
description = "Why this is suspicious, in plain words"
example     = "src/auth.rs:12 contains U+202E"
pattern     = '[\u{202A}-\u{202E}\u{2066}-\u{2069}]'
files       = ["*.rs"]                   # optional; omitted means every file
```

`engine = "line-regex"` matches a regular expression against each line and
needs a `pattern`. Other engines are added as the scanner grows.

Unknown fields, unknown stages, malformed ATT&CK IDs, invalid regexes and
duplicate IDs are rejected when the rules load, so `cargo test` catches them.

The `files` globs ignore case, because Windows and macOS file systems do.

Patterns use the [`regex`](https://docs.rs/regex) crate, which matches in
linear time; never add a regex engine with backtracking.

Workflow for a new family:

1. Open the pull request with the **fixtures first** (positive and negative,
   see below) so reviewers can agree on what should and should not match.
2. Add the rules and tests.
3. Fill in the Rule column in `docs/DETECTIONS.md`.

## Fixtures

Fixtures live in `crates/repo-sniff-core/tests/fixtures/<family>/` with
`positive/` and `negative/` subdirectories.

- **Every rule has both** positive fixtures (must match) and negative
  fixtures (look similar but must not match, e.g. a mention in a comment, an
  escaped form, a legitimate use).
- Every fixture file starts with a comment
  `SYNTHETIC TEST FIXTURE — not functional`.
- Fixtures **imitate** patterns, they never work: a file may contain the
  string `SetWindowsHookEx` but must not install a hook.
- **Domains:** only `example.com` / `example.org` / `example.net` (RFC 2606)
  and the `.invalid` TLD. Never a real domain or IP.
- **Payloads are harmless:** `echo hello`, `true`, a no-op function.
- **Tokens and keys are obviously fake:** `FAKE_DISCORD_TOKEN_FOR_TESTS`,
  never something shaped exactly like a live credential.
- **Binary fixtures are generated in tests, never committed.** A test that
  needs a PE header writes the magic bytes into a temporary file.
- **Strings that antivirus engines flag statically** (EICAR-like test
  strings, well-known tool names in signatures) are assembled in the test from
  pieces, so the repository itself never trips a scanner.
- **Real samples are never committed.** The real-sample suite reads them from
  the directory in the `REPO_SNIFF_REAL_SAMPLES` environment variable and is
  skipped when the variable is unset.
- Line endings in fixtures are preserved exactly (see `.gitattributes`);
  some rules depend on CRLF or on invisible characters.

## Cross-platform rules

repo-sniff runs on Linux, Windows and macOS, and CI tests all three.

- Work with paths only through `Path` / `PathBuf`; never build paths by
  concatenating strings with `/` or `\`.
- Paths shown in reports are **relative to the repository root** and use `/`
  as the separator on every OS, so reports and snapshots are identical
  everywhere.
- Line numbers must be correct for both `\n` and `\r\n` line endings.
- Do not depend on Unix-only tricks (such as `/dev/null`) without a
  cross-platform alternative; gate truly OS-specific tests with `#[cfg(...)]`.

## Scanner security

The scanned repository may try to attack the scanner itself. These are design
guarantees (the ones that exist in the code have tests); none of them is a
promise of absolute safety, so never describe them as one. Changes must keep
them (full list in
[docs/DETECTIONS.md](docs/DETECTIONS.md#5-additional-requirements)):

- symlinks are never followed;
- file size, file count and decoding depth are limited, and every skipped
  file is reported;
- archives are flagged, never unpacked;
- remote repositories are cloned over https only, by a git that runs with an
  empty environment, an empty configuration and an empty home directory (so
  no filter, credential helper or fsmonitor from any configuration runs),
  with hooks and templates off, symlinks written as plain files, submodules
  not fetched and no interactive prompts;
- credentials in a URL are hidden in everything that is printed;
- an inconclusive scan (file limit reached, a file not read, an executable
  binary that no rule reported) is never reported as clean;
- nothing from the scanned repository (locales, configuration, rules) can
  silently change what the report shows: the scanner never loads locales or
  rules from it, and any exclusions it declares are surfaced in the report,
  never applied invisibly.

Found a vulnerability in repo-sniff itself? Please report it privately as
described in `SECURITY.md` instead of opening a public issue.
