# contributing to repo-sniff

How to change repo-sniff: the build, commits, the rule format, fixtures and
the security rules every change must keep. repo-sniff is a security tool that
reads hostile code for a living, so a few rules here are stricter than in a
typical project; please read the whole page before opening a pull request.

## ground rules

- **The scanner never executes code from the scanned repository.** No
  install, no build, no scripts, no `eval` of anything it reads. It only
  reads files.
- **No real malware in this repository.** Not in fixtures, not in
  examples, not "just for a test". See [fixtures](#fixtures).
- **Every detection is documented.** A rule is not done until it has a row in
  the table and a section of its own in
  [docs/DETECTIONS.md](docs/DETECTIONS.md#2-rules-at-a-glance).

## development

Requirements: a stable Rust toolchain and `git`. The workspace has two
crates:

- `crates/repo-sniff-core`: the scanning engine. It never prints and has no
  terminal or UI dependencies.
- `crates/repo-sniff`: the binary (CLI now, TUI later).

Before every commit, the same checks CI runs on Linux, Windows and macOS must
pass:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## commits and pull requests

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

## review findings

Every rule family gets an independent review pass, of its plan and fixtures
before the rules are written and of its diff before it is merged. Findings that block the change
are fixed in the same pull request. New, smaller findings (hardening ideas,
extra evasion cases, nits) are not folded into it: each becomes a GitHub
issue with the `hardening` label, so the pull request stays reviewable and
nothing is lost.

## adding a rule

Rules are TOML files in `crates/repo-sniff-core/rules/`, one per stage. A
line rule from `repo.toml`, shortened:

```toml
[[rule]]
id          = "repo.wsh-javascript"   # <stage>.<short-name>, unique
engine      = "line-regex"            # how the rule matches (see below)
family      = "repository-contents"   # groups related rules
stage       = "repo"                  # repo, ide, deps, build, tests, run, deception, obfuscation
severity    = "medium"                # info, low, medium, high, critical
attack      = ["T1059.007"]           # MITRE ATT&CK IDs, may be empty
description = "Why this is suspicious, in plain words"
example     = 'run.js:3 calls WScript.CreateObject("WScript.Shell")'
pattern     = '''\b(?:WScript|WSH)\s*\.'''
files       = ["**/*.js"]             # optional for line rules; omitted means every file
```

Engines:

- `line-regex` matches the `pattern` against each line of a text file. A new
  pattern needs no Rust code.
- `jsonc`, `file` and `head` are Rust checks with one signature,
  `fn(&Ctx) -> Vec<Hit>`, looked up by the rule id; the TOML entry carries
  the metadata and the file globs. `jsonc` parses a structured file, `file`
  sees one whole file as raw bytes (`files` is required), and `head` judges
  every entry by its name and first bytes (`files` is optional; only a `head`
  rule may set `names_executables = true`).
- `bidi-display` and `nul-byte` are run by the scanner itself for
  `deception.bidi-control` and `deception.nul-byte-in-script`.

Unknown fields, unknown stages, malformed ATT&CK IDs, invalid regexes and
duplicate IDs are rejected when the rules load, so `cargo test` catches them.
The `files` globs ignore case, because Windows and macOS file systems do.
Patterns use the [`regex`](https://docs.rs/regex) crate, which matches in
linear time; never add a regex engine with backtracking.

Workflow for a new family:

1. Open the pull request with the **fixtures first** (positive and negative,
   see below) so reviewers can agree on what should and should not match.
2. Add the rules and tests.
3. Add the rules to [docs/DETECTIONS.md](docs/DETECTIONS.md): a row in the
   table and a section each.

## fixtures

Fixtures live in `crates/repo-sniff-core/tests/fixtures/<family>/` with
`positive/` and `negative/` subdirectories. What the rules must report on
them goes in `crates/repo-sniff-core/tests/fixtures/<family>.expected.toml`,
beside the folder (inside it, the file would be scanned like a fixture).

The harness in `crates/repo-sniff-core/tests/fixture_expectations.rs` scans
the folder as one repository with the built-in rules and fails on any finding
that is not listed, on any listed one that is missing, on a positive fixture
without a finding and on a negative fixture with one, so a new family needs
that file and no test code of its own. The format is described at the top of
the harness:

```toml
files_scanned = 7                        # optional

[[finding]]
file     = "positive/commenting_out.c"   # relative to the folder, with /
line     = 3
rule     = "deception.bidi-control"
severity = "critical"
explanation_contains = "Trojan Source"   # optional
```

### storage format: fixtures are stored defanged

The fixtures imitate attacks, so a tool that greps a repository for attack
patterns would take this one for malware. They are therefore committed in a
harmless form and become real only in a temporary folder while a test runs:

- **Markers instead of words.** Words such tools react to are written as
  `{{NAME}}` (for example `{{EVAL}}({{ATOB}}(x))`). The dictionary is the
  `MARKERS` table in `crates/repo-sniff-core/tests/common/mod.rs`, the only
  place that knows the real words. A marker that is not in the table makes the
  test fail. A new family that needs new dangerous words adds them to that
  table in the same pull request.
- **Invisible characters** (bidi controls, LRM/RLM/ALM, line and paragraph
  separators, NEL, zero-width characters, soft hyphen, BOM) are markers named
  after the Unicode abbreviation (`{{RLO}}`, `{{PDI}}`, `{{LSEP}}`), listed in
  `CHAR_MARKERS`; materializing writes exactly that code point. A long
  generated line can be a generator marker such as `{{MIN_FUNCS_40}}`.
- **Names.** A folder whose real name starts with a dot is stored with `_`
  instead (`.vscode` as `_vscode`; the folders are listed in `DOT_DIRS`). A
  file that a scanner or an editor might run or load (`tasks.json`,
  `package.json`, `next.config.js`, `*.bat`, `*.ps1`, `*.pth`, every `*.json` and
  `*.jsonc`, and the other names and extensions in `needs_suffix`) is stored with the suffix
  `.fixture` (`tasks.json.fixture`).
- **Binary fixtures** and the ones generated in tests are not touched.
- `<family>.expected.toml` and `expectations.tsv` use the real paths.

Every test that scans fixtures first calls `common::materialize`, which copies
the stored tree to a temporary folder with the real names and the markers
replaced. Scanning a stored folder directly gives different results. The test
`the_stored_fixtures_and_the_demo_are_defanged` walks `tests/fixtures/` and
`docs/demo/` and fails, naming the file, on a written-out marker word, a
folder that starts with a dot or an executable file without `.fixture`. The
same applies to `docs/demo/`, which `docs/demo.tape` materializes before
scanning it.

The Python startup families scan each case on its own and keep their
`expectations.tsv` inside the folder with their own tests.

Rules for every fixture:

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

## cross-platform rules

repo-sniff runs on Linux, Windows and macOS, and CI tests all three.

- Work with paths only through `Path` / `PathBuf`; never build paths by
  concatenating strings with `/` or `\`.
- Paths shown in reports are **relative to the repository root** and use `/`
  as the separator on every OS, so reports and snapshots are identical
  everywhere.
- Line numbers must be correct for both `\n` and `\r\n` line endings.
- Do not depend on Unix-only tricks (such as `/dev/null`) without a
  cross-platform alternative; gate truly OS-specific tests with `#[cfg(...)]`.

## scanner security

The scanned repository may try to attack the scanner itself. These are design
guarantees (the ones that exist in the code have tests); none of them is a
promise of absolute safety, so never describe them as one. Changes must keep
them (full list in
[docs/DETECTIONS.md](docs/DETECTIONS.md#5-scanner-hardening)):

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
described in [SECURITY.md](SECURITY.md) instead of opening a public issue.
