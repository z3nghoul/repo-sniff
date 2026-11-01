# Roadmap

Every task is ticked in the same commit that completes it. The detailed list
of detections lives in [docs/DETECTIONS.md](docs/DETECTIONS.md); detection
milestones below only name rule families, and the exact set for each one is
agreed before it starts.

Order (changed on 2026-10-31 so a usable product exists earlier): detections
for automatic execution (M2), report and scoring (M3), SARIF, GitHub Action
and release binaries (M4), the README showcase (M5), the TUI with
localization (M6), and only then capabilities and AST (M7), obfuscation (M8)
and dependencies (M9).

Updated on 2026-11-01 after the security review: scanner hardening and an
architecture refactor were added at the start of milestone 2. The "Before
merging into main" block is a gate: nothing else in milestone 2 starts until
it is done and both open pull requests are merged.

Decisions taken in that review:

- Remote repositories are cloned over https only; ssh is not supported. Users
  who need a private repository clone it themselves and scan the local folder.
- An old git version gives a loud warning (`--allow-old-git` silences it)
  instead of a refusal, because distributions backport security fixes.
- Remote repositories are still read through a `git clone` checkout, now with
  full config isolation. A bare clone or a streamed tarball is in "Later".
- The core stays offline. Anything that needs the network (repository
  signals, OSV, VirusTotal) is an opt-in enrichment layer.

## Milestone 0 — Scaffold (done)

- [x] Local git identity, cargo project, license
- [x] `scan <path|url>` CLI with clap
- [x] Shallow clone of remote repos into a self-deleting temp dir (hooks, LFS smudge and submodules disabled; https credential prompts disabled; full config isolation and other transports: see milestone 2)
- [x] Unit tests for target parsing
- [x] CI: rustfmt, clippy `-D warnings`, tests
- [x] README with project goals
- [x] Detection catalog and threat model (`docs/DETECTIONS.md`)

## Milestone 1 — Walking skeleton

Full path from `scan` to a report with two simple rules, to validate the
architecture early.

- [x] Split into a cargo workspace: `repo-sniff-core` (no UI) + `repo-sniff` binary
- [x] `Finding`, `Severity` and `Stage` model
- [x] Load rules from TOML with full metadata (id, family, stage, severity, ATT&CK, description, example)
- [x] Walk repository files with safety limits (no symlinks, size and count limits, `.gitignore` never applied; for local git repositories see "tracked files" in M2)
- [x] Line-based regex rule engine
- [x] Plain-text report showing severity, stage and ATT&CK ID per finding
- [x] Report text from the scanned repository (file names, task labels) is cleaned of control, bidi and zero-width characters; paths are relative with `/` on every OS
- [x] `--fail-on <severity>` sets the exit-code threshold (default: high) instead of a hard-coded one
- [x] Rule: Trojan Source bidi characters
- [x] Rule: `.vscode/tasks.json` / `*.code-workspace` with `runOn: folderOpen`: JSONC parser, `engine` field, `jsonc` checks
- [x] End-to-end snapshot test with `insta`
- [x] `--ref` option to scan a branch or tag
- [x] Clone hardening: hooks disabled through an empty temporary hooks directory (works on every OS); plain-text transports (`http://`, `git://`) rejected; tests (isolation from user and system git config moved to milestone 2)
- [x] CI matrix (ubuntu, windows, macos) and `.gitattributes` keeping fixture line endings untouched
- [x] CI supply chain: every action pinned to a commit SHA with a version comment; Dependabot for `github-actions` and `cargo`
- [x] `SECURITY.md`: how to report vulnerabilities in the scanner
- [x] `CONTRIBUTING.md`: commits, fixtures, scanner security and cross-platform rules
- [x] Update `DETECTIONS.md` and README

## Milestone 2 — Automatic execution (stages 0–3, 6)

### Before merging into main (gate)

Finish the open work, close the holes that make a scan lie, then merge
`feat/walking-skeleton` and `feat/python-install-hooks` into `main`.

- [x] Python startup family, to finish: scoped re-review by `repo-sniff-reviewer` (only that its earlier findings are closed; a blocker only for a regression or a completely unnoticed executable line), then open the pull request stacked on the milestone 1 pull request (base `feat/walking-skeleton`) while that one is unmerged
- [x] Clone isolation (one pull request): `env_clear()` and re-add only what git needs (PATH, HOME/USERPROFILE, temp, SYSTEMROOT, proxy and SSL certificate variables); `GIT_CONFIG_NOSYSTEM=1`; `GIT_CONFIG_GLOBAL` pointing at an empty file (checked on Git for Windows); `GCM_INTERACTIVE=never`; `-c credential.helper= -c core.symlinks=false -c core.fsmonitor=false -c transfer.fsckObjects=true -c submodule.recurse=false`; `--template= --single-branch --no-tags`. Tests: a global smudge filter in a temporary `HOME` does not run; the same filter through `GIT_CONFIG_COUNT/KEY_0/VALUE_0` has no effect; a symlink in the repository is checked out as a plain file
- [x] https only: `ssh://` and `git@host:path` targets rejected with a message that explains how to scan a local clone instead; `GIT_ALLOW_PROTOCOL=https`
- [x] Credentials in URLs (`https://TOKEN@host/...`) redacted in every message, the report label and error output; test for each output path
- [x] Incomplete scan is never a pass: an INCONCLUSIVE result with its own exit code (3) when bytes were not read (the walk was truncated, a file was too large or could not be read) or an executable binary (ELF, PE, Mach-O including fat binaries, by magic bytes) was not analyzed; other binary files that were read are listed as "binary format, ASCII rules only" and do not change the status; the report says what was not read. Test with padding files that push a payload past the file limit
- [x] Text-like files with NUL bytes still reach line rules: a file with a script extension or a shebang is not treated as binary because of NUL bytes; the NUL itself is reported as concealment (`bash` and `node` run such files). Test with a `.sh` that has a NUL in a comment
- [x] Documentation matches the code: remove "prompts disabled" and "LFS filters skipped" over-claims from `CONTRIBUTING.md`, `docs/DETECTIONS.md` section 5 and the README; state the real guarantees ("no filters from any config run", "no interactive prompts", "an incomplete scan is never reported as clean"); never promise absolute safety
- [x] Merge both pull requests into `main`

### Architecture refactor (before the next rule family)

One pull request while there are only a handful of rules, so new formats stop
needing a new engine variant each.

- [x] One check signature `fn(&Ctx) -> Vec<Hit>` with lazily cached views (`ctx.bytes()`, `ctx.text()`, `ctx.jsonc()`, later `yaml`, `toml`, `xml`, AST) and the repository index available to every check
- [ ] File classification before rules: BOM and UTF-16 decoding, shebang, magic bytes, language; rules may select by `languages = [...]` next to `files` (UTF-16 `.ps1` and Trojan Source in UTF-16 reach line rules)
  - [x] Already done in the gate pull requests: executables recognized by magic bytes (ELF, PE, Mach-O, fat Mach-O) ([#25](https://github.com/z3nghoul/repo-sniff/pull/25)); scripts recognized by extension or shebang, UTF-16 with a byte order mark decoded for script extensions when the first 8 KiB has a NUL byte, so a UTF-16 `.ps1` reaches the line rules, and known binary headers recognized ([#26](https://github.com/z3nghoul/repo-sniff/pull/26)); data with a known header or with NUL bytes that does not read as text (the NUL-density test) read as ASCII only instead of skipped ([#47](https://github.com/z3nghoul/repo-sniff/pull/47)); the same classification for files over 5 MiB read as a stream, except that a UTF-16 script there is listed as too large ([#52](https://github.com/z3nghoul/repo-sniff/pull/52))
  - [ ] Still open: a language per file and `languages = [...]` next to `files`; UTF-16 decoding for every text file, not only scripts (Trojan Source in a UTF-16 `.rs` file is read as ASCII only today, so the bidi rule misses it); UTF-16 decoded whatever the first 8 KiB holds (a UTF-16 `.ps1` whose first 8 KiB has no NUL byte, for example only characters such as U+0101, is not decoded today) and for streamed files; UTF-16 without a byte order mark
- [ ] One phase for every check: offer `jsonc` checks (and the later structured formats) oversized, streamed and symlinked files the way `file` checks are offered them, so that, for example, a `.vscode/tasks.json` that is a symlink to another file in the repository is judged instead of only listed
  - [x] Symbolic links: a `jsonc` check judges the regular file inside the repository that a link it selects points at; a target over the in-memory limit lists the link as too large ([#63](https://github.com/z3nghoul/repo-sniff/issues/63))
  - [ ] Still open: oversized and streamed files (listed as too large today, so the scan is inconclusive, not wrong); a link to another link (#69)
- [x] `Finding` gains column, byte span and a short snippet (more fields come with the milestones that need them; the `.pth` and `.start` checks do not give spans yet)
- [ ] Generic fixture harness: a fixture folder plus `expected.toml`, so a new rule needs no new test code (separate small pull request)

### Rule families

Each in its own branch and pull request, fixtures approved first:

- [x] Repository contents: committed binaries (when this rule lands, remove the "executable binary makes the scan INCONCLUSIVE" exception from the scan engine: such files become findings), disguised executables (magic bytes), droppers (.lnk, .scr, .hta), Windows scripts (.bat, .ps1, .vbs), symlinks out of the repo (a new `head` engine; an executable that no rule reported still makes the scan inconclusive; symlinks only for local targets until the git index is read)
- [ ] Repository contents: committed virtual environments (`pyvenv.cfg`) as a finding of their own, in a separate pull request
- [ ] Repository contents, local targets: dangerous keys in `.git/config` (`core.fsmonitor`, `core.hooksPath`, `core.sshCommand`, `core.pager`, `alias.* = !...`, `filter.*`, `include.path`) and non-sample files in `.git/hooks/`, read as plain files without running git; nested `.git` folders reported
- [ ] Suspicious files: password-protected archives (flagged, never unpacked), data appended after PNG `IEND` / JPEG `EOI`, large high-entropy files of unknown format, binary "test files" referenced by build scripts
- [ ] Submodules pointing at third-party URLs
- [ ] IDE: VS Code tasks/settings, devcontainer, `.idea` run configurations, `.envrc`
- [ ] .NET in the IDE: MSBuild props/targets, analyzers and source generators shipped as DLLs
- [ ] npm install hooks: lifecycle scripts
- [ ] Python install hooks: `setup.py`, build backends
- [x] Python startup files: `.pth` lines run by any supported Python version (graded levels INFO to CRITICAL; symlinked, oversized and non-UTF-8 files included) and `.start` entry points (Python 3.15)
- [ ] Other ecosystem hooks: Dockerfile `curl | sh`, composer scripts, Rakefile / Gemfile, binding.gyp, Maven exec-plugin
- [ ] Build scripts: `build.rs`, Rust proc-macros, `.vcxproj` build events, CMake, Makefile, Gradle wrapper and tasks
- [ ] GitHub Actions workflows
- [ ] Human deception: hidden whitespace code, zero-width characters, homoglyphs, mixed-script path names (`src/maіn.rs` with a Cyrillic `і`), README advice ("disable antivirus", password-protected zip, `curl | bash`)

### Infrastructure

- [x] File-level checks: `Matcher::File` with a `FileCtx`, now `Ctx` (raw bytes, path, index of repository paths, `truncated` flag); rules selected by file name run on raw bytes before binary detection
- [x] Report every skipped file (binary, oversized, symlink, unreadable) in `Report.skipped`; nothing is skipped silently
- [ ] Non-regular files (FIFOs, devices, sockets) listed in `Report.skipped` too
- [ ] Clone limits: timeout with git killed on expiry, disk-size limit during the clone, Ctrl+C removes the temp folder and stops git
- [ ] Minimum git version check with a loud warning and `--allow-old-git` (versions taken from the git security advisories); version parsing tested on `2.43.0`, `2.39.5 (Apple Git-154)`, `2.47.1.windows.1`
- [ ] Local targets: open files without following symlinks and check metadata after opening (no swap between walk and read)
- [ ] Tracked files, local targets only: read the git index directly (`gix` or an own parser) without running git, because a local repository's `.git/config` is attacker-controlled; untracked files still scanned and marked; `.gitignore` is still never applied (cloned repositories need nothing here: the clone has no untracked files)
- [ ] CI: `cargo-deny` or `cargo-audit` next to Dependabot
- [ ] Review point: binary contents via `goblin` (imports, SHA-256, code signature, embedded URLs/IPs); optional VirusTotal hash lookup with the user's own key, never logged, with a note that a third party learns the hash
- [ ] Benchmark on popular honest repositories (target: 0 critical); started here and extended in every later milestone
- [ ] Real-sample test suite gated by `REPO_SNIFF_REAL_SAMPLES` (path to samples outside the repo; skipped when unset)

## Milestone 3 — Report and scoring

- [ ] Colored terminal report: colors added only after sanitizing; `NO_COLOR` and non-TTY output respected
- [ ] JSON output through `serde` only; repository text in it is bounded and marked as untrusted, because AI agents may read it (prompt injection)
- [ ] Rule metadata tags for the trigger, capability and concealment axes
- [ ] Risk score on three axes: trigger, capability, concealment
- [ ] Correlation pass after the scan: all findings plus the repository index in, raised or combined findings out
- [ ] Capability combinations raise severity (built on the correlation pass)
- [ ] "Needs manual review" section: grouped, capped, no (or minimal) effect on the score
- [ ] `.repo-sniff.toml`: `[filters]` and `[[exclude]]` with mandatory reason
- [ ] Parallel scanning with rayon
- [ ] Many rules stay fast: `RegexSet` or Aho-Corasick prefilter for line rules; per-file cap on findings from line rules

## Milestone 4 — SARIF, GitHub Action, releases

- [ ] SARIF output for GitHub code scanning: regions from the byte spans; messages in `text`, never `markdown`
- [ ] GitHub Action that scans pull requests: workflow commands escaped (`::`, `%`, `\r`, `\n`) or output wrapped in `::stop-commands::<token>`; `permissions: contents: read`; never `pull_request_target` with a checkout of the PR head; no tokens in the scan step
- [ ] Release binaries for Linux, Windows and macOS with checksums and GitHub artifact attestations (or signatures)

## Milestone 5 — README as a showcase

- [ ] Demo GIF or screenshot of the report
- [ ] Examples and "how to add your own rule"
- [ ] Publish benchmark results in the README
- [ ] Honest list of blind spots
- [ ] "Security guarantees" section that states exactly what the scanner does to protect the user, matching the code
- [ ] Comparison with similar tools (for example scanrepo): file coverage, Python startup files, build systems, Trojan Source, JSONC parsing, offline by default

## Milestone 6 — TUI and localization

- [ ] ratatui + crossterm app shell: alternate screen, raw mode, panic hook restores the terminal
- [ ] The Elm Architecture: state → event → update → render
- [ ] All repository text shown in the TUI goes through `display_safe` (ratatui does not strip control characters)
- [ ] Start screen: URL/path input, recent scans
- [ ] Scanning screen: background thread, progress by stage over a channel, live finding count
- [ ] Results screen: list, details with code snippet, review points tab, live filters, `/` search
- [ ] Filters and rules screen (fastfetch-style): radio rows, stage × family checkbox grid, tri-state, presets, description line
- [ ] Settings: UI language (shown as UK/EN), default filters, reset; stored in the OS config dir
- [ ] Export filters to `.repo-sniff.toml`

Localization:

- [ ] TOML locale files; built-in `en` and `uk` embedded in the binary, third-party ones from `<config dir>/repo-sniff/locales/` only, never from the scanned repository
- [ ] Mandatory `[meta]`: `code` (validated language tag, `uk` not `ua`), `name` (language name in that language), `description` (built-in note or author message), `schema` (format version)
- [ ] Rule texts translated by rule ID under `[rules."<id>"]`; lookup order: active locale, then English, then the key itself
- [ ] Plural forms via `intl_pluralrules` (CLDR categories)
- [ ] Named placeholders (`{count}`, `{file}`)
- [ ] Color markup (`[red]…[/]`, `[#rrggbb]`, `[b]`, `[i]`, `[u]`) with an escape for a literal bracket; parsed only in the template, substituted values (paths, code snippets) inserted afterwards as plain text
- [ ] Sanitizing locale text: strip ANSI/control characters, bidi controls (U+202A–U+202E, U+2066–U+2069) and zero-width characters
- [ ] Limits on locale file size and string length
- [ ] Severity labels always include the untranslatable code (CRITICAL, HIGH, ...) next to the translation
- [ ] Status bar shows when a third-party locale is active, with its path
- [ ] Hot reload of third-party locales and language switching without restart; on error the last working version stays and a message is shown
- [ ] `repo-sniff locale check <file>`: missing/extra keys, lost/extra placeholders, markup errors, overridden severity labels; run in CI for built-in locales
- [ ] Non-interactive fallback when stdout is not a TTY or `--no-tui`/`--json`/`--sarif` is given

## Milestone 7 — Capabilities and AST

- [ ] tree-sitter for Python, JavaScript, C/C++, with input size and depth limits (tree-sitter is C code; consider running it in a separate process)
- [ ] tree-sitter for Rust, PowerShell, bash and Go
- [ ] `engine = "ts-query"` in rule TOML (`language` + `query`); taint tracking at least within one function
- [ ] Import graph: whether a flagged file is imported or run at all
- [ ] Stage 5 capability families: process spawning, LOLBins, injection, persistence, credential theft, exfiltration, keylogging, defense evasion
- [ ] Download → write → make executable → run chain
- [ ] Crypto mining, ransomware behavior
- [ ] UAC bypass, anti-VM and anti-debugging
- [ ] Dynamic eval and loading code from bytes
- [ ] Clipper, screenshots, auto-update without signature check
- [ ] Web3 drainers: wallet providers (`window.ethereum`, Phantom, Solflare), signing APIs whose result is sent to a server, seed-phrase harvesting
- [ ] Solidity: `delegatecall`, `selfdestruct`, hidden owner, inline `assembly`
- [ ] Stage 4 test hooks: `conftest.py`, npm `test`

Review points:

- [ ] URLs and domains in code (raw IPs, pastebin, raw gists, shorteners, dynamic DNS); network response flowing into exec/eval/file write
- [ ] Encoded URL next to a network call: URL as base64 or a byte array, payload URL in a config file, `axios`/`fetch` result passed to `eval` (an early line or file rule is possible before the AST)
- [ ] Logic bombs: conditions on dates, hostname/user, environment, system language and keyboard layout
- [ ] Bugdoors at LOW: risky C/C++ functions (`strcpy`, `sprintf`, `gets`, unchecked `memcpy`), Rust `unsafe` blocks
- [ ] Capability map: short summary of what the program can do

## Milestone 8 — Obfuscation

- [ ] Shannon entropy, long base64/hex blobs, minified code among normal sources
- [ ] Recursive decoding (base64, hex, char codes, zlib, single-byte XOR, PowerShell `-enc`) with depth and size limits; each finding keeps its decoding chain
- [ ] Packer and obfuscator signatures, reflection and dynamic imports

Review points:

- [ ] Possible code virtualization: large numeric arrays + opcode dispatch loop
- [ ] Decryption (AES, Fernet, CryptoJS) whose result is executed or loaded as code
- [ ] Code that reads image pixels/bytes and executes the result (steganography)

## Milestone 9 — Dependencies

Network lookups form a separate enrichment layer after the scan: cache,
offline mode, timeouts, names from the repository URL-encoded, and a notice
that third parties learn what is scanned.

- [ ] Typosquatting against popular packages
- [ ] Known vulnerabilities via the OSV API
- [ ] Known malicious package names (not only vulnerabilities)
- [ ] Lockfiles resolving outside the official registry, git/URL dependencies

Review points:

- [ ] Young dependencies via registry APIs (npm, crates.io, PyPI): recently published, few downloads, changed owner
- [ ] Release binaries via the GitHub API, README telling users to download releases instead of building

## Later

- [ ] README vs. behavior: compare the stated purpose with the capability map
- [ ] Repository signals behind opt-in `--online` (GitHub API): repository age, zero stars/forks/issues, lists of known malicious repositories and accounts
- [ ] Fake recruiter assignment lures in the name, description and README ("defi exchange test", "real estate rental platform", "dex staking platform"), together with repository signals
- [ ] Reading remote repositories without a checkout: bare clone with `ls-tree`/`cat-file` (with `GIT_NO_LAZY_FETCH=1` for partial clones), or streaming the GitHub tarball without extracting it (symlinks and `../` entries handled)
- [ ] MCP server as a thin wrapper over `--json`, only after M3 and M4

## Considered and rejected

- Web vulnerability rules (XSS, SQL/NoSQL injection, open redirect, missing auth): a different class of tool and noise for a malware scanner.
- An LLM in the core: prompt injection from repository text and non-deterministic results.
