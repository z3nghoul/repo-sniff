# roadmap

What is built, what comes next and in which order. It is for users who want
to know whether a feature is coming and for contributors who pick a task.
Every task is ticked in the same commit that completes it. The detailed list
of detections lives in [docs/DETECTIONS.md](docs/DETECTIONS.md); detection
milestones below only name rule families, and the exact set for each one is
agreed before it starts.

## contents

- [where we are](#where-we-are)
- [design decisions](#design-decisions)
- [milestone 2: automatic execution (in progress)](#milestone-2-automatic-execution-in-progress)
- [milestone 3: report and scoring](#milestone-3-report-and-scoring)
- [milestone 4: SARIF, GitHub Action, releases](#milestone-4-sarif-github-action-releases)
- [milestone 4.5: integrations: MCP server and agent skills](#milestone-45-integrations-mcp-server-and-agent-skills)
- [milestone 5: README as a showcase](#milestone-5-readme-as-a-showcase)
- [milestone 6: TUI and localization](#milestone-6-tui-and-localization)
- [milestone 7: capabilities and AST](#milestone-7-capabilities-and-ast)
- [milestone 8: obfuscation](#milestone-8-obfuscation)
- [milestone 9: dependencies](#milestone-9-dependencies)
- [later](#later)
- [considered and rejected](#considered-and-rejected)
- [done: milestones 0 and 1](#done-milestones-0-and-1)

## where we are

**v0.1.0 is being prepared** (see [CHANGELOG.md](CHANGELOG.md)). It scans a
local folder or an https git repository without running anything from it,
with 21 rules: repository contents, VS Code auto-run tasks, npm scripts,
Python startup files, JavaScript and Windows loader signatures, and Trojan
Source. The report is plain text, with `--fail-on` and `--ref`. On ten
popular honest repositories it gives 0 CRITICAL findings and no inconclusive
scan ([docs/BENCHMARK.md](docs/BENCHMARK.md)).

**Next:** the rest of milestone 2 (the open rule families and infrastructure
below), then the report and scoring of milestone 3.

The order of the milestones: detections for automatic execution (M2), report
and scoring (M3), SARIF, GitHub Action and release binaries (M4), the MCP
server and agent skills (M4.5, numbered so the later milestones keep their
numbers), the README showcase (M5), the TUI with localization (M6), and only then capabilities and
AST (M7), obfuscation (M8) and dependencies (M9). It was chosen on 2026-10-31
so that a usable product exists early.

## design decisions

Taken in the security review of 2026-11-01:

- Remote repositories are cloned over https only; ssh is not supported. Users
  who need a private repository clone it themselves and scan the local folder.
- An old git version gives a loud warning (`--allow-old-git` silences it)
  instead of a refusal, because distributions backport security fixes.
- Remote repositories are still read through a `git clone` checkout, now with
  full config isolation. A bare clone or a streamed tarball is in
  [later](#later).
- The core stays offline. Anything that needs the network (repository
  signals, OSV, VirusTotal) is an opt-in enrichment layer.

## milestone 2: automatic execution (in progress)

Stages 0–3 and 6 of the threat model. Each rule family comes in its own
branch and pull request, with fixtures approved first.

### rule families, open

- [ ] Repository contents: committed virtual environments (`pyvenv.cfg`) as a finding of their own, in a separate pull request
- [ ] Repository contents, local targets: dangerous keys in `.git/config` (`core.fsmonitor`, `core.hooksPath`, `core.sshCommand`, `core.pager`, `alias.* = !...`, `filter.*`, `include.path`) and non-sample files in `.git/hooks/`, read as plain files without running git; nested `.git` folders reported
- [ ] Suspicious files: password-protected archives (flagged, never unpacked), data appended after PNG `IEND` / JPEG `EOI`, large high-entropy files of unknown format, binary "test files" referenced by build scripts
- [ ] Submodules pointing at third-party URLs
- [ ] IDE: VS Code tasks/settings, devcontainer, `.idea` run configurations, `.envrc`
- [ ] .NET in the IDE: MSBuild props/targets, analyzers and source generators shipped as DLLs
- [ ] Python install hooks: `setup.py`, build backends
- [ ] Other ecosystem hooks: Dockerfile `curl | sh`, composer scripts, Rakefile / Gemfile, binding.gyp, Maven exec-plugin
- [ ] Build scripts: `build.rs`, Rust proc-macros, `.vcxproj` build events, CMake, Makefile, Gradle wrapper and tasks
- [ ] GitHub Actions workflows
- [ ] Human deception: hidden whitespace code, zero-width characters, homoglyphs, mixed-script path names (`src/maіn.rs` with a Cyrillic `і`), README advice ("disable antivirus", password-protected zip, `curl | bash`)
- [ ] Windows script loaders, follow-ups:
  - `-ep bypass` alone as LOW, raised only together with `-enc`, `-w hidden` or a download; `Start-BitsTransfer` and `Invoke-Command` as downloads on their own; `regsvr32`/`mshta`/`rundll32` forms beyond the ones listed (`url.dll` for `rundll32`); the same strings in files of other types at a lower level (hits in build and IDE hook files rank above hits in documentation; Markdown defers to the README rule of the human deception family); `.vbe` and `.jse` content; known honest one-liners beyond the installer list (`powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1`)
  - ATT&CK planned for the family but not carried by a rule yet: T1564.003 (hidden window)
  - evasions left for milestones 7 and 8, beyond those listed in [DETECTIONS.md](docs/DETECTIONS.md#34-running-the-program): delayed expansion in batch files; `-join`, reversed strings and `&(gcm i*x)` in PowerShell; JSON `\u` and XML entity escapes unless the rules also run on decoded string values

### architecture, open

- [ ] File classification before rules: still open are a language per file and `languages = [...]` next to `files`; UTF-16 decoding for every text file, not only scripts (Trojan Source in a UTF-16 `.rs` file is read as ASCII only today, so the bidi rule misses it); UTF-16 without a byte order mark
- [ ] One phase for every check: offer `jsonc` checks (and the later structured formats) oversized and streamed files the way `file` checks are offered them (listed as too large today, so the scan is inconclusive, not wrong); a link to another link ([#69](https://github.com/z3nghoul/repo-sniff/issues/69); listed as unreadable today, so the scan is inconclusive)

### infrastructure, open

- [ ] Non-regular files (FIFOs, devices, sockets) listed in `Report.skipped` too
- [ ] `--max-files <N>` and `--max-file-size <SIZE>` flags:
  - they set `Limits::max_files` and `Limits::max_file_size` (sizes take `K`, `M`, `G` suffixes in binary units; 0 is rejected; upper bounds 10 000 000 files and 4 GiB); a `max_file_size` below the 5 MiB in-memory limit also lowers that limit;
  - limits come only from the command line, never from a configuration file;
  - a changed limit is shown in the report and later in the JSON and SARIF output, and lowering a limit can only make a scan inconclusive, never clean
- [ ] Clone limits: timeout with git killed on expiry, disk-size limit during the clone, Ctrl+C removes the temp folder and stops git
- [ ] Minimum git version check with a loud warning and `--allow-old-git` (versions taken from the git security advisories); version parsing tested on `2.43.0`, `2.39.5 (Apple Git-154)`, `2.47.1.windows.1`
- [ ] Local targets: open files without following symlinks and check metadata after opening (no swap between walk and read)
- [ ] Tracked files, local targets only: read the git index directly (`gix` or an own parser) without running git, because a local repository's `.git/config` is attacker-controlled; untracked files still scanned and marked; `.gitignore` is still never applied (cloned repositories need nothing here: the clone has no untracked files)
- [ ] CI: `cargo-deny` or `cargo-audit` next to Dependabot
- [ ] Review point: binary contents via `goblin` (imports, SHA-256, code signature, embedded URLs/IPs); optional VirusTotal hash lookup with the user's own key, never logged, with a note that a third party learns the hash
- [ ] Benchmark on popular honest repositories (target: 0 critical); started here and extended in every later milestone

<details>
<summary>Done in milestone 2</summary>

Scanner hardening, merged before any new rule family:

- [x] Clone isolation: empty environment with a short allow-list, empty `HOME`/`USERPROFILE` sandbox (git before 2.32 ignores `GIT_CONFIG_GLOBAL`, [#29](https://github.com/z3nghoul/repo-sniff/issues/29)), `GIT_CONFIG_NOSYSTEM=1`, empty `GIT_CONFIG_GLOBAL`, `GCM_INTERACTIVE=never`, `-c credential.helper= -c core.symlinks=false -c core.fsmonitor=false -c transfer.fsckObjects=true -c submodule.recurse=false`, `--template= --single-branch --no-tags`
- [x] https only: `ssh://` and `git@host:path` refused with a hint to scan a local clone; `GIT_ALLOW_PROTOCOL=https`
- [x] Credentials in URLs redacted in every message, the report label and error output
- [x] An incomplete scan is never a pass: INCONCLUSIVE with exit code 3, and the report says what was not read
- [x] Text-like files with NUL bytes still reach the line rules, and the NUL is reported
- [x] Documentation states the real guarantees and never promises absolute safety
- [x] Python startup family merged

Architecture:

- [x] One check signature `fn(&Ctx) -> Vec<Hit>` with lazily cached views (`ctx.bytes()`, `ctx.text()`, `ctx.jsonc()`, later `yaml`, `toml`, `xml`, AST) and the repository index available to every check
- [x] File classification, first part: executables by magic bytes ([#25](https://github.com/z3nghoul/repo-sniff/pull/25)), scripts by extension or shebang and UTF-16 `.ps1` decoding ([#26](https://github.com/z3nghoul/repo-sniff/pull/26)), binary-looking data read as ASCII only ([#47](https://github.com/z3nghoul/repo-sniff/pull/47)), the same for streamed files ([#52](https://github.com/z3nghoul/repo-sniff/pull/52)), UTF-16 scripts decoded whatever their first 8 KiB holds ([#64](https://github.com/z3nghoul/repo-sniff/issues/64))
- [x] Symlinked `jsonc` targets judged through the link ([#63](https://github.com/z3nghoul/repo-sniff/issues/63))
- [x] `Finding` gains column, byte span and a short snippet (the `.pth` and `.start` checks do not give spans yet)
- [x] Generic fixture harness: a fixture folder plus `<family>.expected.toml` beside it

Rule families:

- [x] Repository contents: committed binaries, disguised executables, droppers, Windows scripts, symlinks out of the repository (a new `head` engine; symlinks in remote clones recovered from the clone's own index, [#67](https://github.com/z3nghoul/repo-sniff/issues/67))
- [x] npm install hooks and the `start` / `dev` / `build` / `test` scripts that run a local node file next to a front-end tool
- [x] Loader signatures in JavaScript: encoded blobs reaching `eval` / `Function` / `child_process`, obfuscator.io signatures, minified source, a network result passed to `eval` or `Function`
- [x] Windows script loaders, in the same pull request ([#96](https://github.com/z3nghoul/repo-sniff/issues/96))
- [x] Python startup files: `.pth` lines graded INFO to CRITICAL, `.start` entry points (Python 3.15)

Infrastructure:

- [x] File-level checks on raw bytes, before binary detection, for rules selected by file name
- [x] Every skipped file (binary, oversized, symlink, unreadable) is listed in `Report.skipped`
- [x] Real-sample test suite gated by `REPO_SNIFF_REAL_SAMPLES` (path to samples outside the repo; skipped when unset)

</details>

## milestone 3: report and scoring

- [ ] Colored terminal report: colors added only after sanitizing; `NO_COLOR` and non-TTY output respected
- [x] JSON output through `serde` only; repository text in it is bounded and marked as untrusted, because AI agents may read it (prompt injection) ([#122](https://github.com/z3nghoul/repo-sniff/issues/122), schema in [docs/JSON.md](docs/JSON.md)); repository text in explanations gets a field of its own in [#123](https://github.com/z3nghoul/repo-sniff/issues/123)
- [ ] Rule metadata tags for the trigger, capability and concealment axes
- [ ] Risk score on three axes: trigger, capability, concealment
- [ ] Correlation pass after the scan: all findings plus the repository index in, raised or combined findings out
- [ ] Capability combinations raise severity (built on the correlation pass)
- [ ] "Needs manual review" section: grouped, capped, no (or minimal) effect on the score
- [ ] `.repo-sniff.toml`: `[filters]` and `[[exclude]]` with mandatory reason
- [ ] Configuration is never taken from the scanned repository:
  - no implicit lookup of `.repo-sniff.toml` in the target, the current directory or its parents; no other locations (`pyproject.toml`, `Cargo.toml` metadata, `.config/`, subdirectories); no environment variable that changes rules, filters, exclusions or limits (a direnv `.envrc` could set it); no inline suppression comments in scanned files; no `include` or `extends`;
  - a configuration is used only when `--config <path>` names it, and the report says when that path is inside the target. A `.repo-sniff.toml` found in the target is reported as ignored, with the findings it would have hidden (a repository that tries to silence itself is a signal);
  - the scan status is computed before exclusions and filters: they can hide a finding, never turn an unread file, a limit hit or an unanalyzed executable into a clean result;
  - an exclusion names a rule id, an exact path, a reason and a fingerprint of the matched line, so it does not cover a new payload added to the same file later;
  - every exclusion and filter in effect (`[filters]`, and the TUI default filters from the OS config dir) is listed in the report; findings hidden by a filter still count toward `--fail-on`;
  - `CONTRIBUTING.md` and `docs/DETECTIONS.md` are updated to this model when it lands
- [ ] `repo-sniff rules` lists the built-in rules (id, family, stage, level, ATT&CK) and `repo-sniff explain <rule-id>` prints one rule's description, example and what it does not catch; every rule, including the Rust checks, carries a mandatory non-empty `gaps` text that the loader rejects when it is missing
- [ ] Parallel scanning with rayon
- [ ] Many rules stay fast: `RegexSet` or Aho-Corasick prefilter for line rules; per-file cap on findings from line rules

## milestone 4: SARIF, GitHub Action, releases

- [ ] SARIF output for GitHub code scanning: regions from the byte spans; messages in `text`, never `markdown`
- [ ] GitHub Action that scans pull requests:
  - workflow commands escaped (`::`, `%`, `\r`, `\n`) or output wrapped in `::stop-commands::<token>`;
  - `permissions: contents: read`; never `pull_request_target` with a checkout of the PR head; no tokens in the scan step;
  - the configuration is read from the base commit of the event (`pull_request.base.sha`) as a git object, never as a path in the working tree, and a `push` uses the pushed commit's parent;
  - because a pull request that edits the workflow can still change how the Action runs, the documentation requires the check to be enforced by a repository ruleset (required workflow or required status check) with CODEOWNERS review on `.github/`, and the scan flags a pull request that changes `.repo-sniff.toml` or a workflow step that runs repo-sniff
- [ ] Release binaries for Linux, Windows and macOS with checksums and GitHub artifact attestations (or signatures)
- [ ] Man page and shell completions (bash, zsh, fish, PowerShell) generated from the clap definitions in release CI, never written by hand, and shipped with the release binaries

## milestone 4.5: integrations: MCP server and agent skills

Depends on the JSON output of milestone 3 and the release binaries of milestone 4.

- [ ] MCP server as a real integration and a thin wrapper over the same core, with no logic of its own. Tools:
  - `scan_repo(url)`: structured findings, the capability map and the list of automatic-execution points that no rule covers;
  - `get_context(finding_id)`: a bounded, defanged snippet around one finding;
  - `list_execution_points(url)`: every automatic-execution point, also when there are no findings
- [ ] Everything from the scanned repository in the MCP output is marked as untrusted data (in a fence, with a note), never as instructions; an agent's verdict is not presented as the verdict of repo-sniff, the two stay separate
- [ ] Thin per-agent instruction files over the one MCP server, not copies of its logic. Each only tells the agent when to call the scanner and not to read the raw files itself:
  - Claude: `SKILL.md` and a slash command;
  - Codex: an `AGENTS.md` fragment;
  - Gemini: `GEMINI.md` or an extension
- [ ] Lives first as the `integrations/` folder of this repository; moves to a separate addon repository only if it grows (examples, CI against each agent)

## milestone 5: README as a showcase

- [x] Banner for dark and light themes ([#114](https://github.com/z3nghoul/repo-sniff/pull/114))
- [x] Demo GIF of the report ([#114](https://github.com/z3nghoul/repo-sniff/pull/114))
- [x] One row of badges ([#114](https://github.com/z3nghoul/repo-sniff/pull/114))
- [x] README structure: short sections, details moved to `docs/DETECTIONS.md` ([#114](https://github.com/z3nghoul/repo-sniff/pull/114))
- [ ] Examples and "how to add your own rule"
- [x] Publish benchmark results in the README
- [ ] Honest list of blind spots
- [ ] "Security guarantees" section that states exactly what the scanner does to protect the user, matching the code
- [ ] Comparison with similar tools (for example scanrepo): file coverage, Python startup files, build systems, Trojan Source, JSONC parsing, offline by default

## milestone 6: TUI and localization

- [ ] ratatui + crossterm app shell: alternate screen, raw mode, panic hook restores the terminal
- [ ] The Elm Architecture: state → event → update → render
- [ ] All repository text shown in the TUI goes through `display_safe` (ratatui does not strip control characters)
- [ ] Start screen: URL/path input, recent scans
- [ ] Scanning screen: background thread, progress by stage over a channel, live finding count
- [ ] Results screen: list, details with code snippet, review points tab, live filters, `/` search
- [ ] Help screen on `?`: key bindings of the current screen (inside the `/` search box `?` is text)
- [ ] Filters and rules screen (fastfetch-style): radio rows, stage × family checkbox grid, tri-state, presets, description line
- [ ] Settings: UI language (shown as UK/EN), default filters, reset; stored in the OS config dir
- [ ] Export filters to a configuration file in the OS config dir or a path the user picks, used through `--config` (a `.repo-sniff.toml` in the scanned repository is ignored)

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

## milestone 7: capabilities and AST

- [ ] tree-sitter for Python, JavaScript, C/C++, with input size and depth limits (tree-sitter is C code; consider running it in a separate process)
- [ ] tree-sitter for Rust, PowerShell, bash and Go
- [ ] `engine = "ts-query"` in rule TOML (`language` + `query`); taint tracking at least within one function
- [ ] Import graph: whether a flagged file is imported or run at all
- [ ] Stage 5 capability families: process spawning, LOLBins (full version of the Windows script loader signatures of milestone 2), injection, persistence, credential theft, exfiltration, keylogging, defense evasion
- [ ] Download → write → make executable → run chain
- [ ] Crypto mining, ransomware behavior
- [ ] UAC bypass, anti-VM and anti-debugging
- [ ] Dynamic eval and loading code from bytes (full version of the loader signatures of milestone 2)
- [ ] Clipper, screenshots, auto-update without signature check
- [ ] Web3 drainers: wallet providers (`window.ethereum`, Phantom, Solflare), signing APIs whose result is sent to a server, seed-phrase harvesting
- [ ] Solidity: `delegatecall`, `selfdestruct`, hidden owner, inline `assembly`
- [ ] Stage 4 test hooks: `conftest.py`, npm `test`

Review points:

- [ ] URLs and domains in code (raw IPs, pastebin, raw gists, shorteners, dynamic DNS); network response flowing into exec/eval/file write
- [ ] Encoded URL next to a network call: URL as base64 or a byte array, payload URL in a config file, `axios`/`fetch` result passed to `eval` (the data-flow version of the early line rule in the loader signatures)
- [ ] Logic bombs: conditions on dates, hostname/user, environment, system language and keyboard layout
- [ ] Bugdoors at LOW: risky C/C++ functions (`strcpy`, `sprintf`, `gets`, unchecked `memcpy`), Rust `unsafe` blocks
- [ ] Capability map: short summary of what the program can do

## milestone 8: obfuscation

- [ ] Shannon entropy, long base64/hex blobs, minified code among normal sources (full version of the early line and file rules in the loader signatures)
- [ ] Recursive decoding (base64, hex, char codes, zlib, single-byte XOR, PowerShell `-enc`, which the loader signatures only flag) with depth and size limits; each finding keeps its decoding chain
- [ ] Packer and obfuscator signatures, reflection and dynamic imports (obfuscator.io signatures are already in the loader signatures)

Review points:

- [ ] Possible code virtualization: large numeric arrays + opcode dispatch loop
- [ ] Decryption (AES, Fernet, CryptoJS) whose result is executed or loaded as code
- [ ] Code that reads image pixels/bytes and executes the result (steganography)

## milestone 9: dependencies

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

## later

- [ ] README vs. behavior: compare the stated purpose with the capability map
- [ ] Repository signals behind opt-in `--online` (GitHub API): repository age, zero stars/forks/issues, lists of known malicious repositories and accounts
- [ ] Fake recruiter assignment lures in the name, description and README ("defi exchange test", "real estate rental platform", "dex staking platform"), together with repository signals
- [ ] Reading remote repositories without a checkout: bare clone with `ls-tree`/`cat-file` (with `GIT_NO_LAZY_FETCH=1` for partial clones), or streaming the GitHub tarball without extracting it (symlinks and `../` entries handled)
- [ ] Documentation site built with mdBook from `docs/` (detections, rules, guarantees, benchmark)

## considered and rejected

- Web vulnerability rules (XSS, SQL/NoSQL injection, open redirect, missing auth): a different class of tool and noise for a malware scanner.
- An LLM in the core: prompt injection from repository text and non-deterministic results.

## done: milestones 0 and 1

<details>
<summary>Milestone 0: scaffold</summary>

- [x] Local git identity, cargo project, license
- [x] `scan <path|url>` CLI with clap
- [x] Shallow clone of remote repos into a self-deleting temp dir (hooks, LFS smudge and submodules disabled)
- [x] Unit tests for target parsing
- [x] CI: rustfmt, clippy `-D warnings`, tests
- [x] README with project goals
- [x] Detection catalog and threat model (`docs/DETECTIONS.md`)

</details>

<details>
<summary>Milestone 1: walking skeleton (the full path from <code>scan</code> to a report)</summary>

- [x] Cargo workspace: `repo-sniff-core` (no UI) + `repo-sniff` binary
- [x] `Finding`, `Severity` and `Stage` model
- [x] Rules loaded from TOML with full metadata (id, family, stage, severity, ATT&CK, description, example)
- [x] File walk with safety limits (no symlinks, size and count limits, `.gitignore` never applied)
- [x] Line-based regex rule engine
- [x] Plain-text report with severity, stage and ATT&CK ID per finding
- [x] Repository text in the report cleaned of control, bidi and zero-width characters; paths relative with `/` on every OS
- [x] `--fail-on <severity>` sets the exit-code threshold (default: high)
- [x] Rule: Trojan Source bidi characters; an unchanged display is LOW ([#89](https://github.com/z3nghoul/repo-sniff/issues/89))
- [x] Rule: VS Code `runOn: folderOpen` tasks, with a JSONC parser and the `engine` field
- [x] End-to-end snapshot test with `insta`
- [x] `--ref` option to scan a branch or tag
- [x] Clone hardening: hooks off through an empty hooks directory on every OS; `http://` and `git://` refused
- [x] CI matrix (ubuntu, windows, macos) and `.gitattributes` keeping fixture line endings untouched
- [x] CI supply chain: actions pinned to a commit SHA; Dependabot for `github-actions` and `cargo`
- [x] `SECURITY.md` and `CONTRIBUTING.md`
- [x] `DETECTIONS.md` and README updated

</details>
