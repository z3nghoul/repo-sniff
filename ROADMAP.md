# Roadmap

Every task is ticked in the same commit that completes it. The detailed list
of detections lives in [docs/DETECTIONS.md](docs/DETECTIONS.md); detection
milestones below only name rule families, and the exact set for each one is
agreed before it starts.

## Milestone 0 — Scaffold (done)

- [x] Local git identity, cargo project, license
- [x] `scan <path|url>` CLI with clap
- [x] Shallow clone of remote repos into a self-deleting temp dir (hooks, LFS, submodules, prompts disabled)
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
- [x] Walk repository files with safety limits (no symlinks, size and count limits, `.gitignore` not honored)
- [x] Line-based regex rule engine
- [x] Plain-text report showing severity, stage and ATT&CK ID per finding
- [x] Report text from the scanned repository (file names, task labels) is cleaned of control, bidi and zero-width characters; paths are relative with `/` on every OS
- [x] `--fail-on <severity>` sets the exit-code threshold (default: high) instead of a hard-coded one
- [x] Rule: Trojan Source bidi characters
- [x] Rule: `.vscode/tasks.json` / `*.code-workspace` with `runOn: folderOpen`: JSONC parser, `engine` field, `jsonc` checks
- [x] End-to-end snapshot test with `insta`
- [x] `--ref` option to scan a branch or tag
- [x] Clone hardening: hooks disabled through an empty temporary hooks directory (works on every OS); plain-text transports (`http://`, `git://`) rejected; tests
- [x] CI matrix (ubuntu, windows, macos) and `.gitattributes` keeping fixture line endings untouched
- [x] CI supply chain: every action pinned to a commit SHA with a version comment; Dependabot for `github-actions` and `cargo`
- [x] `SECURITY.md`: how to report vulnerabilities in the scanner
- [x] `CONTRIBUTING.md`: commits, fixtures, scanner security and cross-platform rules
- [ ] Update `DETECTIONS.md` and README

## Milestone 2 — Automatic execution (stages 0–3, 6)

Rule families, each in its own branch and PR, fixtures approved first:

- [ ] Repository contents: committed binaries, disguised executables (magic bytes), droppers (.lnk, .scr, .hta), Windows scripts (.bat, .ps1, .vbs), symlinks out of the repo
- [ ] Suspicious files: password-protected archives (flagged, never unpacked), data appended after PNG `IEND` / JPEG `EOI`, large high-entropy files of unknown format, binary "test files" referenced by build scripts
- [ ] Submodules pointing at third-party URLs
- [ ] IDE: VS Code tasks/settings, devcontainer, `.idea` run configurations, `.envrc`
- [ ] .NET in the IDE: MSBuild props/targets, analyzers and source generators shipped as DLLs
- [ ] npm and Python install hooks: lifecycle scripts, `setup.py`, `.pth` (levels INFO to CRITICAL, Python-compatible line splitting), build backends
- [ ] Other ecosystem hooks: Dockerfile `curl | sh`, composer scripts, Rakefile / Gemfile, binding.gyp, Maven exec-plugin
- [ ] Build scripts: `build.rs`, Rust proc-macros, `.vcxproj` build events, CMake, Makefile, Gradle wrapper and tasks
- [ ] GitHub Actions workflows
- [ ] Human deception: hidden whitespace code, zero-width characters, homoglyphs, README advice ("disable antivirus", password-protected zip, `curl | bash`)

Infrastructure:

- [ ] Review point: binary contents via `goblin` (imports, SHA-256, code signature, embedded URLs/IPs); optional VirusTotal hash lookup with the user's own key
- [ ] Benchmark on popular honest repositories (target: 0 critical); started here and extended in every later milestone
- [ ] Real-sample test suite gated by `REPO_SNIFF_REAL_SAMPLES` (path to samples outside the repo; skipped when unset)

## Milestone 3 — Report and scoring

- [ ] Colored terminal report
- [ ] JSON output
- [ ] Risk score on three axes: trigger, capability, concealment
- [ ] Capability combinations raise severity
- [ ] "Needs manual review" section: grouped, capped, no (or minimal) effect on the score
- [ ] `.repo-sniff.toml`: `[filters]` and `[[exclude]]` with mandatory reason
- [ ] Parallel scanning with rayon

## Milestone 3.5 — TUI

- [ ] ratatui + crossterm app shell: alternate screen, raw mode, panic hook restores the terminal
- [ ] The Elm Architecture: state → event → update → render
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

## Milestone 4 — Capabilities and AST

- [ ] tree-sitter for Python, JavaScript, C/C++
- [ ] tree-sitter for Rust, PowerShell and bash
- [ ] Stage 5 capability families: process spawning, LOLBins, injection, persistence, credential theft, exfiltration, keylogging, defense evasion
- [ ] Download → write → make executable → run chain
- [ ] Crypto mining, ransomware behavior
- [ ] UAC bypass, anti-VM and anti-debugging
- [ ] Dynamic eval and loading code from bytes
- [ ] Clipper, screenshots, auto-update without signature check
- [ ] Stage 4 test hooks: `conftest.py`, npm `test`

Review points:

- [ ] URLs and domains in code (raw IPs, pastebin, raw gists, shorteners, dynamic DNS); network response flowing into exec/eval/file write
- [ ] Logic bombs: conditions on dates, hostname/user, environment, system language and keyboard layout
- [ ] Bugdoors at LOW: risky C/C++ functions (`strcpy`, `sprintf`, `gets`, unchecked `memcpy`), Rust `unsafe` blocks
- [ ] Capability map: short summary of what the program can do

## Milestone 5 — Obfuscation

- [ ] Shannon entropy, long base64/hex blobs, minified code among normal sources
- [ ] Recursive decoding (base64, hex, char codes, zlib, single-byte XOR, PowerShell `-enc`) with depth and size limits
- [ ] Packer and obfuscator signatures, reflection and dynamic imports

Review points:

- [ ] Possible code virtualization: large numeric arrays + opcode dispatch loop
- [ ] Decryption (AES, Fernet, CryptoJS) whose result is executed or loaded as code
- [ ] Code that reads image pixels/bytes and executes the result (steganography)

## Milestone 6 — Dependencies

- [ ] Typosquatting against popular packages
- [ ] Known vulnerabilities via the OSV API
- [ ] Lockfiles resolving outside the official registry, git/URL dependencies

Review points:

- [ ] Young dependencies via registry APIs (npm, crates.io, PyPI): recently published, few downloads, changed owner
- [ ] Release binaries via the GitHub API, README telling users to download releases instead of building

## Milestone 7 — SARIF, GitHub Action, releases

- [ ] SARIF output for GitHub code scanning
- [ ] GitHub Action that scans pull requests
- [ ] Release binaries for Linux, Windows and macOS

## Milestone 8 — README as a showcase

- [ ] Demo GIF or screenshot of the report
- [ ] Examples and "how to add your own rule"
- [ ] Publish benchmark results in the README
- [ ] Honest list of blind spots

## Later

- [ ] README vs. behavior: compare the stated purpose with the capability map
