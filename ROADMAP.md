# Roadmap

Every task is ticked in the same commit that completes it. The detailed list
of detections lives in [docs/DETECTIONS.md](docs/DETECTIONS.md); detection
milestones below only name rule families, and the exact set for each one is
agreed before it starts.

## Milestone 0 — Scaffold ✅

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

- [ ] Split into a cargo workspace: `repo-sniff-core` (no UI) + `repo-sniff` binary
- [ ] `Finding`, `Severity` and `Stage` model
- [ ] Load rules from TOML with full metadata (id, family, stage, severity, ATT&CK, description, example)
- [ ] Walk repository files with safety limits (no symlinks, size and count limits, `.gitignore` not honored)
- [ ] Line-based regex rule engine
- [ ] Plain-text report, non-zero exit code on High/Critical
- [ ] Rule: Trojan Source bidi characters
- [ ] Rule: `.vscode/tasks.json` with `runOn: folderOpen` (written by the author)
- [ ] End-to-end snapshot test with `insta`
- [ ] `--ref` option to scan a branch or tag
- [ ] Update `DETECTIONS.md` and README

## Milestone 2 — Automatic execution (stages 0–3, 6)

Rule families, each in its own branch and PR, fixtures approved first:

- [ ] Repository contents: committed binaries, disguised executables (magic bytes), droppers, symlinks out of the repo
- [ ] IDE: VS Code tasks/settings, MSBuild props/targets, devcontainer
- [ ] npm and Python install hooks: lifecycle scripts, `setup.py`, `.pth`, build backends
- [ ] Build scripts: `build.rs`, `.vcxproj` build events, CMake, Makefile, Gradle wrapper
- [ ] GitHub Actions workflows
- [ ] Human deception: hidden whitespace code, zero-width characters, homoglyphs

## Milestone 3 — Report and scoring

- [ ] Colored terminal report
- [ ] JSON output
- [ ] Risk score on three axes: trigger, capability, concealment
- [ ] Capability combinations raise severity
- [ ] "Needs manual review" section
- [ ] `.repo-sniff.toml`: `[filters]` and `[[exclude]]` with mandatory reason
- [ ] Parallel scanning with rayon

## Milestone 3.5 — TUI

- [ ] ratatui + crossterm app shell: alternate screen, raw mode, panic hook restores the terminal
- [ ] The Elm Architecture: state → event → update → render
- [ ] Start screen: URL/path input, recent scans
- [ ] Scanning screen: background thread, progress by stage over a channel, live finding count
- [ ] Results screen: list, details with code snippet, review points tab, live filters, `/` search
- [ ] Filters and rules screen (fastfetch-style): radio rows, stage × family checkbox grid, tri-state, presets, description line
- [ ] Settings: UI language UA/EN, default filters, reset; stored in the OS config dir
- [ ] Export filters to `.repo-sniff.toml`
- [ ] Non-interactive fallback when stdout is not a TTY or `--no-tui`/`--json`/`--sarif` is given

## Milestone 4 — Capabilities and AST

- [ ] tree-sitter for Python, JavaScript, C/C++
- [ ] Stage 5 capability families: process spawning, LOLBins, injection, persistence, credential theft, exfiltration, keylogging, defense evasion
- [ ] Stage 4 test hooks: `conftest.py`, npm `test`

## Milestone 5 — Obfuscation

- [ ] Shannon entropy, long base64/hex blobs, minified code among normal sources
- [ ] Recursive decoding (base64, hex, char codes, zlib, single-byte XOR, PowerShell `-enc`) with depth and size limits
- [ ] Packer and obfuscator signatures

## Milestone 6 — Dependencies

- [ ] Typosquatting against popular packages
- [ ] Known vulnerabilities via the OSV API
- [ ] Lockfiles resolving outside the official registry, git/URL dependencies

## Milestone 7 — SARIF, GitHub Action, releases

- [ ] SARIF output for GitHub code scanning
- [ ] GitHub Action that scans pull requests
- [ ] Release binaries for Linux, Windows and macOS

## Milestone 8 — README as a showcase

- [ ] Demo GIF or screenshot of the report
- [ ] Examples and "how to add your own rule"
- [ ] `CONTRIBUTING.md`
- [ ] Benchmark on popular honest repositories: 0 critical on clean repos
- [ ] Honest list of blind spots
