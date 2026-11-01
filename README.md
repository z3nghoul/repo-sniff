# repo-sniff

[![CI](https://github.com/z3nghoul/repo-sniff/actions/workflows/ci.yml/badge.svg)](https://github.com/z3nghoul/repo-sniff/actions/workflows/ci.yml)

**Sniff a repository before you run it.**

`repo-sniff` is a command-line scanner that **statically** analyzes a GitHub
repository for signs of malicious or suspicious code and produces a readable
report: a risk score plus an explanation for every finding (file and line,
why it is suspicious, how serious it is).

It is aimed at the moment right before you `npm install`, `pip install`,
`cargo build` or open a random Visual Studio project from the internet:
these steps can run code from the repository on your machine, and fake
"cheats", "tools" and "PoCs" exploit exactly that.

> **Early development.** The scanning pipeline works end to end, but only two
> detections exist so far (see [What it detects today](#what-it-detects-today)).
> The rest of the planned layers are being added step by step; progress is
> tracked in [ROADMAP.md](ROADMAP.md).

## Safety first

`repo-sniff` does not run code from the scanned repository: no install, no
build, no scripts. It reads files. That is a design rule, not a promise of
absolute safety. The scanner parses hostile input, so it can have bugs, and a
clean result never proves that a repository is harmless.

What it does to protect you:

- **Cloning.** Remote repositories are cloned over `https` only, shallowly,
  by a `git` that runs with an empty environment, an empty configuration and
  an empty home directory. No filter, credential helper or fsmonitor from
  your own or the system's git configuration runs, hooks and templates are
  off, symlinks are written as plain files, and submodules are not fetched.
  There are no interactive prompts. For a private repository, clone it
  yourself and scan the folder.
- **Secrets.** A token pasted into a URL (`https://TOKEN@host/...`) is hidden
  in the notice, the report and error messages, also when a password contains
  `/`, `?` or `#`, and so is the user of an scp-like address
  (`deploy:TOKEN@host:path`), which is refused as an ssh target.
- **Reading.** Symlinks are never followed. File names and text taken from the
  repository are cleaned before they are printed, so a hostile repository
  cannot paint over the report. The work per file is bounded.
- **Honesty.** A scan is never reported as clean when it cannot vouch for what
  it looked at: if the file limit was reached, a file was too large or could
  not be read, or a repository nested inside it (a `.git` folder below the
  root) was not read, the report says `INCONCLUSIVE` and the exit status is 3.
  An executable binary (ELF, PE, Mach-O including fat binaries, found by magic
  bytes whatever it is called) is a finding of its own, HIGH or CRITICAL, and
  is listed as not analyzed; one that no rule reported would make the scan
  inconclusive. Other binary files
  (images, archives, compressed data) are read and listed as `binary, not
  analyzed`: no rule looks inside them yet.

## What it detects today

| Rule | Level | What it catches |
|---|---|---|
| `deception.bidi-control` | CRITICAL | Unicode bidirectional control characters that make code look different from what it does (Trojan Source, CVE-2021-42574) |
| `ide.vscode-folder-open-task` | HIGH, CRITICAL | VS Code tasks that run when a folder is opened, in `.vscode/tasks.json` and `*.code-workspace`; CRITICAL if the command downloads or runs code from a string |
| `deception.nul-byte-in-script` | HIGH | A NUL byte inside a script (by extension or shebang). The script is still scanned as text, because shells and interpreters run it |
| `deps.python-pth-exec` | INFO to CRITICAL | Python `.pth` files with a line that starts with `import`, which Python runs every time it starts. Judged the way every supported Python version would read it; known honest forms (setuptools, virtualenv, editable installs, pytest-cov) are lowered |
| `deps.python-start-entrypoint` | HIGH | Python 3.15 `.start` files, whose `package.module:callable` entry points Python calls every time it starts |

The full catalog of planned detections, with their levels and MITRE ATT&CK
techniques, is in [docs/DETECTIONS.md](docs/DETECTIONS.md).

## Planned analysis layers

1. **Build/install hooks** — `preinstall`/`postinstall` in `package.json`,
   `setup.py`, `build.rs`, Gradle tasks, `PreBuildEvent`/`PostBuildEvent` in
   `.vcxproj`, GitHub Actions workflows, committed binaries.
2. **Capabilities** — networking, process spawning, persistence (registry Run
   keys, systemd, cron, LaunchAgents), keyboard/clipboard hooks, browser and
   Discord data access, process injection. Risk comes from *combinations* of
   capabilities, not from single matches.
3. **AST analysis** with tree-sitter (Python, JavaScript, C/C++) to tell real
   calls apart from comments and strings.
4. **Obfuscation** — Shannon entropy, long base64/hex blobs, minified code
   hidden among normal sources.
5. **Dependencies** — typosquatting of popular packages, known
   vulnerabilities via the OSV API.
6. **README vs. behavior** — comparing what a project claims to do with what
   its code can do.

Output formats: colored terminal report, JSON, and SARIF for GitHub code
scanning. A GitHub Action for scanning pull requests is planned too.

Rules are plain TOML files, so new detections can be contributed without
touching the engine.

## Usage

Build from source (requires a Rust toolchain and `git`):

```sh
git clone https://github.com/z3nghoul/repo-sniff
cd repo-sniff
cargo build --release
```

Scan a local directory or a remote repository:

```sh
repo-sniff scan ./some-project
repo-sniff scan https://github.com/owner/repo
```

Scan a specific branch or tag of a remote repository:

```sh
repo-sniff scan https://github.com/owner/repo --ref v1.2.3
```

Example report (`repo-sniff scan .` in a project with a risky auto-run task):

```text
Scanned 1 files in .

CRITICAL  .vscode/tasks.json:6  ide.vscode-folder-open-task  [ide]
          task "setup" runs automatically when the folder is opened, and its command contains "curl"

Summary: 1 critical, 0 high, 0 medium, 0 low, 0 info
```

### Options

| Option | Meaning |
|---|---|
| `--fail-on <SEVERITY>` | Exit with status 1 if any finding is at least this severe: `info`, `low`, `medium`, `high` (default) or `critical`. `none` never fails because of findings. |
| `--ref <REF>` | Branch or tag to scan. Only for remote repositories; the default branch is used otherwise. |

### Exit status

| Status | Meaning |
|---|---|
| 0 | Nothing reached the `--fail-on` threshold, and the scan was not inconclusive (files it did not analyze are listed in the report) |
| 1 | The scan found something at or above the threshold |
| 2 | The scan could not run (bad target, clone failure, wrong options) |
| 3 | Nothing reached the threshold, but the scan was **inconclusive**: the file limit was reached, a file was too large or could not be read, a nested `.git` repository was not read, or an executable binary (ELF, PE, Mach-O) was not reported by any rule |

Other binary files (images, archives, compressed test data) are read and listed
as `binary format, ASCII rules only`, and do not change the status. A scan is never
reported as clean when it could not vouch for what it looked at: the report ends
with `Scan: INCONCLUSIVE` and says why, and the exit status is 3 even with
`--fail-on none`. An executable binary is a HIGH finding (CRITICAL when its
name hides it), so it fails the default threshold; with `--fail-on critical` or
`--fail-on none` a plainly named executable is shown but no longer fails the
scan. A Java class file whose header checks out is MEDIUM (bytecode a runtime
loads), so it no longer fails the default threshold either. The `.git` folder at the root is listed as
`git metadata, not analyzed` and does not change the status. This makes
`repo-sniff scan . --fail-on high` usable as a CI check without mistaking "nothing found in what was read" for "safe".

## Development

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the rules about commits, fixtures
and adding a detection, and [SECURITY.md](SECURITY.md) for reporting a
vulnerability in the scanner itself.

Test fixtures are synthetic, harmless files that only *imitate* suspicious
patterns; each one is marked `SYNTHETIC TEST FIXTURE — not functional`.

## License

[AGPL-3.0](LICENSE)
