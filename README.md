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

> **Early development.** `repo-sniff scan` works on a local folder or an
> https repository and prints a plain-text report with 11 rules in four
> families: Trojan Source and NUL bytes, VS Code auto-run tasks, Python
> startup files, and repository contents (committed executables, disguised
> executables, Windows droppers and scripts, symlinks out of the repository);
> see [What it detects today](#what-it-detects-today). There is no risk score,
> JSON, SARIF or GitHub Action yet. Progress is tracked in
> [ROADMAP.md](ROADMAP.md).

## Safety first

`repo-sniff` does not run code from the scanned repository: no install, no
build, no scripts. It reads files. That is a design rule, not a promise of
absolute safety. The scanner parses hostile input, so it can have bugs, and a
clean result never proves that a repository is harmless.

What it does to protect you:

- **Cloning.** Remote repositories are cloned over `https` only, shallowly,
  by a `git` that runs with an empty environment and an empty configuration.
  No filter, credential helper or fsmonitor from your own or the system's git
  configuration runs, hooks and templates are off, symlinks are written as
  plain files, and submodules are not fetched. There are no interactive
  prompts. For a private repository, clone it yourself and scan the folder.
- **Secrets.** A token pasted into a URL (`https://TOKEN@host/...`) is hidden
  in the notice, the report and error messages. Passwords containing `?` or `#`
  and scp-like targets are known gaps.
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
| `repo.disguised-executable` | CRITICAL | A native executable (ELF, PE, Mach-O, found by magic bytes) whose name promises something else: a document or image extension, a double extension such as `invoice.pdf.exe`, bidi or invisible characters in the name |
| `repo.committed-binary` | HIGH, MEDIUM | A committed native executable or library (HIGH); validated bytecode such as `.pyc`, `.class`, `.jar`, `.wasm` (MEDIUM). Its code is not analyzed |
| `repo.windows-dropper` | HIGH | Files that run on a double click on Windows: a `.lnk` with a shortcut header, a `.scr` that is a PE, an `.hta` |
| `repo.windows-script` | LOW, MEDIUM, HIGH | Windows scripts: `.bat`, `.cmd`, `.ps1`, `.psm1` (LOW, common build glue); `.vbs`, `.wsf`, `.wsh` (MEDIUM); Script Encoder output `.vbe`, `.jse` (HIGH); CRITICAL when the name poses as a document or image |
| `repo.wsh-javascript` | MEDIUM | JavaScript that uses Windows Script Host objects (`WScript`, `ActiveXObject` with the shell, file system or HTTP ProgIDs) |
| `repo.symlink-outside` | HIGH | A symbolic link that points outside the repository (MEDIUM into system program folders); local folders only for now |

The full catalog of planned detections, with their levels and MITRE ATT&CK
techniques, is in [docs/DETECTIONS.md](docs/DETECTIONS.md).

## Planned analysis layers

In the order of [ROADMAP.md](ROADMAP.md):

1. **Automatic execution** (milestone 2, in progress): IDE settings
   (devcontainer, `.idea` run configurations, `.envrc`), MSBuild props and
   targets, npm lifecycle scripts, `setup.py` and build backends, other
   ecosystem hooks (Dockerfile, composer, Gemfile, `binding.gyp`, Maven),
   build scripts (`build.rs`, `.vcxproj` build events, CMake, Makefile,
   Gradle), GitHub Actions workflows, `.git/config` of a local repository,
   suspicious files (password-protected archives, data after an image),
   third-party submodules, human deception (zero-width characters,
   homoglyphs, README advice to disable the antivirus).
2. **Report and scoring** (milestone 3): colored output, JSON, a risk score
   on three axes (trigger, capability, concealment), a correlation pass, and
   `.repo-sniff.toml` filters and exclusions.
3. **SARIF, GitHub Action, release binaries** (milestone 4).
4. **Capabilities and AST** (milestone 7): tree-sitter for Python,
   JavaScript, C/C++ and more; process spawning, persistence, injection,
   credential theft, exfiltration. Risk comes from *combinations* of
   capabilities, not from single matches.
5. **Obfuscation** (milestone 8): entropy, long base64/hex blobs, minified
   code among normal sources, recursive decoding.
6. **Dependencies** (milestone 9): typosquatting, known vulnerabilities via
   OSV, known malicious packages, lockfiles that resolve outside the registry.
7. **Later**: comparing what a README claims with what the code can do.

Line rules are plain TOML files (`engine = "line-regex"`), so a pattern can be
added without touching the engine. Structural checks (JSONC, `.pth` files,
file headers) are Rust functions with one signature, `fn(&Ctx) -> Vec<Hit>`;
their TOML entry carries only the metadata.

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
| 3 | Nothing reached the threshold, but the scan was **inconclusive**: the file limit was reached, a file was too large or could not be read, a line of a large file was too long to analyze, a nested `.git` repository was not read, or an executable binary was not reported by any rule |

A scan that could not vouch for what it looked at is never reported as clean:
the report ends with `Scan: INCONCLUSIVE`, says why, and the exit status is 3
even with `--fail-on none`. Files that were read but not analyzed in depth
(images, archives, the root `.git` folder) are listed and do not change the
status. This makes `repo-sniff scan . --fail-on high` usable as a CI check
without mistaking "nothing found in what was read" for "safe". How executables
and other binary files affect the status is described in
[docs/DETECTIONS.md](docs/DETECTIONS.md#exit-status-and-binary-files).

## Benchmark

Ten popular honest repositories, scanned from their default branches with
`repo-sniff scan <url>` on 2026-11-01 (scanner commit `0383fc2`). The target
is 0 CRITICAL findings on honest code.

| Repository | Exit | Critical | High | Medium | Low |
|---|---|---|---|---|---|
| BurntSushi/ripgrep | 0 | 0 | 0 | 0 | 0 |
| rust-lang/cargo | 0 | 0 | 0 | 0 | 0 |
| psf/requests | 0 | 0 | 0 | 0 | 1 |
| pallets/flask | 0 | 0 | 0 | 0 | 1 |
| pypa/pip | 1 | 0 | 6 | 0 | 0 |
| expressjs/express | 0 | 0 | 0 | 0 | 0 |
| microsoft/vscode | 1 | 0 | 8 | 0 | 50 |
| git/git | 0 | 0 | 0 | 3 | 5 |
| python/cpython | 1 | 0 | 2 | 1 | 28 |
| microsoft/terminal | 1 | 0 | 14 | 0 | 74 |

The HIGH findings are mostly vendored executables (true detections of benign
files); exit 1 is the default `--fail-on high` doing its job. Commits of the
scanned repositories, every HIGH and MEDIUM finding with a verdict, and how to
re-run it are in [docs/BENCHMARK.md](docs/BENCHMARK.md).

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
