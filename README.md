# repo-sniff

[![CI](https://github.com/z3nghoul/repo-sniff/actions/workflows/ci.yml/badge.svg)](https://github.com/z3nghoul/repo-sniff/actions/workflows/ci.yml)

**Sniff a repository before you run it.**

`repo-sniff` is a command-line scanner that **statically** analyzes a GitHub
repository for signs of malicious or suspicious code and produces a readable
report: for every finding, the file and line, why it is suspicious and how
serious it is. A risk score is planned (milestone 3).

It is aimed at the moment right before you `npm install`, `pip install`,
`cargo build` or open a random Visual Studio project from the internet:
these steps can run code from the repository on your machine, and fake
"cheats", "tools" and "PoCs" exploit exactly that.

> **Early development.** `repo-sniff scan` works on a local folder or an
> https repository and prints a plain-text report with 11 rules built into
> the binary, in four areas: Trojan Source and NUL bytes, VS Code auto-run tasks, Python
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
  by a `git` that runs with an empty environment, an empty configuration and
  an empty home directory. No filter, credential helper or fsmonitor from
  your own or the system's git configuration runs, hooks and templates are
  off, symlinks are written as plain files (the scanner then reads them as links
  from the clone's own index), and submodules are not fetched.
  There are no interactive prompts. For a private repository, clone it
  yourself and scan the folder.
- **Secrets.** A token pasted into a URL (`https://TOKEN@host/...`) is hidden
  in the notice, the report and error messages. A URL whose password holds
  an unescaped `/`, `?` or `#` is refused before anything is sent (curl would
  take part of it for the host), and so is an scp-like address with any user
  (`deploy:TOKEN@host:path`), which is an ssh target.
- **Reading.** Symlinks are listed, not followed, with one exception: a
  symlinked VS Code tasks file or `.code-workspace` is judged through the
  regular file inside the repository it points at. If that target cannot be
  read for certain (a link to another link, a name that differs between Unix
  and Windows, a path through a directory link, a target over the limit), the
  link is listed as unreadable and the scan is inconclusive. File names and
  text taken from the repository are cleaned before they are printed, so a
  hostile repository cannot paint over the report.
- **Limits.** The work is bounded. The walk stops after 100,000 files. A file
  over 100 MiB is not read. A file over 5 MiB is read as a stream, line by
  line, and only the line rules look at it; a line over 16 MiB is not
  analyzed. Reads through symlinks are capped at 64 MiB per scan. Reaching
  the file limit, a file or line over its limit and the symlink cap each make
  the scan inconclusive instead of passing silently.
- **Honesty.** A scan is never reported as clean when it cannot vouch for what
  it looked at: the report says `INCONCLUSIVE` and the exit status is 3 (see
  [Exit status](#exit-status)).

## What it detects today

| Rule | Level | What it catches |
|---|---|---|
| `deception.bidi-control` | LOW to CRITICAL | Unicode bidirectional control characters that make code look different from what it does (Trojan Source, CVE-2021-42574). A line is laid out with and without them; CRITICAL if the display differs or cannot be judged, LOW ("display unchanged") if it does not, as in the direction helpers of a vendored UI bundle |
| `ide.vscode-folder-open-task` | MEDIUM to CRITICAL | VS Code tasks that run when a folder is opened, in `.vscode/tasks.json` and `*.code-workspace`; CRITICAL if the command downloads or runs code from a string; a file that cannot be parsed is reported for a manual look, HIGH if it mentions `runOn` and `folderOpen`, MEDIUM otherwise |
| `deception.nul-byte-in-script` | HIGH | A NUL byte inside a script (by extension or shebang). The script is still scanned as text, because shells and interpreters run it. A script with a UTF-16 byte order mark is decoded first, so its NUL bytes are not a finding and the line rules see its real text, except `.bat`, `.cmd`, shell and PHP scripts, which run the bytes after the mark and are read as bytes. Not decoded: UTF-16 without a byte order mark, and UTF-16 in files that are not scripts |
| `deps.python-pth-exec` | INFO to CRITICAL | Python `.pth` files with a line that starts with `import`, which Python runs every time it starts. Judged the way every supported Python version would read it; known honest forms (setuptools, virtualenv, editable installs, pytest-cov) are lowered |
| `deps.python-start-entrypoint` | HIGH, LOW | Python 3.15 `.start` files, whose `package.module:callable` entry points Python calls every time it starts; LOW for file names Python never reads |
| `repo.disguised-executable` | CRITICAL | A native executable (ELF, PE, Mach-O, found by magic bytes) whose name promises something else: a document, image, data, archive or script extension (`logo.png`, `tool.sh`), a double extension such as `invoice.pdf.exe`, bidi or invisible characters in the name |
| `repo.committed-binary` | HIGH, MEDIUM | A committed native executable or library (HIGH); validated bytecode such as `.pyc`, `.class`, `.jar`, `.wasm` (MEDIUM). Its code is not analyzed |
| `repo.windows-dropper` | HIGH, CRITICAL | Files that run on a double click on Windows: a `.lnk` with a shortcut header, a `.scr` that is a PE, an `.hta`; CRITICAL when the name poses as a document or image |
| `repo.windows-script` | LOW to CRITICAL | Windows scripts: `.bat`, `.cmd`, `.ps1`, `.psm1` (LOW, common build glue); `.vbs`, `.wsf`, `.wsh` (MEDIUM); Script Encoder output `.vbe`, `.jse` (HIGH); CRITICAL when the name poses as a document or image |
| `repo.wsh-javascript` | MEDIUM | JavaScript that uses Windows Script Host objects: `WScript` or `WSH`, `ActiveXObject` / `CreateObject` with the shell, file system, stream, server-side HTTP, WMI or task scheduler ProgIDs |
| `repo.symlink-outside` | HIGH, MEDIUM | A symbolic link that points outside the repository (MEDIUM into system program folders); local folders and remote clones |

The full catalog of planned detections, with their levels and MITRE ATT&CK
techniques, is in [docs/DETECTIONS.md](docs/DETECTIONS.md).

## Planned analysis layers

In the order of [ROADMAP.md](ROADMAP.md):

1. **Automatic execution** (milestone 2, in progress): IDE settings (VS Code
   settings, devcontainer, `.idea` run configurations, `.envrc`), committed
   virtual environments, MSBuild props and targets and .NET analyzers shipped
   as DLLs, npm lifecycle scripts, `setup.py` and build backends, other
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

Rules are built into the binary, so adding one means a rebuild. Line rules are
plain TOML (`engine = "line-regex"`), so a pattern can be added without
touching the engine. Most structural checks (JSONC, `.pth` files, file
headers) are Rust functions with one signature, `fn(&Ctx) -> Vec<Hit>`,
registered by rule id; their TOML entry carries the metadata and the file
globs.

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
Scan: complete (every file was read)
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
even with `--fail-on none`; findings at the threshold still take precedence
(exit 1). Images, archives, symlinks that no check had to read and the root `.git`
folder are listed and do not change the status. This makes `repo-sniff scan . --fail-on high` usable as a CI check
without mistaking "nothing found in what was read" for "safe". How executables
and other binary files affect the status is described in
[docs/DETECTIONS.md](docs/DETECTIONS.md#6-exit-status-and-binary-files).

## Benchmark

Ten popular honest repositories, scanned from their default branches with
`repo-sniff scan <url>` on 2026-11-01. The scanner was `main` (`71fb3b5`), which
includes the hardening pull requests #75, #76 and #77. The target
is 0 CRITICAL findings on honest code; it is met, and no scan is
INCONCLUSIVE.

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

27 of the 30 HIGH findings are vendored executables (true detections of
benign files) and one is a real folder-open task in vscode (#43). cpython's 2
are a known false positive (#42), and they alone cause its exit 1. The
previous run, with the same changes merged locally, gave the same findings
on the same heads (cpython has moved since). Commits of the
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

Built with Claude Code as the implementing agent. Design, rule semantics, review
policy and merge decisions are mine; every change goes through an independent
review pass, fixtures-first tests, CI on three OSes and a benchmark against 10
well-known repositories.

## License

[AGPL-3.0](LICENSE)
