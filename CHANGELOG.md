# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-03

First release. `repo-sniff scan <TARGET>` scans a local directory or an https
git repository without running anything from it and prints a plain-text report.
Options: `--fail-on <info|low|medium|high|critical|none>` (default `high`) and
`--ref <REF>` for remote repositories.

### Guarantees

- The scanner never executes code from the scanned repository: no install, no
  build, no scripts. It only reads files.
- Your credentials are never used. A remote repository is cloned over https
  only, anonymously; a private repository fails with a message saying so. A
  token pasted into a URL is hidden in the notice, the report and error
  messages.
- The clone is isolated: shallow, by a `git` that runs with an empty
  environment, an empty configuration and an empty home directory, with hooks
  and templates off, symlinks written as plain files, submodules not fetched
  and no interactive prompts.
- Symlinks are not followed (a symlinked VS Code tasks file or `.code-workspace`
  is judged through the regular file in the repository it points at). Text and
  file names taken from the repository are cleaned before they are printed.
- The work is bounded: 100,000 files, no read of a file over 100 MiB, a file
  over 5 MiB is read as a stream, a line over 16 MiB is not analyzed, reads
  through symlinks are capped at 64 MiB per scan.
- An incomplete scan is never reported as clean. When the scan cannot vouch for
  what it looked at (file limit reached, a file or line over its limit,
  unreadable input, a nested `.git` not read, an executable binary no rule
  reported), the report ends with `Scan: INCONCLUSIVE`, says why, and the exit
  status is 3.

### Exit status

| Status | Meaning |
|---|---|
| 0 | Nothing reached the `--fail-on` threshold and the scan was complete |
| 1 | Something reached the `--fail-on` threshold (takes precedence over 3) |
| 2 | The scan could not run (bad target, clone failure, wrong options) |
| 3 | Nothing reached the threshold, but the scan was inconclusive |

### Added

Rule families (21 rules; the full catalog with levels and MITRE ATT&CK
techniques is in [docs/DETECTIONS.md](docs/DETECTIONS.md)):

- Trojan Source and concealment: `deception.bidi-control` (a line is laid out
  with and without the bidi controls; CRITICAL if the display differs or cannot
  be judged, LOW if it does not; MEDIUM inside a string value of a JSON data
  file, #106), `deception.nul-byte-in-script`.
- IDE auto-run: `ide.vscode-folder-open-task` (`.vscode/tasks.json` and
  `*.code-workspace`).
- Python startup files: `deps.python-pth-exec`, `deps.python-start-entrypoint`.
- npm scripts: `deps.npm-lifecycle-hook`, `run.npm-script-local-server`.
- Repository contents: `repo.disguised-executable`, `repo.committed-binary`,
  `repo.windows-dropper`, `repo.windows-script`, `repo.wsh-javascript`,
  `repo.symlink-outside`.
- Loader signatures in JavaScript: `run.js-fetch-eval`,
  `run.js-function-require`, `obfuscation.encoded-payload-sink`,
  `obfuscation.obfuscator-io`, `obfuscation.minified-source`.
- Windows script loaders: `run.windows-remote-code`,
  `obfuscation.windows-encoded-payload`, `run.windows-defender-exclusion`.
- A fixture harness (`tests/fixtures/<family>/` with an `expected.toml`), a
  benchmark script (`scripts/benchmark.sh`) and a real-sample test gated by
  `REPO_SNIFF_REAL_SAMPLES`.

Benchmark on ten popular honest repositories: 0 CRITICAL and no INCONCLUSIVE
scan ([docs/BENCHMARK.md](docs/BENCHMARK.md)).

### Known limitations

A clean result never proves that a repository is harmless. What is known to be
open at this release (each item is an open issue):

- Links: a link target is judged by its text, not resolved component by
  component through directory links and chains inside the clone, so a link can
  still hide a file in some forms and the scan can say complete
  ([#90](https://github.com/z3nghoul/repo-sniff/issues/90); related #80, #81,
  #84, #85, #86, #87).
- Large files: a line over 16 MiB makes an honest repository inconclusive, and
  a streamed file selected by a whole-file rule is reported as too large
  ([#54](https://github.com/z3nghoul/repo-sniff/issues/54),
  [#55](https://github.com/z3nghoul/repo-sniff/issues/55)). A `.js` file over
  32 MiB makes the scan inconclusive; it used to be line-scanned
  ([#108](https://github.com/z3nghoul/repo-sniff/issues/108)).
- npm scripts: some obfuscated forms (caret or backslash inside a command name,
  line continuation, wrappers such as `xargs`, `NODE_OPTIONS` assignments) give
  a lower level than documented, and `binding.gyp`, `.npmrc` and `.yarnrc.yml`
  are not read ([#105](https://github.com/z3nghoul/repo-sniff/issues/105),
  [#103](https://github.com/z3nghoul/repo-sniff/issues/103)).
- Loader signatures are line and file rules, not an analysis of the program:
  download and execution on different lines, string building and several
  PowerShell and batch obfuscations are not seen
  ([#108](https://github.com/z3nghoul/repo-sniff/issues/108),
  [#109](https://github.com/z3nghoul/repo-sniff/issues/109)).
- Bidi: a line that starts with a right-to-left mark or letter reorders with no
  control at all ([#94](https://github.com/z3nghoul/repo-sniff/issues/94)).
- Dependencies are not analyzed: a payload that is only a package name in
  `package.json` is not found (milestone 9; the real-sample test lists four
  such lures as known exceptions).
- Binary files are read as ASCII only, executables are reported but their code
  is not analyzed, and git metadata is not analyzed.
- Known false positives, reported on purpose: shell scripts followed by a zip
  archive ([#42](https://github.com/z3nghoul/repo-sniff/issues/42)).
- There is no risk score, JSON or SARIF output, GitHub Action or TUI yet; see
  [ROADMAP.md](ROADMAP.md).

[0.1.0]: https://github.com/z3nghoul/repo-sniff/releases/tag/v0.1.0
