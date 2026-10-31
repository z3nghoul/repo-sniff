# Benchmark on honest repositories

Date: 2026-11-01. Scanner: `repo-sniff 0.1.0`, release build of `main` at commit
`3d65b24`. Each repository was scanned from its default branch with
`repo-sniff scan <url>` (default `--fail-on high`) and a 300 second limit per
repository including the clone. No repository timed out or hit the file limit.
Re-run with `scripts/benchmark.sh`; the commits below are the heads that were
current at the time of the run.

The target for honest repositories is 0 critical findings. **It is not met:**
all 6 CRITICAL findings below are false positives.

## Results

| Repository | Commit | Result | Exit | Critical | High | Medium | Low | Info | Not analyzed | Seconds |
|---|---|---|---|---|---|---|---|---|---|---|
| BurntSushi/ripgrep | 91f5d22ef48b | clean | 0 | 0 | 0 | 0 | 0 | 0 | 4 binary, 1 git metadata | 1 |
| rust-lang/cargo | 809bcc525b61 | clean | 0 | 0 | 0 | 0 | 0 | 0 | 16 binary, 1 git metadata | 2 |
| psf/requests | 3c7baaa05ab4 | clean | 0 | 0 | 0 | 0 | 0 | 0 | 5 binary, 1 git metadata | 1 |
| pallets/flask | 49943b5a9441 | clean | 0 | 0 | 0 | 0 | 0 | 0 | 5 binary, 1 git metadata | 1 |
| pypa/pip | ec43c48b2f2d | INCONCLUSIVE | 3 | 0 | 0 | 0 | 0 | 0 | 88 binary, 6 executable, 1 git metadata | 2 |
| expressjs/express | 1c6f1b0fe400 | clean | 0 | 0 | 0 | 0 | 0 | 0 | 1 git metadata | 1 |
| microsoft/vscode | d78bac45fca4 | INCONCLUSIVE | 1 | 3 | 1 | 0 | 0 | 0 | 198 binary, 7 executable, 2 too large, 1 git metadata | 10 |
| git/git | 50fe5cc63f9c | clean | 0 | 0 | 0 | 0 | 0 | 0 | 8 binary, 1 git metadata | 4 |
| python/cpython | e80962a4bd68 | findings | 1 | 3 | 2 | 0 | 0 | 0 | 87 binary, 1 git metadata | 6 |
| microsoft/terminal | 703ef7f969d9 | INCONCLUSIVE | 3 | 0 | 0 | 0 | 0 | 0 | 1067 binary, 13 executable, 1 too large, 1 git metadata | 3 |
Seconds include the clone. "Not analyzed" is the count by reason from the report.

6 of 10 repositories are clean or have only binary data left, 3 are
INCONCLUSIVE, 1 has findings.

## HIGH and CRITICAL findings

| Repository | File | Rule | Level | Verdict | Why |
|---|---|---|---|---|---|
| microsoft/vscode | `resources/darwin/java.icns:174`, `json.icns:167` | `deception.bidi-control` | CRITICAL | False | Icon files (binary). Random bytes decode to U+202E-like sequences. B4 path, see below |
| microsoft/vscode | an `.mp3` under `src/vs/workbench/contrib/agentsVoice/browser/media/` | `deception.bidi-control` | CRITICAL | False | Audio file, same cause. B4 path |
| python/cpython | `Mac/IDLE/.../PythonCompiled.icns:8`, `Mac/Icons/PythonCompiled.icns:8`, `PC/icons/launcher.icns:326` | `deception.bidi-control` | CRITICAL | False | Icon files, same cause. B4 path |
| python/cpython | `Lib/test/archivetestdata/exe_with_zip:26`, `exe_with_z64:25` | `deception.nul-byte-in-script` | HIGH | False in intent | Checked the first bytes: a bash script followed by a zip archive (test data for `zipfile`). The NUL is real, the file is not hiding anything |
| microsoft/vscode | `extensions/copilot/.vscode/tasks.json:94` | `ide.vscode-folder-open-task` | HIGH | True detection, benign | Task "watch" does run when the folder is opened; it is an ordinary dev watch task |

### Findings from the "NUL without a known header" path (B4)

This is the path added in the review of PR #26: a file with NUL bytes, no
script name and no known binary header is read by the line rules with the NUL
bytes removed. In this run it produced exactly the 6 CRITICAL false positives
above (3 `.icns` in cpython, 2 `.icns` and 1 `.mp3` in vscode). Binary formats
that are not in the known-header list get their bytes decoded lossily, and the
bidi rule matches the byte sequences `E2 80 AE` and similar that appear in
random data. It also means files such as `.icns` and `.mp3` are no longer
listed as "binary, not analyzed"; they count as scanned. The `.pth` and shell
script paths did not produce any false positive here. The number of B4-path
files that produced no finding is not recorded by the report.

### INCONCLUSIVE results

| Repository | Cause |
|---|---|
| pypa/pip | 6 PE executables in `src/pip/_vendor/distlib/` (the `t32.exe`, `w64.exe` launchers and friends), all vendored script launchers; the report lists 6 of the 6 |
| microsoft/vscode | 7 executables (for example `build/win32/inno_updater.exe`, `vcruntime140.dll`) and 2 files over 5 MiB (a colorize fixture and a 8.9 MB perf data file) |
| microsoft/terminal | 13 executables (for example the DLLs in `dep/WinAppDriver/`) and `dep/nuget/nuget.exe` (8.4 MB, too large) |

These follow the documented policy: an executable is code that nothing
analyzes yet, and an unread file cannot be vouched for. The executable case
goes away when the "committed binaries" rule exists. The report prints only the
first 10 skipped files, so for terminal and vscode the full list of executables
is not visible.

## False positives and gaps filed as issues

- [#41](https://github.com/z3nghoul/repo-sniff/issues/41): bidi-control CRITICAL on binary files without a known header (6 findings)
- [#42](https://github.com/z3nghoul/repo-sniff/issues/42): nul-byte-in-script on a script with an appended archive
- [#43](https://github.com/z3nghoul/repo-sniff/issues/43): vscode-folder-open-task grading by the command
- [#44](https://github.com/z3nghoul/repo-sniff/issues/44): only the first 10 skipped files are listed
- [#45](https://github.com/z3nghoul/repo-sniff/issues/45): 5 MiB limit makes honest repositories INCONCLUSIVE

None of these were fixed in this change; the scanner code is untouched.
