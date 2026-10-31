# Benchmark on honest repositories

Date: 2026-11-01. Scanner: `repo-sniff 0.1.0`, release build of `main` at commit
`5fbdd78` (after the fixes for issues 41, 44 and 45). Each repository was
scanned from its default branch with `repo-sniff scan <url>` (default
`--fail-on high`) and a 300 second limit per repository including the clone.
No repository timed out or hit the file limit. Re-run with
`scripts/benchmark.sh`; the commits below are the heads that were current at
the time of the run.

The target for honest repositories is 0 critical findings. **It is met:**
0 CRITICAL in all ten. The first run, on `3d65b24`, found 6 false CRITICAL
findings; see "What changed since the first run".

## Results

| Repository | Commit | Result | Exit | Critical | High | Medium | Low | Info | Not fully analyzed | Seconds |
|---|---|---|---|---|---|---|---|---|---|---|
| BurntSushi/ripgrep | 91f5d22ef48b | clean | 0 | 0 | 0 | 0 | 0 | 0 | 7 binary, 1 git metadata | 0 |
| rust-lang/cargo | 809bcc525b61 | clean | 0 | 0 | 0 | 0 | 0 | 0 | 18 binary, 1 git metadata | 1 |
| psf/requests | 3c7baaa05ab4 | clean | 0 | 0 | 0 | 0 | 0 | 0 | 6 binary, 1 git metadata | 1 |
| pallets/flask | 49943b5a9441 | clean | 0 | 0 | 0 | 0 | 0 | 0 | 5 binary, 1 git metadata | 1 |
| pypa/pip | ec43c48b2f2d | INCONCLUSIVE | 3 | 0 | 0 | 0 | 0 | 0 | 90 binary, 6 executable, 1 git metadata | 1 |
| expressjs/express | 1c6f1b0fe400 | clean | 0 | 0 | 0 | 0 | 0 | 0 | 1 git metadata | 0 |
| microsoft/vscode | 1306698e328e | INCONCLUSIVE | 1 | 0 | 1 | 0 | 0 | 0 | 330 binary, 7 executable, 1 git metadata | 11 |
| git/git | 50fe5cc63f9c | clean | 0 | 0 | 0 | 0 | 0 | 0 | 16 binary, 1 git metadata | 3 |
| python/cpython | 47c249adf3bc | findings | 1 | 0 | 2 | 0 | 0 | 0 | 146 binary, 1 git metadata | 7 |
| microsoft/terminal | 703ef7f969d9 | INCONCLUSIVE | 3 | 0 | 0 | 0 | 0 | 0 | 1083 binary, 14 executable, 1 git metadata | 3 |

Seconds include the clone. "Binary" means a file with a known binary header or
with NUL bytes that does not read as text; the line rules read its ASCII only
and the report lists it as "binary format, ASCII rules only".

6 of 10 repositories are clean, 3 are INCONCLUSIVE only because of executables,
1 has findings.

## HIGH and CRITICAL findings

| Repository | File | Rule | Level | Verdict | Why |
|---|---|---|---|---|---|
| python/cpython | `Lib/test/archivetestdata/exe_with_zip:26`, `exe_with_z64:25` | `deception.nul-byte-in-script` | HIGH | False in intent | A bash script followed by a zip archive (test data for `zipfile`). The NUL is real, the file is not hiding anything. Issue 42 |
| microsoft/vscode | `extensions/copilot/.vscode/tasks.json:94` | `ide.vscode-folder-open-task` | HIGH | True detection, benign | The task "watch" does run when the folder is opened; it is an ordinary dev watch task. Issue 43 |

There are no CRITICAL findings.

## INCONCLUSIVE results

The report now lists every skipped file, the causes of INCONCLUSIVE first, so
each cause below is visible in the report itself.

| Repository | Cause |
|---|---|
| pypa/pip | 6 PE launchers in `src/pip/_vendor/distlib/` (`t32.exe`, `t64.exe`, `t64-arm.exe`, `w32.exe`, `w64.exe`, `w64-arm.exe`), all vendored script launchers |
| microsoft/vscode | 7 PE files: `build/lib/watch/watcher.exe`, `build/win32/inno_updater.exe`, `build/win32/vcruntime140.dll` and four PSReadLine `.dll` files under `src/vs/workbench/contrib/terminal/common/scripts/psreadline/` |
| microsoft/terminal | 14 PE files: 13 under `dep/WinAppDriver/` and `dep/nuget/nuget.exe` |

These follow the documented policy: an executable is code that nothing
analyzes yet. They go away when the "committed binaries" rule exists, because
such a file then becomes a finding. No repository is INCONCLUSIVE because of a
file size any more.

## What changed since the first run

The first run (commit `3d65b24`) gave 6 CRITICAL false positives, 3 INCONCLUSIVE
results and a report that listed 10 skipped files out of 1082. Changes made
because of it:

- Issue 41 (6 false CRITICAL): the bidi rule was not changed. A file with NUL
  bytes that is not text (icons, audio) is now read by the line rules as ASCII
  only, so a rule for a non-ASCII character cannot match noise. The first
  version of this fix listed such files as binary and never read them; the
  review showed that a shell can still source such a file, so they are read, as
  ASCII, with a "found in a binary-looking file" note on any finding.
- Issue 44: the report lists every skipped file, the causes of INCONCLUSIVE
  first.
- Issue 45: files from 5 MiB up to 100 MiB are read as a stream; only a file
  over 100 MiB, or a line over 16 MiB, still makes the scan INCONCLUSIVE.
  vscode's two large text files and terminal's `nuget.exe` no longer count as
  "too large" (`nuget.exe` is reported as an executable).

## Issues still open from this benchmark

- [#42](https://github.com/z3nghoul/repo-sniff/issues/42): nul-byte-in-script on a script with an appended archive
- [#43](https://github.com/z3nghoul/repo-sniff/issues/43): vscode-folder-open-task grading by the command

Filed from the reviews of the fixes: 49 (memory of the ASCII-only copy), 50
(decoy lines inside one rule), 51 (gaps and missing fixtures around
binary-looking files), 53 (streaming opens a file four times), 54 (a line over
16 MiB), 55 (wording for a streamed file selected by a whole-file rule).
