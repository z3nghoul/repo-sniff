# Benchmark on honest repositories

Date: 2026-11-01, second run. Scanner: `repo-sniff 0.1.0`, release build of a
local branch that merges the hardening pull requests into `main` (`6c671ad`):
#75 at `979fd45` (clone and secrets), #76 at `f238457` (symlinks, including
links in remote clones) and #77 at `1ddfa3c` (UTF-16 scripts). Each
repository was scanned from its default branch with `repo-sniff scan <url>`
(default `--fail-on high`) and a 600 second limit per repository including the
clone. No repository timed out or hit the file limit. Re-run with
`TIMEOUT=600 scripts/benchmark.sh`; the commits below are the heads that were
current at the time of the run (only cpython moved since the first run on
this page).

The target for honest repositories is 0 critical findings. **It is met:**
0 CRITICAL in all ten, and no repository is INCONCLUSIVE. The findings are the
same, file for file, as in the run with the repository contents family
(scanner commit `0383fc2`). The difference is in the list of entries that
were not fully analyzed: symbolic links in remote clones are now recognized
from the clone's index (#76), so cargo lists 121 links, cpython 4, git 3,
requests 2, ripgrep and vscode 1 each. None of them points outside its
repository, and none is a VS Code tasks file.

## Results

| Repository | Commit | Result | Exit | Critical | High | Medium | Low | Info | Not fully analyzed | Seconds |
|---|---|---|---|---|---|---|---|---|---|---|
| BurntSushi/ripgrep | 91f5d22ef48b | clean | 0 | 0 | 0 | 0 | 0 | 0 | 7 binary, 1 symlink, 1 git metadata | 1 |
| rust-lang/cargo | 809bcc525b61 | clean | 0 | 0 | 0 | 0 | 0 | 0 | 18 binary, 121 symlink, 1 git metadata | 1 |
| psf/requests | 3c7baaa05ab4 | findings | 0 | 0 | 0 | 0 | 1 | 0 | 6 binary, 2 symlink, 1 git metadata | 1 |
| pallets/flask | 49943b5a9441 | findings | 0 | 0 | 0 | 0 | 1 | 0 | 5 binary, 1 git metadata | 1 |
| pypa/pip | ec43c48b2f2d | findings | 1 | 0 | 6 | 0 | 0 | 0 | 90 binary, 6 executable, 1 git metadata | 1 |
| expressjs/express | 1c6f1b0fe400 | clean | 0 | 0 | 0 | 0 | 0 | 0 | 1 git metadata | 1 |
| microsoft/vscode | 1306698e328e | findings | 1 | 0 | 8 | 0 | 50 | 0 | 330 binary, 7 executable, 1 symlink, 1 git metadata | 14 |
| git/git | 50fe5cc63f9c | findings | 0 | 0 | 0 | 3 | 5 | 0 | 16 binary, 3 symlink, 1 git metadata | 5 |
| python/cpython | 9c0cfb141c23 | findings | 1 | 0 | 2 | 1 | 28 | 0 | 146 binary, 4 symlink, 1 git metadata | 9 |
| microsoft/terminal | 703ef7f969d9 | findings | 1 | 0 | 14 | 0 | 74 | 0 | 1083 binary, 14 executable, 1 git metadata | 4 |

Seconds include the clone. "Binary" means a file with a known binary header or
with NUL bytes that does not read as text; the line rules read its ASCII only.
"Executable" files are listed because nothing analyzes their code, but each
one is reported above as a finding, so they no longer make a scan
inconclusive. "Symlink" entries are listed as links, not followed; their
targets are judged when they are inside the repository.

## CRITICAL, HIGH and MEDIUM findings

| Repository | File | Rule | Level | Verdict | Why |
|---|---|---|---|---|---|
| pypa/pip | `src/pip/_vendor/distlib/{t32,t64,t64-arm,w32,w64,w64-arm}.exe` | `repo.committed-binary` | HIGH (6) | True detection, benign | Vendored distlib script launchers |
| microsoft/vscode | `build/lib/watch/watcher.exe`, `build/win32/inno_updater.exe`, `build/win32/vcruntime140.dll`, four PSReadLine `.dll` files | `repo.committed-binary` | HIGH (7) | True detection, benign | Build helpers, the installer updater, a runtime library and vendored PowerShell modules |
| microsoft/terminal | 13 files under `dep/WinAppDriver/`, `dep/nuget/nuget.exe` | `repo.committed-binary` | HIGH (14) | True detection, benign | A vendored UI test driver and NuGet |
| microsoft/vscode | `extensions/copilot/.vscode/tasks.json:94` | `ide.vscode-folder-open-task` | HIGH | True detection, benign | As before: a dev watch task that runs on folder open. Issue 43 |
| python/cpython | `Lib/test/archivetestdata/exe_with_zip:26`, `exe_with_z64:25` | `deception.nul-byte-in-script` | HIGH (2) | False in intent | As before: a shell script followed by a zip archive. Issue 42 |
| git/git | `git-gui/lib/win32_shortcut.js:4`, `:5`, `:27` | `repo.wsh-javascript` | MEDIUM (3) | True detection, benign | A real Windows Script Host script that creates shortcuts for git-gui |
| python/cpython | `Lib/test/empty.vbs` | `repo.windows-script` | MEDIUM | True detection, benign | An empty VBScript used by the test suite |

There are no CRITICAL findings. A first run of the repository contents branch reported
`dep/WinAppDriver/Newtonsoft.Json.dll` as a CRITICAL disguised executable
(".json" before ".dll" read as a double extension); dotted .NET assembly
names are now excluded, and a double extension counts only when the outer
extension runs on a double click and the inner one is a document, image,
media, archive or text lure.

## LOW findings

All LOW findings are `repo.windows-script` on command and PowerShell scripts:

| Repository | `.bat` | `.cmd` | `.ps1` | `.psm1` |
|---|---|---|---|---|
| psf/requests | 1 | | | |
| pallets/flask | 1 | | | |
| git/git | 3 | | 2 | |
| python/cpython | 26 | | 2 | |
| microsoft/vscode | 13 | 11 | 24 | 2 |
| microsoft/terminal | 18 | 20 | 35 | 1 |

They are build glue in Windows-heavy repositories; LOW keeps them in the
overall picture without failing anything. A repository with hundreds of them
needs the grouped "needs manual review" section of milestone 3.

## Levels for vendored launchers

The 27 committed executables above are HIGH, and none of them is disguised.
Before this family existed, any of them made the scan inconclusive (exit 3),
which is not a pass. HIGH keeps it a non-pass at the default threshold
(exit 1), and the report now names the file and says its code is not
analyzed. MEDIUM would turn a planted binary into exit 0. Nothing in the scan
can tell an upstream launcher from a replaced one; lowering the level needs
provenance (a hash allow-list or a code signature check), which is a later
item.

## INCONCLUSIVE results

None. In the earlier run, pip (6 PE launchers), vscode (7 PE files) and
terminal (14 PE files) were inconclusive only because of those executables;
they are the HIGH findings above.

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

## Earlier run (before the repository contents family)

On the heads of the first run (cpython has moved since), the scanner before this family (commit `a289486`) gave:
0 CRITICAL; pip, vscode and terminal INCONCLUSIVE only because of their
executables (exit 3, 1 with its HIGH finding, and 3); cpython 2 HIGH (issue 42); vscode 1 HIGH
(issue 43); the other six clean.

## Issues still open from this benchmark

- [#42](https://github.com/z3nghoul/repo-sniff/issues/42): nul-byte-in-script on a script with an appended archive
- [#43](https://github.com/z3nghoul/repo-sniff/issues/43): vscode-folder-open-task grading by the command

Filed from the reviews of the fixes: 49 (memory of the ASCII-only copy), 50
(decoy lines inside one rule), 51 (gaps and missing fixtures around
binary-looking files), 53 (streaming opens a file four times), 54 (a line over
16 MiB), 55 (wording for a streamed file selected by a whole-file rule).
