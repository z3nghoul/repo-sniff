# Benchmark on honest repositories

Date: 2026-11-03, best of three runs. Scanner: `repo-sniff 0.1.0`, release build
of `main` at `46b8501` (the merge of #107, the loader signatures). Each
repository was scanned from its default branch with `repo-sniff scan <url>`
(default `--fail-on high`), three times in a row, with a 300 second limit per
repository including the clone. The findings were the same in all three runs;
the table below gives the best scan time of the three. No repository timed out
or hit the file limit. Re-run with `scripts/benchmark.sh`. The history of the
earlier runs and families follows the current results.

The target for honest repositories is 0 critical findings. **It is met:**
0 CRITICAL in all ten, and no repository is INCONCLUSIVE. The findings are the
same, file for file, as in the run with the repository contents family
(scanner commit `0383fc2`). The difference is in the list of entries that
were not fully analyzed: symbolic links in remote clones are now recognized
from the clone's index (#76), so cargo lists 121 links, cpython 4, git 3,
requests 2, ripgrep and vscode 1 each. None of them points outside its
repository, and none is a VS Code tasks file.

## npm scripts family (run of 2026-11-02)

The rules `deps.npm-lifecycle-hook` and `run.npm-script-local-server` (#95) were
added and the same ten repositories were scanned again (heads in the table
below; the other columns of the Results table above did not change except for
vscode). The target holds: **0 CRITICAL and no INCONCLUSIVE** in all ten. Only
vscode has npm hooks that run files; it is the one honest repository that
reaches MEDIUM, as expected. Its totals (medium, low, info) go from 0 / 50 / 0
to 6 / 52 / 1: the new rules add 6 MEDIUM, 1 LOW and 1 INFO, and the head
moved since the table below (one more `repo.windows-script` LOW). The run scripts
rule found nothing in the ten repositories.

| Repository | File | Rule | Level | Verdict | Why |
|---|---|---|---|---|---|
| microsoft/vscode | `package.json:24`, `:25`, `extensions/package.json:10`, `extensions/copilot/package.json:6777`, `extensions/copilot/chat-lib/package.json:69`, one test fixture under `extensions/copilot/test/` | `deps.npm-lifecycle-hook` | MEDIUM (6) | True detection, benign | `preinstall` and `postinstall` that run `build/npm/preinstall.ts`, `build/npm/postinstall.ts` and similar local files: exactly the shape of the rule, and honest here |
| microsoft/vscode | `test/automation/package.json:18` | `deps.npm-lifecycle-hook` | LOW | True detection, benign | `prepublishOnly` (npm pack and publish, not install) that runs a local copy script |
| microsoft/vscode | `extensions/json-language-features/server/package.json:26` | `deps.npm-lifecycle-hook` | INFO | True detection, benign | `prepublishOnly` that runs `rimraf` |

### Honest JavaScript repositories, and the fail-closed change

The npm rules were also run on four large honest JavaScript repositories
(shallow clones, deleted after the run) with three builds: `107c7b3` (before
the second-review fixes), `ea40370` (after them) and the build with the
fail-closed change and the honest `npx` forms. "Family" counts only
`deps.npm-lifecycle-hook` and `run.npm-script-local-server`; C, H, M, L, I are
CRITICAL to INFO.

| Repository (head) | Before `ea40370`, family / all | After `ea40370`, family / all | After fail-closed, family / all |
|---|---|---|---|
| vitejs/vite (`b3cb057`) | L3 I2 / M9 L3 I2 | L3 I2 / M9 L3 I2 | L4 I1 / M9 L4 I1 |
| vuejs/core (`68f25a4`) | I2 / I2 | I2 / I2 | L1 I1 / L1 I1 |
| facebook/react (`76baa3b`) | H1 M2 L7 I3 / H1 M3 L7 I3 | H1 M2 L7 I3 / H1 M3 L7 I3 | H1 M2 L7 I3 / H1 M3 L7 I3 |
| nodejs/node (`76e8b64e`) | H1 M8 L26 I33 / C1 H3 M126 L82 I33 | H1 M8 L26 I33 / C1 H3 M126 L82 I33 | H1 M8 L12 I47 / C1 H3 M126 L68 I47 |

- The only CRITICAL, in nodejs/node, is `deception.bidi-control` in a Web
  Platform Tests data file (`test/fixtures/wpt/url/resources/urltestdata.json`).
  It is the same on `main` and is not caused by the npm rules
  ([#106](https://github.com/z3nghoul/repo-sniff/issues/106)). No scan is
  INCONCLUSIVE.
- Fail-closed adds no finding on these four repositories: no honest script is
  left unread. The changes are the honest forms: `npx only-allow pnpm` (vite,
  vue/core) goes from INFO to LOW, and `tshy` (14 vendored libraries in
  nodejs/node) from LOW to INFO.
- The two HIGH findings of the family are true detections of inline code in an
  install hook, and benign: nodejs/node `deps/npm/node_modules/postcss-selector-parser`
  runs `prepare` -> `build` -> `clean`, which is `node -e "require('fs').rmSync('dist', ...)"`;
  facebook/react `compiler/packages/snap` runs `perl -p -i -e` in `postinstall` to
  patch a dependency in `node_modules`. They are what the table says (inline
  code is HIGH), not noise from a parsing gap.
- The MEDIUM findings are install hooks that run a local file (for example
  react's `scripts/flow/createFlowConfigs.js`); many in nodejs/node are vendored
  packages whose `scripts/*.sh` are not published, so the finding says the file
  is not in the repository.

## Loader signatures family (run of 2026-11-03)

The rules `run.js-fetch-eval`, `run.js-function-require`,
`obfuscation.encoded-payload-sink`, `obfuscation.obfuscator-io`,
`obfuscation.minified-source`, `run.windows-remote-code`,
`obfuscation.windows-encoded-payload` and `run.windows-defender-exclusion` (#96)
were added. The ten repositories above were scanned again from shallow clones
(the "Before" column is the build of `main` with the npm scripts family, the
"After" column the build with this family; both on the same clone). The target
holds: **0 CRITICAL and no INCONCLUSIVE** in all ten. The two repositories whose
counts changed:

| Repository (head) | Before (C H M L I) | After (C H M L I) | Scan time before / after |
|---|---|---|---|
| microsoft/vscode (`763ca42b86dc`) | 0 8 6 52 1 | 0 9 13 52 1 | 1.9 s / 6.4 s |
| python/cpython (`3945eaf2fcd9`) | 0 2 1 28 0 | 0 2 1 28 3 | 0.6 s / 0.7 s |

- vscode, 1 HIGH: `src/vs/workbench/api/worker/extHostExtensionService.ts:87`
  builds a function with `new Function` from a source it fetched (it loads an
  extension into a web worker). True detection, benign; HIGH and not CRITICAL
  because the file writes no URL.
- vscode, 7 MEDIUM: `obfuscation.minified-source` on generated TypeScript with
  lines of 2000 to 17000 characters (protocol type unions, `semver.js`) and on
  two test files. True detections (the lines are long, with little whitespace),
  benign.
- cpython, 3 INFO: `Lib/profiling/sampling/_vendor/d3*/**/*.min.js`, vendored
  minified bundles. They are INFO because of the `.min.` in the name, not
  silent.

The other eight repositories are unchanged. The rules read every JavaScript
and Windows script file, so scans of repositories with much JavaScript are
slower (vscode 1.9 s to 6.4 s, the clone not counted); the others are within
10 %.

### Honest JavaScript repositories

The same four repositories as for the npm scripts family (shallow clones in a
temporary folder, deleted after the run). nodejs/node has moved since the
earlier table (`a1e1a743`), so its Before column is a new run of the build
before this family on the same clone.

| Repository (head) | Before (C H M L I) | After (C H M L I) | Scan time before / after |
|---|---|---|---|
| vitejs/vite (`b3cb0575`) | 0 0 9 4 1 | 0 0 9 4 1 | 0.2 s / 0.5 s |
| vuejs/core (`68f25a4a`) | 0 0 0 1 1 | 0 0 0 1 1 | 0.05 s / 0.2 s |
| facebook/react (`76baa3b5`) | 0 1 3 7 3 | 0 2 4 7 3 | 0.4 s / 1.9 s |
| nodejs/node (`a1e1a743`) | 1 3 126 68 47 | 1 8 141 68 60 | 3.9 s / 11.9 s |

The one CRITICAL in nodejs/node is the same `deception.bidi-control` in a Web
Platform Tests data file as before
([#106](https://github.com/z3nghoul/repo-sniff/issues/106)). **The loader family
gives no CRITICAL on any of the four.** No scan is INCONCLUSIVE. What the family
reports there:

| Repository | File | Rule | Level | Verdict | Why |
|---|---|---|---|---|---|
| facebook/react | `fixtures/attribute-behavior/src/App.js:842` | `run.js-fetch-eval` | HIGH | True detection, benign | A test page fetches the React builds from a CDN and `eval`s them. Browser code (`window`, `document`, no Node.js feature), so one level below the rule |
| facebook/react | `packages/react-dom-bindings/.../ReactDOMFizzInstructionSetInlineCodeStrings.js:11` | `obfuscation.minified-source` | MEDIUM | True detection, benign | A line of 2705 characters of inline script held as a string |
| nodejs/node | `test/fixtures/wpt/common/dispatcher/dispatcher.js:241` | `run.js-fetch-eval` | HIGH | True detection, benign | The Web Platform Tests dispatcher evaluates a function it receives from the test server; the file writes no URL |
| nodejs/node | `deps/amaro/dist/index.js:370` | `obfuscation.encoded-payload-sink` | HIGH | True detection, benign | wasm-bindgen glue builds a function from a string in wasm memory |
| nodejs/node | `deps/v8/test/mjsunit/regress/regress-559266116.js:11`, `:19`, `deps/v8/tools/clusterfuzz/js_fuzzer/test_data/mutate_unicode_string_literal_expected.js:19` | `obfuscation.encoded-payload-sink` | HIGH (3) | True detection, benign | Engine tests that `eval` a string made of character codes or `\x` escapes |
| nodejs/node | `tools/msvs/install_tools/install_tools.bat:55` | `run.windows-remote-code` | MEDIUM | True detection, benign | The Chocolatey installer, run with `iex` and `DownloadString` as its documentation says: the address is on the list of known installers |
| nodejs/node | `deps/corepack/dist/lib/corepack.cjs:5207`, `deps/undici/undici.js:910`, `deps/npm/node_modules/glob/dist/{commonjs,esm}/index.min.js:3`, `test/fixtures/wpt/resources/idlharness.js:1762` | `run.js-fetch-eval` | MEDIUM (5) | Review by hand, benign | A function is looked up on `globalThis` or `this` by a name that is a variable, in a file that also calls `fetch`: the call the check cannot follow |
| nodejs/node | 10 files under `deps/v8/test/`, `test/fixtures/source-map/` | `obfuscation.minified-source` | MEDIUM (10) | True detection, benign | Lines of 2000 to 14000 characters in test data (regular expression tables, inline source maps) |

### What the first runs changed

The first run of the family on these four repositories gave five CRITICAL
findings on honest code. All five were read, and each led to a change that is
tested by a fixture or a unit test:

- `deps/corepack/dist/lib/corepack.cjs`: `new vm.Script(wrapper, { cachedData })`
  was CRITICAL. Taint was kept per name for the whole file (a bundle holds
  thousands of functions with a parameter called `content`), and `obj.prop =
  tainted` tainted `obj`. Now declarations and parameters give names a scope,
  taint is kept per path (`this.body`), and only the first argument of `eval`,
  `vm.*` and `_compile` is code.
- `test/fixtures/postject-copy/node_modules/postject/dist/api.js`: the same
  scope problem (`new Function("body", ...)(body)` with a `name` tainted in
  another function).
- `test/fixtures/wpt/common/dispatcher/dispatcher.js` and React's
  `attribute-behavior/App.js` are true flows. A file that writes no URL, or that
  is browser code, is held one level below the rule (HIGH); a file that writes
  the address of a remote host and has any Node.js feature stays CRITICAL, as
  every sample in the corpus does.
- `tools/msvs/install_tools/install_tools.bat`: the Chocolatey installer. A
  short list of known installer addresses lowers an `iex` line to MEDIUM when
  every URL on it is, as a whole, on the list.
- Also: 8 `obfuscation.encoded-payload-sink` findings from `String.fromCharCode`
  with one code and `\u` escapes in text (now 8 codes, 16 `\x` or 32 `\u`
  escapes), `vm.Script(code, { cachedData: Buffer.from(b64, "base64") })` (the
  options are not code), and two React components reported as unreadable
  because JSX text has apostrophes and closing tags (only a problem that can hide
  a later line is reported).

The scan of the corpus `rubenmarcus/malicious-repositories` at `dc82f33` (not
committed anywhere): 15 folders. After the npm scripts family one folder was
MEDIUM and none was above it; after this family 8 folders are CRITICAL and 1 is
HIGH (its address is not written in the file). Five folders stay LOW or MEDIUM:
two of them carry their payload in the names of dependencies (milestone 9), the
others have no JavaScript loader. The table of folders is in the pull request.

## Results

| Repository | Commit | Result | Exit | Critical | High | Medium | Low | Info | Not fully analyzed | Scan time (best of 3) |
|---|---|---|---|---|---|---|---|---|---|---|
| BurntSushi/ripgrep | 91f5d22ef48b | clean | 0 | 0 | 0 | 0 | 0 | 0 | 7 binary, 1 symlink, 1 git metadata | 38 ms |
| rust-lang/cargo | 2be5575ba36b | clean | 0 | 0 | 0 | 0 | 0 | 0 | 18 binary, 121 symlink, 1 git metadata | 302 ms |
| psf/requests | 3c7baaa05ab4 | findings | 0 | 0 | 0 | 0 | 1 | 0 | 6 binary, 2 symlink, 1 git metadata | 76 ms |
| pallets/flask | 49943b5a9441 | findings | 0 | 0 | 0 | 0 | 1 | 0 | 5 binary, 1 git metadata | 35 ms |
| pypa/pip | 42f71db06688 | findings | 1 | 0 | 6 | 0 | 0 | 0 | 90 binary, 6 executable, 1 git metadata | 263 ms |
| expressjs/express | 43fca52d28a4 | clean | 0 | 0 | 0 | 0 | 0 | 0 | 1 git metadata | 33 ms |
| microsoft/vscode | 5d029124799a | findings | 1 | 0 | 9 | 13 | 52 | 1 | 330 binary, 7 executable, 1 symlink, 1 git metadata | 11.0 s |
| git/git | ebdc087dc99d | findings | 0 | 0 | 0 | 3 | 5 | 0 | 16 binary, 3 symlink, 1 git metadata | 643 ms |
| python/cpython | 3945eaf2fcd9 | findings | 1 | 0 | 2 | 1 | 28 | 3 | 146 binary, 4 symlink, 1 git metadata | 1.5 s |
| microsoft/terminal | 188822fa51db | findings | 1 | 0 | 14 | 0 | 74 | 0 | 1083 binary, 14 executable, 1 git metadata | 997 ms |

Scan time is the time the scanner reports, without the clone: the best of three runs on the same clone (the findings were identical in all three).

"Binary" means a file with a known binary header or
with NUL bytes that does not read as text; the line rules read its ASCII only.
"Executable" files are listed because nothing analyzes their code, but each
one is reported above as a finding, so they no longer make a scan
inconclusive. "Symlink" entries are listed as links and not followed,
except that a link a check reads through (a VS Code tasks file,
a `.code-workspace`, a `.pth` or `.start` file) is judged by its target when
that is a regular file inside the repository. Every link is checked for
pointing outside the repository.

## CRITICAL, HIGH and MEDIUM findings

| Repository | File | Rule | Level | Verdict | Why |
|---|---|---|---|---|---|
| pypa/pip | `src/pip/_vendor/distlib/{t32,t64,t64-arm,w32,w64,w64-arm}.exe` | `repo.committed-binary` | HIGH (6) | True detection, benign | Vendored distlib script launchers |
| microsoft/vscode | `build/lib/watch/watcher.exe`, `build/win32/inno_updater.exe`, `build/win32/vcruntime140.dll`, four PSReadLine `.dll` files | `repo.committed-binary` | HIGH (7) | True detection, benign | Build helpers, the installer updater, a runtime library and vendored PowerShell modules |
| microsoft/terminal | 13 files under `dep/WinAppDriver/`, `dep/nuget/nuget.exe` | `repo.committed-binary` | HIGH (14) | True detection, benign | A vendored UI test driver and NuGet |
| microsoft/vscode | `extensions/copilot/.vscode/tasks.json:94` | `ide.vscode-folder-open-task` | HIGH | True detection, benign | As before: a dev watch task that runs on folder open. Issue 43 |
| microsoft/vscode | `src/vs/workbench/api/worker/extHostExtensionService.ts:87` | `run.js-fetch-eval` | HIGH | True detection, benign | The extension host builds a function with `new Function` from a source it fetched, to load an extension into a web worker; the file writes no URL, so HIGH. See the loader signatures run |
| microsoft/vscode | 6 `package.json` lifecycle hooks and 7 files of minified-looking source | `deps.npm-lifecycle-hook`, `obfuscation.minified-source` | MEDIUM (13) | True detection, benign | Hooks that run local files; generated TypeScript and test files with very long lines. See the npm scripts and loader signatures runs |
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
