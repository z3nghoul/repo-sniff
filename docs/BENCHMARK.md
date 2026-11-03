# benchmark on honest repositories

How repo-sniff behaves on popular honest repositories, and how to check it
yourself. It is for users who want to know how noisy the scanner is and for
contributors who change a rule. The target for honest repositories is
**0 CRITICAL findings**, and no scan should be INCONCLUSIVE.

## contents

- [how to reproduce](#how-to-reproduce)
- [results](#results)
- [CRITICAL, HIGH and MEDIUM findings](#critical-high-and-medium-findings)
- [LOW findings](#low-findings)
- [levels for vendored launchers](#levels-for-vendored-launchers)
- [honest JavaScript repositories](#honest-javascript-repositories)
- [malicious corpus](#malicious-corpus)
- [history](#history)

## how to reproduce

```sh
scripts/benchmark.sh [OUT_DIR]
```

The script builds a release binary, scans the ten repositories of the table
below from their default branch with `repo-sniff scan <url>` (default
`--fail-on high`), and writes one raw report per repository plus a
`results.tsv` summary to `OUT_DIR` (default `bench-out`). It needs cargo, git,
a network connection and GNU `timeout`. Each repository gets 300 seconds
including the clone (`TIMEOUT` changes it); a repository that takes longer is
recorded as `timeout`.

The current run:

- **Date:** 2026-11-03, best of three runs.
- **Scanner:** `repo-sniff 0.1.0`, release build of `main` at `46b8501` (the
  merge of #107, the loader signatures).
- Each repository was scanned three times in a row. The findings were the
  same in all three runs; the table gives the best scan time of the three. No
  repository timed out or hit the file limit.

## results

**The target is met:** 0 CRITICAL in all ten, and no repository is
INCONCLUSIVE.

| Repository | Commit | Result | Exit | Critical | High | Medium | Low | Info | Not fully analyzed | Scan time |
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

How to read the table:

- **Scan time** is the time the scanner reports, without the clone: the best
  of three runs on the same clone (the findings were identical in all three).
- **Binary** means a file with a known binary header or with NUL bytes that
  does not read as text; the line rules read its ASCII only.
- **Executable** files are listed because nothing analyzes their code, but
  each one is reported below as a finding, so they no longer make a scan
  inconclusive.
- **Symlink** entries are listed as links and not followed, except that a
  link a check reads through (a VS Code tasks file, a `.code-workspace`, a
  `.pth` or `.start` file) is judged by its target when that is a regular file
  inside the repository. Every link is checked for pointing outside the
  repository. None of the links in the table points outside its repository,
  and none is a VS Code tasks file.

## CRITICAL, HIGH and MEDIUM findings

There are no CRITICAL findings. Every HIGH and MEDIUM finding is a true
detection of honest code, except one false positive in intent.

| Repository | Where | Rule | Level | Verdict |
|---|---|---|---|---|
| pypa/pip | `src/pip/_vendor/distlib/{t32,t64,t64-arm,w32,w64,w64-arm}.exe` | `repo.committed-binary` | HIGH (6) | True detection, benign |
| microsoft/vscode | 7 committed executables and libraries | `repo.committed-binary` | HIGH (7) | True detection, benign |
| microsoft/terminal | 13 files under `dep/WinAppDriver/`, `dep/nuget/nuget.exe` | `repo.committed-binary` | HIGH (14) | True detection, benign |
| microsoft/vscode | `extensions/copilot/.vscode/tasks.json:94` | `ide.vscode-folder-open-task` | HIGH | True detection, benign |
| microsoft/vscode | `src/vs/workbench/api/worker/extHostExtensionService.ts:87` | `run.js-fetch-eval` | HIGH | True detection, benign |
| microsoft/vscode | 6 `package.json` hooks, 7 minified-looking files | `deps.npm-lifecycle-hook`, `obfuscation.minified-source` | MEDIUM (13) | True detection, benign |
| python/cpython | `Lib/test/archivetestdata/exe_with_zip:26`, `exe_with_z64:25` | `deception.nul-byte-in-script` | HIGH (2) | False in intent |
| git/git | `git-gui/lib/win32_shortcut.js:4`, `:5`, `:27` | `repo.wsh-javascript` | MEDIUM (3) | True detection, benign |
| python/cpython | `Lib/test/empty.vbs` | `repo.windows-script` | MEDIUM | True detection, benign |

Why each one is there:

- **pip:** vendored distlib script launchers.
- **vscode, executables:** `build/lib/watch/watcher.exe`,
  `build/win32/inno_updater.exe`, `build/win32/vcruntime140.dll` and four
  PSReadLine `.dll` files: build helpers, the installer updater, a runtime
  library and vendored PowerShell modules.
- **terminal:** a vendored UI test driver and NuGet.
- **vscode, folder-open task:** a dev watch task that runs on folder open
  ([#43](https://github.com/z3nghoul/repo-sniff/issues/43)).
- **vscode, `run.js-fetch-eval`:** the extension host builds a function with
  `new Function` from a source it fetched, to load an extension into a web
  worker. The file writes no URL, so HIGH and not CRITICAL.
- **vscode, MEDIUM (13):** `preinstall` and `postinstall` hooks in
  `package.json:24`, `:25`, `extensions/package.json:10`,
  `extensions/copilot/package.json:6777`,
  `extensions/copilot/chat-lib/package.json:69` and one test fixture under
  `extensions/copilot/test/`, which run `build/npm/preinstall.ts`,
  `build/npm/postinstall.ts` and similar local files: exactly the shape of the
  rule, and honest here. The 7 `obfuscation.minified-source` findings are
  generated TypeScript with lines of 2000 to 17000 characters (protocol type
  unions, `semver.js`) and two test files.
- **cpython, NUL byte:** a shell script followed by a zip archive
  ([#42](https://github.com/z3nghoul/repo-sniff/issues/42)).
- **git:** a real Windows Script Host script that creates shortcuts for
  git-gui.
- **cpython, `empty.vbs`:** an empty VBScript used by the test suite.

The LOW and INFO findings of vscode besides `repo.windows-script`:
`test/automation/package.json:18`, a `prepublishOnly` (npm runs it only on
`npm publish`, not on install or pack) that runs a local copy script (LOW), and
`extensions/json-language-features/server/package.json:26`, a
`prepublishOnly` that runs `rimraf` (INFO). The 3 INFO findings of cpython
are `Lib/profiling/sampling/_vendor/d3*/**/*.min.js`, vendored minified
bundles: INFO because of the `.min.` in the name, not silent.

## LOW findings

The other LOW findings are `repo.windows-script` on command and PowerShell
scripts:

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

## levels for vendored launchers

The 27 committed executables above are HIGH, and none of them is disguised.
Before the repository contents family existed, any of them made the scan
inconclusive (exit 3), which is not a pass. HIGH keeps it a non-pass at the
default threshold (exit 1), and the report now names the file and says its
code is not analyzed. MEDIUM would turn a planted binary into exit 0. Nothing
in the scan can tell an upstream launcher from a replaced one; lowering the
level needs provenance (a hash allow-list or a code signature check), which is
a later item.

<a id="loader-signatures-family-run-of-2026-11-03"></a>

## honest JavaScript repositories

The npm and loader rules read every `package.json`, JavaScript and Windows
script file, so they were also run on four large honest JavaScript
repositories (shallow clones in a temporary folder, deleted after the run).
C, H, M, L, I are CRITICAL to INFO, counted over all rules.

| Repository (head) | C H M L I | Scan time |
|---|---|---|
| vitejs/vite (`b3cb0575`) | 0 0 9 4 1 | 0.5 s |
| vuejs/core (`68f25a4a`) | 0 0 0 1 1 | 0.2 s |
| facebook/react (`76baa3b5`) | 0 2 4 7 3 | 1.9 s |
| nodejs/node (`a1e1a743`) | 1 8 141 68 60 | 11.9 s |

The one CRITICAL in nodejs/node was `deception.bidi-control` in a Web
Platform Tests data file (`test/fixtures/wpt/url/resources/urltestdata.json`).
Since [#106](https://github.com/z3nghoul/repo-sniff/issues/106) a bidi control
inside a string value of JSON data is MEDIUM: on nodejs/node at head
`22657630` that line (`:2426`) is MEDIUM, "bidi controls in data; not executed
as code", and the other levels are as before except for the heads that moved.
**So all four give 0 CRITICAL**, and no scan is INCONCLUSIVE.

What the loader family reports there:

| Repository | Where | Rule | Level | Verdict |
|---|---|---|---|---|
| facebook/react | `fixtures/attribute-behavior/src/App.js:842` | `run.js-fetch-eval` | HIGH | True detection, benign |
| facebook/react | `packages/react-dom-bindings/.../ReactDOMFizzInstructionSetInlineCodeStrings.js:11` | `obfuscation.minified-source` | MEDIUM | True detection, benign |
| nodejs/node | `test/fixtures/wpt/common/dispatcher/dispatcher.js:241` | `run.js-fetch-eval` | HIGH | True detection, benign |
| nodejs/node | `deps/amaro/dist/index.js:370` | `obfuscation.encoded-payload-sink` | HIGH | True detection, benign |
| nodejs/node | 3 V8 test files | `obfuscation.encoded-payload-sink` | HIGH (3) | True detection, benign |
| nodejs/node | `tools/msvs/install_tools/install_tools.bat:55` | `run.windows-remote-code` | MEDIUM | True detection, benign |
| nodejs/node | 5 files that look up a function by a variable name | `run.js-fetch-eval` | MEDIUM (5) | Review by hand, benign |
| nodejs/node | 10 files under `deps/v8/test/`, `test/fixtures/source-map/` | `obfuscation.minified-source` | MEDIUM (10) | True detection, benign |

Why each one is there:

- **react, `App.js`:** a test page fetches the React builds from a CDN and
  `eval`s them. Browser code (`window`, `document`, no Node.js feature), so one
  level below the rule.
- **react, inline script:** a line of 2705 characters of inline script held as
  a string.
- **node, dispatcher:** the Web Platform Tests dispatcher evaluates a function
  it receives from the test server; the file writes no URL.
- **node, amaro:** wasm-bindgen glue builds a function from a string in wasm
  memory.
- **node, V8 tests:** `deps/v8/test/mjsunit/regress/regress-559266116.js:11`,
  `:19` and
  `deps/v8/tools/clusterfuzz/js_fuzzer/test_data/mutate_unicode_string_literal_expected.js:19`,
  engine tests that `eval` a string made of character codes or `\x` escapes.
- **node, Chocolatey:** the Chocolatey installer, run with `iex` and
  `DownloadString` as its documentation says: the address is on the list of
  known installers.
- **node, review by hand:** `deps/corepack/dist/lib/corepack.cjs:5207`,
  `deps/undici/undici.js:910`,
  `deps/npm/node_modules/glob/dist/{commonjs,esm}/index.min.js:3`,
  `test/fixtures/wpt/resources/idlharness.js:1762`. A function is looked up on
  `globalThis` or `this` by a name that is a variable, in a file that also
  calls `fetch`: the call the check cannot follow.
- **node, minified:** lines of 2000 to 14000 characters in test data (regular
  expression tables, inline source maps).

The npm family alone on these repositories:

| Repository | `deps.npm-lifecycle-hook` and `run.npm-script-local-server` |
|---|---|
| vitejs/vite | L4 I1 |
| vuejs/core | L1 I1 |
| facebook/react | H1 M2 L7 I3 |
| nodejs/node | H1 M8 L12 I47 |

- The two HIGH findings are true detections of inline code in an install
  hook, and benign: nodejs/node `deps/npm/node_modules/postcss-selector-parser`
  runs `prepare` -> `build` -> `clean`, which is `node -e
  "require('fs').rmSync('dist', ...)"`; facebook/react
  `compiler/packages/snap` runs `perl -p -i -e` in `postinstall` to patch a
  dependency in `node_modules`. They are what the rule says (inline code is
  HIGH), not noise from a parsing gap.
- The MEDIUM findings are install hooks that run a local file (for example
  react's `scripts/flow/createFlowConfigs.js`); many in nodejs/node are
  vendored packages whose `scripts/*.sh` are not published, so the finding
  says the file is not in the repository.
- `npx only-allow pnpm` (vite, vue/core) is LOW and `tshy` (14 vendored
  libraries in nodejs/node) is INFO.

## malicious corpus

The corpus `rubenmarcus/malicious-repositories` at `dc82f33` (scanned in a
temporary folder, not committed anywhere) has 15 folders.

| Scanner | Folders at CRITICAL | At HIGH | Highest otherwise |
|---|---|---|---|
| After the npm scripts family | 0 | 0 | 1 folder MEDIUM |
| After the loader signatures family | 8 | 1 | 5 folders LOW or MEDIUM |

The HIGH folder does not write its address in the file. Of the five that stay
LOW or MEDIUM, two carry their payload in the names of dependencies
(milestone 9), the others have no JavaScript loader. The table of folders is
in pull request #107.

## history

Earlier runs, newest first. The numbers in each one are those of its own
scanner build and repository heads.

<details>
<summary>2026-11-03: bidi controls in JSON data (#106)</summary>

A bidi control inside a string value of a JSON data file is MEDIUM now, not
CRITICAL. The ten repositories of the results table and vite, vuejs/core,
react and nodejs/node were scanned again with a release build of the fix.
Result: **0 CRITICAL in all fourteen, and no scan is INCONCLUSIVE.**
nodejs/node (head `22657630`) reports
`test/fixtures/wpt/url/resources/urltestdata.json:2426` as MEDIUM, "bidi
controls in data; not executed as code", and no other `deception.bidi-control`
finding; the other thirteen have none. The other levels are as before except
for the repository heads that moved.

</details>

<details>
<summary>2026-11-03: loader signatures family (#96)</summary>

The rules `run.js-fetch-eval`, `run.js-function-require`,
`obfuscation.encoded-payload-sink`, `obfuscation.obfuscator-io`,
`obfuscation.minified-source`, `run.windows-remote-code`,
`obfuscation.windows-encoded-payload` and `run.windows-defender-exclusion`
were added. The ten repositories were scanned again from shallow clones (the
"Before" column is the build of `main` with the npm scripts family, the
"After" column the build with this family; both on the same clone). The target
holds: **0 CRITICAL and no INCONCLUSIVE** in all ten. The two repositories
whose counts changed:

| Repository (head) | Before (C H M L I) | After (C H M L I) | Scan time before / after |
|---|---|---|---|
| microsoft/vscode (`763ca42b86dc`) | 0 8 6 52 1 | 0 9 13 52 1 | 1.9 s / 6.4 s |
| python/cpython (`3945eaf2fcd9`) | 0 2 1 28 0 | 0 2 1 28 3 | 0.6 s / 0.7 s |

- vscode, 1 HIGH: `extHostExtensionService.ts:87` (see the findings above).
- vscode, 7 MEDIUM: `obfuscation.minified-source` on generated TypeScript and
  two test files.
- cpython, 3 INFO: vendored minified d3 bundles.

The other eight repositories are unchanged. The rules read every JavaScript
and Windows script file, so scans of repositories with much JavaScript are
slower (vscode 1.9 s to 6.4 s, the clone not counted); the others are within
10 %.

On the four JavaScript repositories, nodejs/node had moved since the npm run
(`a1e1a743`), so its Before column is a new run of the build before this
family on the same clone:

| Repository (head) | Before (C H M L I) | After (C H M L I) | Scan time before / after |
|---|---|---|---|
| vitejs/vite (`b3cb0575`) | 0 0 9 4 1 | 0 0 9 4 1 | 0.2 s / 0.5 s |
| vuejs/core (`68f25a4a`) | 0 0 0 1 1 | 0 0 0 1 1 | 0.05 s / 0.2 s |
| facebook/react (`76baa3b5`) | 0 1 3 7 3 | 0 2 4 7 3 | 0.4 s / 1.9 s |
| nodejs/node (`a1e1a743`) | 1 3 126 68 47 | 1 8 141 68 60 | 3.9 s / 11.9 s |

**The loader family gave no CRITICAL on any of the four.**

What the first runs changed. The first run of the family on these four
repositories gave five CRITICAL findings on honest code. All five were read,
and each led to a change that is tested by a fixture or a unit test:

- `deps/corepack/dist/lib/corepack.cjs`: `new vm.Script(wrapper, {
  cachedData })` was CRITICAL. Taint was kept per name for the whole file (a
  bundle holds thousands of functions with a parameter called `content`), and
  `obj.prop = tainted` tainted `obj`. Now declarations and parameters give
  names a scope, taint is kept per path (`this.body`), and only the first
  argument of `eval`, `vm.*` and `_compile` is code.
- `test/fixtures/postject-copy/node_modules/postject/dist/api.js`: the same
  scope problem (`new Function("body", ...)(body)` with a `name` tainted in
  another function).
- `test/fixtures/wpt/common/dispatcher/dispatcher.js` and React's
  `attribute-behavior/App.js` are true flows. A file that writes no URL, or
  that is browser code, is held one level below the rule (HIGH); a file that
  writes the address of a remote host and has any Node.js feature stays
  CRITICAL, as every sample in the corpus does.
- `tools/msvs/install_tools/install_tools.bat`: the Chocolatey installer. A
  short list of known installer addresses lowers an `iex` line to MEDIUM when
  every URL on it is, as a whole, on the list.
- Also: 8 `obfuscation.encoded-payload-sink` findings from
  `String.fromCharCode` with one code and `\u` escapes in text (now 8 codes,
  16 `\x` or 32 `\u` escapes), `vm.Script(code, { cachedData:
  Buffer.from(b64, "base64") })` (the options are not code), and two React
  components reported as unreadable because JSX text has apostrophes and
  closing tags (only a problem that can hide a later line is reported).

</details>

<details>
<summary>2026-11-02: npm scripts family (#95)</summary>

The rules `deps.npm-lifecycle-hook` and `run.npm-script-local-server` were
added and the same ten repositories were scanned again. The target holds:
**0 CRITICAL and no INCONCLUSIVE** in all ten. Only vscode has npm hooks that
run files; it is the one honest repository that reaches MEDIUM, as expected.
Its totals (medium, low, info) go from 0 / 50 / 0 to 6 / 52 / 1: the new rules
add 6 MEDIUM, 1 LOW and 1 INFO, and the head moved since the previous run (one
more `repo.windows-script` LOW). The run scripts rule found nothing in the ten
repositories.

On the four JavaScript repositories the rules were run with three builds:
`107c7b3` (before the second-review fixes), `ea40370` (after them) and the
build with the fail-closed change and the honest `npx` forms. "Family" counts
only `deps.npm-lifecycle-hook` and `run.npm-script-local-server`.

| Repository (head) | Before `ea40370`, family / all | After `ea40370`, family / all | After fail-closed, family / all |
|---|---|---|---|
| vitejs/vite (`b3cb057`) | L3 I2 / M9 L3 I2 | L3 I2 / M9 L3 I2 | L4 I1 / M9 L4 I1 |
| vuejs/core (`68f25a4`) | I2 / I2 | I2 / I2 | L1 I1 / L1 I1 |
| facebook/react (`76baa3b`) | H1 M2 L7 I3 / H1 M3 L7 I3 | H1 M2 L7 I3 / H1 M3 L7 I3 | H1 M2 L7 I3 / H1 M3 L7 I3 |
| nodejs/node (`76e8b64e`) | H1 M8 L26 I33 / C1 H3 M126 L82 I33 | H1 M8 L26 I33 / C1 H3 M126 L82 I33 | H1 M8 L12 I47 / C1 H3 M126 L68 I47 |

- The only CRITICAL, in nodejs/node, was the `deception.bidi-control` finding
  in Web Platform Tests data, the same on `main` and not caused by the npm
  rules (#106). No scan was INCONCLUSIVE.
- Fail-closed added no finding on these four repositories: no honest script
  is left unread. The changes are the honest forms: `npx only-allow pnpm`
  (vite, vue/core) went from INFO to LOW, and `tshy` (14 vendored libraries in
  nodejs/node) from LOW to INFO.

</details>

<details>
<summary>Symlinks in remote clones (#76)</summary>

Symbolic links in remote clones are recognized from the clone's index, so
cargo lists 121 links, cpython 4, git 3, requests 2, ripgrep and vscode 1
each. None of them points outside its repository, and none is a VS Code tasks
file. The findings were the same, file for file, as in the run with the
repository contents family (scanner commit `0383fc2`); only the list of
entries that were not fully analyzed changed.

</details>

<details>
<summary>Repository contents family</summary>

A first run of the repository contents branch reported
`dep/WinAppDriver/Newtonsoft.Json.dll` as a CRITICAL disguised executable
(".json" before ".dll" read as a double extension); dotted .NET assembly names
are now excluded, and a double extension counts only when the outer extension
runs on a double click and the inner one is a document, image, media, archive
or text lure.

INCONCLUSIVE results: none. In the earlier run, pip (6 PE launchers), vscode
(7 PE files) and terminal (14 PE files) were inconclusive only because of
those executables; they are the HIGH findings above.

Before this family, on the heads of the first run (cpython has moved since),
the scanner (commit `a289486`) gave: 0 CRITICAL; pip, vscode and terminal
INCONCLUSIVE only because of their executables (exit 3, 1 with its HIGH
finding, and 3); cpython 2 HIGH (issue 42); vscode 1 HIGH (issue 43); the
other six clean.

</details>

<details>
<summary>The first run and what it changed</summary>

The first run (commit `3d65b24`) gave 6 CRITICAL false positives, 3
INCONCLUSIVE results and a report that listed 10 skipped files out of 1082.
Changes made because of it:

- Issue 41 (6 false CRITICAL): the bidi rule was not changed. A file with NUL
  bytes that is not text (icons, audio) is now read by the line rules as ASCII
  only, so a rule for a non-ASCII character cannot match noise. The first
  version of this fix listed such files as binary and never read them; the
  review showed that a shell can still source such a file, so they are read,
  as ASCII, with a "found in a binary-looking file" note on any finding.
- Issue 44: the report lists every skipped file, the causes of INCONCLUSIVE
  first.
- Issue 45: files from 5 MiB up to 100 MiB are read as a stream; only a file
  over 100 MiB, or a line over 16 MiB, still makes the scan INCONCLUSIVE.
  vscode's two large text files and terminal's `nuget.exe` no longer count as
  "too large" (`nuget.exe` is reported as an executable).

Issues still open from this benchmark:

- [#42](https://github.com/z3nghoul/repo-sniff/issues/42): nul-byte-in-script
  on a script with an appended archive
- [#43](https://github.com/z3nghoul/repo-sniff/issues/43):
  vscode-folder-open-task grading by the command

Filed from the reviews of the fixes: 49 (memory of the ASCII-only copy), 50
(decoy lines inside one rule), 51 (gaps and missing fixtures around
binary-looking files), 53 (streaming opens a file four times), 54 (a line over
16 MiB), 55 (wording for a streamed file selected by a whole-file rule).

</details>
