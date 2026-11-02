# Detection catalog and threat model

This document is the source of truth for **what repo-sniff detects** and
**why**. It is kept in sync with the code: every rule that lands in the
scanner updates its row here.

- **Rule** column: the rule ID that implements the detection, or `—` if it
  is not implemented yet.
- **ATT&CK** column: the related [MITRE ATT&CK](https://attack.mitre.org/)
  technique, where one fits. The same ID is shown in the scan report.

**Coverage goal:** catch risks at *every* step of the path
"download → open in IDE → install dependencies → build → run tests → run the
program", not only in the program's own code.

---

## Severity levels

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

- **Trigger** — how automatically the code runs (on IDE open, on install, on
  build, only when the user runs the program).
- **Capability** — how dangerous the action is.
- **Concealment** — obfuscation and tricks that deceive the human reviewer.

---

## 1. Detections by stage

### Stage 0: the repository itself (freshly cloned)

| Detection | Level | ATT&CK | Rule |
|---|---|---|---|
| Native executable (ELF, PE with its `PE\0\0` signature, Mach-O, fat Mach-O; found by magic bytes) under a name that promises something else: an extension from a closed list of images, documents, media, fonts, archives, text, data and configuration formats and source or script files (`png jpg jpeg gif bmp ico icns svg webp tif tiff psd heic avif pdf doc docx xls xlsx ppt pptx odt ods odp rtf epub txt md markdown rst csv tsv json jsonc yaml yml toml xml html htm css ini cfg conf log lock properties env pth start mp3 mp4 wav avi mov mkv flac ogg webm m4a aac ttf otf woff woff2 eot zip tar gz tgz bz2 xz 7z rar zst sh bash zsh fish py pyw rb pl pm php js mjs cjs ts tsx jsx java kt kts scala c h cc cpp cxx hpp cs go rs swift lua r ps1 psm1 bat cmd vbs`), a double extension that Windows runs on a double click (`.exe`, `.scr`, `.com`, `.pif`, `.cpl`) with a document, image, media, archive or text extension inside (`invoice.pdf.exe`, also with spaces of any kind before the outer extension; dotted .NET names such as `Newtonsoft.Json.dll` are not double extensions), or bidi and invisible characters in the name. Names are compared lowercased, with trailing dots and spaces dropped as Windows does. Extensions honest repositories use for binary test data (`.bin`, `.dat`, `.o`, `.obj`, `.elf`, `.out`, ...) are not in the list | CRITICAL | T1036 (.008, .007, .002) | `repo.disguised-executable` |
| Binary "test files" referenced by a build script (the xz backdoor pattern) | CRITICAL | T1195.001 | — |
| Committed native executables and libraries (any other name, or none: `.exe`, `.dll`, `.so`, `.so.N`, `.dylib`, `.node`, ...); a file over the size limit is judged by its first bytes, or by name if they cannot be read | HIGH | — | `repo.committed-binary` |
| Committed bytecode a runtime loads: Python bytecode (by its header, under any name), a Java class (`.class` whose version and constant pool check out; any other `CAFEBABE` file counts as a fat Mach-O binary), a Java archive (`.jar`, `.war`, `.ear` with a zip header), WebAssembly (`.wasm` with its header) | MEDIUM | — | `repo.committed-binary` |
| Windows "droppers": `.lnk` with a shortcut header, `.scr` that is a PE, any `.hta`. By name alone when the file is too large to read. A symbolic link is judged by its own name (Windows opens it by that name) and the head of its target, which is looked up both the Unix and the Windows way and without case; a `.lnk` or `.scr` link whose target cannot be read (a chain, a link to a folder) is judged by name. A name that poses as a document or image (`invoice.pdf.hta`, bidi or invisible characters) raises it to CRITICAL | HIGH | T1204.002 | `repo.windows-dropper` |
| Windows command and PowerShell scripts: `.bat`, `.cmd`, `.ps1`, `.psm1` (common build glue in honest repositories). Every Windows script, and a symbolic link named like one, is raised to CRITICAL when its name poses as a document or image (`invoice.pdf.bat`, bidi or invisible characters) | LOW | T1059 | `repo.windows-script` |
| Windows Script Host files: `.vbs`, `.wsf`, `.wsh` | MEDIUM | T1059 | `repo.windows-script` |
| Script Encoder output: `.vbe`, `.jse` (encoding only hides the script) | HIGH | T1059 | `repo.windows-script` |
| JavaScript that uses Windows Script Host objects: `WScript` or `WSH` with a member (in any case, as COM resolves it) or brackets, `ActiveXObject`, `GetObject` or `CreateObject` with the shell, file system, stream, server HTTP, WMI or task scheduler ProgIDs (browser `XMLHTTP` is not matched). Line regex: string concatenation and a line break after `WScript` evade it until the AST milestone | MEDIUM | T1059.007 | `repo.wsh-javascript` |
| Password-protected archives | HIGH | T1027 | — |
| Symlinks pointing outside the repository: the target is resolved as text twice, the Unix way (only `/` separates) and the Windows way (`/` and `\` separate; a leading separator, a drive letter, UNC or device prefix is absolute), and the link is outside when either reading is absolute or climbs above the root. A plain path in a system program folder (`/usr/`, `/bin/`, `/opt/`, ...; not one with `..`, `//` or `\`, and not `/System/Volumes/`, which leads to user data on macOS) is MEDIUM; a link to `/dev/null` is not reported. A link that reaches outside through another in-repository link (`d/a -> ..`, then `l -> d/a/../x`) is not detected yet. In a remote clone, made with `core.symlinks=false`, a link arrives as a plain file holding its target; the links are then read from the clone's own index (`git ls-files --stage`, run with the same isolation as the clone; the index is written by the clone, not taken from the remote) and treated as links, so this rule and the checks that read through links work there too. Their own files are still scanned as content too, because a system without symlinks (Git for Windows by default) reads exactly that file, and a link's blob can be any bytes. Paths from the index are compared with the walk exactly, never through lossy text. Not covered: a local checkout made without symlink support (its links are plain files, scanned as content only), and on HFS+ a name the index holds in NFC but the disk in NFD (scanned as content only) | HIGH | — | `repo.symlink-outside` |
| Committed Python virtual environment (`pyvenv.cfg`, `site-packages/`), reported as a finding of its own; the `.pth` files inside are still judged normally | MEDIUM | — | — |
| Submodules pointing at third-party URLs | MEDIUM | — | — |
| Large high-entropy files of unknown format | MEDIUM | T1027 | — |

### Stage 1: opening in an IDE

| Detection | Level | ATT&CK | Rule |
|---|---|---|---|
| `.vscode/tasks.json` or `*.code-workspace` with a task using `"runOn": "folderOpen"` (parsed as JSONC, so comments, line breaks and `\u` escapes cannot hide it; the per-OS `windows`/`linux`/`osx` overrides are checked too; a file of that name that is a symbolic link to a file in the repository is judged by the file it points at, found the way NTFS and APFS find it (either separator, any case), as VS Code follows it, and the finding says so; a target too large to read whole lists the link as too large, and a target the check cannot read (another link, outside the repository, missing) or whose text does not name one file for certain (not valid UTF-8, or read as different files by Unix and Windows) lists it as unreadable, so in both cases the scan is inconclusive; at most 64 MiB is read through links in one scan, and further links that need their target are listed as too large) | HIGH, with network or shell CRITICAL | — | `ide.vscode-folder-open-task` |
| `.vscode/settings.json` overriding the interpreter, terminal or environment | HIGH | — | — |
| `Directory.Build.props` / `Directory.Build.targets`, custom MSBuild tasks (Visual Studio evaluates them on project load) | HIGH | T1127.001 | — |
| .NET analyzers / source generators shipped as DLLs in the repo (a binary runs inside the IDE) | CRITICAL | — | — |
| `.devcontainer` with `postCreateCommand` / `postStartCommand` | MEDIUM, with network HIGH | — | — |
| `.idea` run configurations, `.envrc` (direnv) | MEDIUM | — | — |

### Stage 2: installing dependencies

| Detection | Level | ATT&CK | Rule |
|---|---|---|---|
| npm install hook in any `package.json` (nested and `node_modules` ones too): `preinstall`, `install`, `postinstall`, `prepublish` (deprecated, but npm still runs it), `preprepare`, `prepare`, `postprepare`, `dependencies`, with their `pre` / `post` variants. The `package.json` is read as `JSON.parse` reads it (last duplicate key wins, BOM dropped). The script is followed through `npm run`, `npm start/test`, `yarn X`, `pnpm X`, `bun run`, `npm-run-all`, `run-p`, `run-s`, `concurrently` (also `npm:name`), `npx`, `cross-env`, `cd dir && npm install` into another `package.json` of the repository, the operators `&&`, `\|\|`, `;`, `\|`, `&`, `$(...)` and backticks, to a depth of 10 with a cycle guard and a budget of 2000 steps. The level is the highest in the chain, and a chain the limits cut short is HIGH, never clean | see the next rows | T1195.001, T1059.007 | `deps.npm-lifecycle-hook` |
| The same, when the chain downloads or sends data (`curl`, `wget`, `iwr`, `certutil`, `bitsadmin`, `mshta`, a URL passed to any program, `npx <url>`), runs `powershell -EncodedCommand`, or runs inline code (`node -e`, `python -c`) that uses the network | CRITICAL | T1195.001, T1059.007 | `deps.npm-lifecycle-hook` |
| The same, when the chain runs inline code (`node -e`, `python -c`, `bash -c`, `cmd /c`, `eval`, `base64`), commands from a pipe (`\| sh`), or `npx` of a package that is not a dependency of the project | HIGH | T1195.001, T1059.007 | `deps.npm-lifecycle-hook` |
| The same, when the chain runs a local file (`node <path>`, `nodemon`, `ts-node`, `tsx`, `python <path>`, `bash <path>`, `./script`, `npm start` with a `server.js`), or starts a front-end dev server (`react-scripts start`, `vite`, `next dev`, ...), which never exits and runs the project's own config file | MEDIUM | T1195.001, T1059.007 | `deps.npm-lifecycle-hook` |
| The same, when the chain only runs a front-end build tool (`vite build`, `webpack`, `next build`: they run the project's config file), a known honest tool that downloads binaries (`prebuild-install`, `node-pre-gyp`, `playwright`, `puppeteer`, `cypress`), a package that honest projects fetch with `npx` or `pnpm dlx` from an install hook (`only-allow`, as in vitejs/vite and vuejs/core, with or without a version; `npm-force-resolutions`; the list, with the repository of each, is `NPX_HONEST`), or a program with no entry in the lists | LOW | T1195.001 | `deps.npm-lifecycle-hook` |
| The same, when the chain only runs a known honest tool (`husky`, `lefthook`, `patch-package`, `node-gyp`, `tsc`, `electron-builder install-app-deps`, `ngcc`, ...; the list is `HONEST` in `checks/npm_scripts.rs`), or `npm install` in another folder of the repository. Shell built-ins such as `echo` and `exit` are not reported. An honest tool does not lower the level of the rest of the line: `husky && curl ... \| sh` is CRITICAL | INFO | T1195.001 | `deps.npm-lifecycle-hook` |
| `prepack`, `postpack`, `prepublishOnly`, `publish`, `postpublish`: not run by a plain `npm install` of the root. `prepack` runs on `npm pack`, `npm publish` and when the repository is installed as a git dependency; `postpack` on `npm pack` and `npm publish`; `prepublishOnly`, `publish` and `postpublish` only on `npm publish`. The finding says which | one level lower than the rows above | T1195.001 | `deps.npm-lifecycle-hook` |
| `package.json` that `JSON.parse` rejects (comments, a trailing comma, a NUL byte): npm refuses it and runs nothing. The finding says what a more lenient reader would find. Nested deeper than 64 levels, larger than the scan limit, or a symbolic link whose target was not read: HIGH | LOW | T1195.001 | `deps.npm-lifecycle-hook` |
| An install, pack or publish hook whose chain starts a local file that has a loader finding of MEDIUM or more (any rule of the loader signatures family) takes the level of that finding (one level less for a pack or publish hook), and the finding names the file and the rule | the level of the file's finding | T1195.001, T1059.007 | `deps.npm-lifecycle-hook` |
| A command the check could not read completely: a quote or `$(...)` that is never closed, a variable, a substitution or a brace expansion as the command name or as the file an interpreter runs, `$'...'`, `eval`, `source`, `alias`, `function`, `trap`, `case`, a heredoc or here-string, a process substitution, input redirected into an interpreter (`node < x.js`), `--script-shell`, `npm restart` without a restart script, and a chain the limits cut short. The finding says "could not fully parse this command; review it by hand" and gives the reason; the part that could be read is still reported. A command that is read completely is not affected | at least HIGH for an install hook, at least MEDIUM for a pack or publish hook and for a `start` / `dev` / `build` / `test` script (`run.npm-script-local-server` then reports it too) | T1195.001, T1059.007 | `deps.npm-lifecycle-hook`, `run.npm-script-local-server` |
| A hook defined twice (npm uses the last one; the earlier definition, or the earlier `scripts` object, is ignored by npm but seen by a tool that reads the first key) | LOW | T1195.001 | `deps.npm-lifecycle-hook` |

Known gaps for the npm family (filed in the issue): the implicit `node-gyp rebuild` when `binding.gyp` exists and there is no `install` script, `<!(...)` command expansions in `binding.gyp`, `.npmrc` and `.yarnrc.yml`, workspace selection (`--workspace`, `--filter`; the other manifest is reported on its own), and shell variables, functions and aliases. The names of honest tools are chosen by whoever writes the repository, so a program called `husky` that is a file in the repository is still reported as a local file.
| `setup.py` containing code other than the `setup()` call | HIGH | T1195.001 | — |
| Python `.pth` file with a line that starts with `import` and a space or tab, which `site.py` runs at every interpreter start-up. A line counts if ANY supported version (3.10 to 3.15) would run it: lines are split like `str.splitlines` (also on `\r`, `\v`, `\f`, `\x1c`-`\x1e`, U+0085, U+2028, U+2029), Python's own whitespace set is stripped (3.15 strips each line), a BOM counts only at the start of the file, and the file is read as raw bytes so a NUL byte or invalid UTF-8 cannot hide it. Any other executable line | HIGH | T1546.018 | `deps.python-pth-exec` |
| The same, when the line uses `exec`, `eval`, `compile`, `__import__`, `base64`, `zlib`, `marshal`, `codecs`, `subprocess`, `system`, `popen`, `socket`, `urllib`, `requests` and similar words, contains non-ASCII characters or `\x`/`\u` escapes, is 200 or more characters long, has a run of 32 or more hex digits, or has a base64-like run of 40 or more characters (letters and digits, entropy of 4.2 bits per character or more, adjacent string literals joined first). These thresholds apply only to executable `.pth` lines | CRITICAL | T1546.018 | `deps.python-pth-exec` |
| `.pth` that is a known honest form: file name AND every line match one written by setuptools (`distutils-precedence.pth`, `*-nspkg.pth`), virtualenv (`_virtualenv.pth`), an editable install (`__editable__.*.pth`) or pytest-cov up to 6.2.1. LOW if the module it imports is not in the repository; MEDIUM if it is (honest repositories do not commit it, and it is attacker-controlled) or if the scan was cut short and presence is unknown | LOW or MEDIUM | T1546.018 | `deps.python-pth-exec` |
| `.pth` that only adds paths to `sys.path` | INFO | T1546.018 | `deps.python-pth-exec` |
| `.pth` that Python never reads (name starts with a dot, or the extension is not exactly lowercase `.pth`) but that has an executable line | LOW | T1546.018 | `deps.python-pth-exec` |
| `.pth` or `.start` file that is a symbolic link (Python follows it; the in-repository target is checked too) or is larger than the scan limit (Python reads it in full) | HIGH | T1546.018 | `deps.python-pth-exec`, `deps.python-start-entrypoint` |
| `.pth` file that is not valid UTF-8 (honest ones are ASCII; Python may decode it with the system's locale encoding) | MEDIUM | T1546.018 | `deps.python-pth-exec` |
| Python 3.15 `.start` file (PEP 829) with an entry point `package.module:callable`, which `site.py` calls at start-up. Only the strict form `pkgutil.resolve_name` accepts counts; a `.start` file that is not UTF-8 is ignored by Python, so it is not reported. A matching `.start` never lowers the finding for the `.pth` next to it | HIGH | T1546.018 | `deps.python-start-entrypoint` |
| `.start` file Python never reads (dot-prefixed name, extension not exactly lowercase `.start`) with an entry point | LOW | T1546.018 | `deps.python-start-entrypoint` |
| Custom build backend inside the repo (pyproject.toml) | HIGH | T1195.001 | — |
| Lockfile resolving a package from outside the official registry | HIGH | T1195.001 | — |
| Typosquatted package names | HIGH | T1195.001 | — |
| Dependencies from git or a URL instead of the registry | MEDIUM | — | — |
| Known vulnerabilities via OSV | MEDIUM, critical CVE HIGH | — | — |
| binding.gyp, composer scripts, Rakefile / Gemfile with code | MEDIUM | — | — |
| Dockerfile with `curl \| sh` | MEDIUM | T1105 | — |

Known gap: a payload kept under another name and renamed to `*.pth` while the package is built (for example hatch `force-include`, setuptools `data_files`) is not seen by the `.pth` rules, because the file in the repository does not have that name yet. It needs a rule that understands the build configuration.

### Stage 3: building

| Detection | Level | ATT&CK | Rule |
|---|---|---|---|
| `gradle-wrapper.jar` not matching the official hash, or `distributionUrl` not on services.gradle.org | CRITICAL | T1195.001 | — |
| Rust proc-macro doing I/O or networking (runs at compile time) | CRITICAL | T1195.001 | — |
| `build.rs` with networking, process spawning or writes outside `OUT_DIR` | HIGH, with obfuscation CRITICAL | T1195.001 | — |
| `.vcxproj` Pre/PostBuildEvent, MSBuild `<Exec>` | HIGH, with `powershell -enc` or a download CRITICAL | T1127.001 | — |
| CMake: `execute_process`, `file(DOWNLOAD)`, `ExternalProject` / `FetchContent` from a third-party URL | HIGH | T1105 | — |
| Makefile or configure with `curl \| sh`, base64 | HIGH | T1105 | — |
| Gradle tasks with exec or download, Maven exec-plugin | MEDIUM to HIGH | — | — |
| `go:generate` (only runs when invoked manually) | LOW | — | — |

### Stage 4: tests

| Detection | Level | ATT&CK | Rule |
|---|---|---|---|
| `conftest.py` or pytest plugins with network or exec (pytest loads them automatically) | HIGH | — | — |
| npm `test` script with suspicious commands | MEDIUM | — | — |

### Stage 5: running the program (code capabilities)

| Detection | Level | ATT&CK | Rule |
|---|---|---|---|
| npm `start`, `dev`, `build` or `test` script (with `pre` / `post`) that runs a local JavaScript file (`node <path>`, `nodemon <path>`, `ts-node`, `tsx`) next to a front-end tool (`react-scripts`, `vite`, `next`, `webpack`, ...), found through `npm run`, `concurrently`, `npm-run-all` and the operators. Full-stack repositories do this honestly, so the level is low; the finding names the file, and says when a build or test script starts a server. When the file it names has a loader finding of MEDIUM or more (see the loader signatures below), the finding takes that level and names the rule | LOW | T1059.007 | `run.npm-script-local-server` |
| **Loader signatures, JavaScript.** A dynamic code sink (`eval`, `new Function`, `Function()`, `Function.constructor`, `vm.runIn*`, `vm.Script`, `vm.compileFunction`, `module._compile`, the indirect forms `(0, eval)(x)`, `window.eval`, `globalThis["eval"]`, `eval.call`, `x.constructor.constructor(code)`, an alias such as `const run = eval`, a name written with `\u` escapes) whose code argument comes from a network call in the same file (`axios`, `fetch`, `http(s).get/request`, `got`, `request`, `superagent`, `needle`, `undici`, `XMLHttpRequest`, `$.get`, ...). Data is followed by variable and by scope through assignments, destructuring, compound assignment, parameters of the callbacks given to a call that has a network call or a tainted value in its callee chain (`.then`, `.catch`, `res.on("data", ...)`), the parameter of a `catch` whose `try` block touched one, a function that returns one, and a property path (`this.body`). The file is lexed first, so a word in a comment or a string is not a call. Only the first argument of `eval`, `vm.*` and `_compile` is code (an options object is not). CRITICAL when the file writes the address of a remote host and is not browser-only; HIGH when it writes no URL at all (the address may be relative or come from elsewhere) or is browser code (it uses `window` or `document` and nothing that only Node.js has). A call it cannot follow (`global["ev" + "al"](x)`, a computed name on `window`, `global`, `globalThis`, `self` or `this`) and a file it cannot read to the end (a template literal or comment that never ends, brackets that do not pair up, too many tokens), while the file makes network calls, are MEDIUM and say "review it by hand". A lexer problem that ends at a line break (a JSX apostrophe, a closing tag) is not reported | CRITICAL, HIGH for a file with no URL or browser code, MEDIUM when it cannot follow | T1105, T1059.007 | `run.js-fetch-eval` |
| `new Function("require", code)(require)`, also `new (Function.constructor)("require", code)` and a function made that way and kept in a variable, then called with `require`: code assembled at run time gets the module loader | CRITICAL | T1059.007, T1620 | `run.js-function-require` |
| A decoder (`atob`, `Buffer.from(x, "base64" \| "hex" \| "latin1" \| "binary")`, `unescape`, `String.fromCharCode` with 8 or more codes or a spread), a base64 string of 64 or more characters with mixed case, or a string of 16 `\x` or 32 `\u` escapes, reaching a code sink or a command sink (`execSync`, `execFile`, `spawnSync`; `exec` and `spawn` only when bound from `child_process`) | HIGH | T1027, T1140 | `obfuscation.encoded-payload-sink` |
| Output of the obfuscator.io tool: 12 or more `_0x` names, 4 of them different, that are at least 5 per 1000 characters of the file or come with a `while(!![])` loop or a string array rotated with `push` and `shift`. CRITICAL when a tool runs the file: a configuration file (`*.config.{js,cjs,mjs,ts,cts,mts}`, `*.conf.js`, `.*rc.js`, `gulpfile`, `Gruntfile`, `babel.config.*`, `webpack.*`, `rollup.*`, `vite.*`) or a file that an npm script starts with `node` (found through `npm run`, `concurrently`, `cd dir && ...`); HIGH in other source; MEDIUM under `dist`, `build`, `out`, `public`, `vendor`, `node_modules`, `third_party`, `static`, `assets`, `.next`, `_next`, `bundles` or in `*.min.*`, `*.bundle.*`, `*.chunk.*`. Names without the structure are one level lower. The folder name does not remove the finding, because whoever writes the repository chooses it | CRITICAL, HIGH, MEDIUM | T1027.013 | `obfuscation.obfuscator-io` |
| A line of 2000 or more characters with less than one blank in eight and a `;`, `{` or `}` every 80 characters (a table of numbers or one base64 string is not code): minified code. MEDIUM in source, INFO under the folders above, HIGH when a tool runs the file | MEDIUM, INFO, HIGH | T1027 | `obfuscation.minified-source` |
| **Loader signatures, Windows.** Read in `.ps1`, `.psm1`, `.bat`, `.cmd`, `.vbs`, `.hta`, `.wsf`, in the scripts of `package.json` and in the commands and arguments of the tasks of `.vscode/tasks.json` and `*.code-workspace` (autorun or not). Logical lines join continuations (`^` in batch, a backtick, an open bracket or a trailing pipe in PowerShell, ` _` in VBScript, 40 lines at most); carets, empty `""` pairs and backticks are removed, dashes of any kind become `-`, text is lowercased, comment lines are skipped. `IEX` / `Invoke-Expression` / `[scriptblock]::Create` / `Invoke-Command` with a download on the same logical line (`DownloadString`, `DownloadData`, `DownloadFile`, `iwr`, `Invoke-WebRequest`, `irm`, `Invoke-RestMethod`, `curl`, `wget`, `Start-BitsTransfer`, `Net.WebClient`); `certutil -urlcache`; `certutil -verifyctl` with a URL; `bitsadmin /transfer` or `/addfile` with a URL (HIGH without one); `mshta` with a URL, a UNC path or `vbscript:` / `javascript:` / `about:`; `regsvr32 /i:` with a URL (HIGH with `scrobj` and no URL); `rundll32` with `javascript:`, `vbscript:` or `mshtml,RunHTMLApplication`. When every URL on the `IEX` line is, as a whole, a well-known installer (Chocolatey, Scoop, the PowerShell, .NET, Deno, Bun and uv installers; Scoop's scheme-less `irm get.scoop.sh \| iex` only as the whole line) the level is MEDIUM | CRITICAL, HIGH, MEDIUM for a known installer | T1105, T1059.001, T1218.005, T1218.010, T1218.011, T1197 | `run.windows-remote-code` |
| `powershell`, `pwsh`, `powershell_ise` with `-EncodedCommand` or any prefix down to `-e` and a base64 operand of 40 or more characters (CRITICAL with a hidden window, `-w h`, or a download on the line); `certutil -decode` and `-decodehex`; `IEX` of `FromBase64String`. `-ExecutionPolicy Bypass` alone is not reported | HIGH, CRITICAL | T1027.010, T1140 | `obfuscation.windows-encoded-payload` |
| `Add-MpPreference -ExclusionPath`, `-ExclusionProcess`, `-ExclusionExtension`; `Set-MpPreference -Disable...`. Some honest developer setup scripts do it for build speed | HIGH | T1562.001 | `run.windows-defender-exclusion` |
| Known gaps of the loader signatures, until milestones 7 and 8: data followed across files, through object fields by name, or through `Array` methods other than callbacks; the address of a request built from pieces; JavaScript outside `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.mts`, `.cts` (inline script in HTML); packers (`eval(function(p,a,c,k,e,d)`); obfuscator.io output with renamed identifiers; download and execution on different lines of a script, `%VAR:~n,m%` substrings, variables joined into a command, string concatenation, the `-f` operator, `[char]` arrays and `Set-Alias` in PowerShell, `"power" & "shell"` and `Chr()` in VBScript; the same words in other file types (Markdown, `.sh`, `.json` outside scripts and tasks). A JavaScript or Windows script file over 5 MiB is read whole up to 32 MiB; a larger one is listed as too large | — | — | — |
| Chain "download → write → make executable → run" | CRITICAL | T1105 | — |
| Shellcode and injection: `VirtualAlloc`/`VirtualAllocEx` with RWX, `WriteProcessMemory`, `CreateRemoteThread`, `mprotect(PROT_EXEC)`, `ptrace` | CRITICAL | T1055 | — |
| Disabling defenses: Defender exclusions (`Add-MpPreference`, `Set-MpPreference`), AMSI bypass | CRITICAL | T1562.001 | — |
| Crypto mining (`stratum+tcp://`, xmrig) | CRITICAL | T1496 | — |
| Ransomware behavior: `vssadmin delete shadows`, mass file enumeration and encryption | CRITICAL | T1490, T1486 | — |
| Data theft: browser passwords and cookies (`Login Data`, `Cookies`), Discord tokens, Telegram `tdata`, crypto wallets, `~/.ssh`, `~/.aws` | HIGH, with network CRITICAL | T1555.003, T1539, T1552 | — |
| Exfiltration via Discord/Telegram webhooks or bot API, pastebin, ngrok, .onion, hard-coded IPs | HIGH | T1567 | — |
| Persistence: registry Run keys, schtasks, services, cron, systemd, LaunchAgents, `.bashrc`/`.profile`, Startup folder, WMI subscriptions | HIGH | T1547.001, T1053, T1543, T1546.004, T1546.003 | — |
| Keylogging (`SetWindowsHookEx`, `GetAsyncKeyState`), clipboard address swapping (clipper) | HIGH | T1056.001, T1115 | — |
| UAC bypass (fodhelper / eventvwr registry keys) | HIGH | T1548.002 | — |
| Anti-VM and anti-debugging (VM, sandbox and debugger checks) | HIGH | T1497, T1622 | — |
| Loading code from bytes (`Assembly.Load(byte[])`, `defineClass`, `marshal.loads`) | HIGH | T1620 | — |
| Screenshots | MEDIUM | T1113 | — |
| Auto-update without signature or hash verification | MEDIUM | — | — |
| Plain process spawning | LOW | T1106 | — |

### Stage 6: deceiving the human

| Detection | Level | ATT&CK | Rule |
|---|---|---|---|
| Trojan Source: Unicode bidi control characters (CVE-2021-42574). Judged by how the line is displayed, see below | LOW to CRITICAL | — | `deception.bidi-control` |
| Code hidden with whitespace past the edge of the screen (beyond ~column 200) or after hundreds of blank lines | CRITICAL | T1027 | — |
| NUL byte inside a script (script extension or shebang; UTF-16 files are not meant here: a script with a UTF-16 byte order mark is decoded from UTF-16, as PowerShell, Windows Script Host, Perl and tsc read it (Python, Ruby, Lua and Node cannot run such a file at all), and read by the line rules whatever its first bytes hold (text made only of characters such as U+0101 has no NUL byte at all), also when it is over 5 MiB and read as a stream; U+0000 is dropped, so a UTF-32 LE file reads as its own text. except a `.bat`, `.cmd`, shell or PHP script, which is read as bytes, as `cmd.exe`, the shells and PHP run it after the mark, so the mark cannot hide a payload behind UTF-16 garbage and the NUL rule still applies; known gap: UTF-16 in non-script files and UTF-16 without a byte order mark are not decoded). Shells such as `dash` drop NUL bytes and run the rest, but tools that take NUL for the mark of a binary stop reading at it. The script is scanned like any other text file. Every file except a recognised executable is read by the line rules with the NUL bytes removed, because a script can source it (`GIF89a=1` is a valid shell assignment). If it has a known binary header (archive, image, WebAssembly, font), or has NUL bytes and does not read as text (more than one byte in eight is NUL, or what is left is not valid UTF-8, as in icons and audio), the rules see only its ASCII (every other byte becomes U+FFFD), the file is listed as "binary format, ASCII rules only" and each finding says "found in a binary-looking file". Known gap, by design: a rule for a non-ASCII character (Trojan Source bidi, later zero-width) cannot match in such a file, because on noise it would match by chance. The NUL itself is reported only for scripts | HIGH | T1027 | `deception.nul-byte-in-script` |
| Invisible (zero-width) characters and homoglyphs in identifiers (Cyrillic `а` instead of Latin `a`) | HIGH | T1036 | — |
| README advising "disable your antivirus", "download the password-protected zip", `curl \| bash` | HIGH | T1204 | — |

How `deception.bidi-control` decides. For a line with any of U+202A to U+202E or U+2066 to U+2069, the scanner lays the line out with the Unicode Bidirectional Algorithm twice, as it is and with those nine characters removed, and compares what is displayed (characters in visual order, and whether each is drawn mirrored). The same display is a LOW finding, "bidi controls present, display unchanged": direction helpers of a vendored UI bundle do this (`"<LRE>" + e + "<PDF>"`). A different display is CRITICAL. The layout is made for a left-to-right base direction (editors, diff views and code hosts) and for the direction the text itself chooses (a viewer with automatic direction); a line is CRITICAL if either differs. Rule L1 is applied, and the characters rule X9 removes (zero-width spaces, soft hyphens) are dropped from both displays. U+200E, U+200F and U+061C are not controls for this rule and stay in both.

What cannot be judged keeps CRITICAL, and the explanation says why: a control next to a word or path character (ASCII letters and digits, `_ $ . / \\ -`, looking past other controls and the marks U+200E, U+200F and U+061C), because the display does not change but the name does (`bash ./setup<LRI>.sh` runs another file than `setup.sh`, `"example.com<PDF>"` never equals a host); a line with a character that some viewers show as a line break (a lone CR, VT, FF, U+001C to U+001E, U+0085, U+2028, U+2029), a line over 64 KiB, and every line after a scan has laid out 8 MiB of lines (files are read in sorted order, so the same lines are left over on every run). A list of 100 findings is kept for each level, so harmless lines do not hide a deceptive one; lines past the CRITICAL list are not laid out and are counted as CRITICAL.

Known gaps: a base direction forced to right to left is not modelled (a viewer only does that when its user asks, a file cannot); a line that starts with a right-to-left mark or Arabic letter flips an auto-direction viewer with no control at all (tracked as a hardening issue); a rendered Markdown paragraph joins source lines, which this per-line judgement does not see; characters newer than the Unicode tables of the `unicode-bidi` crate in use (a test pins the defaults of the right-to-left blocks); binary-looking files are read as ASCII only, so the rule cannot match in them.

---

## 2. Obfuscation

### Detected and decoded

Decoded content is scanned again recursively, with limits on depth and size.
Related technique: T1027 (Obfuscated Files or Information), T1140
(Deobfuscate/Decode).

| Type | Decoding |
|---|---|
| Base64, hex, character-code arrays (`String.fromCharCode`, `chr()`) | yes |
| gzip/zlib inside base64 (`zlib.decompress(b64decode(...))`) | yes |
| XOR with a single-byte key | yes, by brute-forcing all 256 keys |
| String concatenation from pieces, reversed strings | partially |
| PowerShell `-EncodedCommand`, `IEX`, backtick escaping | yes |

### Detected but not decoded

- JS packers: `eval(function(p,a,c,k,e,d)`, obfuscator.io (`_0x...` names,
  rotated string arrays), JSFuck.
- Python: `exec(compile(...))`, `marshal`, lambda chains, PyArmor.
- Calls through reflection or dynamic imports (`getattr(__import__(...))`).
- High-entropy strings (Shannon entropy), minified code among normal sources.

---

## 3. Kinds of execution we look for

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

---

## 4. Review points

Besides **findings**, the report has a separate **"Needs manual review"**
section for places where static analysis cannot reach a verdict but a human
should take a look.

Rules for this section:

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
| Payload downloaded later | Every place where a network response flows into `exec`/`eval`/a file write. A list of all URLs and domains in the code, flagged when they are raw IPs, pastebin, raw gists, URL shorteners or dynamic DNS |
| Encryption | Decryption calls (AES, Fernet, CryptoJS.decrypt) whose result goes into execution or code loading, especially next to a high-entropy blob |
| Malicious logic on ordinary APIs | **Capability map**: a short summary of what the program can do (network, files in the home directory, processes) compared with the README |
| Logic bombs | Conditions guarding dangerous actions: hard-coded future dates, hostname or username checks, environment variables, **system language and keyboard layout** (malware often switches on or off by locale; T1480, T1614.001) |
| Binary contents | Import tables of PE/ELF/Mach-O (crate `goblin`), e.g. a `.dll` importing `VirtualAllocEx` + `WriteProcessMemory`; SHA-256; presence of a code signature; strings from the binary (URLs, IPs). Optional: VirusTotal hash lookup with the user's own key (hash only, the file is never uploaded) |
| Bugdoors | Risky spots at LOW: `strcpy`, `sprintf`, `gets`, `memcpy` without a size check, `unsafe` blocks in Rust |
| Dependency code | Via registry APIs (npm, crates.io, PyPI): packages published a few days ago, with tiny download counts, or with a changed owner. Committed `vendor/` and `node_modules/` are scanned as ordinary code |
| Binaries in Releases | Via the GitHub API: whether releases contain exe/zip files and whether the README says to download releases instead of building. Marked "binary not verified against the source" |
| Custom VM / bytecode | Large numeric arrays + a loop with `switch`/`match` over "opcodes": "possible code virtualization" |
| Steganography | Code that reads pixels or bytes of an image and executes the result (T1027.003). Separately, as a finding rather than a review point: data appended after `IEND` (PNG) or `EOI` (JPEG) |

**What stays truly blind** (stated honestly in the README): malicious logic
built from ordinary APIs with no suspicious signals, real encryption with a
key fetched from outside, and deliberate vulnerabilities that use no risky
functions. Even for these, the report still points at the entry point.

---

## 5. Additional requirements

**The scanner is a target too.** A malicious repository may attack the
scanner itself:

- never follow symlinks;
- limits on file size, decoding recursion depth and number of files. A file up to 5 MiB is read whole. A file from 5 MiB up to 100 MiB (the size at which GitHub refuses a push) is read as a stream, line by line, so memory stays small, and only the line rules look at it; a file-level or JSONC rule that selects it cannot run, so it is listed as too large. A line over 16 MiB in a streamed file, and any file over 100 MiB, make the scan inconclusive;
- never unpack archives (zip-bomb protection), only flag them;
- regular expressions only through the `regex` crate (linear-time matching,
  protection against ReDoS);
- no file is skipped silently: binary, oversized, symlinked and unreadable files, and `.git` folders (not walked into; the one at the root is listed as git metadata, a nested one makes the scan inconclusive), are all listed in the report. Special files such as FIFOs and devices are not listed yet (roadmap); rules that select files by name (such as `.pth` and `.start`) run on the raw bytes before the binary check, and also see oversized files and symlinks, so "too big" or "a link" is not a way around them. Rules that judge a file by its name and first 8 KiB (the repository contents family, `engine = "head"`) see every entry: files read whole or as a stream, files over the size limit (only their first 8 KiB is read) and symlinks (only the first 8 KiB of an in-repository target is read, however many links point at it);
- work per file is bounded: a line rule lists at most 100 findings per rule per file, the rest are counted and the report says "N more findings in this file not shown" with the levels (the limit is per rule, and one rule has one level, so a flood from one rule cannot push another rule's CRITICAL finding out). The `.pth` check also never analyses a line beyond 4096 bytes: a longer one is CRITICAL by itself. Line rules of a streamed file stop at a line over 16 MiB (inconclusive); the regex engine runs in linear time. Memory for a streamed file is one line, and up to three times that for a binary-looking one;
- remote repositories are cloned shallowly over `https` only (`ssh`, `http://` and `git://` are refused; a private repository is cloned by its owner and the folder scanned). `git` runs with an empty environment plus a short allow-list of variables, with its user and system configuration replaced by an empty file and with an empty temporary directory as its home (`HOME` and `USERPROFILE`), so git before 2.32, which ignores `GIT_CONFIG_GLOBAL`, still cannot read `~/.gitconfig`, and no version reads `~/.config/git/attributes` or lets curl read `~/.netrc`; the system attributes file (`$(prefix)/etc/gitattributes`, writable by the user on Homebrew and per-user Git for Windows installs) is skipped with `GIT_ATTR_NOSYSTEM`; so no filter, credential helper or fsmonitor from any configuration runs and `GIT_CONFIG_*` variables do not reach it. Hooks and templates are off, symlinks are written as plain files, objects are checked, submodules are not fetched, and nothing can ask a question interactively. The `--ref` value is passed to git as a single validated argument, and error text coming back from a git server is cleaned before it is printed;
- credentials in a URL (`https://TOKEN@host/...`) are hidden in the notice, the report label and error messages, git's own text included. A URL with an `@` after the first `/`, `?`, `#` or `\`, or with two `@` before the host (user information holding one of them unescaped), or with whitespace, a control character, a quote, an angle bracket or a backtick, is refused before anything is printed or git starts, without repeating it: curl would take the part before such a character for the host, print it in its error and send it to the DNS resolver or a proxy. Wherever such text still appears in a message, the user information is taken to end at the last `@`, so it is hidden whole (an `@` later in a path or query hides more than needed, never less). A target without a scheme that is taken for a local folder (`TOKEN@github.com/o/r`) is shown in errors with everything before its last `@` hidden. An scp-like address with any user (`deploy:TOKEN@host:path`) is taken for an ssh target and refused without repeating it, and its user information, except the plain `git` user, is hidden wherever such an address appears in a message;
- an inconclusive scan is never reported as clean: when the file limit was reached, a file was too large or could not be read, a line of a large file was too long to analyze, a nested `.git` repository was not read, or an executable binary (ELF, PE, Mach-O including fat binaries, found by magic bytes whatever the file is called; a PE by the `PE\0\0` signature its `e_lfanew` points at, up to 256 MiB into the file, even when its first 8 KiB has no NUL byte; an `MZ` file without that signature, such as a 16-bit DOS, NE or LE program that 64-bit Windows does not run, is read as data) was not reported by any rule, the report ends with `Scan: INCONCLUSIVE` and the exit status is 3 even with `--fail-on none`. With the built-in rules every executable is a finding of the repository contents family (HIGH, CRITICAL when disguised, MEDIUM only for a validated Java class), which names it; it is still listed as an executable whose code was not analyzed, and only a finding of a rule that names executables (`names_executables`) takes the place of the inconclusive status. Other binary files that were read are listed as "binary format, ASCII rules only" and do not change the status;
- a script (by extension or shebang) with a NUL byte is read as text, so the NUL does not hide what follows it, and the NUL itself is a finding;
- text taken from the scanned repository (task labels, file names) is passed
  through `display_safe` before it is reported, so it cannot inject terminal
  escape sequences, forge extra lines or reorder text with bidi characters;
- structured files (JSON-like) are parsed rather than matched line by line,
  with a nesting limit, so comments and escapes cannot hide a setting and a
  deeply nested file cannot overflow the stack;
- localizations load only from the built-in set and the OS config directory,
  never from the scanned repository, so a repository cannot change what the
  report says; third-party locale text is stripped of control, bidi and
  zero-width characters, cannot carry raw terminal escape sequences, and
  severity codes (CRITICAL, HIGH, ...) are always shown untranslated.

The items above that exist in the code are design guarantees with tests; the
localization item is a requirement for milestone 6. None of them is a proof that
the scanner is free of bugs or that a repository is safe: a clean result means
"no rule matched in what was read", and the report says what was not read.

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

## 6. Exit status and binary files

`repo-sniff scan` exits with 0 when nothing reached `--fail-on` and the scan was
complete, 1 when a finding reached it, 2 when the scan could not run, and 3
when nothing reached it but the scan was inconclusive. Findings win over an
inconclusive scan. How binary files affect that:

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
