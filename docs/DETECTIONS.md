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
| File with an image/text extension that is actually PE/ELF/Mach-O (magic bytes) | CRITICAL | T1036 | — |
| Binary "test files" referenced by a build script (the xz backdoor pattern) | CRITICAL | T1195.001 | — |
| Committed binaries (.exe, .dll, .so, .dylib, .jar, .pyc, .wasm, .node) | HIGH | — | — |
| Windows "droppers": .lnk, .scr, .hta | HIGH | T1204.002 | — |
| .bat, .cmd, .ps1, .vbs, .js (Windows Script Host) | MEDIUM | T1059 | — |
| Password-protected archives | HIGH | T1027 | — |
| Symlinks pointing outside the repository | HIGH | — | — |
| Committed Python virtual environment (`pyvenv.cfg`, `site-packages/`), reported as a finding of its own; the `.pth` files inside are still judged normally | MEDIUM | — | — |
| Submodules pointing at third-party URLs | MEDIUM | — | — |
| Large high-entropy files of unknown format | MEDIUM | T1027 | — |

### Stage 1: opening in an IDE

| Detection | Level | ATT&CK | Rule |
|---|---|---|---|
| `.vscode/tasks.json` or `*.code-workspace` with a task using `"runOn": "folderOpen"` (parsed as JSONC, so comments, line breaks and `\u` escapes cannot hide it; the per-OS `windows`/`linux`/`osx` overrides are checked too) | HIGH, with network or shell CRITICAL | — | `ide.vscode-folder-open-task` |
| `.vscode/settings.json` overriding the interpreter, terminal or environment | HIGH | — | — |
| `Directory.Build.props` / `Directory.Build.targets`, custom MSBuild tasks (Visual Studio evaluates them on project load) | HIGH | T1127.001 | — |
| .NET analyzers / source generators shipped as DLLs in the repo (a binary runs inside the IDE) | CRITICAL | — | — |
| `.devcontainer` with `postCreateCommand` / `postStartCommand` | MEDIUM, with network HIGH | — | — |
| `.idea` run configurations, `.envrc` (direnv) | MEDIUM | — | — |

### Stage 2: installing dependencies

| Detection | Level | ATT&CK | Rule |
|---|---|---|---|
| npm `preinstall` / `install` / `postinstall` / `prepare` | HIGH, with network, exec or obfuscation CRITICAL | T1195.001 | — |
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
| Trojan Source: Unicode bidi control characters (CVE-2021-42574) | CRITICAL | — | `deception.bidi-control` |
| Code hidden with whitespace past the edge of the screen (beyond ~column 200) or after hundreds of blank lines | CRITICAL | T1027 | — |
| NUL byte inside a script (script extension or shebang; UTF-16 files are not meant here). Shells and interpreters still run the file, but tools that take NUL for the mark of a binary stop reading at it. The script is scanned like any other text file | HIGH | T1027 | `deception.nul-byte-in-script` |
| Invisible (zero-width) characters and homoglyphs in identifiers (Cyrillic `а` instead of Latin `a`) | HIGH | T1036 | — |
| README advising "disable your antivirus", "download the password-protected zip", `curl \| bash` | HIGH | T1204 | — |

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
- limits on file size, decoding recursion depth and number of files;
- never unpack archives (zip-bomb protection), only flag them;
- regular expressions only through the `regex` crate (linear-time matching,
  protection against ReDoS);
- no file is skipped silently: binary, oversized, symlinked and unreadable files are all listed in the report; rules that select files by name (such as `.pth` and `.start`) run on the raw bytes before the binary check, and also see oversized files and symlinks, so "too big" or "a link" is not a way around them;
- work per line and per file is bounded (a line is analysed up to 4096 bytes, a longer one is CRITICAL by itself; at most 100 findings per file per rule), so a hostile file cannot make the scan quadratic or flood the report;
- remote repositories are cloned shallowly over `https` only (`ssh`, `http://` and `git://` are refused; a private repository is cloned by its owner and the folder scanned). `git` runs with an empty environment plus a short allow-list of variables and with its user and system configuration replaced by an empty file, so no filter, credential helper or fsmonitor from any configuration runs and `GIT_CONFIG_*` variables do not reach it. Hooks and templates are off, symlinks are written as plain files, objects are checked, submodules are not fetched, and nothing can ask a question interactively. The `--ref` value is passed to git as a single validated argument, and error text coming back from a git server is cleaned before it is printed;
- credentials in a URL (`https://TOKEN@host/...`) are hidden in the notice, the report label and every error message, git's own text included;
- an inconclusive scan is never reported as clean: when the file limit was reached, a file was too large or could not be read, or an executable binary (ELF, PE, Mach-O, found by magic bytes) was not analyzed, the report ends with `Scan: INCONCLUSIVE` and the exit status is 3 even with `--fail-on none`. Other binary files that were read are listed as "binary, not analyzed" and do not change the status. The executable exception is removed when the "committed binaries" rule exists, because then such a file is a finding;
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
