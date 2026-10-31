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
| 🔴 Critical | Almost certainly malicious, or a dangerous action runs automatically |
| 🟠 High | A dangerous capability in a suspicious context |
| 🟡 Medium | Worth a human look |
| 🔵 Low | Ordinary thing, but useful for the overall picture |
| ⚪ Info | Context (languages, build system) |

**Combination rule:** severity goes up when signals combine. "Spawns a
process" alone is 🔵, while "runs automatically at build time + network +
obfuscation" is 🔴. Scoring uses three axes:

- **Trigger** — how automatically the code runs (on IDE open, on install, on
  build, only when the user runs the program).
- **Capability** — how dangerous the action is.
- **Concealment** — obfuscation and tricks that deceive the human reviewer.

---

## 1. Detections by stage

### Stage 0: the repository itself (freshly cloned)

| Detection | Level | ATT&CK | Rule |
|---|---|---|---|
| File with an image/text extension that is actually PE/ELF/Mach-O (magic bytes) | 🔴 | T1036 | — |
| Binary "test files" referenced by a build script (the xz backdoor pattern) | 🔴 | T1195.001 | — |
| Committed binaries (.exe, .dll, .so, .dylib, .jar, .pyc, .wasm, .node) | 🟠 | — | — |
| Windows "droppers": .lnk, .scr, .hta | 🟠 | T1204.002 | — |
| .bat, .cmd, .ps1, .vbs, .js (Windows Script Host) | 🟡 | T1059 | — |
| Password-protected archives | 🟠 | T1027 | — |
| Symlinks pointing outside the repository | 🟠 | — | — |
| Submodules pointing at third-party URLs | 🟡 | — | — |
| Large high-entropy files of unknown format | 🟡 | T1027 | — |

### Stage 1: opening in an IDE

| Detection | Level | ATT&CK | Rule |
|---|---|---|---|
| `.vscode/tasks.json` with `"runOn": "folderOpen"` | 🟠, with network or shell 🔴 | — | — |
| `.vscode/settings.json` overriding the interpreter, terminal or environment | 🟠 | — | — |
| `Directory.Build.props` / `Directory.Build.targets`, custom MSBuild tasks (Visual Studio evaluates them on project load) | 🟠 | T1127.001 | — |
| .NET analyzers / source generators shipped as DLLs in the repo (a binary runs inside the IDE) | 🔴 | — | — |
| `.devcontainer` with `postCreateCommand` / `postStartCommand` | 🟡, with network 🟠 | — | — |
| `.idea` run configurations, `.envrc` (direnv) | 🟡 | — | — |

### Stage 2: installing dependencies

| Detection | Level | ATT&CK | Rule |
|---|---|---|---|
| npm `preinstall` / `install` / `postinstall` / `prepare` | 🟠, with network, exec or obfuscation 🔴 | T1195.001 | — |
| `setup.py` containing code other than the `setup()` call | 🟠 | T1195.001 | — |
| `.pth` files (executed on every Python start-up) | 🔴 | T1546 | — |
| Custom build backend inside the repo (pyproject.toml) | 🟠 | T1195.001 | — |
| Lockfile resolving a package from outside the official registry | 🟠 | T1195.001 | — |
| Typosquatted package names | 🟠 | T1195.001 | — |
| Dependencies from git or a URL instead of the registry | 🟡 | — | — |
| Known vulnerabilities via OSV | 🟡, critical CVE 🟠 | — | — |
| binding.gyp, composer scripts, Rakefile / Gemfile with code | 🟡 | — | — |
| Dockerfile with `curl \| sh` | 🟡 | T1105 | — |

### Stage 3: building

| Detection | Level | ATT&CK | Rule |
|---|---|---|---|
| `gradle-wrapper.jar` not matching the official hash, or `distributionUrl` not on services.gradle.org | 🔴 | T1195.001 | — |
| Rust proc-macro doing I/O or networking (runs at compile time) | 🔴 | T1195.001 | — |
| `build.rs` with networking, process spawning or writes outside `OUT_DIR` | 🟠, with obfuscation 🔴 | T1195.001 | — |
| `.vcxproj` Pre/PostBuildEvent, MSBuild `<Exec>` | 🟠, with `powershell -enc` or a download 🔴 | T1127.001 | — |
| CMake: `execute_process`, `file(DOWNLOAD)`, `ExternalProject` / `FetchContent` from a third-party URL | 🟠 | T1105 | — |
| Makefile or configure with `curl \| sh`, base64 | 🟠 | T1105 | — |
| Gradle tasks with exec or download, Maven exec-plugin | 🟡 to 🟠 | — | — |
| `go:generate` (only runs when invoked manually) | 🔵 | — | — |

### Stage 4: tests

| Detection | Level | ATT&CK | Rule |
|---|---|---|---|
| `conftest.py` or pytest plugins with network or exec (pytest loads them automatically) | 🟠 | — | — |
| npm `test` script with suspicious commands | 🟡 | — | — |

### Stage 5: running the program (code capabilities)

| Detection | Level | ATT&CK | Rule |
|---|---|---|---|
| Chain "download → write → make executable → run" | 🔴 | T1105 | — |
| Shellcode and injection: `VirtualAlloc`/`VirtualAllocEx` with RWX, `WriteProcessMemory`, `CreateRemoteThread`, `mprotect(PROT_EXEC)`, `ptrace` | 🔴 | T1055 | — |
| Disabling defenses: Defender exclusions (`Add-MpPreference`, `Set-MpPreference`), AMSI bypass | 🔴 | T1562.001 | — |
| Crypto mining (`stratum+tcp://`, xmrig) | 🔴 | T1496 | — |
| Ransomware behavior: `vssadmin delete shadows`, mass file enumeration and encryption | 🔴 | T1490, T1486 | — |
| Data theft: browser passwords and cookies (`Login Data`, `Cookies`), Discord tokens, Telegram `tdata`, crypto wallets, `~/.ssh`, `~/.aws` | 🟠, with network 🔴 | T1555.003, T1539, T1552 | — |
| Exfiltration via Discord/Telegram webhooks or bot API, pastebin, ngrok, .onion, hard-coded IPs | 🟠 | T1567 | — |
| Persistence: registry Run keys, schtasks, services, cron, systemd, LaunchAgents, `.bashrc`/`.profile`, Startup folder, WMI subscriptions | 🟠 | T1547.001, T1053, T1543, T1546.004, T1546.003 | — |
| Keylogging (`SetWindowsHookEx`, `GetAsyncKeyState`), clipboard address swapping (clipper) | 🟠 | T1056.001, T1115 | — |
| UAC bypass (fodhelper / eventvwr registry keys) | 🟠 | T1548.002 | — |
| Anti-VM and anti-debugging (VM, sandbox and debugger checks) | 🟠 | T1497, T1622 | — |
| Loading code from bytes (`Assembly.Load(byte[])`, `defineClass`, `marshal.loads`) | 🟠 | T1620 | — |
| Screenshots | 🟡 | T1113 | — |
| Auto-update without signature or hash verification | 🟡 | — | — |
| Plain process spawning | 🔵 | T1106 | — |

### Stage 6: deceiving the human

| Detection | Level | ATT&CK | Rule |
|---|---|---|---|
| Trojan Source: Unicode bidi control characters (CVE-2021-42574) | 🔴 | — | — |
| Code hidden with whitespace past the edge of the screen (beyond ~column 200) or after hundreds of blank lines | 🔴 | T1027 | — |
| Invisible (zero-width) characters and homoglyphs in identifiers (Cyrillic `а` instead of Latin `a`) | 🟠 | T1036 | — |
| README advising "disable your antivirus", "download the password-protected zip", `curl \| bash` | 🟠 | T1204 | — |

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

## 4. 🔍 Review points

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
| Bugdoors | Risky spots at 🔵: `strcpy`, `sprintf`, `gets`, `memcpy` without a size check, `unsafe` blocks in Rust |
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
  protection against ReDoS).

**False positives.** A `.repo-sniff.toml` file holds exclusions, each with a
**mandatory justification** field. A benchmark on popular honest repositories
(for example ripgrep) targets "0 critical on clean repos", with the results
published in the README.

**What we scan.** The branch or tag the user is going to build (the default
branch unless told otherwise), not the whole history. The ref can be passed
as an argument.

**Implementation order.** Stages 0–3 (automatic execution) and stage 6
(Trojan Source, whitespace hiding) first, because they give the most value
for the least effort. Then stage 5 capabilities, then obfuscation decoding.
The exact set of detections for each milestone is agreed before it starts.
