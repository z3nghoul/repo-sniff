# repo-sniff

[![CI](https://github.com/z3nghoul/repo-sniff/actions/workflows/ci.yml/badge.svg)](https://github.com/z3nghoul/repo-sniff/actions/workflows/ci.yml)

**Sniff a repository before you run it.**

`repo-sniff` is a command-line scanner that **statically** analyzes a GitHub
repository for signs of malicious or suspicious code and produces a readable
report: a risk score plus an explanation for every finding (file and line,
why it is suspicious, how serious it is).

It is aimed at the moment right before you `npm install`, `pip install`,
`cargo build` or open a random Visual Studio project from the internet:
these steps can run code from the repository on your machine, and fake
"cheats", "tools" and "PoCs" exploit exactly that.

> ⚠️ Early development. Right now `repo-sniff` resolves and clones targets;
> the analysis layers below are being built step by step.

## Safety first

`repo-sniff` **never executes code from the scanned repository**. No install,
no build, no scripts — it only reads files. Remote repositories are cloned
with hooks, Git LFS filters and submodules disabled.

## Planned analysis layers

1. **Build/install hooks** — `preinstall`/`postinstall` in `package.json`,
   `setup.py`, `build.rs`, Gradle tasks, `PreBuildEvent`/`PostBuildEvent` in
   `.vcxproj`, GitHub Actions workflows, committed binaries.
2. **Capabilities** — networking, process spawning, persistence (registry Run
   keys, systemd, cron, LaunchAgents), keyboard/clipboard hooks, browser and
   Discord data access, process injection. Risk comes from *combinations* of
   capabilities, not from single matches.
3. **AST analysis** with tree-sitter (Python, JavaScript, C/C++) to tell real
   calls apart from comments and strings.
4. **Obfuscation** — Shannon entropy, long base64/hex blobs, minified code
   hidden among normal sources.
5. **Dependencies** — typosquatting of popular packages, known
   vulnerabilities via the OSV API.
6. **README vs. behavior** — comparing what a project claims to do with what
   its code can do.

Output formats: colored terminal report, JSON, and SARIF for GitHub code
scanning. A GitHub Action for scanning pull requests is planned too.

Rules are plain TOML files, so new detections can be contributed without
touching the engine.

## Usage

Build from source (requires a Rust toolchain and `git`):

```sh
git clone https://github.com/z3nghoul/repo-sniff
cd repo-sniff
cargo build --release
```

Scan a local directory or a remote repository:

```sh
repo-sniff scan ./some-project
repo-sniff scan https://github.com/owner/repo
```

## Development

```sh
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

Test fixtures are synthetic, harmless files that only *imitate* suspicious
patterns; each one is marked `SYNTHETIC TEST FIXTURE — not functional`.

## License

[AGPL-3.0](LICENSE)
