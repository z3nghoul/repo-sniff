//! A small JavaScript lexer for the loader checks (`js_loaders`).
//!
//! It is not a parser. It splits a source file into tokens well enough to tell
//! code from comments, strings, template literals and regular expressions, so
//! that the word `eval` in a comment is not a call, and `eval` is one. It
//! never fails: what it cannot read to the end (an unterminated string,
//! template, comment or regular expression, brackets that do not pair up) is
//! recorded in `problems`, so a check can say "review it by hand" instead of
//! calling the file clean.
//!
//! The scanner is hostile-input safe: one pass over the text, no recursion,
//! template nesting and the number of tokens are limited.

/// Most tokens kept for one file. A file with more is cut here and marked
/// `truncated`; the checks then say they could not read all of it.
pub const MAX_TOKENS: usize = 1_500_000;

/// Template literals nested inside `${...}` deeper than this are not followed.
const MAX_TEMPLATE_DEPTH: usize = 64;

/// How many problems are kept; the first is the one reported.
const MAX_PROBLEMS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An identifier or a keyword (`eval`, `const`, `eval`).
    Ident,
    Number,
    /// A string literal in `'` or `"`, quotes included.
    Str,
    /// A piece of a template literal: from the opening backtick or `}` to the
    /// closing backtick or `${`.
    Template,
    Regex,
    /// A single punctuation byte. `=>` is `=` then `>` with nothing between.
    Punct(u8),
}

#[derive(Debug, Clone, Copy)]
pub struct Token {
    pub kind: Kind,
    pub start: u32,
    pub end: u32,
    /// A line break comes between the previous token and this one.
    pub nl_before: bool,
    /// An identifier written with `\u` escapes.
    pub escaped: bool,
}

/// Something the lexer could not read with certainty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub offset: usize,
    pub what: &'static str,
    /// The problem can hide code that follows it: an unclosed comment or
    /// template literal swallows the rest of the file, and brackets that do not
    /// pair up break the structure. A string or a `/` that is not understood
    /// ends at the line break, where reading resumes, so it hides no later line
    /// (and in JSX text an apostrophe or a closing tag causes them all the time).
    pub swallows: bool,
}

#[derive(Debug, Default)]
pub struct Lexed {
    pub tokens: Vec<Token>,
    /// For a bracket token, the index of its partner; `u32::MAX` otherwise.
    pub matching: Vec<u32>,
    pub problems: Vec<Problem>,
    /// The file has more than `MAX_TOKENS` tokens; the rest was not read.
    pub truncated: bool,
}

pub const NO_MATCH: u32 = u32::MAX;

impl Lexed {
    /// The source text of token `i`.
    pub fn raw<'t>(&self, text: &'t str, i: usize) -> &'t str {
        let token = &self.tokens[i];
        &text[token.start as usize..token.end as usize]
    }

    /// The name of identifier token `i`, with `\u` escapes decoded; `None` if
    /// it is not an identifier.
    pub fn ident(&self, text: &str, i: usize) -> Option<String> {
        let token = self.tokens.get(i)?;
        if token.kind != Kind::Ident {
            return None;
        }
        let raw = self.raw(text, i);
        Some(if token.escaped {
            decode_escapes(raw)
        } else {
            raw.to_string()
        })
    }

    /// Whether token `i` is the identifier `name` (escapes decoded).
    pub fn is_ident(&self, text: &str, i: usize, name: &str) -> bool {
        let Some(token) = self.tokens.get(i) else {
            return false;
        };
        if token.kind != Kind::Ident {
            return false;
        }
        let raw = self.raw(text, i);
        if token.escaped {
            decode_escapes(raw) == name
        } else {
            raw == name
        }
    }

    /// The value of string token `i` without its quotes, escapes decoded.
    pub fn str_value(&self, text: &str, i: usize) -> Option<String> {
        let token = self.tokens.get(i)?;
        if token.kind != Kind::Str {
            return None;
        }
        let raw = self.raw(text, i);
        let inner = raw.get(1..raw.len().saturating_sub(1)).unwrap_or("");
        Some(decode_escapes(inner))
    }

    pub fn is_punct(&self, i: usize, byte: u8) -> bool {
        self.tokens
            .get(i)
            .is_some_and(|t| t.kind == Kind::Punct(byte))
    }

    /// Whether token `i` directly follows token `i - 1` with no space.
    pub fn adjacent(&self, i: usize) -> bool {
        i > 0 && self.tokens[i - 1].end == self.tokens[i].start
    }

    pub fn is_open(&self, i: usize) -> bool {
        matches!(
            self.tokens.get(i).map(|t| t.kind),
            Some(Kind::Punct(b'(' | b'[' | b'{'))
        )
    }

    /// The partner of the bracket at `i`.
    pub fn partner(&self, i: usize) -> Option<usize> {
        match self.matching.get(i) {
            Some(&m) if m != NO_MATCH => Some(m as usize),
            _ => None,
        }
    }
}

/// Decodes `\xHH`, `\uHHHH`, `\u{H...}` and the one-letter escapes. Anything
/// else after a backslash stands for itself. Used for names and for values
/// that a check compares with a word.
pub fn decode_escapes(raw: &str) -> String {
    if !raw.contains('\\') {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('0') => out.push('\0'),
            Some('x') => {
                let hex: String = (0..2)
                    .filter_map(|_| chars.next_if(char::is_ascii_hexdigit))
                    .collect();
                push_code(&mut out, &hex);
            }
            Some('u') => {
                if chars.next_if_eq(&'{').is_some() {
                    let mut hex = String::new();
                    while let Some(d) = chars.next_if(char::is_ascii_hexdigit) {
                        hex.push(d);
                    }
                    chars.next_if_eq(&'}');
                    push_code(&mut out, &hex);
                } else {
                    let hex: String = (0..4)
                        .filter_map(|_| chars.next_if(char::is_ascii_hexdigit))
                        .collect();
                    push_code(&mut out, &hex);
                }
            }
            Some('\r') => {
                chars.next_if_eq(&'\n');
            }
            Some('\n') => {}
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

fn push_code(out: &mut String, hex: &str) {
    if let Some(c) = u32::from_str_radix(hex, 16).ok().and_then(char::from_u32) {
        out.push(c);
    }
}

/// Words after which a `/` starts a regular expression and not a division.
const REGEX_AFTER_WORD: &[&str] = &[
    "return",
    "typeof",
    "instanceof",
    "in",
    "of",
    "new",
    "delete",
    "void",
    "throw",
    "case",
    "do",
    "else",
    "yield",
    "await",
];

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || c == '$' || (!c.is_ascii() && !is_space(c))
}

fn is_ident_part(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$' || (!c.is_ascii() && !is_space(c))
}

fn is_space(c: char) -> bool {
    c.is_whitespace() || c == '\u{feff}' || c == '\u{200b}'
}

/// Splits `text` into tokens.
pub fn lex(text: &str) -> Lexed {
    Lexer::new(text).run()
}

struct Lexer<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
    out: Lexed,
    nl: bool,
    /// One entry per open `${`: how many `{` are open inside it.
    templates: Vec<usize>,
    stack: Vec<u32>,
    /// No regular expression is tried before this offset: one that failed on a
    /// line would otherwise be tried again at every `/` of the line (quadratic).
    no_regex_before: usize,
}

impl<'a> Lexer<'a> {
    fn new(text: &'a str) -> Self {
        Lexer {
            text,
            bytes: text.as_bytes(),
            pos: 0,
            out: Lexed::default(),
            nl: false,
            templates: Vec::new(),
            stack: Vec::new(),
            no_regex_before: 0,
        }
    }

    fn problem(&mut self, offset: usize, what: &'static str, swallows: bool) {
        if self.out.problems.len() < MAX_PROBLEMS {
            self.out.problems.push(Problem {
                offset,
                what,
                swallows,
            });
        }
    }

    fn push(&mut self, kind: Kind, start: usize, end: usize, escaped: bool) -> bool {
        if self.out.tokens.len() >= MAX_TOKENS {
            self.out.truncated = true;
            return false;
        }
        self.out.tokens.push(Token {
            kind,
            start: start as u32,
            end: end as u32,
            nl_before: self.nl,
            escaped,
        });
        self.out.matching.push(NO_MATCH);
        self.nl = false;
        true
    }

    fn regex_allowed(&self) -> bool {
        let Some(last) = self.out.tokens.last() else {
            return true;
        };
        match last.kind {
            Kind::Number | Kind::Str | Kind::Regex => false,
            // Closing a template piece, or its `${`: an expression follows.
            Kind::Template => self.text[last.start as usize..last.end as usize].ends_with("${"),
            Kind::Ident => {
                let raw = &self.text[last.start as usize..last.end as usize];
                // `o.in / 2`: a property named like a keyword is a value.
                let n = self.out.tokens.len();
                let property = n >= 2 && self.out.tokens[n - 2].kind == Kind::Punct(b'.');
                !property && REGEX_AFTER_WORD.contains(&raw)
            }
            Kind::Punct(b')' | b']' | b'}') => false,
            // `n++ / 2`, `n-- / 2`
            Kind::Punct(b'+' | b'-') => {
                let n = self.out.tokens.len();
                let doubled = n >= 2
                    && self.out.tokens[n - 2].kind == last.kind
                    && self.out.tokens[n - 2].end == last.start;
                !doubled
            }
            Kind::Punct(_) => true,
        }
    }

    fn run(mut self) -> Lexed {
        // A hashbang line.
        if self.text.starts_with("#!") {
            self.pos = self.text[..].find('\n').unwrap_or(self.text.len());
        }
        while self.pos < self.bytes.len() {
            if self.out.truncated {
                break;
            }
            let b = self.bytes[self.pos];
            match b {
                b'\n' | b'\r' => {
                    self.nl = true;
                    self.pos += 1;
                }
                b' ' | b'\t' | 0x0b | 0x0c => self.pos += 1,
                b'/' => self.slash(),
                b'"' | b'\'' => self.string(b),
                b'`' => self.template(self.pos + 1, self.pos),
                b'0'..=b'9' => self.number(),
                b'.' if self.bytes.get(self.pos + 1).is_some_and(u8::is_ascii_digit) => {
                    self.number()
                }
                b'{' => {
                    if let Some(top) = self.templates.last_mut() {
                        *top += 1;
                    }
                    self.open(b);
                }
                b'}' => {
                    match self.templates.last_mut() {
                        Some(0) => {
                            self.templates.pop();
                            // Back into the template text, after the `}`.
                            self.template(self.pos + 1, self.pos);
                            continue;
                        }
                        Some(top) => *top -= 1,
                        None => {}
                    }
                    self.close(b);
                }
                b'(' | b'[' => self.open(b),
                b')' | b']' => self.close(b),
                _ if b < 0x80
                    && !(b.is_ascii_alphabetic() || b == b'_' || b == b'$' || b == b'\\') =>
                {
                    if b.is_ascii_graphic() {
                        let at = self.pos;
                        self.push(Kind::Punct(b), at, at + 1, false);
                    }
                    self.pos += 1;
                }
                _ => self.word(),
            }
        }
        for open in std::mem::take(&mut self.stack) {
            let offset = self.out.tokens[open as usize].start as usize;
            self.problem(offset, "a bracket that is never closed", true);
        }
        if !self.templates.is_empty() {
            self.problem(
                self.text.len(),
                "a template literal expression that is never closed",
                true,
            );
        }
        self.out
    }

    fn open(&mut self, b: u8) {
        let at = self.pos;
        let index = self.out.tokens.len();
        if self.push(Kind::Punct(b), at, at + 1, false) {
            self.stack.push(index as u32);
        }
        self.pos += 1;
    }

    fn close(&mut self, b: u8) {
        let at = self.pos;
        let want = if b == b')' {
            b'('
        } else if b == b']' {
            b'['
        } else {
            b'{'
        };
        let index = self.out.tokens.len();
        if !self.push(Kind::Punct(b), at, at + 1, false) {
            return;
        }
        match self.stack.last().copied() {
            Some(open) if self.out.tokens[open as usize].kind == Kind::Punct(want) => {
                self.stack.pop();
                self.out.matching[index] = open;
                self.out.matching[open as usize] = index as u32;
            }
            _ => self.problem(at, "a closing bracket with no matching opening one", true),
        }
        self.pos += 1;
    }

    fn slash(&mut self) {
        let start = self.pos;
        match self.bytes.get(start + 1) {
            Some(b'/') => {
                // Line comment: to the end of the line.
                let rest = &self.bytes[start..];
                let len = rest
                    .iter()
                    .position(|&c| c == b'\n' || c == b'\r')
                    .unwrap_or(rest.len());
                self.pos = start + len;
            }
            Some(b'*') => match self.text[start + 2..].find("*/") {
                Some(at) => {
                    if self.text[start..start + 2 + at].contains('\n') {
                        self.nl = true;
                    }
                    self.pos = start + 2 + at + 2;
                }
                None => {
                    self.problem(start, "a comment that is never closed", true);
                    self.pos = self.bytes.len();
                }
            },
            _ if start >= self.no_regex_before && self.regex_allowed() => self.regex(),
            _ => {
                self.push(Kind::Punct(b'/'), start, start + 1, false);
                self.pos += 1;
            }
        }
    }

    fn regex(&mut self) {
        let start = self.pos;
        let mut i = start + 1;
        let mut class = false;
        while i < self.bytes.len() {
            match self.bytes[i] {
                b'\\' => i += 1,
                b'[' => class = true,
                b']' => class = false,
                b'/' if !class => {
                    i += 1;
                    while i < self.bytes.len() && (self.bytes[i] as char).is_ascii_alphabetic() {
                        i += 1;
                    }
                    // A "regular expression" that holds code words is more likely
                    // a division that was misjudged: read its body as code too,
                    // which can only add findings.
                    let body = &self.text[start..i];
                    if ["eval", "Function", "require", "exec", "constructor"]
                        .iter()
                        .any(|word| body.contains(word))
                    {
                        break;
                    }
                    self.push(Kind::Regex, start, i, false);
                    self.pos = i;
                    return;
                }
                b'\n' | b'\r' => break,
                _ => {}
            }
            i += 1;
        }
        // Not a regular expression after all; a division sign.
        self.no_regex_before = i;
        self.problem(
            start,
            "a `/` that is neither a division nor a complete regular expression",
            false,
        );
        self.push(Kind::Punct(b'/'), start, start + 1, false);
        self.pos = start + 1;
    }

    fn string(&mut self, quote: u8) {
        let start = self.pos;
        let mut i = start + 1;
        while i < self.bytes.len() {
            match self.bytes[i] {
                b'\\' => {
                    // An escaped line break continues the string.
                    if self.bytes.get(i + 1) == Some(&b'\r')
                        && self.bytes.get(i + 2) == Some(&b'\n')
                    {
                        i += 1;
                    }
                    i += 2;
                    continue;
                }
                c if c == quote => {
                    self.push(Kind::Str, start, i + 1, false);
                    self.pos = i + 1;
                    return;
                }
                b'\n' | b'\r' => break,
                _ => {}
            }
            i += 1;
        }
        let end = i.min(self.bytes.len());
        self.problem(start, "a string that is never closed", false);
        self.push(Kind::Str, start, end, false);
        self.pos = end;
    }

    /// Reads template text from `from` up to the closing backtick or `${`.
    /// `start` is where the token begins (the backtick or the `}`).
    fn template(&mut self, from: usize, start: usize) {
        let mut i = from;
        while i < self.bytes.len() {
            match self.bytes[i] {
                b'\\' => i += 2,
                b'`' => {
                    self.push(Kind::Template, start, i + 1, false);
                    self.pos = i + 1;
                    return;
                }
                b'$' if self.bytes.get(i + 1) == Some(&b'{') => {
                    if self.templates.len() >= MAX_TEMPLATE_DEPTH {
                        self.problem(i, "template literals nested too deeply to follow", true);
                        self.pos = self.bytes.len();
                        return;
                    }
                    self.push(Kind::Template, start, i + 2, false);
                    self.templates.push(0);
                    self.pos = i + 2;
                    return;
                }
                b'\n' => {
                    self.nl = true;
                    i += 1;
                }
                _ => i += 1,
            }
        }
        self.problem(start, "a template literal that is never closed", true);
        self.push(Kind::Template, start, self.bytes.len(), false);
        self.pos = self.bytes.len();
    }

    fn number(&mut self) {
        let start = self.pos;
        let mut i = start;
        while i < self.bytes.len() {
            let c = self.bytes[i];
            let exponent_sign = (c == b'+' || c == b'-')
                && matches!(self.bytes[i - 1], b'e' | b'E')
                && !self.text[start..i].starts_with("0x")
                && !self.text[start..i].starts_with("0X");
            if c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || exponent_sign {
                i += 1;
            } else {
                break;
            }
        }
        self.push(Kind::Number, start, i, false);
        self.pos = i;
    }

    fn word(&mut self) {
        let start = self.pos;
        let mut escaped = false;
        let mut chars = self.text[start..].char_indices().peekable();
        let mut end = start;
        while let Some(&(offset, c)) = chars.peek() {
            let first = offset == 0;
            if c == '\\' && self.text[start + offset..].starts_with("\\u") {
                // `\uXXXX` or `\u{...}` inside a name.
                escaped = true;
                chars.next();
                chars.next();
                if chars.next_if(|&(_, c)| c == '{').is_some() {
                    while chars.next_if(|&(_, c)| c.is_ascii_hexdigit()).is_some() {}
                    chars.next_if(|&(_, c)| c == '}');
                } else {
                    for _ in 0..4 {
                        chars.next_if(|&(_, c)| c.is_ascii_hexdigit());
                    }
                }
                end = chars.peek().map_or(self.text.len(), |&(o, _)| start + o);
                continue;
            }
            let fits = if first {
                is_ident_start(c)
            } else {
                is_ident_part(c)
            };
            if !fits {
                break;
            }
            chars.next();
            end = start + offset + c.len_utf8();
        }
        if end == start {
            // A character that starts nothing (a lone backslash, a space-like
            // character): skip it.
            let c = self.text[start..].chars().next().map_or(1, char::len_utf8);
            if self.text[start..].chars().next().is_some_and(is_space) {
                self.nl |= matches!(
                    self.text[start..].chars().next(),
                    Some('\u{2028}' | '\u{2029}')
                );
            }
            self.pos = start + c;
            return;
        }
        self.push(Kind::Ident, start, end, escaped);
        self.pos = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idents(text: &str) -> Vec<String> {
        let lexed = lex(text);
        (0..lexed.tokens.len())
            .filter_map(|i| lexed.ident(text, i))
            .collect()
    }

    #[test]
    fn comments_and_strings_hide_their_words() {
        let text = "// eval(x)\n/* Function(y) */ a = \"eval(z)\"; b = 'eval'; c = `eval`;";
        assert_eq!(idents(text), ["a", "b", "c"]);
        assert!(lex(text).problems.is_empty());
    }

    #[test]
    fn an_escaped_name_is_decoded() {
        let text = "\\u0065val(x); ev\\u{61}l(y);";
        let lexed = lex(text);
        assert!(lexed.is_ident(text, 0, "eval"));
        assert!(lexed.is_ident(text, 5, "eval"));
    }

    #[test]
    fn code_inside_a_template_expression_is_read() {
        let text = "`a ${eval(x)} b ${ {k: 1}.k } c`; d";
        assert_eq!(idents(text), ["eval", "x", "k", "k", "d"]);
        assert!(lex(text).problems.is_empty());
    }

    #[test]
    fn a_slash_is_a_regex_after_an_operator_and_a_division_after_a_name() {
        let text = "a = x / 2 / y; b = /ev\"al/.test(c); d = (e) / 3;";
        let lexed = lex(text);
        let regexes = lexed
            .tokens
            .iter()
            .filter(|t| t.kind == Kind::Regex)
            .count();
        assert_eq!(regexes, 1);
        assert!(lexed.problems.is_empty(), "{:?}", lexed.problems);
    }

    #[test]
    fn brackets_pair_up() {
        let text = "f(a[1], {b: (2)})";
        let lexed = lex(text);
        assert_eq!(lexed.partner(1), Some(lexed.tokens.len() - 1));
        assert!(lexed.problems.is_empty());
    }

    #[test]
    fn what_cannot_be_read_is_recorded() {
        for text in [
            "a = 'never closed\nb = 1",
            "a = `never closed",
            "a = 1 /* never closed",
            "f(a",
            "a)",
        ] {
            assert!(!lex(text).problems.is_empty(), "{text}");
        }
    }

    #[test]
    fn string_values_are_decoded() {
        let text = r#"x = "\x65val"; y = 'a\
b';"#;
        let lexed = lex(text);
        let string = lexed
            .tokens
            .iter()
            .position(|t| t.kind == Kind::Str)
            .unwrap();
        assert_eq!(lexed.str_value(text, string).as_deref(), Some("eval"));
    }

    #[test]
    fn line_breaks_are_remembered() {
        let text = "a\nb c\n// x\nd";
        let lexed = lex(text);
        let flags: Vec<bool> = lexed.tokens.iter().map(|t| t.nl_before).collect();
        assert_eq!(flags, [false, true, false, true]);
    }

    #[test]
    fn a_hashbang_line_is_skipped() {
        assert_eq!(idents("#!/usr/bin/env node\nfoo()"), ["foo"]);
    }

    #[test]
    fn numbers_keep_their_exponent_sign() {
        let lexed = lex("a = 1e-3 + 0x1e-3;");
        let numbers = lexed
            .tokens
            .iter()
            .filter(|t| t.kind == Kind::Number)
            .count();
        assert_eq!(numbers, 3);
    }

    #[test]
    fn a_huge_input_is_cut_at_the_token_limit() {
        let text = ";".repeat(MAX_TOKENS + 10);
        let lexed = lex(&text);
        assert!(lexed.truncated);
        assert_eq!(lexed.tokens.len(), MAX_TOKENS);
    }

    #[test]
    fn deeply_nested_templates_are_stopped() {
        let text = "`${".repeat(200);
        let lexed = lex(&text);
        assert!(!lexed.problems.is_empty());
    }
}
