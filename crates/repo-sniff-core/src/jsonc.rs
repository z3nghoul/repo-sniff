//! A small, strict-enough JSONC parser (JSON + `//` and `/* */` comments +
//! trailing commas), the dialect VS Code uses for `tasks.json` and
//! `*.code-workspace`.
//!
//! It exists so rules can look at *data* instead of text: comments disappear,
//! line breaks do not matter and `\uXXXX` escapes are decoded, so the keys
//! `"runOn"` and `"\u0072unOn"` are the same, exactly as VS Code sees them.
//!
//! Every value remembers the byte range it was read from, so findings can still
//! point at a line and a column. Nesting depth is limited because the input is untrusted: a
//! file made of 100 000 `[` would otherwise overflow the stack.

/// Deeper nesting than this is rejected instead of recursing further.
pub const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    /// Byte offset of the first character of this value in the source text.
    pub offset: usize,
    /// Byte offset just after the last character of this value (for a string,
    /// after its closing quote).
    pub end: usize,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Object(Vec<Member>),
    Array(Vec<Node>),
    String(String),
    /// Numbers, `true`, `false` and `null`: rules here never need their value.
    Other,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Member {
    /// The decoded key, so escapes such as `\u0072` are already resolved.
    pub key: String,
    pub value: Node,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub offset: usize,
    pub message: &'static str,
}

impl Node {
    /// Looks up a key in an object. Returns `None` for non-objects.
    /// If a key appears twice, the last one wins, as in VS Code.
    pub fn get(&self, key: &str) -> Option<&Node> {
        match &self.value {
            Value::Object(members) => members
                .iter()
                .rev()
                .find(|m| m.key == key)
                .map(|m| &m.value),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match &self.value {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Node]> {
        match &self.value {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }
}

/// Parses a whole JSONC document.
pub fn parse(text: &str) -> Result<Node, ParseError> {
    parse_with(text, false)
}

/// Parses a document the way `JSON.parse` does, which is how npm reads a
/// `package.json`: no comments, no trailing commas, numbers in the JSON
/// grammar, no raw control characters in strings, and a lone surrogate escape
/// is accepted (it becomes U+FFFD here). A leading byte order mark is dropped,
/// as npm does. Duplicate keys are kept; `Node::get` returns the last one,
/// which is the one `JSON.parse` keeps.
pub fn parse_json(text: &str) -> Result<Node, ParseError> {
    parse_with(text, true)
}

fn parse_with(text: &str, strict: bool) -> Result<Node, ParseError> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        text,
        pos: 0,
        strict,
    };
    // A UTF-8 byte order mark is allowed at the very start.
    if text.starts_with('\u{feff}') {
        parser.pos = 3;
    }
    parser.skip_trivia()?;
    let node = parser.value(0)?;
    parser.skip_trivia()?;
    if parser.pos != parser.bytes.len() {
        return Err(parser.error("unexpected content after the document"));
    }
    Ok(node)
}

/// Converts a byte offset into a 1-based line number. Counting `\n` works for
/// both LF and CRLF files.
pub fn line_of(text: &str, offset: usize) -> usize {
    text.as_bytes()[..offset.min(text.len())]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

struct Parser<'a> {
    bytes: &'a [u8],
    text: &'a str,
    pos: usize,
    /// `JSON.parse` rules instead of the JSONC dialect.
    strict: bool,
}

impl Parser<'_> {
    fn error(&self, message: &'static str) -> ParseError {
        ParseError {
            offset: self.pos,
            message,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Skips whitespace and both kinds of comments.
    fn skip_trivia(&mut self) -> Result<(), ParseError> {
        loop {
            match self.peek() {
                Some(b' ' | b'\t' | b'\n' | b'\r') => self.pos += 1,
                Some(b'/') if self.strict => return Err(self.error("comments are not JSON")),
                Some(b'/') => match self.bytes.get(self.pos + 1) {
                    Some(b'/') => {
                        while let Some(b) = self.peek() {
                            if b == b'\n' {
                                break;
                            }
                            self.pos += 1;
                        }
                    }
                    Some(b'*') => {
                        let start = self.pos;
                        self.pos += 2;
                        loop {
                            match self.peek() {
                                None => {
                                    self.pos = start;
                                    return Err(self.error("unterminated block comment"));
                                }
                                Some(b'*') if self.bytes.get(self.pos + 1) == Some(&b'/') => {
                                    self.pos += 2;
                                    break;
                                }
                                Some(_) => self.pos += 1,
                            }
                        }
                    }
                    _ => return Err(self.error("unexpected '/'")),
                },
                _ => return Ok(()),
            }
        }
    }

    fn value(&mut self, depth: usize) -> Result<Node, ParseError> {
        if depth > MAX_DEPTH {
            return Err(self.error("nesting is too deep"));
        }
        let offset = self.pos;
        let value = match self.peek() {
            Some(b'{') => self.object(depth)?,
            Some(b'[') => self.array(depth)?,
            Some(b'"') => Value::String(self.string()?),
            Some(b'-' | b'0'..=b'9') if self.strict => {
                self.number()?;
                Value::Other
            }
            Some(b'-' | b'0'..=b'9') => {
                while matches!(
                    self.peek(),
                    Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                ) {
                    self.pos += 1;
                }
                Value::Other
            }
            Some(b't') => self.literal("true")?,
            Some(b'f') => self.literal("false")?,
            Some(b'n') => self.literal("null")?,
            _ => return Err(self.error("expected a value")),
        };
        Ok(Node {
            offset,
            end: self.pos,
            value,
        })
    }

    /// A number in the JSON grammar: `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`.
    fn number(&mut self) -> Result<(), ParseError> {
        let digits = |p: &mut Self| {
            let start = p.pos;
            while matches!(p.peek(), Some(b'0'..=b'9')) {
                p.pos += 1;
            }
            p.pos > start
        };
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                digits(self);
            }
            _ => return Err(self.error("bad number")),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !digits(self) {
                return Err(self.error("bad number"));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !digits(self) {
                return Err(self.error("bad number"));
            }
        }
        Ok(())
    }

    fn literal(&mut self, word: &'static str) -> Result<Value, ParseError> {
        if self.text[self.pos..].starts_with(word) {
            self.pos += word.len();
            Ok(Value::Other)
        } else {
            Err(self.error("unknown literal"))
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.pos += 1; // '{'
        let mut members = Vec::new();
        let mut trailing = false;
        loop {
            self.skip_trivia()?;
            match self.peek() {
                Some(b'}') if self.strict && trailing => {
                    return Err(self.error("trailing comma"));
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(members));
                }
                Some(b'"') => {}
                _ => return Err(self.error("expected a key or '}'")),
            }
            let key = self.string()?;
            self.skip_trivia()?;
            if self.peek() != Some(b':') {
                return Err(self.error("expected ':'"));
            }
            self.pos += 1;
            self.skip_trivia()?;
            let value = self.value(depth + 1)?;
            members.push(Member { key, value });
            self.skip_trivia()?;
            trailing = false;
            match self.peek() {
                // A trailing comma before '}' is fine in JSONC: the next loop
                // iteration sees '}' and returns.
                Some(b',') => {
                    self.pos += 1;
                    trailing = true;
                }
                Some(b'}') => {}
                _ => return Err(self.error("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        let mut trailing = false;
        loop {
            self.skip_trivia()?;
            if self.peek() == Some(b']') {
                if self.strict && trailing {
                    return Err(self.error("trailing comma"));
                }
                self.pos += 1;
                return Ok(Value::Array(items));
            }
            items.push(self.value(depth + 1)?);
            self.skip_trivia()?;
            trailing = false;
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    trailing = true;
                }
                Some(b']') => {}
                _ => return Err(self.error("expected ',' or ']'")),
            }
        }
    }

    /// Reads a string literal and decodes its escapes.
    fn string(&mut self) -> Result<String, ParseError> {
        let start = self.pos;
        self.pos += 1; // opening quote
        let mut out = String::new();
        loop {
            let Some(b) = self.peek() else {
                self.pos = start;
                return Err(self.error("unterminated string"));
            };
            match b {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let esc = self.peek().ok_or_else(|| self.error("bad escape"))?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let first = self.hex4()?;
                            let ch = if (0xD800..0xDC00).contains(&first) {
                                // High surrogate: a low one must follow.
                                if self.text[self.pos..].starts_with("\\u") {
                                    self.pos += 2;
                                    let second = self.hex4()?;
                                    if (0xDC00..0xE000).contains(&second) {
                                        0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
                                    } else if self.strict {
                                        0xFFFD
                                    } else {
                                        return Err(self.error("lone surrogate"));
                                    }
                                } else if self.strict {
                                    0xFFFD
                                } else {
                                    return Err(self.error("lone surrogate"));
                                }
                            } else {
                                first
                            };
                            let lone_low = (0xDC00..0xE000).contains(&ch);
                            if lone_low && self.strict {
                                out.push('\u{FFFD}');
                            } else {
                                out.push(
                                    char::from_u32(ch)
                                        .ok_or_else(|| self.error("bad \\u escape"))?,
                                );
                            }
                        }
                        _ => return Err(self.error("bad escape")),
                    }
                }
                0x00..=0x1f if self.strict => {
                    return Err(self.error("raw control character in a string"));
                }
                _ => {
                    // Copy one whole UTF-8 character.
                    let ch = self.text[self.pos..]
                        .chars()
                        .next()
                        .expect("pos is always on a char boundary");
                    out.push(ch);
                    self.pos += ch.len_utf8();
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let digits = self
            .text
            .get(self.pos..self.pos + 4)
            .filter(|d| d.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| self.error("bad \\u escape"))?;
        let value = u32::from_str_radix(digits, 16).map_err(|_| self.error("bad \\u escape"))?;
        self.pos += 4;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(node: &Node) -> Vec<&str> {
        match &node.value {
            Value::Object(members) => members.iter().map(|m| m.key.as_str()).collect(),
            _ => panic!("not an object"),
        }
    }

    #[test]
    fn comments_and_trailing_commas_are_accepted() {
        let text = "{\n // line comment\n \"a\": 1, /* block */ \"b\": [1, 2,],\n}";
        let root = parse(text).unwrap();
        assert_eq!(keys(&root), ["a", "b"]);
        assert_eq!(root.get("b").unwrap().as_array().unwrap().len(), 2);
    }

    #[test]
    fn comment_markers_inside_strings_are_just_text() {
        let root = parse(r#"{"url": "https://example.com/a//b /* c */"}"#).unwrap();
        assert_eq!(
            root.get("url").unwrap().as_str(),
            Some("https://example.com/a//b /* c */")
        );
    }

    #[test]
    fn unicode_escapes_are_decoded_in_keys_and_values() {
        let root = parse(r#"{"\u0072unOn": "folder\u004Fpen"}"#).unwrap();
        assert_eq!(root.get("runOn").unwrap().as_str(), Some("folderOpen"));
    }

    #[test]
    fn surrogate_pairs_are_combined() {
        let root = parse(r#"{"x": "\ud83d\ude00"}"#).unwrap();
        assert_eq!(root.get("x").unwrap().as_str(), Some("\u{1F600}"));
    }

    #[test]
    fn lone_surrogate_is_an_error() {
        assert!(parse(r#"{"x": "\ud83d"}"#).is_err());
        assert!(parse(r#"{"x": "\ud83d\u0041"}"#).is_err());
    }

    #[test]
    fn last_duplicate_key_wins() {
        let root = parse(r#"{"a": "first", "a": "second"}"#).unwrap();
        assert_eq!(root.get("a").unwrap().as_str(), Some("second"));
    }

    #[test]
    fn byte_order_mark_is_skipped() {
        let root = parse("\u{feff}{\"a\": 1}").unwrap();
        assert_eq!(keys(&root), ["a"]);
    }

    #[test]
    fn malformed_documents_are_errors_with_an_offset() {
        let unterminated = parse("{\"a\": \"oops").unwrap_err();
        assert_eq!(unterminated.message, "unterminated string");
        assert_eq!(unterminated.offset, 6);

        assert!(parse("{\"a\": 1} garbage").is_err());
        assert!(parse("{\"a\" 1}").is_err());
        assert!(parse("/* never closed").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn nodes_remember_where_their_value_starts() {
        let text = "{\n  \"a\": \"x\"\n}";
        let root = parse(text).unwrap();
        let offset = root.get("a").unwrap().offset;
        assert_eq!(&text[offset..offset + 3], "\"x\"");
    }

    #[test]
    fn nodes_remember_where_their_value_ends() {
        let text = "{\"a\": \"x\\u0079\", \"b\": [1, 2], \"c\": -1.5e3}";
        let root = parse(text).unwrap();
        let span = |key| {
            let node = root.get(key).unwrap();
            &text[node.offset..node.end]
        };
        assert_eq!(span("a"), "\"x\\u0079\"");
        assert_eq!(span("b"), "[1, 2]");
        assert_eq!(span("c"), "-1.5e3");
        assert_eq!((root.offset, root.end), (0, text.len()));
    }

    #[test]
    fn line_numbers_work_for_lf_and_crlf() {
        let lf = "a\nb\nc";
        let crlf = "a\r\nb\r\nc";
        assert_eq!(line_of(lf, lf.len() - 1), 3);
        assert_eq!(line_of(crlf, crlf.len() - 1), 3);
        assert_eq!(line_of("abc", 0), 1);
        // An offset past the end is clamped instead of panicking.
        assert_eq!(line_of("a\nb", 999), 2);
    }

    #[test]
    fn nesting_up_to_the_limit_is_accepted_and_beyond_is_rejected() {
        let nested = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert!(parse(&nested(MAX_DEPTH + 1)).is_ok());
        assert!(parse(&nested(MAX_DEPTH + 2)).is_err());
    }

    #[test]
    fn deep_nesting_is_rejected_without_stack_overflow() {
        let text = "[".repeat(100_000);
        assert!(parse(&text).is_err());
    }

    #[test]
    fn json_mode_rejects_what_json_parse_rejects() {
        for bad in [
            "{\"a\": 1, }",
            "[1, 2, ]",
            "{\"a\": 1} // c",
            "/* c */ {}",
            "{\"a\": 01}",
            "{\"a\": 1.}",
            "{\"a\": .5}",
            "{\"a\": +1}",
            "{\"a\": -}",
            "{\"a\": 1e}",
            "{\"a\": \"x\ty\"}",
            "{'a': 1}",
            "{\"a\": 1}\0",
        ] {
            assert!(parse_json(bad).is_err(), "accepted {bad:?}");
        }
        // The dialect VS Code reads still takes the comments and commas.
        assert!(parse("{\"a\": 1, } // c").is_ok());
    }

    #[test]
    fn json_mode_accepts_what_json_parse_accepts() {
        for good in [
            "{}",
            "\u{feff}{\"a\": [1, -2.5e+3, 0, true, false, null, \"\\u00e9\"]}",
            " \r\n\t{\"a\": {\"b\": []}}\n",
            "{\"a\": \"\\ud800\"}",
            "{\"a\": \"\\udc00\"}",
            "{\"a\": \"\\ud83d\\ude00\"}",
        ] {
            assert!(parse_json(good).is_ok(), "rejected {good:?}");
        }
    }

    #[test]
    fn json_mode_keeps_duplicates_and_the_last_one_wins() {
        let root = parse_json(r#"{"a": "first", "a": "last"}"#).unwrap();
        assert_eq!(keys(&root), vec!["a", "a"]);
        assert_eq!(root.get("a").and_then(Node::as_str), Some("last"));
    }
}
