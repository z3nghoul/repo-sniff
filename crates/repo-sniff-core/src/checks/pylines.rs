//! Reading a file the way Python's `site` module reads `.pth` and `.start`
//! files: how it splits lines, and what it counts as whitespace.
//!
//! Sources: `Lib/site.py` of CPython 3.10 to 3.15. Python 3.12 and later
//! split with `str.splitlines()`; 3.10 and 3.11 only break on `\n`, `\r` and
//! `\r\n`. The split used here is the most permissive one, so a line that any
//! supported version would see is seen.

/// Whitespace as Python's `str.strip()` sees it (`str.isspace()`).
pub(super) fn is_python_space(c: char) -> bool {
    matches!(
        c as u32,
        0x09..=0x0D
            | 0x1C..=0x1F
            | 0x20
            | 0x85
            | 0xA0
            | 0x1680
            | 0x2000..=0x200A
            | 0x2028
            | 0x2029
            | 0x202F
            | 0x205F
            | 0x3000
    )
}

/// Characters that end a line for `str.splitlines()`.
fn is_line_break(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r'
            | '\x0B'
            | '\x0C'
            | '\x1C'
            | '\x1D'
            | '\x1E'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

/// One line as Python 3.12+ splits it.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Line<'a> {
    /// 1-based; `\r\n` counts as a single break.
    pub(super) number: usize,
    /// The line without its terminator.
    pub(super) body: &'a str,
    /// From the start of the line to the next `\n` or `\r`. Python 3.10 and
    /// 3.11 only split there, so they run all of this as one statement, even
    /// when the other splitting characters cut it into several lines.
    pub(super) physical: &'a str,
}

pub(super) struct PythonLines<'a> {
    text: &'a str,
    pos: usize,
    number: usize,
    /// End of the physical line the last returned line belongs to, cached so
    /// a line cut into many pieces is not rescanned for every piece.
    hard_end: Option<usize>,
}

pub(super) fn python_lines(text: &str) -> PythonLines<'_> {
    PythonLines {
        text,
        pos: 0,
        number: 0,
        hard_end: None,
    }
}

impl<'a> Iterator for PythonLines<'a> {
    type Item = Line<'a>;

    fn next(&mut self) -> Option<Line<'a>> {
        if self.pos >= self.text.len() {
            return None;
        }
        let start = self.pos;
        let rest = &self.text[start..];
        let (end, after) = match rest.char_indices().find(|&(_, c)| is_line_break(c)) {
            Some((offset, c)) => {
                let end = start + offset;
                let mut after = end + c.len_utf8();
                if c == '\r' && self.text[after..].starts_with('\n') {
                    after += 1;
                }
                (end, after)
            }
            None => (self.text.len(), self.text.len()),
        };
        // A cached break at or after `start` is still the next one, because
        // it was the first break after an earlier start.
        let hard_end = match self.hard_end {
            Some(cached) if cached >= start => cached,
            _ => rest
                .find(['\n', '\r'])
                .map_or(self.text.len(), |offset| start + offset),
        };
        self.hard_end = Some(hard_end);
        self.number += 1;
        self.pos = after;
        Some(Line {
            number: self.number,
            body: &self.text[start..end],
            physical: &self.text[start..hard_end],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &str) -> Vec<(usize, &str, &str)> {
        python_lines(text)
            .map(|l| (l.number, l.body, l.physical))
            .collect()
    }

    #[test]
    fn lines_are_split_like_python_splitlines() {
        // Python: "a\nb".splitlines() == ["a", "b"]; a final break adds no line.
        assert_eq!(lines("a\nb"), [(1, "a", "a"), (2, "b", "b")]);
        assert_eq!(lines("a\n"), [(1, "a", "a")]);
        assert_eq!(lines("\n"), [(1, "", "")]);
        assert_eq!(lines(""), []);
        assert_eq!(lines("a\n\nb"), [(1, "a", "a"), (2, "", ""), (3, "b", "b")]);
    }

    #[test]
    fn crlf_is_one_break_and_cr_cr_lf_is_two() {
        assert_eq!(lines("a\r\nb"), [(1, "a", "a"), (2, "b", "b")]);
        assert_eq!(
            lines("a\r\r\nb"),
            [(1, "a", "a"), (2, "", ""), (3, "b", "b")]
        );
        assert_eq!(lines("a\rb"), [(1, "a", "a"), (2, "b", "b")]);
    }

    #[test]
    fn every_splitlines_separator_ends_a_line() {
        for sep in [
            '\x0B', '\x0C', '\x1C', '\x1D', '\x1E', '\u{85}', '\u{2028}', '\u{2029}',
        ] {
            let text = format!("a{sep}b");
            let bodies: Vec<_> = python_lines(&text).map(|l| l.body.to_string()).collect();
            assert_eq!(bodies, ["a", "b"], "separator U+{:04X}", sep as u32);
        }
    }

    #[test]
    fn physical_line_runs_to_the_next_newline_not_to_the_next_separator() {
        // Python 3.10/3.11 see "import sys;\x0cexec('x')" as one statement.
        let got = lines("import sys;\x0cexec('x')\nnext");
        assert_eq!(
            got,
            [
                (1, "import sys;", "import sys;\x0cexec('x')"),
                (2, "exec('x')", "exec('x')"),
                (3, "next", "next"),
            ]
        );
        // A lone CR is a hard break for every version.
        assert_eq!(lines("a\rb")[0].2, "a");
    }

    #[test]
    fn a_line_cut_into_many_pieces_is_not_rescanned_for_every_piece() {
        // 20000 pieces of one physical line; must finish instantly.
        let text = "x\x0C".repeat(20_000);
        let count = python_lines(&text).count();
        assert_eq!(count, 20_000);
    }

    #[test]
    fn python_whitespace_is_the_isspace_set() {
        for c in [
            '\t', '\x0B', '\x0C', '\r', '\x1C', '\x1F', ' ', '\u{85}', '\u{A0}', '\u{1680}',
            '\u{2000}', '\u{200A}', '\u{2028}', '\u{202F}', '\u{205F}', '\u{3000}',
        ] {
            assert!(is_python_space(c), "U+{:04X}", c as u32);
        }
        for c in [
            'a', '\0', '\u{200B}', '\u{180E}', '\u{FEFF}', '\u{FFFD}', '#',
        ] {
            assert!(!is_python_space(c), "U+{:04X}", c as u32);
        }
    }
}
