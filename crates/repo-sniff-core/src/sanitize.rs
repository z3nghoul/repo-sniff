//! Making text and paths from a scanned repository safe to show in a report.
//!
//! Names and strings that come from the scanned repository are attacker
//! controlled. Printed raw, they could carry terminal escape sequences (to
//! recolor, overwrite or hide parts of the report), line breaks (to forge
//! extra findings) or bidi characters (to reorder what the reader sees).

use std::path::Path;

/// Longest path shown in a report; longer ones are cut.
const MAX_PATH_CHARS: usize = 300;

/// Joins path components with `/`, whatever the operating system, so globs
/// and reports behave the same everywhere. A backslash inside a Linux file
/// name is left alone: only real separators are replaced.
pub fn to_slash(path: &Path) -> String {
    path.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// A path as shown to the user: `/`-separated and safe to print, because file
/// names in a scanned repository are chosen by its author.
pub fn display_path(path: &Path) -> String {
    display_safe(&to_slash(path), MAX_PATH_CHARS)
}

/// Returns `text` with every dangerous character replaced by a visible
/// `\u{XXXX}` escape, cut to about `max_chars` characters (`...` marks the cut).
pub fn display_safe(text: &str, max_chars: usize) -> String {
    display_safe_cut(text, max_chars).0
}

/// `display_safe`, and whether the text was cut.
pub fn display_safe_cut(text: &str, max_chars: usize) -> (String, bool) {
    escape(text, max_chars, is_unsafe)
}

/// Like `display_safe`, for code quoted from the scanned file in a snippet: it
/// also escapes characters that are invisible or change the layout without
/// being control characters, so a snippet shows exactly what is in the file.
pub fn snippet_safe(text: &str, max_chars: usize) -> String {
    snippet_safe_cut(text, max_chars).0
}

/// `snippet_safe`, and whether the text was cut.
pub fn snippet_safe_cut(text: &str, max_chars: usize) -> (String, bool) {
    escape(text, max_chars, |ch| is_unsafe(ch) || is_invisible(ch))
}

fn escape(text: &str, max_chars: usize, needs_escape: impl Fn(char) -> bool) -> (String, bool) {
    let mut out = String::new();
    let mut count = 0;
    for ch in text.chars() {
        if count >= max_chars {
            out.push_str("...");
            return (out, true);
        }
        if needs_escape(ch) {
            let escaped = format!("\\u{{{:04X}}}", ch as u32);
            count += escaped.chars().count();
            out.push_str(&escaped);
        } else {
            out.push(ch);
            count += 1;
        }
    }
    (out, false)
}

/// Control characters (which include ESC, newline and carriage return), plus
/// invisible formatting characters that change how text is laid out.
fn is_unsafe(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch as u32,
            0x061C            // Arabic letter mark
            | 0x200B..=0x200F // zero-width characters, LRM, RLM
            | 0x202A..=0x202E // bidi embeddings and overrides
            | 0x2060..=0x2064 // word joiner and invisible operators
            | 0x2066..=0x2069 // bidi isolates
            | 0xFEFF          // zero-width no-break space / BOM
        )
}

/// Characters that draw nothing, or join and alter their neighbours, without
/// being control or bidi characters: harmless in a terminal, but in quoted code
/// they hide what is really there.
fn is_invisible(ch: char) -> bool {
    matches!(
        ch as u32,
        0x00AD                 // soft hyphen
        | 0x034F               // combining grapheme joiner
        | 0x115F | 0x1160      // Hangul choseong and jungseong fillers
        | 0x17B4 | 0x17B5      // Khmer inherent vowels
        | 0x180E               // Mongolian vowel separator
        | 0x2028 | 0x2029      // line and paragraph separators
        | 0x206A..=0x206F      // deprecated format characters
        | 0x3164 | 0xFFA0      // Hangul fillers
        | 0xFE00..=0xFE0F      // variation selectors
        | 0xFFF9..=0xFFFB      // interlinear annotation
        | 0x1D173..=0x1D17A    // musical formatting
        | 0xE0000..=0xE007F    // tag characters
        | 0xE0100..=0xE01EF // variation selectors supplement
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snippets_also_escape_invisible_characters() {
        let text = "a\u{2028}b\u{AD}c\u{E0041}d\u{3164}e\u{FE0F}f\u{202E}g\u{1B}";
        assert_eq!(
            snippet_safe(text, 200),
            "a\\u{2028}b\\u{00AD}c\\u{E0041}d\\u{3164}e\\u{FE0F}f\\u{202E}g\\u{001B}"
        );
        // Paths and labels keep their current form.
        assert_eq!(display_safe("a\u{2028}b", 200), "a\u{2028}b");
    }

    #[test]
    fn ordinary_text_is_unchanged() {
        assert_eq!(display_safe("build: cargo test", 100), "build: cargo test");
        assert_eq!(
            display_safe("\u{41f}\u{440}\u{438}\u{432}\u{456}\u{442}", 100),
            "\u{41f}\u{440}\u{438}\u{432}\u{456}\u{442}"
        );
    }

    #[test]
    fn terminal_escape_sequences_are_neutralized() {
        let hostile = "ok\u{1b}[2J\u{1b}[31mfake";
        let safe = display_safe(hostile, 100);
        assert!(!safe.contains('\u{1b}'));
        assert_eq!(safe, "ok\\u{001B}[2J\\u{001B}[31mfake");
    }

    #[test]
    fn line_breaks_cannot_forge_extra_lines() {
        assert_eq!(display_safe("a\nb\rc", 100), "a\\u{000A}b\\u{000D}c");
    }

    #[test]
    fn bidi_and_zero_width_characters_are_made_visible() {
        let safe = display_safe("a\u{202e}b\u{2066}c\u{200b}d", 100);
        assert_eq!(safe, "a\\u{202E}b\\u{2066}c\\u{200B}d");
    }

    #[test]
    fn paths_use_forward_slashes() {
        let path = Path::new("crates").join("core").join("lib.rs");
        assert_eq!(display_path(&path), "crates/core/lib.rs");
        assert_eq!(to_slash(&path), "crates/core/lib.rs");
    }

    #[test]
    fn hostile_file_names_are_neutralized() {
        let path = Path::new("dir").join("evil\u{1b}[2J\nFAKE.txt");
        let shown = display_path(&path);
        assert!(!shown.chars().any(|c| c.is_control()), "{shown:?}");
        assert!(shown.starts_with("dir/evil\\u{001B}"));
    }

    #[test]
    fn long_text_is_truncated() {
        assert_eq!(display_safe("abcdefghij", 4), "abcd...");
        assert_eq!(display_safe("abcd", 4), "abcd");
    }

    #[test]
    fn the_cut_variants_say_whether_the_text_was_cut() {
        assert_eq!(display_safe_cut("abcd", 4), ("abcd".to_string(), false));
        assert_eq!(display_safe_cut("abcde", 4), ("abcd...".to_string(), true));
        // Text that ends in `...` of its own is not taken for a cut.
        assert_eq!(display_safe_cut("a...", 4), ("a...".to_string(), false));
        assert_eq!(
            snippet_safe_cut("\u{200B}xyz", 8),
            ("\\u{200B}...".to_string(), true)
        );
    }

    #[test]
    fn truncation_never_splits_a_character() {
        // Each Cyrillic letter is two bytes; cutting by chars must stay valid.
        let safe = display_safe("\u{430}\u{431}\u{432}\u{433}", 2);
        assert_eq!(safe, "\u{430}\u{431}...");
    }
}
