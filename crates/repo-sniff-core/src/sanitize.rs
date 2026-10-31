//! Making text from a scanned repository safe to show in a report.
//!
//! Names and strings that come from the scanned repository are attacker
//! controlled. Printed raw, they could carry terminal escape sequences (to
//! recolor, overwrite or hide parts of the report), line breaks (to forge
//! extra findings) or bidi characters (to reorder what the reader sees).

/// Returns `text` with every dangerous character replaced by a visible
/// `\u{XXXX}` escape, cut to about `max_chars` characters (`...` marks the cut).
pub fn display_safe(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut count = 0;
    for ch in text.chars() {
        if count >= max_chars {
            out.push_str("...");
            break;
        }
        if is_unsafe(ch) {
            let escaped = format!("\\u{{{:04X}}}", ch as u32);
            count += escaped.chars().count();
            out.push_str(&escaped);
        } else {
            out.push(ch);
            count += 1;
        }
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn long_text_is_truncated() {
        assert_eq!(display_safe("abcdefghij", 4), "abcd...");
        assert_eq!(display_safe("abcd", 4), "abcd");
    }

    #[test]
    fn truncation_never_splits_a_character() {
        // Each Cyrillic letter is two bytes; cutting by chars must stay valid.
        let safe = display_safe("\u{430}\u{431}\u{432}\u{433}", 2);
        assert_eq!(safe, "\u{430}\u{431}...");
    }
}
