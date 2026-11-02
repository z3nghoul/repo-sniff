//! Whether the explicit bidirectional controls of one line change how the line
//! is displayed.
//!
//! A line with such a character is laid out twice by the Unicode Bidirectional
//! Algorithm: as it is, and with the nine controls removed. If the two
//! displays are the same, the controls are only there (a direction helper in a
//! vendored bundle); if not, what a reviewer reads is not the order the code
//! is in (Trojan Source, CVE-2021-42574).
//!
//! Both layouts are made for a base direction of left to right (what editors,
//! diff views and code hosts use for source) and for the one the text chooses
//! (first strong character, what an auto-direction viewer uses). A base
//! direction forced to right to left is not modelled: a viewer only draws that
//! when its user asks for it, and a file cannot ask.
//!
//! Anything this module cannot judge with certainty is reported as such and
//! the rule keeps its full level: a line that may be shown on several lines, a
//! line too long to lay out cheaply and a scan that spent its budget.

use std::cell::Cell;

use unicode_bidi::{BidiClass, BidiInfo, Level, bidi_class};

/// The longest line, in bytes, that is laid out. Line 745 of the vendored
/// charting bundle that motivated this has 2.7 KiB, the longest line of that
/// file 15 KiB; a 64 KiB line takes a few milliseconds.
pub(crate) const MAX_ANALYZED_LINE: usize = 64 * 1024;

/// Bytes of lines a scan may lay out in total. The scan reads files one after
/// the other, in sorted order, so which lines are left over once it is spent
/// does not depend on the machine. The cell would have to be atomic if the scan
/// ever ran on several threads.
pub(crate) const SCAN_BUDGET: usize = 8 * 1024 * 1024;

/// What is known about the display of a line that has a control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Same display with and without the controls.
    Unchanged,
    /// Different display.
    Differs,
    /// Not laid out; the controls are treated as a deception.
    NotAnalyzed(Reason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reason {
    TooLong,
    LineBreak,
    Budget,
    InsideToken,
}

impl Reason {
    pub(crate) fn text(self) -> &'static str {
        match self {
            Reason::TooLong => "the line is too long to lay out",
            Reason::LineBreak => {
                "the line holds a character that some viewers show as a line break"
            }
            Reason::Budget => "the budget for laying out lines in this scan is spent",
            Reason::InsideToken => {
                "a control sits next to a word or path character, so it can change what a name is"
            }
        }
    }
}

/// U+202A..U+202E and U+2066..U+2069, the characters the rule reports.
pub(crate) fn is_control(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// The byte range of the first control in `line`.
pub(crate) fn first_control(line: &str) -> Option<std::ops::Range<usize>> {
    let bytes = line.as_bytes();
    // Every control is three bytes: E2 80 AA..AE or E2 81 A6..A9.
    let mut start = 0;
    while let Some(offset) = bytes[start..].iter().position(|&b| b == 0xE2) {
        let at = start + offset;
        if let [_, second, third, ..] = bytes[at..]
            && matches!((second, third), (0x80, 0xAA..=0xAE) | (0x81, 0xA6..=0xA9))
        {
            return Some(at..at + 3);
        }
        start = at + 1;
    }
    None
}

/// Characters a viewer may draw as the end of a line: `str::lines` only splits
/// at `\n`, but a lone `\r`, VT, FF, the separators U+001C..U+001E, U+0085,
/// U+2028 and U+2029 end a line or a paragraph somewhere.
fn breaks_line(c: char) -> bool {
    matches!(
        c,
        '\r' | '\u{B}' | '\u{C}' | '\u{1C}'..='\u{1E}' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}

/// Characters that make up a name, a path or a host: a control beside one is
/// part of that name, invisible, and no layout shows it.
fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '.' | '/' | '\\' | '-')
}

/// Whether a control touches a name character, looking past other controls and
/// the marks U+200E, U+200F and U+061C (`a<LRM><LRE>b` is `a` beside `b`).
fn control_beside_name(line: &str) -> bool {
    let skipped = |c: char| is_control(c) || matches!(c, '\u{200E}' | '\u{200F}' | '\u{61C}');
    let chars: Vec<char> = line.chars().collect();
    chars.iter().enumerate().any(|(at, &c)| {
        is_control(c)
            && (chars[..at]
                .iter()
                .rev()
                .find(|&&c| !skipped(c))
                .is_some_and(|&c| is_name_char(c))
                || chars[at + 1..]
                    .iter()
                    .find(|&&c| !skipped(c))
                    .is_some_and(|&c| is_name_char(c)))
    })
}

/// Judges a line known to hold a control. `budget` is what the scan has left
/// for laying out lines.
pub(crate) fn judge(line: &str, budget: &Cell<usize>) -> Verdict {
    if line.chars().any(breaks_line) {
        return Verdict::NotAnalyzed(Reason::LineBreak);
    }
    if line.len() > MAX_ANALYZED_LINE {
        return Verdict::NotAnalyzed(Reason::TooLong);
    }
    // A layout compares the order of what is shown; a control inside a name
    // changes the name and not the order (`./setup<LRI>.sh` is another file).
    if control_beside_name(line) {
        return Verdict::NotAnalyzed(Reason::InsideToken);
    }
    let Some(left) = budget.get().checked_sub(line.len()) else {
        return Verdict::NotAnalyzed(Reason::Budget);
    };
    budget.set(left);

    compare(line)
}

/// Lays the line out with and without its controls and compares.
fn compare(line: &str) -> Verdict {
    let stripped: String = line.chars().filter(|&c| !is_control(c)).collect();
    for direction in [Some(Level::ltr()), None] {
        match (display(line, direction), display(&stripped, direction)) {
            (Some(with), Some(without)) if with == without => {}
            _ => return Verdict::Differs,
        }
    }
    Verdict::Unchanged
}

/// What a viewer draws, left to right: each character with whether it is drawn
/// mirrored, the controls and the other characters rule X9 removes left out.
/// `None` when the text is more than one paragraph, which a line without a line
/// break cannot be.
fn display(text: &str, direction: Option<Level>) -> Option<Vec<(char, bool)>> {
    if text.is_empty() {
        return Some(Vec::new());
    }
    let info = BidiInfo::new(text, direction);
    let [paragraph] = info.paragraphs.as_slice() else {
        return None;
    };
    // Rule L1 on top of the resolved levels.
    let all = info.reordered_levels_per_char(paragraph, paragraph.range.clone());
    let mut chars = Vec::new();
    let mut levels = Vec::new();
    for ((index, c), level) in text.char_indices().zip(all) {
        if is_control(c) || info.original_classes[index] == BidiClass::BN {
            continue;
        }
        chars.push(c);
        levels.push(level);
    }
    Some(
        BidiInfo::reorder_visual(&levels)
            .into_iter()
            .map(|at| (chars[at], mirrorable(chars[at]) && levels[at].is_rtl()))
            .collect(),
    )
}

/// Whether a character may be drawn as its mirror image in a right-to-left
/// run. The crate has no mirroring table, so every non-ASCII character of
/// class ON counts, which can only make two displays differ.
fn mirrorable(c: char) -> bool {
    matches!(c, '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}')
        || (!c.is_ascii() && bidi_class(c) == BidiClass::ON)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LRM: char = '\u{200E}';
    const LRE: char = '\u{202A}';
    const RLE: char = '\u{202B}';
    const PDF: char = '\u{202C}';
    const RLO: char = '\u{202E}';
    const RLI: char = '\u{2067}';
    const PDI: char = '\u{2069}';

    fn judged(line: &str) -> Verdict {
        judge(line, &Cell::new(SCAN_BUDGET))
    }

    /// The layout alone, for lines a name check would catch first.
    fn laid_out(line: &str) -> Verdict {
        compare(line)
    }

    #[test]
    fn the_first_control_is_found_by_its_bytes() {
        assert_eq!(first_control("abc"), None);
        assert_eq!(first_control(&format!("ab{RLO}c")), Some(2..5));
        // E2 80 AF (narrow no-break space) and E2 81 A5 are next to the ranges.
        assert_eq!(first_control("a\u{202F}b\u{2065}c"), None);
        assert_eq!(first_control(&format!("\u{2014}{PDI}")), Some(3..6));
        for code in (0x202A..=0x202E).chain(0x2066..=0x2069) {
            let c = char::from_u32(code).unwrap();
            assert!(is_control(c) && first_control(&c.to_string()).is_some());
        }
    }

    #[test]
    fn a_direction_helper_with_a_symmetric_frame_is_unchanged() {
        for line in [
            format!("function a(e){{return\"{LRE}\"+e+\"{PDF}\"}}"),
            format!("function a(e){{return\"{RLE}\"+e+\"{PDF}\"}}"),
            format!("n=new RegExp(\"{LRM}|{LRE}|{RLE}|{PDF}\",\"g\")"),
            format!("t = \"{LRE}\u{645}\u{631}\u{62D}\u{628}\u{627}{PDF}\""),
        ] {
            assert_eq!(judged(&line), Verdict::Unchanged, "{line:?}");
        }
    }

    #[test]
    fn a_control_alone_or_with_nothing_to_move_is_unchanged() {
        assert_eq!(judged(&RLO.to_string()), Verdict::Unchanged);
        assert_eq!(judged(&format!("{RLE}{PDF}")), Verdict::Unchanged);
        assert_eq!(judged(&format!("= {LRE} {PDF}")), Verdict::Unchanged);
    }

    #[test]
    fn a_control_inside_a_name_keeps_the_full_level() {
        for line in [
            format!("before{LRE}after"),
            format!("bash ./setup{RLI}.sh"),
            format!("require(\"./util{LRE}\")"),
            format!("if host == \"example.com{PDF}\":"),
            format!("run(\"a{LRM}{LRE}b\")"),
            format!("run(\"a{LRE}{LRM}{PDF}b\")"),
            format!("run(\"a\u{200F}\u{61C}{LRE}\")"),
            format!("{LRE}name"),
        ] {
            assert_eq!(
                judged(&line),
                Verdict::NotAnalyzed(Reason::InsideToken),
                "{line:?}"
            );
        }
        // Quotes, spaces, bars and non-ASCII letters are not name characters.
        assert_eq!(judged(&format!("a = \"{LRE}\" + b")), Verdict::Unchanged);
        assert_eq!(
            judged(&format!("\"{LRE}\u{645}{PDF}\"")),
            Verdict::Unchanged
        );
    }

    #[test]
    fn code_that_is_shown_in_another_order_differs() {
        for line in [
            format!("function a(e){{return\"{RLE}\"+e.trim()+\"{PDF}\"}}"),
            format!("if (x) {{ {RLI}a(); b();{PDI} }}"),
            format!("var a = 1; {RLE} foo(); bar(); // x"),
            format!("x = \"{RLO}abc\""),
            format!("name = a{RLO} \u{5D1} "),
        ] {
            assert_eq!(laid_out(&line), Verdict::Differs, "{line:?}");
            assert_ne!(judged(&line), Verdict::Unchanged, "{line:?}");
        }
    }

    /// Short strings that are the same without rule L1 and different with it:
    /// white space at the end of the line goes back to the base direction.
    #[test]
    fn rule_l1_decides_these() {
        for line in [
            format!("ab{RLO} \u{5D1} "),
            format!("\t{RLE} \u{5D1} "),
            format!("{RLI} + "),
            format!("a{RLO} \u{5D1} "),
            format!("\"{RLI} {RLO}a "),
            format!("{PDF}{RLI} 1b "),
            format!("\t){RLO} a "),
        ] {
            assert_eq!(laid_out(&line), Verdict::Differs, "{line:?}");
        }
    }

    #[test]
    fn a_first_strong_right_to_left_character_is_judged_as_the_viewer_draws_it() {
        let line =
            format!("l = \"\u{5E9}\u{5DC}\u{5D5}\u{5DD}\"; run(\"{RLE}\" + e.trim() + \"{PDF}\");");
        assert_eq!(judged(&line), Verdict::Differs);
        // The Hebrew word first makes the auto direction right to left.
        let line = format!("\u{5E9}\u{5DC}\u{5D5}\u{5DD} = \"{RLE}\" + e.trim() + \"{PDF}\";");
        assert_eq!(judged(&line), Verdict::Differs);
    }

    #[test]
    fn invisible_characters_are_dropped_from_both_displays() {
        let line =
            format!("f(e){{return\"{RLE}\u{200B}\u{AD}\"+e.trim()+\"\u{AD}\u{200B}{PDF}\"}}");
        assert_eq!(judged(&line), Verdict::Differs);
        let line = format!("f(e){{return\"{LRE}\u{200B}\u{AD}\"+e+\"\u{AD}\u{200B}{PDF}\"}}");
        assert_eq!(judged(&line), Verdict::Unchanged);
    }

    #[test]
    fn marks_stay_in_both_displays() {
        let ltr = format!("f(e){{return\"{LRE}{LRM}\"+e+\"{PDF}\"}}");
        assert_eq!(judged(&ltr), Verdict::Unchanged);
        let rtl = format!("f(e){{return\"{RLE}\u{200F}\"+e.trim()+\"{PDF}\"}}");
        assert_eq!(judged(&rtl), Verdict::Differs);
    }

    #[test]
    fn a_character_that_may_end_a_line_is_never_laid_out() {
        for c in [
            '\r', '\u{B}', '\u{C}', '\u{1C}', '\u{1E}', '\u{85}', '\u{2028}', '\u{2029}',
        ] {
            // Equal over the whole text, shown on two lines by some viewers.
            let line = format!("x = \"{RLO}ab{c}ba{PDF}\";");
            assert_eq!(
                judged(&line),
                Verdict::NotAnalyzed(Reason::LineBreak),
                "U+{:04X}",
                c as u32
            );
        }
    }

    #[test]
    fn a_line_over_the_limit_is_not_laid_out_and_one_at_it_is() {
        let at = format!(
            "{LRE} {}",
            "a".repeat(MAX_ANALYZED_LINE - LRE.len_utf8() - 1)
        );
        assert_eq!(at.len(), MAX_ANALYZED_LINE);
        assert_eq!(judged(&at), Verdict::Unchanged);
        let over = format!("{at}a");
        assert_eq!(judged(&over), Verdict::NotAnalyzed(Reason::TooLong));
    }

    #[test]
    fn lines_cost_budget_until_it_is_spent() {
        let budget = Cell::new(100);
        let line = format!("{LRE} {}", "a".repeat(36)); // 40 bytes
        assert_eq!(judge(&line, &budget), Verdict::Unchanged);
        assert_eq!(judge(&line, &budget), Verdict::Unchanged);
        assert_eq!(budget.get(), 20);
        assert_eq!(judge(&line, &budget), Verdict::NotAnalyzed(Reason::Budget));
        assert_eq!(budget.get(), 20);
    }

    #[test]
    fn the_crate_gives_unassigned_right_to_left_blocks_a_right_to_left_class() {
        // The default class of an unassigned code point in these blocks is R or
        // AL. If a crate update changes that, a character a newer editor draws
        // right to left would compare as left to right here.
        let blocks = [
            0x0590..=0x08FF,
            0xFB1D..=0xFDCF,
            0xFDF0..=0xFDFF,
            0xFE70..=0xFEFF,
            0x10800..=0x10FFF,
            0x1E800..=0x1EFFF,
        ];
        for code in blocks.into_iter().flatten() {
            let Some(c) = char::from_u32(code) else {
                continue;
            };
            assert_ne!(bidi_class(c), BidiClass::L, "U+{code:04X}");
        }
    }
}
