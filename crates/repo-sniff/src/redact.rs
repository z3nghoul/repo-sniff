//! Keeping credentials out of everything the tool prints.
//!
//! People paste URLs such as `https://TOKEN@github.com/owner/repo`. The token
//! must not end up in a terminal, a CI log or a report that gets shared, so
//! every piece of text that can contain a URL goes through here first: the
//! "Cloning" notice, the report label, error messages and the text git prints
//! about a failed clone (git repeats the URL it was given).

/// Replaces the user and password part of every `scheme://user:pass@host`
/// found in `text` with `***`.
///
/// The user information is taken to end at the last `@` before the first
/// `?` or `#` of the word, not only before the first `/`. A valid URL cannot
/// have a `/` in its user information, but a pasted one with an unescaped
/// secret might, and showing half of a secret is a leak. The price is that an
/// `@` inside a path also hides what comes before it, which is acceptable.
pub fn redact_credentials(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(position) = rest.find("://") {
        let (head, tail) = rest.split_at(position + 3);
        out.push_str(head);

        let word_end = tail
            .find(|c: char| c.is_whitespace() || matches!(c, '\'' | '"' | '<' | '>' | '`'))
            .unwrap_or(tail.len());
        let (word, after) = tail.split_at(word_end);
        let query = word.find(['?', '#']).unwrap_or(word.len());
        let (before_query, query_and_fragment) = word.split_at(query);

        match before_query.rfind('@') {
            Some(at) => {
                out.push_str("***@");
                out.push_str(&before_query[at + 1..]);
            }
            None => out.push_str(before_query),
        }
        out.push_str(query_and_fragment);
        rest = after;
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_only_user_information_is_hidden() {
        assert_eq!(
            redact_credentials("https://TOKEN@github.com/owner/repo"),
            "https://***@github.com/owner/repo"
        );
    }

    #[test]
    fn user_and_password_are_both_hidden() {
        assert_eq!(
            redact_credentials("https://user:p4ss@example.com/owner/repo.git"),
            "https://***@example.com/owner/repo.git"
        );
    }

    #[test]
    fn urls_without_credentials_are_unchanged() {
        for text in [
            "https://github.com/owner/repo",
            "https://github.com/owner/repo?ref=main#top",
            "no url here",
            "",
            "ftp://",
        ] {
            assert_eq!(redact_credentials(text), text);
        }
    }

    #[test]
    fn a_secret_with_an_unescaped_slash_is_still_hidden() {
        let shown = redact_credentials("https://user:pa/ss@example.com/repo");
        assert!(
            !shown.contains("pa/ss") && !shown.contains("user"),
            "{shown}"
        );
        assert!(shown.contains("example.com"));
    }

    #[test]
    fn an_at_sign_in_the_query_is_not_user_information() {
        assert_eq!(
            redact_credentials("https://example.com/path?email=a@b.c"),
            "https://example.com/path?email=a@b.c"
        );
    }

    #[test]
    fn every_url_in_a_message_is_handled_including_git_error_text() {
        let message = "fatal: unable to access 'https://SECRET@example.invalid/o/r/': \
                       Could not resolve host; also tried https://u:SECRET2@mirror.invalid/o/r";
        let shown = redact_credentials(message);
        assert!(!shown.contains("SECRET"), "{shown}");
        assert!(
            shown.contains("'https://***@example.invalid/o/r/'"),
            "{shown}"
        );
        assert!(shown.contains("https://***@mirror.invalid/o/r"), "{shown}");
    }

    #[test]
    fn redacting_twice_changes_nothing() {
        let once = redact_credentials("see https://TOKEN@host/x and https://host2/y");
        assert_eq!(redact_credentials(&once), once);
    }

    #[test]
    fn non_ascii_text_is_kept() {
        let shown =
            redact_credentials("\u{43f}\u{440}\u{438}\u{432}\u{456}\u{442} https://T@h/\u{44f}");
        assert_eq!(
            shown,
            "\u{43f}\u{440}\u{438}\u{432}\u{456}\u{442} https://***@h/\u{44f}"
        );
    }
}
