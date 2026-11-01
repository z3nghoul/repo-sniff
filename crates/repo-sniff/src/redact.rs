//! Keeping credentials out of everything the tool prints.
//!
//! People paste URLs such as `https://TOKEN@github.com/owner/repo`. The token
//! must not end up in a terminal, a CI log or a report that gets shared, so
//! every piece of text that can contain a URL goes through here first: the
//! "Cloning" notice, the report label, error messages and the text git prints
//! about a failed clone (git repeats the URL it was given).

use std::borrow::Cow;

/// Replaces the user and password part of every `scheme://user:pass@host`
/// found in `text` with `***`.
///
/// The user information is taken to end at the last `@` of the word. A valid
/// URL has no `/`, `?` or `#` in its user information, but a pasted one with
/// an unescaped secret might (`https://user:pa#ss@host/r`), and from the text
/// alone `user:a/b?c@host` cannot be told apart from `host/path?mail=a@b`.
/// Showing half of a secret is a leak, so the ambiguous case is hidden: the
/// price is that an `@` inside a path or query also hides what comes before
/// it, which only shortens the message.
pub fn redact_credentials(text: &str) -> String {
    redact_scp_like(&redact_urls(text))
}

/// A target that was taken for a local path, as it may be shown in an error:
/// if it holds an `@`, everything up to its last `@` is hidden.
/// `TOKEN@github.com/o/r`, `user:TO/KEN@host/o/r` and a mistyped
/// `https:/user:TOKEN@host/r` are URLs with credentials that did not look like
/// URLs, and a token may hold `/` (base64, cloud secret keys), so the cut is
/// not made per path component. An honest folder such as `C:/Users/first@corp`
/// only loses the part before the `@` in the message.
pub fn redact_path(raw: &str) -> String {
    match raw.rfind('@') {
        Some(at) if at > 0 => format!("***{}", &raw[at..]),
        _ => raw.to_string(),
    }
}

/// Characters that end a word: whitespace and the quotes and brackets that
/// messages put around a URL.
fn ends_word(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\'' | '"' | '<' | '>' | '`')
}

/// Hides the user information of scp-like addresses (`user:TOKEN@host:path`)
/// in words without `://`: everything before the last `@` that is followed by
/// a host and a `:`. The plain `git` user is not a secret and is kept. An
/// e-mail address followed by a colon is hidden too, which only shortens the
/// message.
fn redact_scp_like(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        let start = rest.find(|c: char| !ends_word(c)).unwrap_or(rest.len());
        out.push_str(&rest[..start]);
        rest = &rest[start..];
        let end = rest.find(ends_word).unwrap_or(rest.len());
        let (word, after) = rest.split_at(end);
        out.push_str(&hide_scp_user(word));
        rest = after;
    }
    out
}

fn hide_scp_user(word: &str) -> Cow<'_, str> {
    if word.contains("://") {
        return Cow::Borrowed(word);
    }
    let user_end = word.match_indices('@').rev().find_map(|(at, _)| {
        let host_end = word[at + 1..].find([':', '/', '\\', '@'])?;
        (host_end > 0 && word[at + 1 + host_end..].starts_with(':')).then_some(at)
    });
    match user_end {
        Some(at) if at > 0 && &word[..at] != "git" && &word[..at] != "***" => {
            Cow::Owned(format!("***{}", &word[at..]))
        }
        _ => Cow::Borrowed(word),
    }
}

/// The `scheme://user:pass@host` half of `redact_credentials`.
fn redact_urls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(position) = rest.find("://") {
        let (head, tail) = rest.split_at(position + 3);
        out.push_str(head);

        let word_end = tail.find(ends_word).unwrap_or(tail.len());
        let (word, after) = tail.split_at(word_end);

        match word.rfind('@') {
            Some(at) => {
                out.push_str("***@");
                out.push_str(&word[at + 1..]);
            }
            None => out.push_str(word),
        }
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
    fn a_secret_with_a_question_mark_or_hash_is_still_hidden() {
        for (url, secret) in [
            ("https://u:p#w@example.invalid/r", "p#w"),
            ("https://u:p?w@example.invalid/r", "p?w"),
            ("https://user:pa#ss@example.invalid/r", "pa#ss"),
            ("https://u:a/b?c@example.invalid/r", "a/b?c"),
            ("https://TOKEN#x?y@example.invalid/r?ref=main#top", "TOKEN"),
        ] {
            let shown = redact_credentials(url);
            assert!(!shown.contains(secret), "{url} -> {shown}");
            assert!(
                shown.starts_with("https://***@example.invalid/r"),
                "{shown}"
            );
        }
    }

    #[test]
    fn a_query_or_fragment_after_the_host_is_kept() {
        assert_eq!(
            redact_credentials("https://T@example.invalid/r?ref=main#top"),
            "https://***@example.invalid/r?ref=main#top"
        );
    }

    #[test]
    fn an_at_sign_in_a_query_hides_what_comes_before_it() {
        // `host/path?mail=a@b` reads the same as `user:a/b?c@host`, so the
        // ambiguous case is hidden rather than risk showing a secret.
        assert_eq!(
            redact_credentials("https://example.com/path?email=a@b.c"),
            "https://***@b.c"
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
    fn scp_like_user_information_is_hidden_except_the_git_user() {
        assert_eq!(
            redact_credentials("cannot access deploy:FAKE_TOKEN@example.invalid:o/r.git"),
            "cannot access ***@example.invalid:o/r.git"
        );
        assert_eq!(
            redact_credentials("'u:p@ss@example.invalid:o/r'"),
            "'***@example.invalid:o/r'"
        );
        assert_eq!(
            redact_credentials("u:a/b@example.invalid:o/r"),
            "***@example.invalid:o/r"
        );
        for kept in [
            "git@example.invalid:o/r.git",
            "mail me at a@example.invalid today",
            "see src/main.rs:12",
            "@example.invalid:x",
        ] {
            assert_eq!(redact_credentials(kept), kept);
        }
    }

    #[test]
    fn credentials_in_a_target_taken_for_a_path_are_hidden() {
        for (raw, shown) in [
            ("FAKE_TOKEN@github.com/o/r", "***@github.com/o/r"),
            ("user:FAKE_TOKEN@github.com/o/r", "***@github.com/o/r"),
            ("user:FA/KETOKEN@github.com/o/r", "***@github.com/o/r"),
            (
                "https:/user:FA/KETOKEN@example.invalid/r",
                "***@example.invalid/r",
            ),
            (
                "https:\\\\user:FAKE_TOKEN@example.invalid\\r",
                "***@example.invalid\\r",
            ),
            ("C:/Users/first@corp/repo", "***@corp/repo"),
            ("./missing", "./missing"),
            ("", ""),
            ("@b/c", "@b/c"),
        ] {
            assert_eq!(redact_path(raw), shown, "{raw}");
        }
    }

    #[test]
    fn percent_encoded_secrets_are_hidden_whole() {
        assert_eq!(
            redact_credentials("https://user:FAKE%40TOKEN@example.invalid/r"),
            "https://***@example.invalid/r"
        );
        assert_eq!(
            redact_credentials("deploy:FAKE%3ATOKEN@example.invalid:o/r"),
            "***@example.invalid:o/r"
        );
    }

    #[test]
    fn redacting_twice_changes_nothing() {
        let once = redact_credentials(
            "see https://TOKEN@host/x and https://host2/y and u:T@h:p and 'git@h:p'",
        );
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
