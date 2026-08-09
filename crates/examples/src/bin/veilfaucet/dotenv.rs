//! A `.env` parser matching Dart's `dotenv` package.
//!
//! The faucet must read the *same* `.env` file the Dart bot used, and the popular
//! Rust `.env` crates cannot: they reject an unquoted value containing spaces,
//! which is exactly how the Dart bot's `.env.example` stores `VEIL_MNEMONIC`.
//!
//! ```text
//! VEIL_MNEMONIC=abandon abandon abandon ... about
//! ```
//!
//! `dotenvy` fails that line with `Error parsing line`, and then every key below
//! it is lost. Rather than ask operators to edit a working file, this module
//! reproduces the rules from `dotenv`'s `parser.dart`:
//!
//! - a line is split at the **first** `=`; everything after it is the value
//! - both sides are trimmed
//! - a leading `export` on the key is dropped
//! - a value wrapped in matching single or double quotes has them removed
//! - a `#` begins a comment and is stripped to end of line, unless the line ends
//!   with a quote character
//! - `$VAR` and `${VAR}` are substituted in unquoted and double-quoted values,
//!   from earlier keys in the same file or from the process environment
//! - single-quoted values are taken literally, with no substitution
//! - a line with no `=` is ignored rather than treated as an error
//!
//! The last rule is why a half-filled `.env.example`, where values are still
//! `<bot token>` placeholders, produces a clear "not set" message about the key
//! that matters instead of a parse error about a line the operator has not
//! reached yet.

use std::collections::HashMap;

/// Parse `.env` content into key-value pairs, in file order.
///
/// Later duplicates overwrite earlier ones, matching Dart, which builds a map as
/// it goes.
pub fn parse(content: &str) -> Vec<(String, String)> {
    let mut resolved: HashMap<String, String> = HashMap::new();
    let mut ordered: Vec<(String, String)> = Vec::new();

    for line in content.lines() {
        let Some((key, value)) = parse_line(line, &resolved) else {
            continue;
        };

        resolved.insert(key.clone(), value.clone());

        // Keep one entry per key, at its first position, with the latest value.
        match ordered.iter_mut().find(|(existing, _)| existing == &key) {
            Some(entry) => entry.1 = value,
            None => ordered.push((key, value)),
        }
    }

    ordered
}

/// Parse one line, or `None` when it carries no assignment.
fn parse_line(line: &str, env: &HashMap<String, String>) -> Option<(String, String)> {
    let stripped = strip_comment(line);

    // Dart's `_isValid`: the line must be non-empty and contain an `=`.
    let separator = stripped.find('=')?;

    let key = swallow_export(&stripped[..separator]);

    if key.is_empty() {
        return None;
    }

    let raw_value = stripped[separator + 1..].trim();

    let quote = surrounding_quote(raw_value);
    let value = unquote(raw_value);

    // A single-quoted value is literal, so `$` stays as typed.
    if quote == Some('\'') {
        return Some((key, value));
    }

    Some((key, interpolate(&value, env)))
}

/// Strip a trailing or whole-line comment, then trim.
///
/// Mirrors Dart's `#.*(?:[^'"])$` regex: the comment runs from the first `#` to
/// the end of the line, but only when the line does not end with a quote
/// character. That exception is what lets a quoted value contain a `#`.
fn strip_comment(line: &str) -> String {
    let trimmed = line.trim_end();

    let ends_with_quote = trimmed
        .chars()
        .last()
        .is_some_and(|last| last == '\'' || last == '"');

    if ends_with_quote {
        return trimmed.trim().to_string();
    }

    match trimmed.find('#') {
        // The regex needs at least one character after the `#`, so a line ending
        // in a lone `#` is left alone.
        Some(position) if position + 1 < trimmed.len() => trimmed[..position].trim().to_string(),
        _ => trimmed.trim().to_string(),
    }
}

/// Drop a leading `export` from a key and trim it.
fn swallow_export(key: &str) -> String {
    let trimmed = key.trim();

    // Dart removes every occurrence of the literal "export"; only a leading one
    // is meaningful, and matching just that avoids mangling a key such as
    // `MY_export_KEY`.
    match trimmed.strip_prefix("export") {
        Some(rest) if rest.starts_with(char::is_whitespace) => rest.trim().to_string(),
        _ => trimmed.to_string(),
    }
}

/// The quote character wrapping `value`, when it is wrapped in a matching pair.
fn surrounding_quote(value: &str) -> Option<char> {
    let mut chars = value.chars();
    let first = chars.next()?;
    let last = chars.next_back()?;

    // Two characters minimum, so `"` alone is not treated as a pair.
    ((first == '\'' || first == '"') && first == last).then_some(first)
}

/// Remove matching surrounding quotes, then trim.
fn unquote(value: &str) -> String {
    match surrounding_quote(value) {
        Some(_) => value[1..value.len() - 1].trim().to_string(),
        None => value.to_string(),
    }
}

/// Substitute `$VAR` and `${VAR}` from earlier keys, then the environment.
///
/// An unknown variable becomes an empty string, as in Dart. A `\$` is left as
/// written, which is how Dart's regex treats an escaped marker.
fn interpolate(value: &str, env: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();

    while let Some(character) = chars.next() {
        if character == '\\' {
            // Keep an escaped dollar sign literal, including its backslash, which
            // is what Dart's `(?:\\)?(\$)` group does.
            if chars.peek() == Some(&'$') {
                out.push('\\');
                out.push('$');
                chars.next();
                continue;
            }

            out.push(character);
            continue;
        }

        if character != '$' {
            out.push(character);
            continue;
        }

        let braced = chars.peek() == Some(&'{');
        if braced {
            chars.next();
        }

        // A variable name is a leading letter or underscore, then word characters.
        let mut name = String::new();

        while let Some(&next) = chars.peek() {
            let valid = if name.is_empty() {
                next.is_ascii_alphabetic() || next == '_'
            } else {
                next.is_ascii_alphanumeric() || next == '_'
            };

            if !valid {
                break;
            }

            name.push(next);
            chars.next();
        }

        if braced && chars.peek() == Some(&'}') {
            chars.next();
        }

        if name.is_empty() {
            // Not a variable reference after all, so keep the marker.
            out.push('$');
            if braced {
                out.push('{');
            }
            continue;
        }

        let replacement = env
            .get(&name)
            .cloned()
            .or_else(|| std::env::var(&name).ok())
            .unwrap_or_default();

        out.push_str(&replacement);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Look a key up in parsed output.
    fn get(pairs: &[(String, String)], key: &str) -> Option<String> {
        pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, value)| value.clone())
    }

    #[test]
    fn an_unquoted_value_may_contain_spaces() {
        // The reason this module exists: dotenvy rejects this line outright.
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";

        let parsed = parse(&format!("VEIL_MNEMONIC={mnemonic}\nOTHER=1\n"));

        assert_eq!(get(&parsed, "VEIL_MNEMONIC").as_deref(), Some(mnemonic));

        // And crucially, the keys after it are still read.
        assert_eq!(get(&parsed, "OTHER").as_deref(), Some("1"));
    }

    #[test]
    fn the_dart_example_file_parses_completely() {
        // Verbatim from ref/veil-faucet/.env.example, placeholders included. The
        // point is that unfilled placeholder lines never abort the parse.
        let content = "\
DISCORD_TOKEN=<bot token>
DISCORD_CLIENT_ID=<client id>
DISCORD_SERVER_ID=<server on which bot started>
DISCORD_TARGET_CHANNEL_ID=<channel on which bot work>
VEIL_MNEMONIC=<mnemonic phrase separated by space, don't use your primary wallet>
VEIL_ENCRYPTION_PASSWORD=<optional, leave empty if your wallet is not encrypted>
VEIL_NODE_ADDRESS=https://explorer-api.veil-project.com
VEIL_NODE_PASSWORD=<optional, node basic authentication>
VEIL_EXPLORER_TX=https://explorer.veil-project.com/tx/
FAUCET_TIMESTAMP_LIMIT=<how often user can request coins in seconds>
FAUCET_PAYOUTS_DELAY=<how often service should try to make payouts in seconds>
FAUCET_PAYOUTS_PER_CYCLE=<how many users will be payed in single transaction>
FAUCET_PAYOUTS_AMOUNT=<how many coins will be sent per user>
";

        let parsed = parse(content);

        assert_eq!(parsed.len(), 13, "every key should be read: {parsed:?}");

        // The two real values in the example survive intact.
        assert_eq!(
            get(&parsed, "VEIL_NODE_ADDRESS").as_deref(),
            Some("https://explorer-api.veil-project.com")
        );
        assert_eq!(
            get(&parsed, "VEIL_EXPLORER_TX").as_deref(),
            Some("https://explorer.veil-project.com/tx/")
        );
    }

    #[test]
    fn a_realistic_filled_file_parses() {
        let content = "\
DISCORD_TOKEN=MTA1.abcdef.ghijkl
DISCORD_SERVER_ID=123456789012345678
VEIL_MNEMONIC=one two three four five six seven eight nine ten eleven twelve
VEIL_ENCRYPTION_PASSWORD=
VEIL_NODE_ADDRESS=https://explorer-api.veil-project.com
FAUCET_TIMESTAMP_LIMIT=3600
FAUCET_PAYOUTS_AMOUNT=1.5
";

        let parsed = parse(content);

        assert_eq!(
            get(&parsed, "VEIL_MNEMONIC").as_deref(),
            Some("one two three four five six seven eight nine ten eleven twelve")
        );
        assert_eq!(get(&parsed, "VEIL_ENCRYPTION_PASSWORD").as_deref(), Some(""));
        assert_eq!(get(&parsed, "FAUCET_PAYOUTS_AMOUNT").as_deref(), Some("1.5"));
    }

    #[test]
    fn surrounding_quotes_are_removed() {
        let parsed = parse(
            "A=\"double quoted\"\nB='single quoted'\nC=\"trailing spaces  \"\nD=unquoted\n",
        );

        assert_eq!(get(&parsed, "A").as_deref(), Some("double quoted"));
        assert_eq!(get(&parsed, "B").as_deref(), Some("single quoted"));
        // Dart trims inside the quotes too.
        assert_eq!(get(&parsed, "C").as_deref(), Some("trailing spaces"));
        assert_eq!(get(&parsed, "D").as_deref(), Some("unquoted"));
    }

    #[test]
    fn mismatched_or_lone_quotes_are_left_alone() {
        let parsed = parse("A=\"unclosed\nB='mixed\"\nC=\"\n");

        assert_eq!(get(&parsed, "A").as_deref(), Some("\"unclosed"));
        assert_eq!(get(&parsed, "B").as_deref(), Some("'mixed\""));
        assert_eq!(get(&parsed, "C").as_deref(), Some("\""));
    }

    #[test]
    fn only_the_first_equals_sign_splits_the_line() {
        // A base64 value or a URL query can easily contain '='.
        let parsed = parse("TOKEN=abc=def==\nURL=https://x/y?a=1&b=2\n");

        assert_eq!(get(&parsed, "TOKEN").as_deref(), Some("abc=def=="));
        assert_eq!(get(&parsed, "URL").as_deref(), Some("https://x/y?a=1&b=2"));
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let content = "\
# a whole-line comment

A=1 # a trailing comment
B=2

  # an indented comment
C=3
";

        let parsed = parse(content);

        assert_eq!(parsed.len(), 3, "got {parsed:?}");
        assert_eq!(get(&parsed, "A").as_deref(), Some("1"));
        assert_eq!(get(&parsed, "B").as_deref(), Some("2"));
        assert_eq!(get(&parsed, "C").as_deref(), Some("3"));
    }

    #[test]
    fn a_quoted_value_may_contain_a_hash() {
        // The line ends with a quote, so Dart does not strip the comment.
        let parsed = parse("A=\"pass#word\"\n");

        assert_eq!(get(&parsed, "A").as_deref(), Some("pass#word"));
    }

    #[test]
    fn a_line_without_an_equals_sign_is_skipped_not_an_error() {
        // This is the behaviour that keeps a partly filled file usable.
        let parsed = parse("this is not an assignment\nA=1\n");

        assert_eq!(parsed.len(), 1);
        assert_eq!(get(&parsed, "A").as_deref(), Some("1"));
    }

    #[test]
    fn an_export_prefix_is_dropped() {
        let parsed = parse("export A=1\nexport  B=2\nC=3\n");

        assert_eq!(get(&parsed, "A").as_deref(), Some("1"));
        assert_eq!(get(&parsed, "B").as_deref(), Some("2"));
        assert_eq!(get(&parsed, "C").as_deref(), Some("3"));
    }

    #[test]
    fn variables_are_substituted_from_earlier_keys() {
        let parsed = parse("HOST=example.com\nURL=https://$HOST/tx/\nBRACED=${HOST}/x\n");

        assert_eq!(get(&parsed, "URL").as_deref(), Some("https://example.com/tx/"));
        assert_eq!(get(&parsed, "BRACED").as_deref(), Some("example.com/x"));
    }

    #[test]
    fn a_single_quoted_value_is_literal() {
        let parsed = parse("HOST=example.com\nLITERAL='$HOST'\n");

        assert_eq!(get(&parsed, "LITERAL").as_deref(), Some("$HOST"));
    }

    #[test]
    fn an_unknown_variable_becomes_empty() {
        let parsed = parse("A=[$VEILFAUCET_DEFINITELY_UNSET_VARIABLE]\n");

        assert_eq!(get(&parsed, "A").as_deref(), Some("[]"));
    }

    #[test]
    fn a_lone_dollar_sign_is_kept() {
        let parsed = parse("A=100$\nB=a$-b\n");

        assert_eq!(get(&parsed, "A").as_deref(), Some("100$"));
        assert_eq!(get(&parsed, "B").as_deref(), Some("a$-b"));
    }

    #[test]
    fn a_later_duplicate_wins() {
        let parsed = parse("A=first\nA=second\n");

        assert_eq!(parsed.len(), 1);
        assert_eq!(get(&parsed, "A").as_deref(), Some("second"));
    }

    #[test]
    fn crlf_line_endings_are_handled() {
        // A .env edited on Windows, which is where this port is being built.
        let parsed = parse("A=1\r\nVEIL_MNEMONIC=one two three\r\nB=2\r\n");

        assert_eq!(get(&parsed, "A").as_deref(), Some("1"));
        assert_eq!(get(&parsed, "VEIL_MNEMONIC").as_deref(), Some("one two three"));
        assert_eq!(get(&parsed, "B").as_deref(), Some("2"));
    }

    #[test]
    fn an_empty_or_keyless_file_yields_nothing() {
        assert!(parse("").is_empty());
        assert!(parse("\n\n\n").is_empty());
        assert!(parse("# only comments\n").is_empty());
        assert!(parse("=novalue\n").is_empty());
    }
}
