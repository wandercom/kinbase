//! Canonical data model (architecture §3): RFC 8785 JCS bytes after NFC
//! normalization, duplicate keys and non-finite numbers rejected, integers
//! bounded to ±(2^53−1), C0/C1/bidi/noncharacter text rejected, and a
//! bijective escaped renderer whose round trip reproduces the signed buffer.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use unicode_normalization::UnicodeNormalization;

pub const JSON_INTEGER_BOUND: i128 = 9_007_199_254_740_991;

pub fn canonical_bytes(value: &Value) -> Vec<u8> {
    try_canonical_bytes(value).unwrap_or_default()
}

pub fn canonical_text(value: &Value) -> String {
    String::from_utf8(canonical_bytes(value)).unwrap_or_default()
}

pub fn try_canonical_bytes(value: &Value) -> Result<Vec<u8>, String> {
    validate_json(value)?;
    let mut out = Vec::new();
    canonical_unchecked(value, &mut out);
    Ok(out)
}

/// RFC 8785 serialization of a display document that may legitimately carry
/// control characters in strings (a rendered file preview, for instance).
/// Durable records use [`canonical_text`], which additionally enforces the
/// architecture §3 text rule before serialization.
pub fn jcs_text(value: &Value) -> String {
    let mut out = Vec::new();
    canonical_unchecked(value, &mut out);
    String::from_utf8(out).unwrap_or_default()
}

pub fn try_canonical_text(value: &Value) -> Result<String, String> {
    try_canonical_bytes(value).and_then(|bytes| {
        String::from_utf8(bytes).map_err(|_| "canonical JSON is not UTF-8".to_owned())
    })
}

fn canonical_unchecked(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(value) => out.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => out.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => write_string(&value.nfc().collect::<String>(), out),
        Value::Array(values) => {
            out.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                canonical_unchecked(value, out);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // RFC 8785 §3.2.3: keys sorted by UTF-16 code unit sequence.
            let mut entries: Vec<(String, Vec<u16>, &Value)> = map
                .iter()
                .map(|(key, value)| {
                    let normalized = key.nfc().collect::<String>();
                    let units = normalized.encode_utf16().collect::<Vec<u16>>();
                    (normalized, units, value)
                })
                .collect();
            entries.sort_by(|left, right| left.1.cmp(&right.1));
            out.push(b'{');
            for (index, (key, _, value)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                canonical_unchecked(value, out);
            }
            out.push(b'}');
        }
    }
}

/// JCS string serialization: the RFC 8785 §3.2.2.2 escape set, everything
/// else literal UTF-8.
fn write_string(value: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for character in value.chars() {
        match character {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes())
            }
            c => {
                let mut buffer = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

pub fn validate_json(value: &Value) -> Result<(), String> {
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Number(number) => {
            if number.is_f64() {
                return Err("binary floats are forbidden in canonical records".to_owned());
            }
            if let Some(value) = number.as_i64() {
                if i128::from(value).abs() > JSON_INTEGER_BOUND {
                    return Err("integer exceeds the JSON interoperable bound".to_owned());
                }
            } else if let Some(value) = number.as_u64() {
                if i128::from(value) > JSON_INTEGER_BOUND {
                    return Err("integer exceeds the JSON interoperable bound".to_owned());
                }
            }
            Ok(())
        }
        Value::String(value) => validate_text(value),
        Value::Array(values) => values.iter().try_for_each(validate_json),
        Value::Object(map) => {
            // Canonical bytes carry NFC keys; two keys that normalize alike
            // would be written as a duplicate no reader accepts.
            let mut normalized = std::collections::BTreeSet::new();
            for key in map.keys() {
                if !normalized.insert(key.nfc().collect::<String>()) {
                    return Err(format!(
                        "object keys differ only by Unicode normalization at field `{}`",
                        key.nfc().collect::<String>()
                    ));
                }
            }
            for (key, value) in map {
                validate_text(key)?;
                // Name the field. A canonical-model refusal three layers from its
                // cause is a bug report nobody can act on: the same rejection took
                // four guesses to localise because it only said which rule broke,
                // never which field broke it.
                validate_json(value).map_err(|error| {
                    if error.contains(" at field ") {
                        error
                    } else {
                        format!("{error} at field `{key}`")
                    }
                })?;
            }
            Ok(())
        }
    }
}

/// Every human-readable text field rejects C0/C1 controls, Unicode
/// noncharacters, and the listed bidi formatting controls before signature
/// verification (architecture §3).
pub fn validate_text(value: &str) -> Result<(), String> {
    match value.chars().find_map(text_rule) {
        Some(reason) => Err(reason.to_owned()),
        None => Ok(()),
    }
}

/// The reason the text rule rejects one character, or None when it is
/// allowed. One predicate serves the validator and the boundary fold.
fn text_rule(character: char) -> Option<&'static str> {
    let code = character as u32;
    if code <= 0x1f || (0x80..=0x9f).contains(&code) {
        return Some("C0/C1 control characters are forbidden");
    }
    if code == 0x61c
        || (0x200e..=0x200f).contains(&code)
        || (0x202a..=0x202e).contains(&code)
        || (0x2066..=0x2069).contains(&code)
    {
        return Some("bidirectional formatting controls are forbidden");
    }
    if (0xfdd0..=0xfdef).contains(&code) || ((code & 0xfffe) == 0xfffe && code <= 0x10ffff) {
        return Some("Unicode noncharacters are forbidden");
    }
    None
}

/// `text` with every character the text rule rejects replaced by one space.
/// Structure a host put in a message (newlines, tabs) becomes word
/// separation; the length in characters is unchanged.
pub fn fold_to_canonical_text(text: &str) -> String {
    text.chars()
        .map(|character| {
            if text_rule(character).is_some() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

/// Top-level envelope fields that name something (a session, an event, a
/// path, an instant, a tool) rather than say something. They are validated,
/// never folded: a control character in an identifier is a different
/// identifier and in a path a different directory, so such an envelope is
/// refused rather than acted on under a rewritten identity.
const HOST_IDENTIFIER_FIELDS: [&str; 10] = [
    "session_id",
    "id",
    "cwd",
    "transcript_path",
    "hook_event_name",
    "event_type",
    "type",
    "timestamp",
    "tool_name",
    "tool_use_id",
];

/// Fold every string in `value`, keys included, so each one passes the text
/// rule without changing the value's shape. Two keys that fold to the same
/// spelling are a duplicate the raw-text scan could not see; refuse rather
/// than keep one of them.
fn fold_text_fields(value: &mut Value) -> Result<(), String> {
    match value {
        Value::String(text) => {
            if validate_text(text).is_err() {
                *text = fold_to_canonical_text(text);
            }
        }
        Value::Array(values) => {
            for value in values.iter_mut() {
                fold_text_fields(value)?;
            }
        }
        Value::Object(map) => {
            let entries = std::mem::take(map);
            for (key, mut entry) in entries {
                fold_text_fields(&mut entry)?;
                let key = if validate_text(&key).is_err() {
                    fold_to_canonical_text(&key)
                } else {
                    key
                };
                if map.insert(key, entry).is_some() {
                    return Err("duplicate object key after folding".to_owned());
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// Parse a coding host's hook envelope: strict JSON (UTF-8, no duplicate
/// keys, no trailing input); identifier and path fields validated as they
/// are; every other string folded to canonical text. The envelope is data
/// from another authority and carries newlines in prompts, tool commands and
/// assistant messages by design, and tool inputs carry whatever numbers the
/// tool takes. Validating it as a canonical record made every such hook exit
/// 3 before doing anything, so no session was ever checkpointed. The
/// disposition is the projector's for a pasted ticket (fold, do not refuse);
/// the predicate is the text rule's own, so the result always passes it.
/// Numbers are left as sent: nothing in the envelope is itself a record, and
/// each record built from it goes through a writer that refuses a
/// non-canonical value.
pub fn parse_host_envelope(bytes: &[u8]) -> Result<Value, String> {
    let text = std::str::from_utf8(bytes).map_err(|error| format!("invalid UTF-8: {error}"))?;
    reject_duplicate_keys(text, KeyIdentity::Decoded)?;
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let mut value =
        Value::deserialize(&mut deserializer).map_err(|error| format!("invalid JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("trailing JSON input: {error}"))?;
    if let Value::Object(map) = &value {
        for field in HOST_IDENTIFIER_FIELDS {
            if let Some(text) = map.get(field).and_then(Value::as_str) {
                validate_text(text).map_err(|reason| format!("{reason} at field `{field}`"))?;
            }
        }
    }
    fold_text_fields(&mut value)?;
    Ok(value)
}

/// The bijective approval renderer: printable ASCII except `"` and `\` stays
/// literal; every other code point is `\uXXXX` (UTF-16 surrogate pairs above
/// the BMP). [`unescape_exact`] is the exact inverse.
pub fn escape_exact(value: &str) -> Result<String, String> {
    validate_text(value)?;
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        let code = character as u32;
        if (0x20..=0x7e).contains(&code) && character != '"' && character != '\\' {
            output.push(character);
        } else {
            let mut units = [0u16; 2];
            for unit in character.encode_utf16(&mut units).iter() {
                output.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    Ok(output)
}

/// Inverse of [`escape_exact`]; refuses any byte the renderer would not
/// have produced so a mutated preview cannot re-verify.
pub fn unescape_exact(rendered: &str) -> Result<String, String> {
    let mut output = String::with_capacity(rendered.len());
    let mut chars = rendered.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\\' {
            if chars.next() != Some('u') {
                return Err("escaped form must use \\uXXXX only".to_owned());
            }
            let unit = read_unit(&mut chars)?;
            if (0xd800..=0xdbff).contains(&unit) {
                if chars.next() != Some('\\') || chars.next() != Some('u') {
                    return Err("unpaired high surrogate".to_owned());
                }
                let low = read_unit(&mut chars)?;
                let decoded = char::decode_utf16([unit, low])
                    .next()
                    .and_then(Result::ok)
                    .ok_or_else(|| "invalid surrogate pair".to_owned())?;
                output.push(decoded);
            } else if (0xdc00..=0xdfff).contains(&unit) {
                return Err("unpaired low surrogate".to_owned());
            } else {
                let decoded = char::from_u32(u32::from(unit))
                    .ok_or_else(|| "invalid code unit".to_owned())?;
                let code = decoded as u32;
                if (0x20..=0x7e).contains(&code) && decoded != '"' && decoded != '\\' {
                    return Err("printable ASCII must be literal in the escaped form".to_owned());
                }
                output.push(decoded);
            }
        } else {
            let code = character as u32;
            if !(0x20..=0x7e).contains(&code) || character == '"' || character == '\\' {
                return Err("non-printable or quote/backslash byte appears unescaped".to_owned());
            }
            output.push(character);
        }
    }
    validate_text(&output)?;
    Ok(output)
}

fn read_unit(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Result<u16, String> {
    let mut value = 0u16;
    for _ in 0..4 {
        let digit = chars
            .next()
            .ok_or_else(|| "truncated \\u escape".to_owned())?;
        let nibble = match digit {
            '0'..='9' => digit as u16 - '0' as u16,
            'a'..='f' => digit as u16 - 'a' as u16 + 10,
            _ => return Err("escape digits must be lowercase hex".to_owned()),
        };
        value = (value << 4) | nibble;
    }
    Ok(value)
}

/// The single strict parse shared by verification and semantic use: one
/// immutable byte buffer, no trailing input, duplicate keys rejected,
/// data-model validation applied.
pub fn parse_strict_object(bytes: &[u8]) -> Result<Map<String, Value>, String> {
    let text = std::str::from_utf8(bytes).map_err(|error| format!("invalid UTF-8: {error}"))?;
    reject_duplicate_keys(text, KeyIdentity::Normalized)?;
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value =
        Value::deserialize(&mut deserializer).map_err(|error| format!("invalid JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("trailing JSON input: {error}"))?;
    validate_json(&value)?;
    if let Value::Object(map) = value {
        Ok(map)
    } else {
        Err("expected a JSON object".to_owned())
    }
}

/// A user's own JSON document (a host settings file): one value with no
/// duplicate keys, kept exactly as written. Durable-record rules (no floats,
/// no control characters) do not apply to it.
pub fn parse_user_document(bytes: &[u8]) -> Result<Value, String> {
    let text = std::str::from_utf8(bytes).map_err(|error| format!("invalid UTF-8: {error}"))?;
    // The user's keys are theirs: a precomposed and a decomposed spelling
    // are two keys to JSON and to the host, so only a decoded repeat is one.
    reject_duplicate_keys(text, KeyIdentity::Decoded)?;
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value =
        Value::deserialize(&mut deserializer).map_err(|error| format!("invalid JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("trailing JSON input: {error}"))?;
    Ok(value)
}

pub fn parse_strict_value(bytes: &[u8]) -> Result<Value, String> {
    let text = std::str::from_utf8(bytes).map_err(|error| format!("invalid UTF-8: {error}"))?;
    reject_duplicate_keys(text, KeyIdentity::Normalized)?;
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value =
        Value::deserialize(&mut deserializer).map_err(|error| format!("invalid JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("trailing JSON input: {error}"))?;
    validate_json(&value)?;
    Ok(value)
}

/// What makes two object keys the same key.
#[derive(Clone, Copy)]
enum KeyIdentity {
    /// The decoded text: `a` and `\u0061` are one key.
    Decoded,
    /// The decoded, NFC-normalized text, as canonical bytes write it: `é`
    /// and `e\u0301` are one key too. Only for the data model.
    Normalized,
}

/// A key's identity for duplicate detection. An escape the parser would
/// refuse is left as written; the parse that follows reports it.
fn object_key(raw: &str, identity: KeyIdentity) -> String {
    match serde_json::from_str::<String>(&format!("\"{raw}\"")) {
        Ok(decoded) => match identity {
            KeyIdentity::Decoded => decoded,
            KeyIdentity::Normalized => decoded.nfc().collect(),
        },
        Err(_) => raw.to_owned(),
    }
}

/// serde_json silently keeps the last duplicate key; the data model rejects
/// duplicates, so scan the token stream once before parsing.
fn reject_duplicate_keys(text: &str, identity: KeyIdentity) -> Result<(), String> {
    let mut stack: Vec<Option<std::collections::BTreeSet<String>>> = Vec::new();
    let mut chars = text.chars().peekable();
    let mut expecting_key = false;
    while let Some(c) = chars.next() {
        match c {
            '{' => {
                stack.push(Some(std::collections::BTreeSet::new()));
                expecting_key = true;
            }
            '[' => {
                stack.push(None);
                expecting_key = false;
            }
            '}' | ']' => {
                stack.pop();
                expecting_key = false;
            }
            ',' => {
                expecting_key = matches!(stack.last(), Some(Some(_)));
            }
            '"' => {
                let mut key = String::new();
                let mut escaped = false;
                for inner in chars.by_ref() {
                    if escaped {
                        key.push('\\');
                        key.push(inner);
                        escaped = false;
                    } else if inner == '\\' {
                        escaped = true;
                    } else if inner == '"' {
                        break;
                    } else {
                        key.push(inner);
                    }
                }
                if expecting_key {
                    if let Some(Some(keys)) = stack.last_mut() {
                        // Compare keys as the parser will read them: `a` and
                        // `\u0061` are one key, and serde_json would silently
                        // keep the last.
                        if !keys.insert(object_key(&key, identity)) {
                            return Err("duplicate object key".to_owned());
                        }
                    }
                    expecting_key = false;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

pub fn strict<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, String> {
    let value = parse_strict_value(bytes)?;
    serde_json::from_value(value).map_err(|error| error.to_string())
}

pub fn to_value<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

/// Digest of the canonical form of a value.
pub fn digest(value: &Value) -> String {
    crate::hash::sha256_bytes(&canonical_bytes(value))
}

pub fn get_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

pub fn get_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

pub fn get_array<'a>(value: &'a Value, key: &str) -> Option<&'a Vec<Value>> {
    value.get(key).and_then(Value::as_array)
}

/// Remove `signature` and return the canonical bytes that were signed.
pub fn unsigned_bytes(value: &Value) -> Result<Vec<u8>, String> {
    let mut copy = value.clone();
    if let Value::Object(map) = &mut copy {
        map.remove("signature");
    }
    try_canonical_bytes(&copy)
}

#[cfg(test)]
mod duplicate_key_tests {
    use super::*;

    #[test]
    fn a_key_spelled_two_ways_is_still_a_duplicate() {
        for document in [
            r#"{"a":1,"\u0061":2}"#,
            r#"{"\/":1,"/":2}"#,
            "{\"\u{e9}\":1,\"\\u00e9\":2}",
            "{\"e\u{301}\":1,\"\\u00e9\":2}",
            r#"{"outer":{"k":1,"\u006b":2}}"#,
        ] {
            let error = parse_strict_value(document.as_bytes()).expect_err(document);
            assert!(
                error.contains("duplicate object key"),
                "{document}: {error}"
            );
        }
        assert!(parse_strict_value(br#"{"a":1,"b":{"a":2}}"#).is_ok());
    }

    #[test]
    fn a_user_document_keeps_keys_that_differ_only_by_normalization() {
        let document = "{\"e\u{301}\":1,\"\\u00e9\":2}";
        let value = parse_user_document(document.as_bytes()).expect("two keys");
        assert_eq!(value.as_object().map(Map::len), Some(2));
        let envelope = parse_host_envelope(document.as_bytes()).expect("two keys");
        assert_eq!(envelope.as_object().map(Map::len), Some(2));
        let repeated = parse_user_document(br#"{"a":1,"\u0061":2}"#).expect_err("one key");
        assert!(repeated.contains("duplicate object key"), "{repeated}");
    }

    #[test]
    fn keys_that_normalize_alike_cannot_be_written() {
        let mut map = Map::new();
        map.insert("e\u{301}".to_owned(), Value::from(1));
        map.insert("\u{e9}".to_owned(), Value::from(2));
        let error = validate_json(&Value::Object(map)).expect_err("collision");
        assert!(error.contains("Unicode normalization"), "{error}");
    }
}
