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
            for (key, value) in map {
                validate_text(key)?;
                validate_json(value)?;
            }
            Ok(())
        }
    }
}

/// Every human-readable text field rejects C0/C1 controls, Unicode
/// noncharacters, and the listed bidi formatting controls before signature
/// verification (architecture §3).
pub fn validate_text(value: &str) -> Result<(), String> {
    for character in value.chars() {
        let code = character as u32;
        if code <= 0x1f || (0x80..=0x9f).contains(&code) {
            return Err("C0/C1 control characters are forbidden".to_owned());
        }
        if code == 0x61c
            || (0x200e..=0x200f).contains(&code)
            || (0x202a..=0x202e).contains(&code)
            || (0x2066..=0x2069).contains(&code)
        {
            return Err("bidirectional formatting controls are forbidden".to_owned());
        }
        if (0xfdd0..=0xfdef).contains(&code) || ((code & 0xfffe) == 0xfffe && code <= 0x10ffff) {
            return Err("Unicode noncharacters are forbidden".to_owned());
        }
    }
    Ok(())
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
    reject_duplicate_keys(text)?;
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

pub fn parse_strict_value(bytes: &[u8]) -> Result<Value, String> {
    let text = std::str::from_utf8(bytes).map_err(|error| format!("invalid UTF-8: {error}"))?;
    reject_duplicate_keys(text)?;
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value =
        Value::deserialize(&mut deserializer).map_err(|error| format!("invalid JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("trailing JSON input: {error}"))?;
    validate_json(&value)?;
    Ok(value)
}

/// serde_json silently keeps the last duplicate key; the data model rejects
/// duplicates, so scan the token stream once before parsing.
fn reject_duplicate_keys(text: &str) -> Result<(), String> {
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
                        if !keys.insert(key) {
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
