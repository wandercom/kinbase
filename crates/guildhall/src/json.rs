use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use unicode_normalization::UnicodeNormalization;

const JSON_INTEGER_BOUND: i128 = 9_007_199_254_740_991;

pub fn canonical_bytes(value: &Value) -> Vec<u8> {
    validate_json(value).expect("canonical JSON value is valid");
    canonical_unchecked(value)
}

pub fn canonical_text(value: &Value) -> String {
    String::from_utf8(canonical_bytes(value)).expect("canonical JSON is UTF-8")
}

pub fn try_canonical_bytes(value: &Value) -> Result<Vec<u8>, String> {
    validate_json(value)?;
    Ok(canonical_unchecked(value))
}

fn canonical_unchecked(value: &Value) -> Vec<u8> {
    match value {
        Value::Null => b"null".to_vec(),
        Value::Bool(value) => value.to_string().into_bytes(),
        Value::Number(value) => value.to_string().into_bytes(),
        Value::String(value) => serde_json::to_vec(&value.nfc().collect::<String>())
            .expect("string serialization cannot fail"),
        Value::Array(values) => {
            let mut bytes = Vec::from(b"[");
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    bytes.push(b',');
                }
                bytes.extend_from_slice(&canonical_unchecked(value));
            }
            bytes.push(b']');
            bytes
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
            let mut bytes = Vec::from(b"{");
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index > 0 {
                    bytes.push(b',');
                }
                bytes.extend_from_slice(
                    &serde_json::to_vec(&key.nfc().collect::<String>())
                        .expect("key serialization cannot fail"),
                );
                bytes.push(b':');
                bytes.extend_from_slice(&canonical_unchecked(value));
            }
            bytes.push(b'}');
            bytes
        }
    }
}

pub fn validate_json(value: &Value) -> Result<(), String> {
    match value {
        Value::Null => Ok(()),
        Value::Bool(_) => Ok(()),
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
        if (0xfdd0..=0xfdef).contains(&code) || ((code & 0xfffe) == 0xfffe && code <= 0x10fffe) {
            return Err("Unicode noncharacters are forbidden".to_owned());
        }
    }
    Ok(())
}

pub fn escape_exact(value: &str) -> Result<String, String> {
    validate_text(value)?;
    let mut output = String::new();
    for character in value.chars() {
        let code = character as u32;
        if (0x20..=0x7e).contains(&code) && character != '"' && character != '\\' {
            output.push(character);
        } else if code <= 0xffff {
            output.push_str(&format!("\\u{code:04x}"));
        } else {
            output.push_str(&format!("\\u{{{code:x}}}"));
        }
    }
    Ok(output)
}

pub fn parse_strict_object(bytes: &[u8]) -> Result<Map<String, Value>, String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
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

pub fn strict<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, String> {
    serde_json::from_slice(bytes).map_err(|error| error.to_string())
}

pub fn to_value<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("serialization cannot fail")
}
