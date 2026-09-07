use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub fn canonical_bytes(value: &Value) -> Vec<u8> {
    match value {
        Value::Null => b"null".to_vec(),
        Value::Bool(value) => value.to_string().into_bytes(),
        Value::Number(value) => value.to_string().into_bytes(),
        Value::String(value) => {
            serde_json::to_vec(value).expect("string serialization cannot fail")
        }
        Value::Array(values) => {
            let mut bytes = Vec::from(b"[");
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    bytes.push(b',');
                }
                bytes.extend_from_slice(&canonical_bytes(value));
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
                    &serde_json::to_vec(key).expect("key serialization cannot fail"),
                );
                bytes.push(b':');
                bytes.extend_from_slice(&canonical_bytes(value));
            }
            bytes.push(b'}');
            bytes
        }
    }
}

pub fn canonical_text(value: &Value) -> String {
    String::from_utf8(canonical_bytes(value)).expect("canonical JSON is UTF-8")
}

pub fn parse_strict_object(bytes: &[u8]) -> Result<Map<String, Value>, String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value =
        Value::deserialize(&mut deserializer).map_err(|error| format!("invalid JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("trailing JSON input: {error}"))?;
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
