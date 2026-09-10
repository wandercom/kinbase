//! Output discipline (interface contract §0, C23): under `--json` exactly
//! one single-line JSON document on stdout; every stderr line is one JSON
//! object; human output preserves the same IDs, state, and remediation.

use serde_json::Value;

/// Emit a success document. JSON is one canonical line; human output is a
/// compact key/value rendering of the top-level scalars plus the full
/// document as a single JSON line for inspection.
pub fn emit(value: &Value, json: bool) {
    if json {
        println!("{}", single_line(value));
        return;
    }
    if let Value::Object(map) = value {
        for (key, item) in map {
            match item {
                Value::String(text) => println!("{key}: {text}"),
                Value::Bool(flag) => println!("{key}: {flag}"),
                Value::Number(number) => println!("{key}: {number}"),
                Value::Null => println!("{key}: null"),
                Value::Array(items) => println!("{key}: [{} item(s)]", items.len()),
                Value::Object(_) => println!("{key}: {}", single_line(item)),
            }
        }
    } else {
        println!("{}", single_line(value));
    }
}

/// Canonical single-line JSON (falls back to serde_json when the value is
/// outside the canonical data model, e.g. contains floats in diagnostics).
pub fn single_line(value: &Value) -> String {
    crate::json::try_canonical_text(value)
        .unwrap_or_else(|_| serde_json::to_string(value).unwrap_or_else(|_| "{}".to_owned()))
}

/// A structured diagnostic on stderr: one JSON object per line, never raw
/// private bytes.
pub fn diagnostic(kind: &str, detail: Value) {
    let line = serde_json::json!({"diagnostic": kind, "detail": detail, "at": crate::time::now_rfc3339_millis()});
    eprintln!("{}", single_line(&line));
}

/// Render a typed error as the nested error document. Extra top-level keys
/// (counts) travel beside `error`.
pub fn error_document(error: &crate::error::ContractError) -> Value {
    let mut document = serde_json::json!({"error": {
        "code": error.code,
        "message": error.message,
        "remediation": error.remediation,
        "retryable": error.retryable,
        "evidence_id": error.evidence_id
    }});
    if let Some(Value::Object(detail)) = &error.detail {
        for (key, value) in detail {
            document[key] = value.clone();
        }
        document["error"]["detail"] = Value::Object(detail.clone());
    }
    document
}
