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

/// Rows a reader skipped: a total and the first few, described without
/// their bytes. The total is what a rising count is judged on; retaining
/// every skipped row's detail turned a corrupt ledger into a memory spike.
#[derive(Default)]
pub(crate) struct Skipped {
    total: usize,
    samples: Vec<Value>,
}

impl Skipped {
    const SAMPLES: usize = 8;

    pub(crate) fn push(&mut self, position: usize, bytes: usize, error: &str) {
        self.total += 1;
        if self.samples.len() < Self::SAMPLES {
            self.samples
                .push(serde_json::json!({"position": position, "bytes": bytes, "error": error}));
        }
    }

    /// The Recovered signal: one diagnostic per read naming the source, the
    /// total skipped and the first samples, so a rising count is visible
    /// before it becomes a lost ledger. Silence here is how the loss stayed
    /// hidden.
    pub(crate) fn report(&self, source: &str) {
        if self.total == 0 {
            return;
        }
        diagnostic(
            "unreadable-ledger-rows",
            serde_json::json!({"source": source, "skipped": self.total, "rows": self.samples}),
        );
    }
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
