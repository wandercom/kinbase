//! Compatibility facade for the completed command surface.
//!
//! The command modules operate on the three physical roots. Personal is the
//! configured Personal data root; Company is the configured private Company
//! cache root; Codebase is the repository `.kin/`. No root is accepted from
//! a product-specific environment variable.

use crate::error::ContractError;
use crate::hash::{is_sha256, sha256_bytes, sha256_text};
use crate::json::{canonical_bytes, canonical_text, parse_strict_object};
use crate::model::FactEvent;
use serde_json::{Map, Value, json};
use std::fs;
use std::io::{BufRead as _, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub fn store_root(store: crate::StoreKind, repo: &Path) -> PathBuf {
    match store {
        crate::StoreKind::Personal => crate::config::load_user_config()
            .ok()
            .flatten()
            .map(|config| config.personal.data_root)
            .unwrap_or_else(|| crate::private::state_dir().join("codebase-personal")),
        crate::StoreKind::Company => crate::config::load_user_config()
            .ok()
            .flatten()
            .and_then(|config| config.company.map(|company| company.cache_root))
            .unwrap_or_else(|| crate::private::state_dir().join("company-cache")),
        crate::StoreKind::Codebase => repo.join(".kin"),
    }
}

pub fn ensure_store_root(store: crate::StoreKind, repo: &Path) -> Result<PathBuf, ContractError> {
    let root = store_root(store, repo);
    crate::paths::ensure_private_dir(&root, "physical store root")?;
    Ok(root)
}

pub fn append_record(
    store: crate::StoreKind,
    repo: &Path,
    filename: &str,
    value: &Value,
) -> Result<(), ContractError> {
    let root = ensure_store_root(store, repo)?;
    append_jsonl(&root.join(filename), value)
}

pub fn read_records(
    store: crate::StoreKind,
    repo: &Path,
    filename: &str,
) -> Result<Vec<Value>, ContractError> {
    let root = store_root(store, repo);
    read_jsonl(&root.join(filename))
}

/// The records of `filename` whose raw canonical line satisfies `keep`, read
/// by stream. A ledger holds every session's records and one host event
/// wants one session's: the caller passes a marker only that session's
/// canonical lines can contain, only those lines are parsed, and the exact
/// filter still runs on the parsed record. Nothing else is materialised, so
/// the cost is a scan of the file rather than a parse of it. A line that is
/// not the caller's is never parsed and never decoded, so it cannot hide the
/// caller's; a kept line that cannot be read is skipped and reported, the
/// disposition every ledger reader here takes. A ledger that was never
/// written holds no records.
pub fn read_records_where(
    store: crate::StoreKind,
    repo: &Path,
    filename: &str,
    keep: impl Fn(&str) -> bool,
) -> Result<Vec<Value>, ContractError> {
    let root = store_root(store, repo);
    read_jsonl_where(&root.join(filename), keep)
}

pub fn read_jsonl_where(
    path: &Path,
    keep: impl Fn(&str) -> bool,
) -> Result<Vec<Value>, ContractError> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(ContractError::io("read JSONL", error)),
    };
    // The signal names the ledger, never its directory.
    let ledger = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut reader = std::io::BufReader::new(file);
    let mut buffer = Vec::new();
    let mut output = Vec::new();
    let mut skipped = Vec::new();
    let mut position = 0usize;
    loop {
        buffer.clear();
        let read = reader
            .read_until(b'\n', &mut buffer)
            .map_err(|error| ContractError::io("read JSONL", error))?;
        if read == 0 {
            break;
        }
        position += 1;
        // The predicate sees the line even when it is not UTF-8: a foreign
        // line's bytes are nobody's business, and a kept one is reported.
        let (text, valid) = match std::str::from_utf8(&buffer) {
            Ok(text) => (std::borrow::Cow::Borrowed(text), true),
            Err(_) => (String::from_utf8_lossy(&buffer), false),
        };
        let text = text.trim_end_matches(['\n', '\r']);
        if text.trim().is_empty() || !keep(text) {
            continue;
        }
        if !valid {
            skipped.push(crate::output::unreadable_row(
                position,
                buffer.len(),
                "invalid UTF-8",
            ));
            continue;
        }
        match parse_strict_object(text.as_bytes()) {
            Ok(map) => output.push(Value::Object(map)),
            Err(error) => skipped.push(crate::output::unreadable_row(position, text.len(), &error)),
        }
    }
    crate::output::report_unreadable_rows(&ledger, &skipped);
    Ok(output)
}

/// Whether `canonical` already appears as a whole line of `path`, scanned by
/// stream: materialising the ledger for a line comparison cost 1.6 GB per
/// append on a 275 MB file.
fn line_present(path: &Path, canonical: &str) -> Result<bool, ContractError> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(ContractError::io("read JSONL", error)),
    };
    let mut reader = std::io::BufReader::new(file);
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        let read = reader
            .read_until(b'\n', &mut buffer)
            .map_err(|error| ContractError::io("read JSONL", error))?;
        if read == 0 {
            return Ok(false);
        }
        let line = buffer.strip_suffix(b"\n").unwrap_or(&buffer);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line == canonical.as_bytes() {
            return Ok(true);
        }
    }
}

pub fn append_jsonl(path: &Path, value: &Value) -> Result<(), ContractError> {
    if let Some(parent) = path.parent() {
        crate::paths::ensure_private_dir(parent, "record directory")?;
    }
    // `canonical_text` yields "" for a record that fails the canonical rule,
    // and the empty line it appended was skipped on read: a silent drop, the
    // same shape that lost observations and blanked query_log. Refuse instead.
    let canonical = crate::json::try_canonical_bytes(value)
        .map_err(|error| ContractError::internal(format!("record is not canonical: {error}")))
        .and_then(|bytes| {
            String::from_utf8(bytes).map_err(|_| ContractError::internal("record is not UTF-8"))
        })?;
    if line_present(path, &canonical)? {
        return Ok(());
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| ContractError::io("append JSONL", error))?;
    let mut line = canonical.into_bytes();
    line.push(b'\n');
    file.write_all(&line)
        .map_err(|error| ContractError::io("write JSONL", error))
}

pub fn read_jsonl(path: &Path) -> Result<Vec<Value>, ContractError> {
    let text = fs::read_to_string(path).map_err(|error| ContractError::io("read JSONL", error))?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let map = parse_strict_object(line.as_bytes()).map_err(|error| {
                ContractError::integrity(
                    "DIGEST_MISMATCH",
                    error,
                    "Quarantine the malformed JSONL record.",
                )
            });
            serde_json::from_value(Value::Object(map?)).map_err(|error| {
                ContractError::integrity(
                    "DIGEST_MISMATCH",
                    format!("malformed JSONL record: {error}"),
                    "Quarantine the record.",
                )
            })
        })
        .collect()
}

pub fn write_private_body(root: &Path, bytes: &[u8]) -> Result<String, ContractError> {
    let digest = sha256_bytes(bytes);
    let directory = root.join("bodies");
    crate::paths::ensure_private_dir(&directory, "private body store")?;
    let path = directory.join(&digest);
    if !path.exists() {
        crate::paths::write_atomic(&path, bytes, 0o600, false)?;
    }
    Ok(format!("sha256:{digest}"))
}

pub fn write_content_addressed_event(
    root: &Path,
    event: &FactEvent,
) -> Result<(PathBuf, String), ContractError> {
    let canonical = canonical_text(&event.document());
    let digest = sha256_text(&canonical);
    if !is_sha256(&digest) {
        return Err(ContractError::integrity(
            "DIGEST_MISMATCH",
            "event digest is malformed",
            "Quarantine the event.",
        ));
    }
    let relative = crate::paths::sharded_relative(&digest)?;
    let destination = root.join("events").join(&relative);
    if let Some(parent) = destination.parent() {
        crate::paths::ensure_dir(parent, "event store")?;
    }
    crate::paths::write_atomic(&destination, canonical.as_bytes(), 0o644, true)?;
    Ok((destination, digest))
}

pub fn read_events(root: &Path) -> Result<Vec<FactEvent>, ContractError> {
    let mut texts = Vec::new();
    collect_files(&root.join("events"), &mut texts)?;
    texts.sort();
    texts
        .iter()
        .map(|text| {
            FactEvent::parse(text.as_bytes()).map_err(|error| {
                ContractError::integrity(
                    "DIGEST_MISMATCH",
                    error,
                    "Quarantine the malformed event.",
                )
            })
        })
        .collect()
}

pub fn event_canonical_text(event: &FactEvent) -> String {
    let mut value = event.document();
    if let Value::Object(map) = &mut value {
        map.remove("signature");
    }
    canonical_text(&value)
}

pub fn verify_event_signature(event: &FactEvent, public_key: &Path) -> Result<bool, ContractError> {
    let key = crate::crypto::PublicKey::load(public_key, "event signing public key")?;
    let message = event_canonical_text(event);
    Ok(key.verify("fact-event", message.as_bytes(), &event.signature))
}

pub fn parse_event(bytes: &[u8]) -> Result<FactEvent, ContractError> {
    FactEvent::parse(bytes).map_err(|error| {
        ContractError::integrity("DIGEST_MISMATCH", error, "Quarantine the malformed event.")
    })
}

pub fn manifest_placeholder() -> Value {
    json!({"schema":"kinbase-manifest/1"})
}

fn collect_files(path: &Path, output: &mut Vec<String>) -> Result<(), ContractError> {
    if path.is_dir() {
        let mut children = fs::read_dir(path)
            .map_err(|error| ContractError::io("walk event store", error))?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| ContractError::io("walk event store", error))?;
        children.sort();
        for child in children {
            collect_files(&child, output)?;
        }
    } else if path.is_file() {
        let bytes = fs::read(path).map_err(|error| ContractError::io("read event", error))?;
        if bytes.len() <= 256 * 1024 {
            output.push(String::from_utf8_lossy(&bytes).into_owned());
        }
    }
    Ok(())
}
