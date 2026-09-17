//! Compatibility facade for the completed command surface.
//!
//! The command modules operate on the three physical roots. Personal is the
//! configured Personal data root; Company is the configured private Company
//! cache root; Codebase is the repository `.kin/`. No root is accepted from
//! a product-specific environment variable.

use crate::error::ContractError;
use crate::hash::{is_sha256, sha256_bytes, sha256_text};
use crate::json::{canonical_text, parse_strict_object};
use crate::model::FactEvent;
use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead as _, Write};
use std::os::unix::fs::FileExt as _;
use std::os::unix::io::AsRawFd as _;
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

/// `append_record` for a ledger no replay can rebuild (decisions, receipts,
/// apologies, abandonments): the file and its directory are synced before
/// the call returns.
pub fn append_record_durable(
    store: crate::StoreKind,
    repo: &Path,
    filename: &str,
    value: &Value,
) -> Result<(), ContractError> {
    let root = ensure_store_root(store, repo)?;
    append_jsonl_with(&root.join(filename), value, true)
}

/// Every readable record of `filename`. An unreadable line is skipped and
/// reported, never allowed to hide the rest of the ledger.
pub fn read_records(
    store: crate::StoreKind,
    repo: &Path,
    filename: &str,
) -> Result<Vec<Value>, ContractError> {
    let root = store_root(store, repo);
    read_jsonl_where(&root.join(filename), |_| true)
}

/// Every record of `filename`, for a reader that decides whether something
/// already happened (a receipt, an apology, an abandonment, a
/// classification). A line it cannot read may be the very record that says
/// it did, so an unreadable line refuses the decision instead of reading as
/// absent and letting the step run twice.
pub fn read_records_complete(
    store: crate::StoreKind,
    repo: &Path,
    filename: &str,
) -> Result<Vec<Value>, ContractError> {
    let root = store_root(store, repo);
    let (records, skipped) = read_jsonl_counted(&root.join(filename), |_| true)?;
    if skipped.total() == 0 {
        return Ok(records);
    }
    let lines = skipped
        .positions()
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    Err(ContractError::integrity(
        "DIGEST_MISMATCH",
        format!(
            "{filename} has {} unreadable line(s) (line {lines}); whether this step already happened cannot be decided",
            skipped.total()
        ),
        format!(
            "Move the named line(s) of {filename} aside and rerun; nothing was repeated or admitted."
        ),
    ))
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
    keep: impl Fn(&[u8]) -> bool,
) -> Result<Vec<Value>, ContractError> {
    let root = store_root(store, repo);
    read_jsonl_where(&root.join(filename), keep)
}

/// Where `needle` first occurs in `haystack`, for marker checks on raw
/// ledger bytes. A line is small and a marker starts with a quote, so a
/// first-byte scan with an early-exit compare is enough, and nothing is
/// decoded to find out whether a line is the caller's.
pub fn bytes_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if haystack.len() < needle.len() {
        return None;
    }
    let last_start = haystack.len() - needle.len();
    let mut start = 0;
    while let Some(offset) = haystack[start..=last_start]
        .iter()
        .position(|&byte| byte == needle[0])
    {
        let at = start + offset;
        if &haystack[at..at + needle.len()] == needle {
            return Some(at);
        }
        start = at + 1;
    }
    None
}

pub fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    bytes_find(haystack, needle).is_some()
}

/// A line without its terminator.
fn trim_line(buffer: &[u8]) -> &[u8] {
    let line = buffer.strip_suffix(b"\n").unwrap_or(buffer);
    line.strip_suffix(b"\r").unwrap_or(line)
}

pub fn read_jsonl_where(
    path: &Path,
    keep: impl Fn(&[u8]) -> bool,
) -> Result<Vec<Value>, ContractError> {
    Ok(read_jsonl_counted(path, keep)?.0)
}

fn read_jsonl_counted(
    path: &Path,
    keep: impl Fn(&[u8]) -> bool,
) -> Result<(Vec<Value>, crate::output::Skipped), ContractError> {
    let mut skipped = crate::output::Skipped::default();
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((Vec::new(), skipped));
        }
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
        // The predicate sees raw bytes: a foreign line is neither decoded nor
        // copied, however large or broken it is, and a kept one that is not
        // UTF-8 is reported rather than decoded.
        let line = trim_line(&buffer);
        if line.iter().all(u8::is_ascii_whitespace) || !keep(line) {
            continue;
        }
        let Ok(text) = std::str::from_utf8(line) else {
            skipped.push(position, line.len(), "invalid UTF-8");
            continue;
        };
        match parse_strict_object(text.as_bytes()) {
            Ok(map) => output.push(Value::Object(map)),
            Err(error) => skipped.push(position, text.len(), &error),
        }
    }
    skipped.report(&ledger);
    Ok((output, skipped))
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
        if trim_line(&buffer) == canonical.as_bytes() {
            return Ok(true);
        }
    }
}

pub fn append_jsonl(path: &Path, value: &Value) -> Result<(), ContractError> {
    append_jsonl_with(path, value, false)
}

fn append_jsonl_with(path: &Path, value: &Value, durable: bool) -> Result<(), ContractError> {
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
    let mut file = fs::OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)
        .map_err(|error| ContractError::io("append JSONL", error))?;
    // One writer at a time from the duplicate check to the write: two hooks
    // appending the same record otherwise both find it absent. Released when
    // the file closes.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(ContractError::io(
            "lock JSONL",
            std::io::Error::last_os_error(),
        ));
    }
    if line_present(path, &canonical)? {
        return Ok(());
    }
    // A write cut short (a full disk, a crash before the page cache reached
    // the disk) leaves a last line with no terminator. Appending straight
    // after it glued the new record onto the torn one and both read back as
    // one unreadable line; terminating the torn line first loses only it.
    let length = file
        .metadata()
        .map_err(|error| ContractError::io("inspect JSONL", error))?
        .len();
    let mut line = Vec::with_capacity(canonical.len() + 2);
    if length > 0 {
        let mut last = [0u8; 1];
        file.read_exact_at(&mut last, length - 1)
            .map_err(|error| ContractError::io("inspect JSONL", error))?;
        if last[0] != b'\n' {
            line.push(b'\n');
            crate::output::diagnostic(
                "torn-ledger-tail",
                json!({"ledger": path.file_name().map(|name| name.to_string_lossy().into_owned()), "bytes": length}),
            );
        }
    }
    line.extend_from_slice(canonical.as_bytes());
    line.push(b'\n');
    file.write_all(&line)
        .map_err(|error| ContractError::io("write JSONL", error))?;
    if durable {
        file.sync_all()
            .map_err(|error| ContractError::io("sync JSONL", error))?;
        if let Some(parent) = path.parent() {
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| ContractError::io("sync JSONL directory", error))?;
        }
    }
    Ok(())
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

/// Every readable event under `root/events`. A file that cannot be read as
/// an event is skipped and reported: one leftover or damaged file used to
/// fail the whole read, and callers took that for an empty store.
pub fn read_events(root: &Path) -> Result<Vec<FactEvent>, ContractError> {
    let events_root = root.join("events");
    let mut files = Vec::new();
    collect_files(&events_root, &mut files)?;
    let mut skipped = crate::output::Skipped::default();
    let mut texts = Vec::new();
    for path in files {
        let name = path
            .strip_prefix(&events_root)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                skipped.push_file(&name, 0, &error.to_string());
                continue;
            }
        };
        // The parser enforces the same bound; checking first keeps an
        // oversized file from being decoded at all.
        if bytes.len() > crate::model::MAX_EVENT_BYTES {
            skipped.push_file(&name, bytes.len(), "event exceeds the size bound");
            continue;
        }
        texts.push((String::from_utf8_lossy(&bytes).into_owned(), name));
    }
    texts.sort();
    let mut events = Vec::with_capacity(texts.len());
    for (text, name) in texts {
        match FactEvent::parse(text.as_bytes()) {
            Ok(event) => events.push(event),
            Err(error) => skipped.push_file(&name, text.len(), &error),
        }
    }
    skipped.report("events");
    Ok(events)
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

/// Event files under `path`: `.json` files only, never a `write_atomic`
/// temporary (`.tmp-*`) a crash left behind.
fn collect_files(path: &Path, output: &mut Vec<PathBuf>) -> Result<(), ContractError> {
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
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy())
            .unwrap_or_default();
        if !name.starts_with(".tmp-") && name.ends_with(".json") {
            output.push(path.to_path_buf());
        }
    }
    Ok(())
}
