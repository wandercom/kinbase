use crate::hash::event_path;
use crate::json::{canonical_bytes, canonical_text};
use crate::model::FactEvent;
use serde_json::{Map, Value, json};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn append_jsonl(path: &Path, value: &Value) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let canonical = canonical_bytes(value);
    let mut line = canonical.clone();
    line.push(b'\n');
    if path.exists() {
        let prior = fs::read_to_string(path)?;
        if prior
            .lines()
            .any(|existing| existing.as_bytes() == canonical.as_slice())
        {
            return Ok(());
        }
    }
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?
        .write_all(&line)
}

pub fn read_jsonl(path: &Path) -> std::io::Result<Vec<Value>> {
    let text = fs::read_to_string(path)?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
        })
        .collect()
}

pub fn write_content_addressed_event(
    root: &Path,
    event: &FactEvent,
) -> std::io::Result<(PathBuf, String)> {
    let map: Map<String, Value> =
        serde_json::from_value(serde_json::to_value(event).expect("event serializes"))
            .expect("event is an object");
    let canonical = canonical_text(&Value::Object(map));
    let digest = crate::hash::sha256_text(&canonical);
    let relative = event_path(&digest);
    let destination = root.join(".kin/events").join(format!("{relative}.json"));
    fs::create_dir_all(destination.parent().expect("event path has a parent"))?;
    if destination.exists() {
        let existing = fs::read(&destination)?;
        if existing != canonical.as_bytes() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "content-address path collision",
            ));
        }
    } else {
        fs::write(&destination, canonical.as_bytes())?;
    }
    Ok((destination, digest))
}

pub fn manifest(
    root: &Path,
    repository_id: &str,
    branch: &str,
    revision: &str,
    observed_at: &str,
) -> std::io::Result<Value> {
    let events_dir = root.join(".kin/events");
    let mut events = Vec::new();
    if events_dir.exists() {
        collect_files(&events_dir, &mut events)?;
    }
    let count = events.len();
    let digest = crate::hash::sha256_text(&events.join("\n"));
    let manifest = json!({
        "schema": "guildhall-manifest/1",
        "repository_uuid": repository_id,
        "branch": branch,
        "revision": revision,
        "event_count": count,
        "merkle_root": digest,
        "observed_at": observed_at
    });
    let canonical = canonical_bytes(&manifest);
    let manifest_digest = crate::hash::sha256_bytes(&canonical);
    let relative = event_path(&manifest_digest);
    let destination = root.join(".kin/manifests").join(format!("{relative}.json"));
    fs::create_dir_all(destination.parent().expect("manifest path has a parent"))?;
    fs::write(destination, canonical)?;
    Ok(manifest)
}

fn collect_files(path: &Path, output: &mut Vec<String>) -> std::io::Result<()> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            collect_files(&entry?.path(), output)?;
        }
    } else if path.is_file() {
        output.push(fs::read_to_string(path)?);
    }
    Ok(())
}

pub fn parse_event(bytes: &[u8]) -> Result<FactEvent, String> {
    let map = crate::json::parse_strict_object(bytes)?;
    if map.get("schema").and_then(Value::as_str) != Some("guildhall-event/1") {
        return Err("unsupported event schema".to_owned());
    }
    serde_json::from_value(Value::Object(map)).map_err(|error| error.to_string())
}
