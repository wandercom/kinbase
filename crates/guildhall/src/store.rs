use crate::hash::{event_path, is_sha256, sha256_bytes, sha256_text};
use crate::json::{canonical_bytes, canonical_text, parse_strict_object};
use crate::model::FactEvent;
use serde_json::{Map, Value, json};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub fn store_root(store: crate::StoreKind, repo: &Path) -> PathBuf {
    match store {
        crate::StoreKind::Personal => std::env::var_os("GUILDHALL_PERSONAL_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| home_root("personal")),
        crate::StoreKind::Company => std::env::var_os("GUILDHALL_COMPANY_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| home_root("company")),
        crate::StoreKind::Codebase => repo.join(".kin"),
    }
}

fn home_root(store: &str) -> PathBuf {
    let home = std::env::var_os("HOME").unwrap_or_else(|| std::ffi::OsString::from("/tmp"));
    PathBuf::from(home).join(".guildhall").join(store)
}

pub fn ensure_store_root(store: crate::StoreKind, repo: &Path) -> std::io::Result<PathBuf> {
    let root = store_root(store, repo);
    fs::create_dir_all(&root)?;
    match store {
        crate::StoreKind::Codebase => Ok(root),
        crate::StoreKind::Personal | crate::StoreKind::Company => {
            secure_directory(&root)?;
            Ok(root)
        }
    }
}

pub fn secure_directory(path: &Path) -> std::io::Result<()> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "secure path is not a directory",
        ));
    }
    let mode = metadata.permissions().mode();
    if mode & 0o022 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "directory is writable by group or other",
        ));
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(mode & !0o077 | 0o0700);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

pub fn append_record(
    store: crate::StoreKind,
    repo: &Path,
    filename: &str,
    value: &Value,
) -> std::io::Result<()> {
    let root = ensure_store_root(store, repo)?;
    append_jsonl(&root.join(filename), value)
}

pub fn read_records(
    store: crate::StoreKind,
    repo: &Path,
    filename: &str,
) -> std::io::Result<Vec<Value>> {
    let root = store_root(store, repo);
    read_jsonl(&root.join(filename))
}

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
            let map = parse_strict_object(line.as_bytes())
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            serde_json::from_value(Value::Object(map))
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
        })
        .collect()
}

pub fn write_private_body(root: &Path, bytes: &[u8]) -> std::io::Result<String> {
    let digest = sha256_bytes(bytes);
    let directory = root.join("bodies");
    fs::create_dir_all(&directory)?;
    secure_directory(&directory)?;
    let path = directory.join(&digest);
    if !path.exists() {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(bytes)?;
    }
    Ok(format!("sha256:{digest}"))
}

pub fn write_content_addressed_event(
    root: &Path,
    event: &FactEvent,
) -> std::io::Result<(PathBuf, String)> {
    let map: Map<String, Value> = serde_json::from_value(
        serde_json::to_value(event).expect("event serializes"),
    )
    .expect("event is an object");
    let canonical = canonical_text(&Value::Object(map));
    let digest = sha256_text(&canonical);
    if !is_sha256(&digest) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "event digest is malformed",
        ));
    }
    let relative = event_path(&digest);
    let destination = root.join("events").join(format!("{relative}.json"));
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

pub fn read_events(root: &Path) -> std::io::Result<Vec<FactEvent>> {
    let mut texts = Vec::new();
    collect_files(&root.join("events"), &mut texts)?;
    texts.sort();
    texts
        .iter()
        .map(|text| {
            parse_event(text.as_bytes())
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
        })
        .collect()
}

pub fn event_canonical_text(event: &FactEvent) -> String {
    let mut value = serde_json::to_value(event).expect("event serializes");
    if let Value::Object(map) = &mut value {
        map.remove("signature");
    }
    canonical_text(&value)
}

pub fn verify_event_signature(
    event: &FactEvent,
    public_key: &Path,
) -> Result<bool, String> {
    let message = event_canonical_text(event);
    crate::crypto::verify_message(
        "fact-event",
        message.as_bytes(),
        &event.signature,
        public_key,
    )
    .map_err(|error| error.to_string())
}

pub fn manifest(
    root: &Path,
    repository_id: &str,
    branch: &str,
    revision: &str,
    observed_at: &str,
) -> std::io::Result<Value> {
    let events = read_events(root)?;
    let event_count = events.len();
    let mut leaves = Vec::with_capacity(event_count);
    for event in &events {
        let canonical = event_canonical_text(event);
        leaves.push(canonical.as_bytes().to_vec());
    }
    let merkle_root = merkle_root(&leaves);
    let fresh_until = crate::time::format_rfc3339_millis(
        crate::time::parse_rfc3339_millis(observed_at)
            .map_err(std::io::Error::other)?
            + chrono::Duration::hours(1),
    );
    let mut manifest = json!({
        "schema": "guildhall-manifest/1",
        "repository_uuid": repository_id,
        "branch": branch,
        "revision": revision,
        "event_count": event_count,
        "merkle_root": merkle_root,
        "observed_at": observed_at,
        "fresh_until": fresh_until,
        "signer": "repository-maintainer"
    });
    let private_key = root.join("local").join("keys").join("ed25519.key");
    let signature = crate::crypto::sign_message("manifest", canonical_bytes(&manifest).as_slice(), &private_key)
        .map_err(std::io::Error::other)?;
    manifest["signature"] = Value::String(signature);
    let canonical = canonical_bytes(&manifest);
    let manifest_digest = sha256_bytes(&canonical);
    let relative = event_path(&manifest_digest);
    let destination = root.join("manifests").join(format!("{relative}.json"));
    fs::create_dir_all(destination.parent().expect("manifest path has a parent"))?;
    fs::write(destination, canonical)?;
    Ok(manifest)
}

fn merkle_root(leaves: &[Vec<u8>]) -> String {
    if leaves.is_empty() {
        return sha256_bytes(&[]);
    }
    let mut level: Vec<[u8; 32]> = leaves
        .iter()
        .map(|leaf| {
            let digest = sha256_bytes(leaf);
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&hex_bytes(&digest));
            bytes
        })
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(pair[0]);
            let digest = sha256_bytes(&[left, right].concat());
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&hex_bytes(&digest));
            next.push(bytes);
        }
        level = next;
    }
    crate::hash::hex_string(&level[0])
}

fn hex_bytes(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("valid hex"))
        .collect()
}

fn collect_files(path: &Path, output: &mut Vec<String>) -> std::io::Result<()> {
    if path.is_dir() {
        let mut children = fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()?;
        children.sort();
        for child in children {
            collect_files(&child, output)?;
        }
    } else if path.is_file() {
        output.push(fs::read_to_string(path)?);
    }
    Ok(())
}

pub fn parse_event(bytes: &[u8]) -> Result<FactEvent, String> {
    let map = parse_strict_object(bytes)?;
    if map.get("schema").and_then(Value::as_str) != Some(crate::model::EVENT_SCHEMA) {
        return Err("unsupported event schema".to_owned());
    }
    serde_json::from_value(Value::Object(map)).map_err(|error| error.to_string())
}
