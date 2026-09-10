//! The out-of-worktree Company cache (architecture §2, §6): a mode-0700
//! root holding `facts-cache.sqlite3` with the last verified signed
//! snapshot, the local cursor high-water mark, repository pins
//! `(discovery hint, repository UUID, certificate digest)`, installed
//! certificates, and the freshness clocks behind the projection truth table.

use crate::crypto::PublicKey;
use crate::error::ContractError;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub const CACHE_FILE: &str = "facts-cache.sqlite3";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheState {
    Cold,
    Invalid,
    Warm,
}

pub struct Cache {
    pub root: PathBuf,
    pub connection: Option<Connection>,
    pub state: CacheState,
}

fn sqlite_error(context: &str) -> impl Fn(rusqlite::Error) -> ContractError + '_ {
    move |error| ContractError::internal(format!("{context}: {error}"))
}

impl Cache {
    pub fn open(root: &Path) -> Result<Self, ContractError> {
        crate::paths::ensure_private_dir(root, "Company cache root")?;
        let path = root.join(CACHE_FILE);
        crate::paths::reject_symlink(&path, "Company cache")?;
        let existed = path.exists();
        if existed {
            let bytes =
                std::fs::read(&path).map_err(|error| ContractError::io("read cache", error))?;
            if bytes.len() < 16 || !bytes.starts_with(b"SQLite format 3\0") {
                // An invalid cache is cold, never trusted, and never repaired
                // silently: it is renamed aside so the next refresh is clean.
                let quarantine = root.join(format!(
                    "{CACHE_FILE}.invalid-{}",
                    crate::time::now_utc().timestamp_millis()
                ));
                let _ = std::fs::rename(&path, &quarantine);
                return Ok(Self {
                    root: root.to_path_buf(),
                    connection: None,
                    state: CacheState::Invalid,
                });
            }
        }
        let connection = Connection::open(&path)
            .map_err(|error| ContractError::internal(format!("open cache: {error}")))?;
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(sqlite_error("busy timeout"))?;
        let migrated = connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS snapshot(id INTEGER PRIMARY KEY CHECK(id=1), bytes BLOB NOT NULL, digest TEXT NOT NULL, stored_at TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS pins(hint TEXT PRIMARY KEY, repository_uuid TEXT NOT NULL, certificate_digest TEXT NOT NULL, pinned_at TEXT NOT NULL, cursor TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS certificates(repository_uuid TEXT PRIMARY KEY, document TEXT NOT NULL, digest TEXT NOT NULL, installed_at TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS pending_sagas(candidate_id TEXT PRIMARY KEY, record TEXT NOT NULL, updated_at TEXT NOT NULL);",
        );
        if migrated.is_err() {
            let quarantine = root.join(format!(
                "{CACHE_FILE}.invalid-{}",
                crate::time::now_utc().timestamp_millis()
            ));
            drop(connection);
            let _ = std::fs::rename(&path, &quarantine);
            return Ok(Self {
                root: root.to_path_buf(),
                connection: None,
                state: CacheState::Invalid,
            });
        }
        let has_snapshot: i64 = connection
            .query_row("SELECT COUNT(*) FROM snapshot", [], |row| row.get(0))
            .unwrap_or(0);
        Ok(Self {
            root: root.to_path_buf(),
            connection: Some(connection),
            state: if has_snapshot > 0 {
                CacheState::Warm
            } else {
                CacheState::Cold
            },
        })
    }

    fn connection(&self) -> Result<&Connection, ContractError> {
        self.connection.as_ref().ok_or_else(|| {
            ContractError::degraded(
                "CACHE_EXPIRED",
                "the Company cache is invalid and was quarantined",
                "Refresh Company state; no cached fact is used.",
            )
        })
    }

    pub fn meta(&self, key: &str) -> Option<String> {
        self.connection
            .as_ref()?
            .query_row("SELECT value FROM meta WHERE key=?1", params![key], |row| {
                row.get(0)
            })
            .optional()
            .ok()
            .flatten()
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), ContractError> {
        self.connection()?
            .execute(
                "INSERT INTO meta(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![key, value],
            )
            .map(|_| ())
            .map_err(sqlite_error("cache meta"))
    }

    /// The locally sealed cursor high-water mark (never trusted offline
    /// after deletion; a cold cache must refetch at least this cursor).
    pub fn high_water(&self) -> String {
        self.meta("high_water_cursor")
            .unwrap_or_else(|| "0".to_owned())
    }

    /// Store a verified snapshot. A snapshot whose cursor is older than the
    /// sealed high-water mark is a replay and is refused.
    pub fn store_snapshot(
        &mut self,
        snapshot: &Value,
        root: &PublicKey,
        now: &str,
    ) -> Result<(), ContractError> {
        let signer = PublicKey::verify_document("receipt", snapshot).ok_or_else(|| {
            ContractError::integrity(
                "SIGNATURE_INVALID",
                "snapshot signature failed",
                "Quarantine the snapshot and contact the Company steward.",
            )
        })?;
        if signer != *root {
            return Err(ContractError::integrity(
                "SIGNATURE_INVALID",
                "snapshot is not signed by the configured root",
                "Verify the root public key.",
            ));
        }
        let cursor = crate::json::get_str(snapshot, "cursor")
            .unwrap_or("0")
            .to_owned();
        let high_water = self.high_water();
        if crate::reducer::cursor_order(&cursor, &high_water) == std::cmp::Ordering::Less {
            return Err(ContractError::integrity(
                "SIGNATURE_INVALID",
                format!(
                    "snapshot cursor {cursor} is older than the sealed high-water mark {high_water} (replay)"
                ),
                "Refresh from the live Company; a replayed snapshot cannot rebuild trust.",
            ));
        }
        let bytes = crate::json::canonical_bytes(snapshot);
        let digest = crate::hash::sha256_bytes(&bytes);
        let connection = self.connection()?;
        connection
            .execute(
                "INSERT INTO snapshot(id, bytes, digest, stored_at) VALUES (1, ?1, ?2, ?3) ON CONFLICT(id) DO UPDATE SET bytes=excluded.bytes, digest=excluded.digest, stored_at=excluded.stored_at",
                params![bytes, digest, now],
            )
            .map_err(sqlite_error("store snapshot"))?;
        for key in [
            "cursor",
            "authority_cursor",
            "revocation_cursor",
            "revocation_valid_until",
            "fact_valid_until",
            "issued_at",
            "company_id",
        ] {
            if let Some(value) = crate::json::get_str(snapshot, key) {
                self.set_meta(key, value)?;
            }
        }
        self.set_meta("high_water_cursor", &cursor)?;
        self.set_meta("snapshot_digest", &digest)?;
        self.set_meta("refreshed_at", now)?;
        for certificate in crate::json::get_array(snapshot, "certificates")
            .cloned()
            .unwrap_or_default()
        {
            if let Some(uuid) = crate::json::get_str(&certificate, "repository_uuid") {
                let mut document = certificate.clone();
                if let Some(map) = document.as_object_mut() {
                    map.remove("discovery_hint");
                    map.remove("certificate_digest");
                    map.remove("status");
                }
                let digest = crate::json::digest(&document);
                self.connection()?
                    .execute(
                        "INSERT INTO certificates(repository_uuid, document, digest, installed_at) VALUES (?1, ?2, ?3, ?4)
                         ON CONFLICT(repository_uuid) DO UPDATE SET document=excluded.document, digest=excluded.digest",
                        params![uuid, crate::json::canonical_text(&document), digest, now],
                    )
                    .map_err(sqlite_error("store certificate"))?;
            }
        }
        self.state = CacheState::Warm;
        Ok(())
    }

    pub fn snapshot(&self) -> Result<Option<Value>, ContractError> {
        let Some(connection) = self.connection.as_ref() else {
            return Ok(None);
        };
        let bytes: Option<Vec<u8>> = connection
            .query_row("SELECT bytes FROM snapshot WHERE id=1", [], |row| {
                row.get(0)
            })
            .optional()
            .map_err(sqlite_error("read snapshot"))?;
        match bytes {
            None => Ok(None),
            Some(bytes) => crate::json::parse_strict_value(&bytes)
                .map(Some)
                .map_err(|error| {
                    ContractError::integrity(
                        "DIGEST_MISMATCH",
                        format!("cached snapshot is corrupt ({error})"),
                        "Delete the cache and refresh.",
                    )
                }),
        }
    }

    /// Company's published current view, proxied as reducer input.
    ///
    /// Each entry of a root-signed snapshot's `facts` is Company's own derived
    /// current fact: data on the outside, immutable, versioned by the snapshot
    /// cursor, a reference to a point in time. The client never re-derives
    /// Company's supersession or authority ranking; it re-applies only its own
    /// clocks (the architecture §6 truth table) and certificate state. The
    /// proxy therefore carries one FactEvent-shaped document per published
    /// fact, authenticated by the snapshot signature rather than a per-event
    /// signature. A snapshot that already publishes full signed events is
    /// passed through unchanged.
    pub fn snapshot_fact_documents(&self) -> Result<Vec<Value>, ContractError> {
        Ok(self
            .snapshot()?
            .as_ref()
            .map(snapshot_fact_documents)
            .unwrap_or_default())
    }

    /// Install a steward certificate into the cache (C2): verify the closed
    /// certificate shape and root signature, then copy the supplied bytes
    /// verbatim to the UUID-keyed path. The SQLite row remains an index, but
    /// trust resolution reads only the cache file.
    pub fn install_certificate(
        &self,
        document: &Value,
        certificate_bytes: &[u8],
        root: Option<&PublicKey>,
        now: &str,
    ) -> Result<Value, ContractError> {
        validate_certificate(document)?;
        let signer = PublicKey::verify_document("repo-certificate", document).ok_or_else(|| {
            ContractError::integrity("SIGNATURE_INVALID", "repository certificate signature failed", "Quarantine the certificate and ask the Company steward for a valid one; no trust-on-first-use fallback exists.")
        })?;
        let Some(root) = root else {
            return Err(ContractError::user_action(
                "REPO_UNCERTIFIED",
                "no Company root public key is configured to verify the certificate",
                "Create the launcher user config with [company] root_public_key_file before installing a certificate.",
            ));
        };
        if signer != *root {
            return Err(ContractError::integrity(
                "SIGNATURE_INVALID",
                "certificate is not signed by the configured Company root",
                "Only the configured steward root may issue repository certificates.",
            ));
        }
        let uuid = crate::json::get_str(document, "repository_uuid")
            .unwrap_or_default()
            .to_owned();
        let digest = crate::json::digest(document);
        let connection = self.connection()?;
        let existing: Option<String> = connection
            .query_row(
                "SELECT digest FROM certificates WHERE repository_uuid=?1",
                params![uuid],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error("certificate lookup"))?;
        if let Some(existing) = existing {
            if existing != digest {
                let _ = self.set_meta(&format!("certificate_identity_conflict:{uuid}"), &digest);
                return Err(ContractError::refused(
                    "FOREIGN_REPO_EVENTS",
                    "a different certificate is already installed for this repository UUID",
                    "Obtain a signed Company lineage/move event; the binding never silently repins.",
                ));
            }
        }

        let repositories = self.root.join("repositories");
        crate::paths::ensure_private_dir(&repositories, "Company repositories cache")?;
        let repository_dir = repositories.join(&uuid);
        crate::paths::ensure_private_dir(&repository_dir, "Company repository cache")?;
        let path = repository_dir.join("certificate.json");
        let relative = format!("repositories/{uuid}/certificate.json");
        if path.exists() {
            let existing_bytes =
                crate::paths::read_bounded(&path, 64 * 1024, "cached certificate")?;
            let existing_document = crate::json::parse_strict_value(&existing_bytes).map_err(|error| {
                ContractError::integrity("DIGEST_MISMATCH", format!("cached certificate is corrupt ({error})"), "Delete the corrupt certificate cache entry and reinstall the steward certificate.")
            })?;
            if crate::json::digest(&existing_document) != digest {
                let _ = self.set_meta(&format!("certificate_identity_conflict:{uuid}"), &digest);
                return Err(ContractError::refused(
                    "FOREIGN_REPO_EVENTS",
                    "a different certificate is already installed for this repository UUID",
                    "Obtain a signed Company lineage/move event; the binding never silently repins.",
                ));
            }
            enforce_certificate_file_mode(&path)?;
        } else {
            crate::paths::write_atomic(&path, certificate_bytes, 0o600, true).map_err(|error| {
                if error.code == "DIGEST_MISMATCH" {
                    ContractError::integrity(
                        "DIGEST_MISMATCH",
                        "the certificate cache path changed concurrently",
                        "Retry repo init; the UUID-keyed certificate path is never overwritten.",
                    )
                } else {
                    error
                }
            })?;
        }
        connection
            .execute(
                "INSERT OR IGNORE INTO certificates(repository_uuid, document, digest, installed_at) VALUES (?1, ?2, ?3, ?4)",
                params![uuid, crate::json::canonical_text(document), digest, now],
            )
            .map_err(sqlite_error("install certificate"))?;
        Ok(json!({
            "repository_uuid": uuid,
            "certificate_digest": digest,
            "signer": signer.to_hex(),
            "certificate_cached_path": relative
        }))
    }

    /// Resolve a certificate only from its UUID-keyed cache file. The SQLite
    /// index is deliberately not a trust source.
    pub fn certificate(
        &self,
        repository_uuid: &str,
    ) -> Result<Option<(Value, String)>, ContractError> {
        let path = self.certificate_file(repository_uuid)?;
        if !path.exists() {
            return Ok(None);
        }
        let bytes = crate::paths::read_bounded(&path, 64 * 1024, "cached certificate")?;
        let document = crate::json::parse_strict_value(&bytes).map_err(|error| {
            ContractError::integrity(
                "DIGEST_MISMATCH",
                format!("cached certificate is corrupt ({error})"),
                "Delete the corrupt certificate cache entry and reinstall the steward certificate.",
            )
        })?;
        let digest = crate::json::digest(&document);
        Ok(Some((document, digest)))
    }

    /// Every installed certificate document claiming `repository_uuid`:
    /// the UUID-keyed file plus any other JSON document under the
    /// repositories cache that certifies the same UUID, and the SQLite index
    /// row. One repository UUID binds exactly one certificate (architecture
    /// §2); two distinct claims make the binding ambiguous and block.
    pub fn certificate_claims(&self, repository_uuid: &str) -> Result<Vec<Value>, ContractError> {
        let mut claims = Vec::new();
        let repositories = self.root.join("repositories");
        if repositories.is_dir() {
            let mut pending = vec![repositories.clone()];
            let mut visited = 0usize;
            while let Some(directory) = pending.pop() {
                let Ok(entries) = std::fs::read_dir(&directory) else {
                    continue;
                };
                for entry in entries.flatten() {
                    visited += 1;
                    if visited > 10_000 {
                        break;
                    }
                    let path = entry.path();
                    let Ok(metadata) = std::fs::symlink_metadata(&path) else {
                        continue;
                    };
                    if metadata.is_dir() {
                        pending.push(path);
                        continue;
                    }
                    if !metadata.is_file()
                        || path.extension().and_then(|value| value.to_str()) != Some("json")
                    {
                        continue;
                    }
                    let Ok(bytes) =
                        crate::paths::read_bounded(&path, 64 * 1024, "cached certificate")
                    else {
                        continue;
                    };
                    let Ok(document) = crate::json::parse_strict_value(&bytes) else {
                        continue;
                    };
                    if crate::json::get_str(&document, "schema")
                        != Some(crate::model::CERTIFICATE_SCHEMA)
                        || crate::json::get_str(&document, "repository_uuid")
                            != Some(repository_uuid)
                    {
                        continue;
                    }
                    let relative = path
                        .strip_prefix(&self.root)
                        .map(|value| value.to_string_lossy().into_owned())
                        .unwrap_or_else(|_| path.to_string_lossy().into_owned());
                    claims.push(json!({
                        "source": "file",
                        "path": relative,
                        "digest": crate::json::digest(&document),
                        "issued_at": crate::json::get_str(&document, "issued_at"),
                        "signer": crate::json::get_str(&document, "signer")
                    }));
                }
            }
        }
        if let Some(connection) = self.connection.as_ref() {
            let indexed: Option<(String, String)> = connection
                .query_row(
                    "SELECT document, digest FROM certificates WHERE repository_uuid=?1",
                    params![repository_uuid],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(sqlite_error("certificate index"))?;
            if let Some((document, digest)) = indexed {
                let issued_at = serde_json::from_str::<Value>(&document)
                    .ok()
                    .and_then(|value| crate::json::get_str(&value, "issued_at").map(str::to_owned));
                claims.push(json!({
                    "source": "index",
                    "path": CACHE_FILE,
                    "digest": digest,
                    "issued_at": issued_at
                }));
            }
        }
        claims.sort_by(|left, right| {
            crate::json::get_str(left, "path").cmp(&crate::json::get_str(right, "path"))
        });
        Ok(claims)
    }

    fn certificate_file(&self, repository_uuid: &str) -> Result<PathBuf, ContractError> {
        if uuid::Uuid::parse_str(repository_uuid).is_err() {
            return Err(ContractError::integrity(
                "DIGEST_MISMATCH",
                "repository UUID is malformed",
                "Reinstall the steward-issued certificate.",
            ));
        }
        Ok(self
            .root
            .join("repositories")
            .join(repository_uuid)
            .join("certificate.json"))
    }

    pub fn pin(
        &self,
        hint: &str,
        repository_uuid: &str,
        digest: &str,
        cursor: &str,
        now: &str,
    ) -> Result<PinOutcome, ContractError> {
        let connection = self.connection()?;
        let existing: Option<(String, String)> = connection
            .query_row(
                "SELECT repository_uuid, certificate_digest FROM pins WHERE hint=?1",
                params![hint],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sqlite_error("pin lookup"))?;
        match existing {
            Some((uuid, existing_digest))
                if uuid == repository_uuid && existing_digest == digest =>
            {
                Ok(PinOutcome::Unchanged)
            }
            Some((uuid, _)) => Ok(PinOutcome::Conflict(uuid)),
            None => {
                connection
                    .execute(
                        "INSERT INTO pins(hint, repository_uuid, certificate_digest, pinned_at, cursor) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![hint, repository_uuid, digest, now, cursor],
                    )
                    .map_err(sqlite_error("pin"))?;
                Ok(PinOutcome::Pinned)
            }
        }
    }

    pub fn pins(&self) -> Vec<Value> {
        let Some(connection) = self.connection.as_ref() else {
            return Vec::new();
        };
        let Ok(mut statement) = connection.prepare(
            "SELECT hint, repository_uuid, certificate_digest, pinned_at FROM pins ORDER BY hint",
        ) else {
            return Vec::new();
        };
        statement
            .query_map([], |row| {
                Ok(json!({"hint": row.get::<_, String>(0)?, "repository_uuid": row.get::<_, String>(1)?, "certificate_digest": row.get::<_, String>(2)?, "pinned_at": row.get::<_, String>(3)?}))
            })
            .map(|rows| rows.filter_map(Result::ok).collect())
            .unwrap_or_default()
    }

    /// The freshness clocks (both rechecked at every projection).
    pub fn freshness(&self, now: &str) -> Freshness {
        let revocation_valid_until = self.meta("revocation_valid_until");
        let fact_valid_until = self.meta("fact_valid_until");
        Freshness {
            state: self.state.clone(),
            revocation_fresh: revocation_valid_until
                .as_deref()
                .is_some_and(|until| until > now),
            fact_fresh: fact_valid_until.as_deref().is_some_and(|until| until > now),
            revocation_valid_until,
            fact_valid_until,
            cursor: self.meta("cursor").unwrap_or_else(|| "0".to_owned()),
            revocation_cursor: self
                .meta("revocation_cursor")
                .unwrap_or_else(|| "0".to_owned()),
            refreshed_at: self.meta("refreshed_at"),
        }
    }

    pub fn save_saga(
        &self,
        candidate_id: &str,
        record: &Value,
        now: &str,
    ) -> Result<(), ContractError> {
        self.connection()?
            .execute(
                "INSERT INTO pending_sagas(candidate_id, record, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(candidate_id) DO UPDATE SET record=excluded.record, updated_at=excluded.updated_at",
                params![candidate_id, crate::json::canonical_text(record), now],
            )
            .map(|_| ())
            .map_err(sqlite_error("saga"))
    }

    pub fn sagas(&self) -> Vec<Value> {
        let Some(connection) = self.connection.as_ref() else {
            return Vec::new();
        };
        let Ok(mut statement) =
            connection.prepare("SELECT record FROM pending_sagas ORDER BY updated_at")
        else {
            return Vec::new();
        };
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .map(|rows| {
                rows.filter_map(Result::ok)
                    .filter_map(|text| serde_json::from_str(&text).ok())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Proxy every fact of a signed snapshot into a FactEvent-shaped document.
pub fn snapshot_fact_documents(snapshot: &Value) -> Vec<Value> {
    let cursor = crate::json::get_str(snapshot, "cursor").unwrap_or("0");
    crate::json::get_array(snapshot, "facts")
        .into_iter()
        .flatten()
        .filter_map(|fact| proxy_fact_document(fact, cursor))
        .collect()
}

fn proxy_fact_document(fact: &Value, snapshot_cursor: &str) -> Option<Value> {
    if crate::json::get_str(fact, "schema") == Some(crate::model::EVENT_SCHEMA) {
        return Some(fact.clone());
    }
    let map = fact.as_object()?;
    let text = |key: &str| map.get(key).and_then(Value::as_str).map(str::to_owned);
    let list = |key: &str| {
        map.get(key)
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new()))
    };
    let effective_from = text("effective_from")?;
    let mut document = serde_json::Map::new();
    document.insert(
        "schema".to_owned(),
        Value::String(crate::model::EVENT_SCHEMA.to_owned()),
    );
    document.insert("event_id".to_owned(), Value::String(text("event_id")?));
    document.insert("store_kind".to_owned(), Value::String("company".to_owned()));
    document.insert(
        "authority_id".to_owned(),
        Value::String(text("authority_id")?),
    );
    document.insert(
        "authority_scope".to_owned(),
        Value::String(text("authority_scope")?),
    );
    document.insert("fact_id".to_owned(), Value::String(text("fact_id")?));
    document.insert(
        "logical_key".to_owned(),
        Value::String(text("logical_key")?),
    );
    document.insert("atom_kind".to_owned(), Value::String(text("atom_kind")?));
    document.insert(
        "scope".to_owned(),
        Value::String(text("scope").or_else(|| text("authority_scope"))?),
    );
    document.insert("statement".to_owned(), Value::String(text("statement")?));
    document.insert("evidence_refs".to_owned(), list("evidence_refs"));
    document.insert(
        "asserted_at".to_owned(),
        Value::String(text("asserted_at").unwrap_or_else(|| effective_from.clone())),
    );
    document.insert("effective_from".to_owned(), Value::String(effective_from));
    if let Some(until) = text("effective_until") {
        document.insert("effective_until".to_owned(), Value::String(until));
    }
    document.insert(
        "disposition".to_owned(),
        Value::String(text("disposition").unwrap_or_else(|| "accepted".to_owned())),
    );
    document.insert(
        "distortion".to_owned(),
        map.get("distortion").cloned().unwrap_or_else(|| {
            json!({"trigger": "dependent decision", "loss_if_absent": 3000, "rationale": "unstated"})
        }),
    );
    document.insert("parents".to_owned(), list("parents"));
    document.insert("supersedes".to_owned(), list("supersedes"));
    document.insert("redundancy_with".to_owned(), list("redundancy_with"));
    document.insert("complements".to_owned(), list("complements"));
    document.insert("company_refs".to_owned(), list("company_refs"));
    document.insert(
        "authority_snapshot_cursor".to_owned(),
        Value::String(
            text("authority_snapshot_cursor").unwrap_or_else(|| snapshot_cursor.to_owned()),
        ),
    );
    document.insert(
        "confidence".to_owned(),
        map.get("confidence")
            .cloned()
            .unwrap_or_else(|| Value::from(6_000)),
    );
    document.insert("unresolved_uncertainty".to_owned(), Value::Null);
    document.insert(
        "signer".to_owned(),
        Value::String(text("signer").unwrap_or_default()),
    );
    document.insert(
        "signature".to_owned(),
        Value::String(text("signature").unwrap_or_default()),
    );
    Some(Value::Object(document))
}

fn validate_certificate(document: &Value) -> Result<(), ContractError> {
    let malformed = |message: &str| {
        ContractError::integrity(
            "DIGEST_MISMATCH",
            message.to_owned(),
            "Use a steward-issued certificate; malformed certificates are quarantined.",
        )
    };
    if crate::json::get_str(document, "schema") != Some(crate::model::CERTIFICATE_SCHEMA) {
        return Err(malformed(
            "certificate schema is not kinbase-repo-certificate/1",
        ));
    }
    let uuid = crate::json::get_str(document, "repository_uuid").unwrap_or_default();
    if uuid::Uuid::parse_str(uuid).is_err() {
        return Err(malformed("certificate repository_uuid is not a UUID"));
    }
    let issued_at = crate::json::get_str(document, "issued_at").unwrap_or_default();
    if crate::time::parse_rfc3339_millis(issued_at).is_err() {
        return Err(malformed(
            "certificate issued_at is not RFC 3339 UTC millisecond time",
        ));
    }
    if crate::json::get_str(document, "company_id")
        .unwrap_or_default()
        .is_empty()
    {
        return Err(malformed("certificate company_id is missing"));
    }
    if document.get("lineage_parent_uuid").is_some() {
        let parent = crate::json::get_str(document, "lineage_parent_uuid")
            .ok_or_else(|| malformed("certificate lineage_parent_uuid is not a string UUID"))?;
        if uuid::Uuid::parse_str(parent).is_err() {
            return Err(malformed("certificate lineage_parent_uuid is not a UUID"));
        }
    }
    let signer = crate::json::get_str(document, "signer").unwrap_or_default();
    if !crate::hash::is_sha256(signer) {
        return Err(ContractError::integrity(
            "SIGNATURE_INVALID",
            "certificate signer is not 64-hex",
            "Quarantine the certificate and ask the Company steward for a valid one.",
        ));
    }
    let signature = crate::json::get_str(document, "signature").unwrap_or_default();
    if signature.len() != 128
        || !signature
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ContractError::integrity(
            "SIGNATURE_INVALID",
            "certificate signature is not 128-hex",
            "Quarantine the certificate and ask the Company steward for a valid one.",
        ));
    }
    Ok(())
}

fn enforce_certificate_file_mode(path: &Path) -> Result<(), ContractError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path)
        .map_err(|error| ContractError::io("stat cached certificate", error))?;
    if !metadata.is_file() {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            "cached certificate path is not a regular file",
            "Delete the path and reinstall the steward certificate.",
        ));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| ContractError::io("chmod cached certificate", error))?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinOutcome {
    Pinned,
    Unchanged,
    Conflict(String),
}

#[derive(Debug, Clone)]
pub struct Freshness {
    pub state: CacheState,
    pub revocation_fresh: bool,
    pub fact_fresh: bool,
    pub revocation_valid_until: Option<String>,
    pub fact_valid_until: Option<String>,
    pub cursor: String,
    pub revocation_cursor: String,
    pub refreshed_at: Option<String>,
}

impl Freshness {
    /// Re-evaluate both bounded clocks at the caller's proof time. A projection
    /// never reuses booleans captured when the cache was built.
    pub fn at(&self, now: &str) -> Freshness {
        Freshness {
            state: self.state.clone(),
            revocation_fresh: self
                .revocation_valid_until
                .as_deref()
                .is_some_and(|until| until > now),
            fact_fresh: self
                .fact_valid_until
                .as_deref()
                .is_some_and(|until| until > now),
            revocation_valid_until: self.revocation_valid_until.clone(),
            fact_valid_until: self.fact_valid_until.clone(),
            cursor: self.cursor.clone(),
            revocation_cursor: self.revocation_cursor.clone(),
            refreshed_at: self.refreshed_at.clone(),
        }
    }

    /// Architecture §6 truth table row for one fact.
    pub fn projection(
        &self,
        safety: bool,
        certificate_valid: bool,
    ) -> (&'static str, Vec<&'static str>) {
        if !certificate_valid {
            return ("withheld", vec!["certificate-or-root-invalid"]);
        }
        match (self.revocation_fresh, self.fact_fresh, safety) {
            (true, true, _) => ("trusted", vec![]),
            (true, false, true) => ("withheld", vec!["CACHE_EXPIRED"]),
            (true, false, false) => ("excluded", vec!["CACHE_EXPIRED"]),
            (false, _, true) => ("withheld", vec!["REVOCATION_STALE"]),
            (false, true, false) => ("excluded", vec!["REVOCATION_STALE"]),
            (false, false, false) => ("excluded", vec!["REVOCATION_STALE", "CACHE_EXPIRED"]),
        }
    }

    pub fn to_value(&self) -> Value {
        json!({
            "cache_state": match self.state { CacheState::Cold => "cold", CacheState::Invalid => "invalid", CacheState::Warm => "warm" },
            "revocation_fresh": self.revocation_fresh,
            "fact_fresh": self.fact_fresh,
            "revocation_valid_until": self.revocation_valid_until,
            "fact_valid_until": self.fact_valid_until,
            "cursor": self.cursor,
            "revocation_cursor": self.revocation_cursor,
            "refreshed_at": self.refreshed_at
        })
    }
}

#[cfg(test)]
mod freshness_tests {
    use super::*;

    fn freshness(revocation: &str, fact: &str, now: &str) -> Freshness {
        let value = Freshness {
            state: CacheState::Warm,
            revocation_fresh: revocation > now,
            fact_fresh: fact > now,
            revocation_valid_until: Some(revocation.to_owned()),
            fact_valid_until: Some(fact.to_owned()),
            cursor: "10".to_owned(),
            revocation_cursor: "9".to_owned(),
            refreshed_at: None,
        };
        value.at(now)
    }

    #[test]
    fn projection_applies_six_row_cache_truth_table() {
        let now = "2026-01-02T00:00:00.000Z";
        let fresh = "2026-01-03T00:00:00.000Z";
        let expired = "2026-01-01T00:00:00.000Z";
        let fresh_fresh = freshness(fresh, fresh, now);
        assert_eq!(
            fresh_fresh.projection(true, true),
            ("trusted", Vec::<&str>::new())
        );
        assert_eq!(
            fresh_fresh.projection(false, true),
            ("trusted", Vec::<&str>::new())
        );
        assert_eq!(
            freshness(fresh, expired, now).projection(true, true),
            ("withheld", vec!["CACHE_EXPIRED"])
        );
        assert_eq!(
            freshness(fresh, expired, now).projection(false, true),
            ("excluded", vec!["CACHE_EXPIRED"])
        );
        assert_eq!(
            freshness(expired, fresh, now).projection(true, true),
            ("withheld", vec!["REVOCATION_STALE"])
        );
        assert_eq!(
            freshness(expired, expired, now).projection(true, true),
            ("withheld", vec!["REVOCATION_STALE"])
        );
        assert_eq!(
            freshness(expired, fresh, now).projection(false, true),
            ("excluded", vec!["REVOCATION_STALE"])
        );
        assert_eq!(
            freshness(expired, expired, now).projection(false, true),
            ("excluded", vec!["REVOCATION_STALE", "CACHE_EXPIRED"])
        );
    }

    #[test]
    fn certificate_or_root_failure_dominates_and_clocks_are_rechecked() {
        let now = "2026-01-02T00:00:00.000Z";
        let fresh = "2026-01-03T00:00:00.000Z";
        let value = freshness(fresh, fresh, now);
        assert_eq!(
            value.projection(true, false),
            ("withheld", vec!["certificate-or-root-invalid"])
        );
        let later = value.at("2026-01-04T00:00:00.000Z");
        assert!(!later.revocation_fresh);
        assert!(!later.fact_fresh);
    }
}
