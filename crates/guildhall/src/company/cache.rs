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
            let bytes = std::fs::read(&path).map_err(|error| ContractError::io("read cache", error))?;
            if bytes.len() < 16 || !bytes.starts_with(b"SQLite format 3\0") {
                // An invalid cache is cold, never trusted, and never repaired
                // silently: it is renamed aside so the next refresh is clean.
                let quarantine = root.join(format!("{CACHE_FILE}.invalid-{}", crate::time::now_utc().timestamp_millis()));
                let _ = std::fs::rename(&path, &quarantine);
                return Ok(Self {
                    root: root.to_path_buf(),
                    connection: None,
                    state: CacheState::Invalid,
                });
            }
        }
        let connection = Connection::open(&path).map_err(|error| ContractError::internal(format!("open cache: {error}")))?;
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
            let quarantine = root.join(format!("{CACHE_FILE}.invalid-{}", crate::time::now_utc().timestamp_millis()));
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
            state: if has_snapshot > 0 { CacheState::Warm } else { CacheState::Cold },
        })
    }

    fn connection(&self) -> Result<&Connection, ContractError> {
        self.connection
            .as_ref()
            .ok_or_else(|| ContractError::degraded("CACHE_EXPIRED", "the Company cache is invalid and was quarantined", "Refresh Company state; no cached fact is used."))
    }

    pub fn meta(&self, key: &str) -> Option<String> {
        self.connection
            .as_ref()?
            .query_row("SELECT value FROM meta WHERE key=?1", params![key], |row| row.get(0))
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
        self.meta("high_water_cursor").unwrap_or_else(|| "0".to_owned())
    }

    /// Store a verified snapshot. A snapshot whose cursor is older than the
    /// sealed high-water mark is a replay and is refused.
    pub fn store_snapshot(&mut self, snapshot: &Value, root: &PublicKey, now: &str) -> Result<(), ContractError> {
        let signer = PublicKey::verify_document("receipt", snapshot).ok_or_else(|| {
            ContractError::integrity("SIGNATURE_INVALID", "snapshot signature failed", "Quarantine the snapshot and contact the Company steward.")
        })?;
        if signer != *root {
            return Err(ContractError::integrity("SIGNATURE_INVALID", "snapshot is not signed by the configured root", "Verify the root public key."));
        }
        let cursor = crate::json::get_str(snapshot, "cursor").unwrap_or("0").to_owned();
        let high_water = self.high_water();
        if crate::reducer::cursor_order(&cursor, &high_water) == std::cmp::Ordering::Less {
            return Err(ContractError::integrity(
                "SIGNATURE_INVALID",
                format!("snapshot cursor {cursor} is older than the sealed high-water mark {high_water} (replay)"),
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
        for key in ["cursor", "authority_cursor", "revocation_cursor", "revocation_valid_until", "fact_valid_until", "issued_at", "company_id"] {
            if let Some(value) = crate::json::get_str(snapshot, key) {
                self.set_meta(key, value)?;
            }
        }
        self.set_meta("high_water_cursor", &cursor)?;
        self.set_meta("snapshot_digest", &digest)?;
        self.set_meta("refreshed_at", now)?;
        for certificate in crate::json::get_array(snapshot, "certificates").cloned().unwrap_or_default() {
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
        let Some(connection) = self.connection.as_ref() else { return Ok(None) };
        let bytes: Option<Vec<u8>> = connection
            .query_row("SELECT bytes FROM snapshot WHERE id=1", [], |row| row.get(0))
            .optional()
            .map_err(sqlite_error("read snapshot"))?;
        match bytes {
            None => Ok(None),
            Some(bytes) => crate::json::parse_strict_value(&bytes)
                .map(Some)
                .map_err(|error| ContractError::integrity("DIGEST_MISMATCH", format!("cached snapshot is corrupt ({error})"), "Delete the cache and refresh.")),
        }
    }

    /// Install a steward certificate into the cache (C2): verified against
    /// the root key; a UUID already pinned to a different certificate blocks.
    pub fn install_certificate(&self, document: &Value, root: Option<&PublicKey>, now: &str) -> Result<Value, ContractError> {
        if crate::json::get_str(document, "schema") != Some(crate::model::CERTIFICATE_SCHEMA) {
            return Err(ContractError::integrity("DIGEST_MISMATCH", "certificate schema is not guildhall-repo-certificate/1", "Use a steward-issued certificate; malformed certificates are quarantined."));
        }
        let signer = PublicKey::verify_document("repo-certificate", document).ok_or_else(|| {
            ContractError::integrity("SIGNATURE_INVALID", "repository certificate signature failed", "Quarantine the certificate and ask the Company steward for a valid one; no trust-on-first-use fallback exists.")
        })?;
        if let Some(root) = root {
            if signer != *root {
                return Err(ContractError::integrity("SIGNATURE_INVALID", "certificate is not signed by the configured Company root", "Only the configured steward root may issue repository certificates."));
            }
        } else {
            return Err(ContractError::user_action("REPO_UNCERTIFIED", "no Company root public key is configured to verify the certificate", "Create the launcher user config with [company] root_public_key_file before installing a certificate."));
        }
        let uuid = crate::json::get_str(document, "repository_uuid").unwrap_or_default().to_owned();
        if uuid::Uuid::parse_str(&uuid).is_err() {
            return Err(ContractError::integrity("DIGEST_MISMATCH", "certificate repository_uuid is not a UUID", "Ask the steward for a valid certificate."));
        }
        let digest = crate::json::digest(document);
        let connection = self.connection()?;
        let existing: Option<String> = connection
            .query_row("SELECT digest FROM certificates WHERE repository_uuid=?1", params![uuid], |row| row.get(0))
            .optional()
            .map_err(sqlite_error("certificate lookup"))?;
        if let Some(existing) = existing {
            if existing != digest {
                return Err(ContractError::refused(
                    "FOREIGN_REPO_EVENTS",
                    "a different certificate is already installed for this repository UUID",
                    "Obtain a signed Company lineage/move event; the binding never silently repins.",
                ));
            }
        }
        connection
            .execute(
                "INSERT OR IGNORE INTO certificates(repository_uuid, document, digest, installed_at) VALUES (?1, ?2, ?3, ?4)",
                params![uuid, crate::json::canonical_text(document), digest, now],
            )
            .map_err(sqlite_error("install certificate"))?;
        Ok(json!({"repository_uuid": uuid, "certificate_digest": digest, "signer": signer.to_hex()}))
    }

    pub fn certificate(&self, repository_uuid: &str) -> Result<Option<(Value, String)>, ContractError> {
        let Some(connection) = self.connection.as_ref() else { return Ok(None) };
        let row: Option<(String, String)> = connection
            .query_row(
                "SELECT document, digest FROM certificates WHERE repository_uuid=?1",
                params![repository_uuid],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sqlite_error("certificate"))?;
        Ok(row.and_then(|(document, digest)| serde_json::from_str(&document).ok().map(|value| (value, digest))))
    }

    pub fn pin(&self, hint: &str, repository_uuid: &str, digest: &str, cursor: &str, now: &str) -> Result<PinOutcome, ContractError> {
        let connection = self.connection()?;
        let existing: Option<(String, String)> = connection
            .query_row("SELECT repository_uuid, certificate_digest FROM pins WHERE hint=?1", params![hint], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()
            .map_err(sqlite_error("pin lookup"))?;
        match existing {
            Some((uuid, existing_digest)) if uuid == repository_uuid && existing_digest == digest => Ok(PinOutcome::Unchanged),
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
        let Some(connection) = self.connection.as_ref() else { return Vec::new() };
        let Ok(mut statement) = connection.prepare("SELECT hint, repository_uuid, certificate_digest, pinned_at FROM pins ORDER BY hint") else {
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
            revocation_fresh: revocation_valid_until.as_deref().is_some_and(|until| until > now),
            fact_fresh: fact_valid_until.as_deref().is_some_and(|until| until > now),
            revocation_valid_until,
            fact_valid_until,
            cursor: self.meta("cursor").unwrap_or_else(|| "0".to_owned()),
            revocation_cursor: self.meta("revocation_cursor").unwrap_or_else(|| "0".to_owned()),
            refreshed_at: self.meta("refreshed_at"),
        }
    }

    pub fn save_saga(&self, candidate_id: &str, record: &Value, now: &str) -> Result<(), ContractError> {
        self.connection()?
            .execute(
                "INSERT INTO pending_sagas(candidate_id, record, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(candidate_id) DO UPDATE SET record=excluded.record, updated_at=excluded.updated_at",
                params![candidate_id, crate::json::canonical_text(record), now],
            )
            .map(|_| ())
            .map_err(sqlite_error("saga"))
    }

    pub fn sagas(&self) -> Vec<Value> {
        let Some(connection) = self.connection.as_ref() else { return Vec::new() };
        let Ok(mut statement) = connection.prepare("SELECT record FROM pending_sagas ORDER BY updated_at") else {
            return Vec::new();
        };
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .map(|rows| rows.filter_map(Result::ok).filter_map(|text| serde_json::from_str(&text).ok()).collect())
            .unwrap_or_default()
    }
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
    /// Architecture §6 truth table row for one fact.
    pub fn projection(&self, safety: bool, certificate_valid: bool) -> (&'static str, Vec<&'static str>) {
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
