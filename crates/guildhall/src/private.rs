//! Private stores (architecture §6 "Personal" and §5 prompt-budget Core).
//!
//! `PrivateStore` is one SQLite database under a mode-0700 directory that is
//! never inside a worktree: the Personal data root when a user config
//! exists, otherwise `${XDG_STATE_HOME:-~/.local/state}/guildhall`. It holds
//! raw private provenance under retention, session runs, candidates,
//! decisions, receipts, and the serialized prompt-budget shard. No shared
//! process ever receives its path.

use crate::error::ContractError;
use crate::model::{Atom, Observation};
use crate::paths;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub const PRIVATE_SCHEMA_VERSION: i64 = 3;
pub const RAW_RETENTION_SECONDS: i64 = 24 * 60 * 60;
pub const CANDIDATE_LIFETIME_SECONDS: i64 = 15 * 60;
pub const PROMPT_WINDOW_SECONDS: i64 = 60 * 60;
pub const PROMPT_WINDOW_LIMIT: i64 = 4;
pub const CONSECUTIVE_LIMIT: i64 = 3;
pub const REISSUE_LOCK_SECONDS: i64 = 24 * 60 * 60;

pub struct PrivateStore {
    pub root: PathBuf,
    pub connection: Connection,
    pub kind: &'static str,
}

pub fn state_dir() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| paths::home_dir().join(".local").join("state"))
        .join("guildhall")
}

fn sqlite_error(context: &str) -> impl Fn(rusqlite::Error) -> ContractError + '_ {
    move |error| ContractError::internal(format!("{context}: {error}"))
}

impl PrivateStore {
    /// Open the Personal store under `data_root` (mode 0700 enforced).
    pub fn open_personal(data_root: &Path) -> Result<Self, ContractError> {
        paths::ensure_private_dir(data_root, "Personal data root")?;
        Self::open_at(data_root, "guildhall-personal.sqlite3", "personal")
    }

    /// Open the host-wide Core store (prompt budget, session runs in
    /// Codebase-only mode).
    pub fn open_core() -> Result<Self, ContractError> {
        let root = state_dir();
        paths::ensure_private_dir(&root, "Guildhall state directory")?;
        Self::open_at(&root, "core.sqlite3", "core")
    }

    fn open_at(root: &Path, file: &str, kind: &'static str) -> Result<Self, ContractError> {
        let path = root.join(file);
        paths::reject_symlink(&path, "private store")?;
        let connection = Connection::open(&path).map_err(|error| {
            ContractError::refused(
                "CONFIG_INVARIANT",
                format!("private store cannot be opened ({error})"),
                format!(
                    "Make {} writable by the current user; no partial schema was created.",
                    root.display()
                ),
            )
        })?;
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(sqlite_error("busy timeout"))?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
            )
            .map_err(sqlite_error("pragma"))?;
        let store = Self {
            root: root.to_path_buf(),
            connection,
            kind,
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), ContractError> {
        self.connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS observations(
                    observation_id TEXT PRIMARY KEY, source_kind TEXT NOT NULL, source_identity TEXT NOT NULL,
                    native_id TEXT NOT NULL, content_digest TEXT NOT NULL, record TEXT NOT NULL,
                    observed_at TEXT NOT NULL, lifecycle TEXT NOT NULL);
                 CREATE INDEX IF NOT EXISTS observations_source ON observations(source_identity, native_id);
                 CREATE TABLE IF NOT EXISTS bodies(
                    content_digest TEXT PRIMARY KEY, bytes BLOB NOT NULL, stored_at TEXT NOT NULL,
                    retention_until TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS atoms(
                    atom_id TEXT PRIMARY KEY, observation_id TEXT NOT NULL, record TEXT NOT NULL,
                    created_at TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS personal_facts(
                    fact_id TEXT PRIMARY KEY, logical_key TEXT NOT NULL, record TEXT NOT NULL,
                    created_at TEXT NOT NULL, status TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS sessions(
                    session_id TEXT PRIMARY KEY, host TEXT NOT NULL, repository_id TEXT,
                    started_at TEXT NOT NULL, ended_at TEXT, status TEXT NOT NULL, record TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS session_events(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, event_id TEXT NOT NULL,
                    event_type TEXT NOT NULL, observed_at TEXT NOT NULL, record TEXT NOT NULL,
                    UNIQUE(session_id, event_id));
                 CREATE TABLE IF NOT EXISTS candidates(
                    candidate_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, destination TEXT NOT NULL,
                    payload_digest TEXT NOT NULL, record TEXT NOT NULL, created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL, status TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS decisions(
                    receipt_id TEXT PRIMARY KEY, candidate_id TEXT NOT NULL, destination TEXT NOT NULL,
                    decision TEXT NOT NULL, digest TEXT NOT NULL, record TEXT NOT NULL, decided_at TEXT NOT NULL,
                    UNIQUE(candidate_id, destination));
                 CREATE TABLE IF NOT EXISTS destination_receipts(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, candidate_id TEXT NOT NULL, destination TEXT NOT NULL,
                    status TEXT NOT NULL, record TEXT NOT NULL, recorded_at TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS prompt_reservations(
                    reservation_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, host_instance_id TEXT NOT NULL,
                    destination TEXT NOT NULL, candidate_id TEXT NOT NULL, content_digest TEXT NOT NULL,
                    reserved_at TEXT NOT NULL, expires_at TEXT NOT NULL, display_token TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS reissue_locks(
                    principal_id TEXT NOT NULL, destination TEXT NOT NULL, content_digest TEXT NOT NULL,
                    lock_window TEXT NOT NULL, locked_at TEXT NOT NULL, source_revision TEXT NOT NULL,
                    UNIQUE(principal_id, destination, content_digest, lock_window));
                 CREATE TABLE IF NOT EXISTS consecutive(
                    principal_id TEXT NOT NULL, host_instance_id TEXT NOT NULL, count INTEGER NOT NULL,
                    last_reset_event TEXT, updated_at TEXT NOT NULL,
                    PRIMARY KEY(principal_id, host_instance_id));
                 CREATE TABLE IF NOT EXISTS resets(
                    reset_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, host_instance_id TEXT NOT NULL,
                    after_event_id TEXT NOT NULL, reason_code TEXT NOT NULL, reset_at TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS budget_metrics(name TEXT PRIMARY KEY, count INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS reminders(
                    reminder_id TEXT PRIMARY KEY, record TEXT NOT NULL, due_at TEXT NOT NULL, status TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS checkpoints(
                    source_identity TEXT PRIMARY KEY, record TEXT NOT NULL, updated_at TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS query_log(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, record TEXT NOT NULL, logged_at TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS private_unknowns(
                    unknown_id TEXT PRIMARY KEY, record TEXT NOT NULL, status TEXT NOT NULL, updated_at TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS audit(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, record TEXT NOT NULL, recorded_at TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS shard_observations(
                    observed_at TEXT PRIMARY KEY, record TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS quarantine(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, record TEXT NOT NULL, recorded_at TEXT NOT NULL);",
            )
            .map_err(sqlite_error("private schema"))?;
        self.connection
            .execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?1)",
                params![PRIVATE_SCHEMA_VERSION.to_string()],
            )
            .map_err(sqlite_error("schema version"))?;
        Ok(())
    }

    pub fn meta(&self, key: &str) -> Result<Option<String>, ContractError> {
        self.connection
            .query_row("SELECT value FROM meta WHERE key=?1", params![key], |row| {
                row.get(0)
            })
            .optional()
            .map_err(sqlite_error("meta read"))
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO meta(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![key, value],
            )
            .map(|_| ())
            .map_err(sqlite_error("meta write"))
    }

    pub fn audit(&self, kind: &str, record: &Value) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO audit(kind, record, recorded_at) VALUES (?1, ?2, ?3)",
                params![
                    kind,
                    crate::json::canonical_text(record),
                    crate::time::now_rfc3339_millis()
                ],
            )
            .map(|_| ())
            .map_err(sqlite_error("audit"))
    }

    // ----- observations and bodies -----

    pub fn store_body(&self, bytes: &[u8], now: &str) -> Result<String, ContractError> {
        let digest = crate::hash::sha256_bytes(bytes);
        let retention_until = crate::time::plus_seconds(now, RAW_RETENTION_SECONDS)
            .map_err(ContractError::internal)?;
        self.connection
            .execute(
                "INSERT OR IGNORE INTO bodies(content_digest, bytes, stored_at, retention_until) VALUES (?1, ?2, ?3, ?4)",
                params![digest, bytes, now, retention_until],
            )
            .map_err(sqlite_error("store body"))?;
        Ok(format!("sha256:{digest}"))
    }

    pub fn body(&self, content_digest: &str) -> Result<Option<Vec<u8>>, ContractError> {
        self.connection
            .query_row(
                "SELECT bytes FROM bodies WHERE content_digest=?1",
                params![content_digest],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error("read body"))
    }

    /// Garbage-collect raw bodies past their retention clock. Returns the
    /// count removed; observations keep their digests (evidence tombstones).
    pub fn expire_bodies(&self, now: &str) -> Result<usize, ContractError> {
        self.connection
            .execute(
                "DELETE FROM bodies WHERE retention_until <= ?1",
                params![now],
            )
            .map_err(sqlite_error("expire bodies"))
    }

    pub fn observation(&self, observation_id: &str) -> Result<Option<Observation>, ContractError> {
        let record: Option<String> = self
            .connection
            .query_row(
                "SELECT record FROM observations WHERE observation_id=?1",
                params![observation_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error("read observation"))?;
        record
            .map(|text| {
                serde_json::from_str(&text)
                    .map_err(|error| ContractError::internal(error.to_string()))
            })
            .transpose()
    }

    pub fn insert_observation(&self, observation: &Observation) -> Result<bool, ContractError> {
        let record = crate::json::canonical_text(&crate::model::value_of(observation));
        let inserted = self
            .connection
            .execute(
                "INSERT OR IGNORE INTO observations(observation_id, source_kind, source_identity, native_id, content_digest, record, observed_at, lifecycle)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    observation.observation_id,
                    observation.source_kind,
                    observation.source_identity,
                    observation.native_id,
                    observation.content_digest,
                    record,
                    observation.observed_at,
                    observation.lifecycle
                ],
            )
            .map_err(sqlite_error("insert observation"))?;
        Ok(inserted == 1)
    }

    /// Retire the previous observation for a changed native source. The old
    /// row remains as history with a superseded lifecycle, and the explicit
    /// disposition transition is recorded for `status --json`.
    pub fn supersede_observation(
        &self,
        observation_id: &str,
        from_disposition: &str,
        to_disposition: &str,
        new_observation_id: &str,
        now: &str,
    ) -> Result<(), ContractError> {
        self.connection
            .execute(
                "UPDATE observations SET lifecycle='superseded' WHERE observation_id=?1 AND lifecycle='observed'",
                params![observation_id],
            )
            .map_err(sqlite_error("supersede observation"))?;
        self.audit(
            "disposition-change",
            &json!({
                "observation_id": observation_id,
                "new_observation_id": new_observation_id,
                "from_disposition": from_disposition,
                "to_disposition": to_disposition,
                "observed_at": now
            }),
        )
    }

    pub fn observations_for_source(
        &self,
        source_identity: &str,
    ) -> Result<Vec<Observation>, ContractError> {
        let mut statement = self
            .connection
            .prepare("SELECT record FROM observations WHERE source_identity=?1 ORDER BY observed_at, observation_id")
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map(params![source_identity], |row| row.get::<_, String>(0))
            .map_err(sqlite_error("query"))?;
        let mut output = Vec::new();
        for row in rows {
            let text = row.map_err(sqlite_error("row"))?;
            output.push(
                serde_json::from_str(&text)
                    .map_err(|error| ContractError::internal(error.to_string()))?,
            );
        }
        Ok(output)
    }

    pub fn observation_count(&self) -> Result<i64, ContractError> {
        self.connection
            .query_row("SELECT COUNT(*) FROM observations", [], |row| row.get(0))
            .map_err(sqlite_error("count"))
    }

    pub fn insert_atom(&self, atom: &Atom, now: &str) -> Result<bool, ContractError> {
        let record = crate::json::canonical_text(&crate::model::value_of(atom));
        let inserted = self
            .connection
            .execute(
                "INSERT OR IGNORE INTO atoms(atom_id, observation_id, record, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![atom.atom_id, atom.observation_id, record, now],
            )
            .map_err(sqlite_error("insert atom"))?;
        Ok(inserted == 1)
    }

    pub fn atoms(&self) -> Result<Vec<Atom>, ContractError> {
        self.records("SELECT record FROM atoms ORDER BY created_at, atom_id")
    }

    pub fn atoms_for_session(&self, session_id: &str) -> Result<Vec<Atom>, ContractError> {
        let source_identity = format!("session:{session_id}");
        let mut statement = self
            .connection
            .prepare(
                "SELECT a.record FROM atoms a JOIN observations o ON o.observation_id = a.observation_id
                 WHERE o.source_identity = ?1 ORDER BY a.created_at, a.atom_id",
            )
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map(params![source_identity], |row| row.get::<_, String>(0))
            .map_err(sqlite_error("query"))?;
        let mut output = Vec::new();
        for row in rows {
            let text = row.map_err(sqlite_error("row"))?;
            output.push(
                serde_json::from_str(&text)
                    .map_err(|error| ContractError::internal(error.to_string()))?,
            );
        }
        Ok(output)
    }

    fn records<T: serde::de::DeserializeOwned>(&self, sql: &str) -> Result<Vec<T>, ContractError> {
        let mut statement = self
            .connection
            .prepare(sql)
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(sqlite_error("query"))?;
        let mut output = Vec::new();
        for row in rows {
            let text = row.map_err(sqlite_error("row"))?;
            output.push(
                serde_json::from_str(&text)
                    .map_err(|error| ContractError::internal(error.to_string()))?,
            );
        }
        Ok(output)
    }

    pub fn values(
        &self,
        sql: &str,
        args: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<Value>, ContractError> {
        let mut statement = self
            .connection
            .prepare(sql)
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map(args, |row| row.get::<_, String>(0))
            .map_err(sqlite_error("query"))?;
        let mut output = Vec::new();
        for row in rows {
            let text = row.map_err(sqlite_error("row"))?;
            output.push(
                serde_json::from_str(&text)
                    .map_err(|error| ContractError::internal(error.to_string()))?,
            );
        }
        Ok(output)
    }

    // ----- personal facts -----

    pub fn upsert_personal_fact(&self, fact: &Value, now: &str) -> Result<bool, ContractError> {
        let fact_id = crate::json::get_str(fact, "fact_id")
            .unwrap_or_default()
            .to_owned();
        let logical_key = crate::json::get_str(fact, "logical_key")
            .unwrap_or_default()
            .to_owned();
        let inserted = self
            .connection
            .execute(
                "INSERT OR IGNORE INTO personal_facts(fact_id, logical_key, record, created_at, status) VALUES (?1, ?2, ?3, ?4, 'current')",
                params![fact_id, logical_key, crate::json::canonical_text(fact), now],
            )
            .map_err(sqlite_error("personal fact"))?;
        Ok(inserted == 1)
    }

    pub fn personal_facts(&self) -> Result<Vec<Value>, ContractError> {
        self.values(
            "SELECT record FROM personal_facts WHERE status='current' ORDER BY created_at, fact_id",
            &[],
        )
    }

    // ----- sessions -----

    pub fn insert_session(&self, record: &Value) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO sessions(session_id, host, repository_id, started_at, status, record) VALUES (?1, ?2, ?3, ?4, 'started', ?5)",
                params![
                    crate::json::get_str(record, "session_id").unwrap_or_default(),
                    crate::json::get_str(record, "host").unwrap_or_default(),
                    crate::json::get_str(record, "repository_id"),
                    crate::json::get_str(record, "started_at").unwrap_or_default(),
                    crate::json::canonical_text(record)
                ],
            )
            .map(|_| ())
            .map_err(sqlite_error("insert session"))
    }

    pub fn session(&self, session_id: &str) -> Result<Option<Value>, ContractError> {
        let row: Option<(String, String, Option<String>)> = self
            .connection
            .query_row(
                "SELECT record, status, ended_at FROM sessions WHERE session_id=?1",
                params![session_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(sqlite_error("read session"))?;
        Ok(row.map(|(record, status, ended_at)| {
            let mut value: Value = serde_json::from_str(&record).unwrap_or(Value::Null);
            value["status"] = Value::String(status);
            value["ended_at"] = ended_at.map(Value::String).unwrap_or(Value::Null);
            value
        }))
    }

    pub fn end_session(&self, session_id: &str, now: &str) -> Result<(), ContractError> {
        self.connection
            .execute(
                "UPDATE sessions SET status='ended', ended_at=?2 WHERE session_id=?1",
                params![session_id, now],
            )
            .map(|_| ())
            .map_err(sqlite_error("end session"))
    }

    pub fn insert_session_event(
        &self,
        session_id: &str,
        event_id: &str,
        event_type: &str,
        record: &Value,
        now: &str,
    ) -> Result<bool, ContractError> {
        let inserted = self
            .connection
            .execute(
                "INSERT OR IGNORE INTO session_events(session_id, event_id, event_type, observed_at, record) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![session_id, event_id, event_type, now, crate::json::canonical_text(record)],
            )
            .map_err(sqlite_error("insert session event"))?;
        Ok(inserted == 1)
    }

    pub fn session_events(&self, session_id: &str) -> Result<Vec<Value>, ContractError> {
        self.values(
            "SELECT record FROM session_events WHERE session_id=?1 ORDER BY id",
            &[&session_id],
        )
    }

    pub fn session_event_exists(
        &self,
        event_id: &str,
        event_type: &str,
    ) -> Result<bool, ContractError> {
        let count: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM session_events WHERE event_id=?1 AND event_type=?2",
                params![event_id, event_type],
                |row| row.get(0),
            )
            .map_err(sqlite_error("event exists"))?;
        Ok(count > 0)
    }

    // ----- candidates and decisions -----

    pub fn insert_candidate(&self, record: &Value) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO candidates(candidate_id, session_id, destination, payload_digest, record, created_at, expires_at, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending')",
                params![
                    crate::json::get_str(record, "candidate_id").unwrap_or_default(),
                    crate::json::get_str(record, "session_id").unwrap_or_default(),
                    crate::json::get_str(record, "destination").unwrap_or_default(),
                    crate::json::get_str(record, "payload_digest").unwrap_or_default(),
                    crate::json::canonical_text(record),
                    crate::json::get_str(record, "created_at").unwrap_or_default(),
                    crate::json::get_str(record, "expires_at").unwrap_or_default(),
                ],
            )
            .map(|_| ())
            .map_err(sqlite_error("insert candidate"))
    }

    pub fn candidate(&self, candidate_id: &str) -> Result<Option<Value>, ContractError> {
        let row: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT record, status FROM candidates WHERE candidate_id=?1",
                params![candidate_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sqlite_error("read candidate"))?;
        Ok(row.map(|(record, status)| {
            let mut value: Value = serde_json::from_str(&record).unwrap_or(Value::Null);
            value["status"] = Value::String(status);
            value
        }))
    }

    pub fn set_candidate_status(
        &self,
        candidate_id: &str,
        status: &str,
    ) -> Result<(), ContractError> {
        self.connection
            .execute(
                "UPDATE candidates SET status=?2 WHERE candidate_id=?1",
                params![candidate_id, status],
            )
            .map(|_| ())
            .map_err(sqlite_error("candidate status"))
    }

    pub fn candidates_for_session(&self, session_id: &str) -> Result<Vec<Value>, ContractError> {
        let mut statement = self
            .connection
            .prepare("SELECT record, status FROM candidates WHERE session_id=?1 ORDER BY created_at, candidate_id")
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map(params![session_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sqlite_error("query"))?;
        let mut output = Vec::new();
        for row in rows {
            let (record, status) = row.map_err(sqlite_error("row"))?;
            let mut value: Value = serde_json::from_str(&record)
                .map_err(|error| ContractError::internal(error.to_string()))?;
            value["status"] = Value::String(status);
            output.push(value);
        }
        Ok(output)
    }

    pub fn decision(
        &self,
        candidate_id: &str,
        destination: &str,
    ) -> Result<Option<Value>, ContractError> {
        let record: Option<String> = self
            .connection
            .query_row(
                "SELECT record FROM decisions WHERE candidate_id=?1 AND destination=?2",
                params![candidate_id, destination],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error("read decision"))?;
        Ok(record.and_then(|text| serde_json::from_str(&text).ok()))
    }

    pub fn any_decision(&self, candidate_id: &str) -> Result<Option<Value>, ContractError> {
        let record: Option<String> = self
            .connection
            .query_row(
                "SELECT record FROM decisions WHERE candidate_id=?1 ORDER BY decided_at LIMIT 1",
                params![candidate_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error("read decision"))?;
        Ok(record.and_then(|text| serde_json::from_str(&text).ok()))
    }

    pub fn insert_decision(&self, record: &Value) -> Result<bool, ContractError> {
        let inserted = self
            .connection
            .execute(
                "INSERT OR IGNORE INTO decisions(receipt_id, candidate_id, destination, decision, digest, record, decided_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    crate::json::get_str(record, "receipt_id").unwrap_or_default(),
                    crate::json::get_str(record, "candidate_id").unwrap_or_default(),
                    crate::json::get_str(record, "destination").unwrap_or_default(),
                    crate::json::get_str(record, "decision").unwrap_or_default(),
                    crate::json::get_str(record, "digest").unwrap_or_default(),
                    crate::json::canonical_text(record),
                    crate::json::get_str(record, "decided_at").unwrap_or_default(),
                ],
            )
            .map_err(sqlite_error("insert decision"))?;
        Ok(inserted == 1)
    }

    pub fn insert_destination_receipt(
        &self,
        candidate_id: &str,
        destination: &str,
        status: &str,
        record: &Value,
    ) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO destination_receipts(candidate_id, destination, status, record, recorded_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![candidate_id, destination, status, crate::json::canonical_text(record), crate::time::now_rfc3339_millis()],
            )
            .map(|_| ())
            .map_err(sqlite_error("destination receipt"))
    }

    pub fn destination_receipts(&self, candidate_id: &str) -> Result<Vec<Value>, ContractError> {
        self.values(
            "SELECT record FROM destination_receipts WHERE candidate_id=?1 ORDER BY id",
            &[&candidate_id],
        )
    }

    pub fn recent_decision_digests(
        &self,
        principal_destination: &str,
    ) -> Result<Vec<String>, ContractError> {
        let mut statement = self
            .connection
            .prepare("SELECT digest FROM decisions WHERE destination=?1 AND decision IN ('reject','defer') ORDER BY decided_at DESC LIMIT 200")
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map(params![principal_destination], |row| {
                row.get::<_, String>(0)
            })
            .map_err(sqlite_error("query"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error("rows"))
    }

    // ----- prompt budget core (architecture §5) -----

    /// One `BEGIN IMMEDIATE` transaction that checks reissue eligibility,
    /// inserts the unique reissue lock, reserves one of four sliding-hour
    /// slots, increments the consecutive count, and issues a single-use
    /// display token. Returns the reservation record or the typed refusal.
    /// `reissue_trusted` says whether a byte-change reissue is eligible
    /// (authority-trusted source revision).
    pub fn reserve_prompt_slot(
        &mut self,
        principal_id: &str,
        host_instance_id: &str,
        destination: &str,
        candidate_id: &str,
        content_digest: &str,
        source_revision: &str,
        now: &str,
    ) -> Result<Value, ContractError> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(sqlite_error("begin immediate"))?;
        let now_dt = crate::time::parse_rfc3339_millis(now).map_err(ContractError::internal)?;
        let window_start = crate::time::format_rfc3339_millis(
            now_dt - chrono::Duration::seconds(PROMPT_WINDOW_SECONDS),
        );
        // Existing live reservation for this candidate is returned as-is
        // (idempotent render of the same item).
        let existing: Option<String> = transaction
            .query_row(
                "SELECT record FROM (SELECT reservation_id, candidate_id, expires_at, display_token, status,
                     json_object('reservation_id', reservation_id, 'candidate_id', candidate_id, 'display_token', display_token,
                                 'reserved_at', reserved_at, 'expires_at', expires_at, 'status', status, 'destination', destination) AS record
                     FROM prompt_reservations)
                 WHERE candidate_id=?1 AND expires_at > ?2 AND status='reserved'",
                params![candidate_id, now],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error("existing reservation"))?;
        if let Some(record) = existing {
            transaction.commit().map_err(sqlite_error("commit"))?;
            let mut value: Value = serde_json::from_str(&record).unwrap_or(Value::Null);
            value["reused"] = Value::Bool(true);
            return Ok(value);
        }
        // Reissue eligibility: a rejected/deferred/expired content digest
        // cannot be reissued for 24 hours unless its source revision or
        // rendered bytes changed.
        let lock_window = &now[..10];
        let prior_lock: Option<(String, String)> = transaction
            .query_row(
                "SELECT locked_at, source_revision FROM reissue_locks WHERE principal_id=?1 AND destination=?2 AND content_digest=?3 ORDER BY locked_at DESC LIMIT 1",
                params![principal_id, destination, content_digest],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sqlite_error("reissue lock read"))?;
        if let Some((locked_at, locked_revision)) = prior_lock {
            let age = crate::time::seconds_between(&locked_at, now).unwrap_or(0);
            if age < REISSUE_LOCK_SECONDS && locked_revision == source_revision {
                self_bump(&transaction, "suppressed")?;
                transaction.commit().map_err(sqlite_error("commit"))?;
                return Err(ContractError::limit(
                    "this content digest was decided within the last 24 hours and its source revision is unchanged",
                    json!({"refused_count": 1, "omitted_count": 1, "lock_age_seconds": age, "lock_seconds": REISSUE_LOCK_SECONDS}),
                ));
            }
        }
        transaction
            .execute(
                "INSERT OR IGNORE INTO reissue_locks(principal_id, destination, content_digest, lock_window, locked_at, source_revision) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![principal_id, destination, content_digest, lock_window, now, source_revision],
            )
            .map_err(sqlite_error("reissue lock insert"))?;
        // Four total cross-destination slots in the sliding hour; crash or
        // abandonment never releases a slot, it expires on the same clock.
        let reserved_in_window: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM prompt_reservations WHERE principal_id=?1 AND host_instance_id=?2 AND reserved_at > ?3",
                params![principal_id, host_instance_id, window_start],
                |row| row.get(0),
            )
            .map_err(sqlite_error("window count"))?;
        if reserved_in_window >= PROMPT_WINDOW_LIMIT {
            self_bump(&transaction, "suppressed")?;
            transaction.commit().map_err(sqlite_error("commit"))?;
            return Err(ContractError::limit(
                "four shared approval opportunities are already reserved in the sliding hour for this principal and host instance",
                json!({"refused_count": 1, "omitted_count": 1, "reserved_in_window": reserved_in_window, "window_seconds": PROMPT_WINDOW_SECONDS, "ceiling": PROMPT_WINDOW_LIMIT}),
            ));
        }
        let consecutive: i64 = transaction
            .query_row(
                "SELECT count FROM consecutive WHERE principal_id=?1 AND host_instance_id=?2",
                params![principal_id, host_instance_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error("consecutive read"))?
            .unwrap_or(0);
        if consecutive >= CONSECUTIVE_LIMIT {
            self_bump(&transaction, "suppressed")?;
            // The suppressed opportunity itself breaks the consecutive run,
            // allowing a fourth non-consecutive slot within the hourly cap.
            transaction
                .execute(
                    "UPDATE consecutive SET count=0, updated_at=?3 WHERE principal_id=?1 AND host_instance_id=?2",
                    params![principal_id, host_instance_id, now],
                )
                .map_err(sqlite_error("reset consecutive after suppression"))?;
            transaction.commit().map_err(sqlite_error("commit"))?;
            return Err(ContractError::limit(
                "three consecutive shared prompts were surfaced without returning to the primary task",
                json!({"refused_count": 1, "omitted_count": 1, "consecutive": consecutive, "ceiling": CONSECUTIVE_LIMIT}),
            ));
        }
        let reservation_id = crate::crypto::random_id("resv");
        let display_token = crate::crypto::random_token();
        let expires_at = crate::time::plus_seconds(now, PROMPT_WINDOW_SECONDS)
            .map_err(ContractError::internal)?;
        transaction
            .execute(
                "INSERT INTO prompt_reservations(reservation_id, principal_id, host_instance_id, destination, candidate_id, content_digest, reserved_at, expires_at, display_token, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'reserved')",
                params![reservation_id, principal_id, host_instance_id, destination, candidate_id, content_digest, now, expires_at, display_token],
            )
            .map_err(sqlite_error("reserve"))?;
        transaction
            .execute(
                "INSERT INTO consecutive(principal_id, host_instance_id, count, updated_at) VALUES (?1, ?2, 1, ?3)
                 ON CONFLICT(principal_id, host_instance_id) DO UPDATE SET count=count+1, updated_at=excluded.updated_at",
                params![principal_id, host_instance_id, now],
            )
            .map_err(sqlite_error("consecutive"))?;
        self_bump(&transaction, "reserved")?;
        transaction.commit().map_err(sqlite_error("commit"))?;
        Ok(json!({
            "reservation_id": reservation_id,
            "candidate_id": candidate_id,
            "destination": destination,
            "display_token": display_token,
            "reserved_at": now,
            "expires_at": expires_at,
            "status": "reserved",
            "reserved_in_window": reserved_in_window + 1,
            "consecutive": consecutive + 1,
            "reused": false
        }))
    }

    /// Mark a reservation rendered/decided (metrics only; never releases the slot).
    pub fn mark_reservation(&self, candidate_id: &str, status: &str) -> Result<(), ContractError> {
        self.connection
            .execute(
                "UPDATE prompt_reservations SET status=?2 WHERE candidate_id=?1 AND status='reserved'",
                params![candidate_id, status],
            )
            .map_err(sqlite_error("mark reservation"))?;
        self.bump(status)
    }

    pub fn bump(&self, name: &str) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO budget_metrics(name, count) VALUES (?1, 1) ON CONFLICT(name) DO UPDATE SET count=count+1",
                params![name],
            )
            .map(|_| ())
            .map_err(sqlite_error("metric"))
    }

    /// One `BEGIN IMMEDIATE` reissue eligibility transaction. A digest is locked
    /// for 24 hours unless the trusted source revision changed.
    pub fn reserve_reissue(
        &mut self,
        principal_id: &str,
        destination: &str,
        content_digest: &str,
        source_revision: &str,
        now: &str,
    ) -> Result<Value, ContractError> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(sqlite_error("begin immediate"))?;
        let lock_window = &now[..10];
        let prior_lock: Option<(String, String)> = transaction
            .query_row(
                "SELECT locked_at, source_revision FROM reissue_locks WHERE principal_id=?1 AND destination=?2 AND content_digest=?3 ORDER BY locked_at DESC LIMIT 1",
                params![principal_id, destination, content_digest],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sqlite_error("reissue lock read"))?;
        if let Some((locked_at, locked_revision)) = prior_lock {
            let age = crate::time::seconds_between(&locked_at, now).unwrap_or(0);
            if age < REISSUE_LOCK_SECONDS && locked_revision == source_revision {
                self_bump(&transaction, "suppressed")?;
                transaction.commit().map_err(sqlite_error("commit"))?;
                return Err(ContractError::limit(
                    "candidate source bytes and revision are unchanged within 24 hours",
                    json!({"refused_count": 1, "omitted_count": 1, "lock_age_seconds": age, "lock_seconds": REISSUE_LOCK_SECONDS}),
                ));
            }
        }
        let inserted = transaction
            .execute(
                "INSERT OR IGNORE INTO reissue_locks(principal_id, destination, content_digest, lock_window, locked_at, source_revision) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![principal_id, destination, content_digest, lock_window, now, source_revision],
            )
            .map_err(sqlite_error("reissue lock insert"))?;
        transaction.commit().map_err(sqlite_error("commit"))?;
        Ok(json!({
            "transaction": "BEGIN IMMEDIATE",
            "committed": true,
            "lock_inserted": inserted == 1,
            "at": now
        }))
    }

    /// Consecutive-counter reset: only after a real primary-task event and at
    /// most once per hour. The hourly ceiling is untouched.
    pub fn reset_consecutive(
        &mut self,
        principal_id: &str,
        host_instance_id: &str,
        after_event_id: &str,
        reason_code: &str,
        now: &str,
    ) -> Result<Value, ContractError> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(sqlite_error("begin immediate"))?;
        let event_exists: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM session_events WHERE event_id=?1 AND event_type IN ('primary-task','UserPromptSubmit','user_prompt_submit','prompt')",
                params![after_event_id],
                |row| row.get(0),
            )
            .map_err(sqlite_error("event lookup"))?;
        if event_exists == 0 {
            transaction.commit().map_err(sqlite_error("commit"))?;
            return Err(ContractError::refused(
                "CONFIG_INVARIANT",
                "no recorded primary-task event matches the supplied event id",
                "Record a real new primary-task event (a host prompt) before resetting the consecutive counter.",
            ));
        }
        let already_used: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM resets WHERE after_event_id=?1",
                params![after_event_id],
                |row| row.get(0),
            )
            .map_err(sqlite_error("reset lookup"))?;
        if already_used > 0 {
            transaction.commit().map_err(sqlite_error("commit"))?;
            return Err(ContractError::limit(
                "this primary-task event already authorized a reset",
                json!({"refused_count": 1, "omitted_count": 1}),
            ));
        }
        let now_dt = crate::time::parse_rfc3339_millis(now).map_err(ContractError::internal)?;
        let hour_ago = crate::time::format_rfc3339_millis(
            now_dt - chrono::Duration::seconds(PROMPT_WINDOW_SECONDS),
        );
        let recent: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM resets WHERE principal_id=?1 AND host_instance_id=?2 AND reset_at > ?3",
                params![principal_id, host_instance_id, hour_ago],
                |row| row.get(0),
            )
            .map_err(sqlite_error("recent resets"))?;
        if recent > 0 {
            transaction.commit().map_err(sqlite_error("commit"))?;
            return Err(ContractError::limit(
                "consecutive-counter reset is limited to once per hour; the hourly ceiling never resets",
                json!({"refused_count": 1, "omitted_count": 1, "cooldown_seconds": PROMPT_WINDOW_SECONDS}),
            ));
        }
        let reset_id = crate::crypto::random_id("reset");
        transaction
            .execute(
                "INSERT INTO resets(reset_id, principal_id, host_instance_id, after_event_id, reason_code, reset_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![reset_id, principal_id, host_instance_id, after_event_id, reason_code, now],
            )
            .map_err(sqlite_error("insert reset"))?;
        transaction
            .execute(
                "INSERT INTO consecutive(principal_id, host_instance_id, count, last_reset_event, updated_at) VALUES (?1, ?2, 0, ?3, ?4)
                 ON CONFLICT(principal_id, host_instance_id) DO UPDATE SET count=0, last_reset_event=excluded.last_reset_event, updated_at=excluded.updated_at",
                params![principal_id, host_instance_id, after_event_id, now],
            )
            .map_err(sqlite_error("reset consecutive"))?;
        transaction.commit().map_err(sqlite_error("commit"))?;
        Ok(json!({
            "reset_id": reset_id,
            "after_primary_event": after_event_id,
            "reason_code": reason_code,
            "reset_at": now,
            "scope": "consecutive-counter-only",
            "hourly_ceiling_reset": false
        }))
    }

    /// Budget shard summary for `doctor`.
    pub fn budget_shard(
        &self,
        principal_id: &str,
        host_instance_id: &str,
        now: &str,
    ) -> Result<Value, ContractError> {
        let now_dt = crate::time::parse_rfc3339_millis(now).map_err(ContractError::internal)?;
        let window_start = crate::time::format_rfc3339_millis(
            now_dt - chrono::Duration::seconds(PROMPT_WINDOW_SECONDS),
        );
        let reserved_in_window: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM prompt_reservations WHERE principal_id=?1 AND host_instance_id=?2 AND reserved_at > ?3",
                params![principal_id, host_instance_id, window_start],
                |row| row.get(0),
            )
            .map_err(sqlite_error("window count"))?;
        let consecutive: i64 = self
            .connection
            .query_row(
                "SELECT count FROM consecutive WHERE principal_id=?1 AND host_instance_id=?2",
                params![principal_id, host_instance_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error("consecutive"))?
            .unwrap_or(0);
        let mut metrics = serde_json::Map::new();
        let mut statement = self
            .connection
            .prepare("SELECT name, count FROM budget_metrics ORDER BY name")
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(sqlite_error("query"))?;
        for row in rows {
            let (name, count) = row.map_err(sqlite_error("row"))?;
            metrics.insert(name, Value::from(count));
        }
        for name in [
            "reserved",
            "rendered",
            "decided",
            "expired",
            "suppressed",
            "delivery_loss",
        ] {
            metrics.entry(name).or_insert(Value::from(0));
        }
        Ok(json!({
            "principal_id": principal_id,
            "host_instance_id": host_instance_id,
            "window_seconds": PROMPT_WINDOW_SECONDS,
            "total_limit": PROMPT_WINDOW_LIMIT,
            "consecutive_limit": CONSECUTIVE_LIMIT,
            "reserved_in_window": reserved_in_window,
            "consumed_in_window": reserved_in_window,
            "consecutive": consecutive,
            "metrics": metrics,
            "global_cross_machine_total_known": false,
            "warning": "no global cross-machine prompt total is known; this shard covers exactly one (principal_id, host_instance_id)"
        }))
    }

    pub fn record_shard_observation(&self, record: &Value, now: &str) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT OR REPLACE INTO shard_observations(observed_at, record) VALUES (?1, ?2)",
                params![now, crate::json::canonical_text(record)],
            )
            .map(|_| ())
            .map_err(sqlite_error("shard observation"))
    }

    /// Expire candidates and count delivery losses (reservations that were
    /// never rendered before expiry).
    pub fn sweep(&self, now: &str) -> Result<Value, ContractError> {
        let expired_candidates = self
            .connection
            .execute(
                "UPDATE candidates SET status='expired' WHERE status='pending' AND expires_at <= ?1",
                params![now],
            )
            .map_err(sqlite_error("expire candidates"))?;
        let lost = self
            .connection
            .execute(
                "UPDATE prompt_reservations SET status='delivery_loss' WHERE status='reserved' AND expires_at <= ?1",
                params![now],
            )
            .map_err(sqlite_error("delivery loss"))?;
        for _ in 0..expired_candidates {
            self.bump("expired")?;
        }
        for _ in 0..lost {
            self.bump("delivery_loss")?;
        }
        let bodies = self.expire_bodies(now)?;
        Ok(
            json!({"expired_candidates": expired_candidates, "delivery_loss": lost, "expired_bodies": bodies}),
        )
    }

    // ----- checkpoints, query log, reminders, unknowns -----

    pub fn checkpoint(&self, source_identity: &str) -> Result<Option<Value>, ContractError> {
        let record: Option<String> = self
            .connection
            .query_row(
                "SELECT record FROM checkpoints WHERE source_identity=?1",
                params![source_identity],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error("checkpoint"))?;
        Ok(record.and_then(|text| serde_json::from_str(&text).ok()))
    }

    pub fn set_checkpoint(
        &self,
        source_identity: &str,
        record: &Value,
        now: &str,
    ) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO checkpoints(source_identity, record, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(source_identity) DO UPDATE SET record=excluded.record, updated_at=excluded.updated_at",
                params![source_identity, crate::json::canonical_text(record), now],
            )
            .map(|_| ())
            .map_err(sqlite_error("set checkpoint"))
    }

    pub fn log_query(&self, session_id: Option<&str>, record: &Value) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO query_log(session_id, record, logged_at) VALUES (?1, ?2, ?3)",
                params![
                    session_id,
                    crate::json::canonical_text(record),
                    crate::time::now_rfc3339_millis()
                ],
            )
            .map(|_| ())
            .map_err(sqlite_error("query log"))
    }

    pub fn query_log(&self, session_id: Option<&str>) -> Result<Vec<Value>, ContractError> {
        match session_id {
            Some(session) => self.values(
                "SELECT record FROM query_log WHERE session_id=?1 ORDER BY id",
                &[&session],
            ),
            None => self.values("SELECT record FROM query_log ORDER BY id", &[]),
        }
    }

    pub fn insert_reminder(&self, record: &Value) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT OR IGNORE INTO reminders(reminder_id, record, due_at, status) VALUES (?1, ?2, ?3, 'pending')",
                params![
                    crate::json::get_str(record, "reminder_id").unwrap_or_default(),
                    crate::json::canonical_text(record),
                    crate::json::get_str(record, "due_at").unwrap_or_default(),
                ],
            )
            .map(|_| ())
            .map_err(sqlite_error("reminder"))
    }

    pub fn upsert_private_unknown(
        &self,
        unknown_id: &str,
        record: &Value,
        status: &str,
        now: &str,
    ) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO private_unknowns(unknown_id, record, status, updated_at) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(unknown_id) DO UPDATE SET record=excluded.record, status=excluded.status, updated_at=excluded.updated_at",
                params![unknown_id, crate::json::canonical_text(record), status, now],
            )
            .map(|_| ())
            .map_err(sqlite_error("private unknown"))
    }

    pub fn private_unknowns(&self) -> Result<Vec<Value>, ContractError> {
        self.values("SELECT record FROM private_unknowns WHERE status <> 'closed' ORDER BY updated_at, unknown_id", &[])
    }

    pub fn quarantine(&self, kind: &str, record: &Value) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO quarantine(kind, record, recorded_at) VALUES (?1, ?2, ?3)",
                params![
                    kind,
                    crate::json::canonical_text(record),
                    crate::time::now_rfc3339_millis()
                ],
            )
            .map(|_| ())
            .map_err(sqlite_error("quarantine"))
    }

    pub fn quarantine_count(&self, kind: &str) -> Result<i64, ContractError> {
        self.connection
            .query_row(
                "SELECT COUNT(*) FROM quarantine WHERE kind=?1",
                params![kind],
                |row| row.get(0),
            )
            .map_err(sqlite_error("quarantine count"))
    }
}

fn self_bump(transaction: &rusqlite::Transaction<'_>, name: &str) -> Result<(), ContractError> {
    transaction
        .execute(
            "INSERT INTO budget_metrics(name, count) VALUES (?1, 1) ON CONFLICT(name) DO UPDATE SET count=count+1",
            params![name],
        )
        .map(|_| ())
        .map_err(sqlite_error("metric"))
}
