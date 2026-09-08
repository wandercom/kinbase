//! Boundary tests for packet 12: config round-tripping, idempotent
//! destination records, receipt identity binding, and journal recovery.

use guildhall::codebase::{RepoConfig, Repository};
use guildhall::company::db::CompanyDb;
use guildhall::json::{canonical_bytes, canonical_text, parse_strict_value};
use guildhall::paths::sharded_relative;
use guildhall::hash::sha256_bytes;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn init_git_repository(path: &Path) -> Repository {
    let output = Command::new("git")
        .arg("init")
        .arg("--initial-branch=main")
        .arg(path)
        .output()
        .expect("run git init");
    assert!(
        output.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::create_dir_all(path.join(".kin")).expect("create .kin");
    Repository::discover(path).expect("discover repository")
}

#[test]
fn repo_config_round_trips_and_fails_closed() {
    let mut local_policy = BTreeMap::new();
    local_policy.insert("admission_lock_timeout_seconds".to_owned(), "30".to_owned());
    local_policy.insert("retention_policy".to_owned(), "seven-days".to_owned());
    let config = RepoConfig {
        schema_version: "guildhall-repo/1".to_owned(),
        repository_uuid_hint: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
        safe_name: "boundary-repo".to_owned(),
        domains: vec!["architecture".to_owned(), "runtime".to_owned()],
        local_policy,
    };
    let serialized = config.to_toml();
    let parsed = RepoConfig::parse(&serialized).expect("parse serialized config");
    assert_eq!(parsed, config);

    let malformed = [
        r##"schema_version = "guildhall-repo/1"
repository_uuid_hint = "01234567-89ab-cdef-0123-456789abcdef"
safe_name = "boundary-repo"
domains = [1]
"##,
        r##"schema_version = "guildhall-repo/1"
repository_uuid_hint = "01234567-89ab-cdef-0123-456789abcdef"
safe_name = "boundary-repo"
domains = ["architecture"]

[local_policy]
retention = 7
"##,
        r##"schema_version = "guildhall-repo/1"
repository_uuid_hint = "01234567-89ab-cdef-0123-456789abcdef"
safe_name = "boundary-repo"
unknown_root = "cannot introduce trust"
domains = ["architecture"]
"##,
        r##"schema_version = "guildhall-repo/1"
repository_uuid_hint = "01234567-89ab-cdef-0123-456789abcdef"
safe_name = "boundary-repo"
"##,
    ];
    for text in malformed {
        let error = RepoConfig::parse(text).expect_err("malformed config must fail closed");
        assert_eq!(error.code, "DIGEST_MISMATCH");
        assert_eq!(error.exit(), 5);
    }
}

#[test]
fn destination_nonce_is_unique_and_matching_retry_reads_stored_receipt() {
    let temp = TempDir::new().expect("temporary Company directory");
    let db = CompanyDb::open(&temp.path().join("company.sqlite")).expect("open Company database");
    let receipt = json!({"schema": "guildhall-receipt/1", "destination": "company", "status": "reserved"});
    let inserted = db
        .connection
        .execute(
            "INSERT OR IGNORE INTO nonces(destination, nonce, payload_digest, client_key, authority_scope, receipt, consumed_at, expires_at) VALUES ('company', ?1, ?2, ?3, 'architecture:root', ?4, ?5, '2030-01-01T00:00:00.000Z')",
            rusqlite::params!["nonce-1", "digest-a", "client-a", canonical_text(&receipt), "2026-01-01T00:00:00.000Z"],
        )
        .expect("reserve nonce");
    assert_eq!(inserted, 1);
    let duplicate = db
        .connection
        .execute(
            "INSERT OR IGNORE INTO nonces(destination, nonce, payload_digest, client_key, authority_scope, receipt, consumed_at, expires_at) VALUES ('company', ?1, ?2, ?3, 'architecture:root', ?4, ?5, '2030-01-01T00:00:00.000Z')",
            rusqlite::params!["nonce-1", "digest-a", "client-a", canonical_text(&json!({"status": "other"})), "2026-01-01T00:00:00.000Z"],
        )
        .expect("duplicate reservation is ignored");
    assert_eq!(duplicate, 0);

    let record = db
        .nonce_record("company", "nonce-1")
        .expect("read reserved nonce")
        .expect("nonce exists");
    assert_eq!(record["payload_digest"], "digest-a");
    assert_eq!(record["client_key"], "client-a");
    assert_eq!(record["receipt"]["status"], "reserved");
    let count: i64 = db
        .connection
        .query_row("SELECT COUNT(*) FROM nonces WHERE destination='company' AND nonce='nonce-1'", [], |row| row.get(0))
        .expect("count nonce rows");
    assert_eq!(count, 1);
}

#[test]
fn manifest_lineage_head_has_one_observation() {
    let temp = TempDir::new().expect("temporary Company directory");
    let db = CompanyDb::open(&temp.path().join("company.sqlite")).expect("open Company database");
    let document = json!({
        "repository_uuid": "01234567-89ab-cdef-0123-456789abcdef",
        "branch": "main",
        "observed_default_branch_revision": "lineage-head-1",
        "event_count": 2,
        "merkle_root": "merkle-1",
        "event_digests": ["digest-1", "digest-2"],
        "observed_at": "2026-09-08T00:00:00.000Z",
        "fresh_until": "2026-09-08T01:00:00.000Z"
    });
    db.insert_manifest_observation(&document, 1).expect("insert first observation");
    let error = db
        .insert_manifest_observation(&document, 2)
        .expect_err("duplicate lineage must be constrained");
    assert_eq!(error.code, "DIGEST_MISMATCH");
    let count: i64 = db
        .connection
        .query_row("SELECT COUNT(*) FROM manifest_observations", [], |row| row.get(0))
        .expect("count manifest observations");
    assert_eq!(count, 1);
}

#[test]
fn codebase_receipt_is_bound_to_repository_and_destination() {
    let temp = TempDir::new().expect("temporary repository root");
    let repository = init_git_repository(&temp.path().join("repository"));
    let uuid = "01234567-89ab-cdef-0123-456789abcdef";
    let canonical = canonical_bytes(&json!({"schema": "guildhall-event/1", "event_id": "evt-boundary"}));
    let receipt = repository
        .admit_event(uuid, &canonical, "fact-event", Value::Null)
        .expect("admit codebase event");
    let destination = format!("codebase:{uuid}");
    assert_eq!(receipt["repository_uuid"], uuid);
    assert_eq!(receipt["destination"], destination.as_str());
    assert_eq!(receipt["status"], "committed");

    let digest = sha256_bytes(&canonical);
    let receipt_path = repository
        .local_dir()
        .join("receipts")
        .join(uuid)
        .join(format!("{digest}.json"));
    let mut stored = parse_strict_value(&fs::read(&receipt_path).expect("read receipt")).expect("parse receipt");
    stored["destination"] = Value::String("codebase:foreign-uuid".to_owned());
    fs::write(&receipt_path, canonical_bytes(&stored)).expect("corrupt receipt destination");
    let refused = repository
        .admit_event(uuid, &canonical, "fact-event", Value::Null)
        .expect_err("foreign receipt must not be returned");
    assert_eq!(refused.code, "DIGEST_MISMATCH");

    let other_uuid = "fedcba98-7654-3210-fedc-ba9876543210";
    let other = repository
        .admit_event(other_uuid, &canonical, "fact-event", Value::Null)
        .expect("repository-keyed lookup admits the same bytes for another identity");
    assert_eq!(other["repository_uuid"], other_uuid);
    assert_eq!(other["destination"], format!("codebase:{other_uuid}"));
}

fn write_journal_state(
    repository: &Repository,
    repository_uuid: &str,
    generation: i64,
    state: &str,
    with_staged: bool,
    with_final: bool,
    with_receipt: bool,
) {
    let local = repository.ensure_local().expect("ensure local store");
    let journal_dir = local.join("journal");
    fs::create_dir_all(&journal_dir).expect("create journal directory");
    let payload = canonical_bytes(&json!({"journal-payload": generation}));
    let digest = sha256_bytes(&payload);
    let relative = sharded_relative(&digest).expect("sharded event path");
    let staged = local.join("staging").join(format!("{digest}.json"));
    let final_path = repository.kin.join("events").join(&relative);
    let receipt_path = local
        .join("receipts")
        .join(repository_uuid)
        .join(format!("{digest}.json"));
    if with_staged {
        fs::create_dir_all(staged.parent().expect("staging parent")).expect("create staging parent");
        fs::write(&staged, &payload).expect("write staged bytes");
    }
    if with_final {
        fs::create_dir_all(final_path.parent().expect("event parent")).expect("create event parent");
        fs::write(&final_path, &payload).expect("write final event");
    }
    if with_receipt {
        fs::create_dir_all(receipt_path.parent().expect("receipt parent")).expect("create receipt parent");
        fs::write(
            &receipt_path,
            canonical_bytes(&json!({
                "schema": "guildhall-receipt/1",
                "destination": format!("codebase:{repository_uuid}"),
                "repository_uuid": repository_uuid,
                "status": "committed",
                "event_digest": digest
            })),
        )
        .expect("write receipt");
    }
    let entry = json!({
        "schema": "guildhall-journal/1",
        "generation": generation,
        "repository_uuid": repository_uuid,
        "digest": digest,
        "kind": "fact-event",
        "relative_path": relative.to_string_lossy(),
        "state": state,
        "updated_at": "2026-09-08T00:00:00.000Z"
    });
    fs::write(
        journal_dir.join(format!("{generation:012}.json")),
        canonical_bytes(&entry),
    )
    .expect("write journal marker");
}

#[test]
fn journal_recovery_replays_every_step_and_is_idempotent() {
    let temp = TempDir::new().expect("temporary repository root");
    let repository = init_git_repository(&temp.path().join("repository"));
    let uuid = "01234567-89ab-cdef-0123-456789abcdef";
    write_journal_state(&repository, uuid, 1, "staged", true, false, false);
    write_journal_state(&repository, uuid, 2, "renamed", false, true, false);
    write_journal_state(&repository, uuid, 3, "indexed", false, true, false);
    write_journal_state(&repository, uuid, 4, "receipted", false, true, true);
    write_journal_state(&repository, uuid, 5, "done", false, true, true);

    let replayed = repository.recover_journal(uuid).expect("recover journal states");
    assert_eq!(replayed.len(), 4);
    let journal_dir = repository.local_dir().join("journal");
    for generation in 1..=5 {
        let bytes = fs::read(journal_dir.join(format!("{generation:012}.json"))).expect("read journal");
        let entry = parse_strict_value(&bytes).expect("parse journal");
        assert_eq!(entry["state"], "done", "generation {generation}");
    }
    let receipts = repository.local_dir().join("receipts").join(uuid);
    assert_eq!(fs::read_dir(&receipts).expect("list receipts").count(), 5);
    let replayed_again = repository.recover_journal(uuid).expect("rerun recovery");
    assert!(replayed_again.is_empty(), "completed markers are not replayed");
}

#[test]
fn journal_recovery_refuses_malformed_marker() {
    let temp = TempDir::new().expect("temporary repository root");
    let repository = init_git_repository(&temp.path().join("repository"));
    let journal = repository.local_dir().join("journal");
    fs::create_dir_all(&journal).expect("create journal directory");
    fs::write(journal.join("000000000001.json"), b"{ not canonical").expect("write malformed journal");
    let error = repository
        .recover_journal("01234567-89ab-cdef-0123-456789abcdef")
        .expect_err("malformed journal must fail closed");
    assert_eq!(error.code, "DIGEST_MISMATCH");
}

#[test]
fn journal_cleanup_failure_is_typed_not_ignored() {
    let temp = TempDir::new().expect("temporary repository root");
    let repository = init_git_repository(&temp.path().join("repository"));
    let uuid = "01234567-89ab-cdef-0123-456789abcdef";
    write_journal_state(&repository, uuid, 1, "renamed", false, true, false);
    let receipt_path = repository
        .local_dir()
        .join("receipts")
        .join(uuid)
        .join(format!("{}.json", {
            let bytes = fs::read(
                repository
                    .local_dir()
                    .join("journal")
                    .join("000000000001.json"),
            )
            .expect("read journal");
            let entry = parse_strict_value(&bytes).expect("parse journal");
            entry["digest"].as_str().expect("digest").to_owned()
        }));
    let receipt_parent = receipt_path.parent().expect("receipt parent");
    fs::create_dir_all(receipt_parent.parent().expect("receipt root")).expect("create receipt root");
    fs::write(receipt_parent, b"not-a-directory").expect("make receipt parent unwritable");
    let error = repository
        .recover_journal(uuid)
        .expect_err("write failure must be typed");
    assert_eq!(error.code, "RUN_INTEGRITY_FAILED");
}
