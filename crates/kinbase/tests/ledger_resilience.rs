//! Readers skip and report; decisions refuse; writers refuse; appends never
//! lose a record to a torn line.

mod support;

use kinbase::StoreKind;
use kinbase::store::{
    append_jsonl, read_events, read_jsonl_where, read_records, read_records_complete,
    write_content_addressed_event,
};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::process::Command;
use support::SpawnAlone;
use tempfile::TempDir;

fn lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .expect("read ledger")
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn an_append_after_a_torn_line_keeps_the_new_record() {
    let temp = TempDir::new().expect("tempdir");
    let ledger = temp.path().join("sessions.jsonl");
    fs::write(&ledger, b"{\"a\":1").expect("torn tail");
    append_jsonl(&ledger, &json!({"b": 2})).expect("append");
    assert_eq!(lines(&ledger), vec!["{\"a\":1", "{\"b\":2}"]);
    assert_eq!(
        read_jsonl_where(&ledger, |_| true).expect("read"),
        vec![json!({"b": 2})]
    );
}

#[test]
fn concurrent_appends_of_one_record_write_it_once() {
    let temp = TempDir::new().expect("tempdir");
    let ledger = temp.path().join("candidates.jsonl");
    const WRITERS: usize = 16;
    const RECORDS: usize = 150;
    let start = std::sync::Arc::new(std::sync::Barrier::new(WRITERS));
    let threads: Vec<_> = (0..WRITERS)
        .map(|_| {
            let ledger = ledger.clone();
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                for record in 0..RECORDS {
                    append_jsonl(&ledger, &json!({"candidate_id": record}))?;
                }
                Ok::<(), kinbase::error::ContractError>(())
            })
        })
        .collect();
    for thread in threads {
        thread.join().expect("thread").expect("append");
    }
    assert_eq!(lines(&ledger).len(), RECORDS, "each record exactly once");
}

fn codebase_ledger(repo: &Path, name: &str, body: &str) {
    fs::create_dir_all(repo.join(".kin")).expect("store root");
    fs::write(repo.join(".kin").join(name), body).expect("ledger");
}

#[test]
fn one_unreadable_line_does_not_hide_the_ledger() {
    let temp = TempDir::new().expect("tempdir");
    codebase_ledger(
        temp.path(),
        "decisions.jsonl",
        "not json\n{\"receipt_id\":\"r1\"}\n",
    );
    let records = read_records(StoreKind::Codebase, temp.path(), "decisions.jsonl").expect("read");
    assert_eq!(records, vec![json!({"receipt_id": "r1"})]);
}

#[test]
fn a_decision_refuses_rather_than_reading_an_unreadable_line_as_absent() {
    let temp = TempDir::new().expect("tempdir");
    codebase_ledger(
        temp.path(),
        "decisions.jsonl",
        "{\"receipt_id\":\"r1\"}\n{\"receipt_id\":\n",
    );
    let error = read_records_complete(StoreKind::Codebase, temp.path(), "decisions.jsonl")
        .expect_err("refused");
    assert_eq!(error.code, "DIGEST_MISMATCH");
    assert!(error.message.contains("line 2"), "{}", error.message);
    assert!(
        read_records_complete(StoreKind::Codebase, temp.path(), "absent.jsonl")
            .expect("a ledger never written holds nothing")
            .is_empty()
    );
}

fn event(fact: &str) -> kinbase::model::FactEvent {
    kinbase::model::FactEvent {
        schema: "kinbase-event/1".to_owned(),
        event_id: format!("event_{fact}"),
        store_kind: "codebase".to_owned(),
        authority_id: "maintainer".to_owned(),
        authority_scope: "codebase:x".to_owned(),
        repository_id: None,
        fact_id: format!("fact_{fact}"),
        logical_key: format!("key_{fact}"),
        atom_kind: "claim".to_owned(),
        scope: "tests".to_owned(),
        statement: "The ledger reader skips what it cannot read.".to_owned(),
        evidence_refs: Vec::new(),
        asserted_at: "2026-09-08T12:00:00.000Z".to_owned(),
        effective_from: "2026-09-08T12:00:00.000Z".to_owned(),
        effective_until: None,
        disposition: "current".to_owned(),
        distortion: kinbase::model::Distortion {
            trigger: "a damaged event file".to_owned(),
            loss_if_absent: 4000,
            rationale: "test".to_owned(),
        },
        parents: Vec::new(),
        supersedes: Vec::new(),
        redundancy_with: Vec::new(),
        complements: Vec::new(),
        company_refs: Vec::new(),
        authority_snapshot_cursor: "0".to_owned(),
        confidence: kinbase::model::Bp(6000),
        standing: kinbase::model::default_standing_pub(),
        provenance: kinbase::model::default_provenance_pub(),
        governs_paths: Vec::new(),
        anchors: Vec::new(),
        unresolved_uncertainty: None,
        signer: String::new(),
        signature: String::new(),
        raw: None,
    }
}

#[test]
fn a_leftover_or_damaged_event_file_does_not_empty_the_store() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    let (path, _) = write_content_addressed_event(root, &event("kept")).expect("event");
    let shard = path.parent().expect("shard");
    // A crash between writing a temporary and renaming it leaves complete
    // bytes that were never committed.
    let uncommitted = kinbase::json::canonical_text(&event("uncommitted").document());
    fs::write(shard.join(".tmp-123-abc"), uncommitted).expect("leftover");
    fs::write(shard.join("damaged.json"), b"not an event").expect("damaged");
    fs::write(shard.join("oversized.json"), vec![b' '; 70 * 1024]).expect("oversized");
    let events = read_events(root).expect("read");
    assert_eq!(
        events
            .iter()
            .map(|event| event.fact_id.as_str())
            .collect::<Vec<_>>(),
        vec!["fact_kept"]
    );
}

#[test]
fn an_observation_update_that_is_not_canonical_leaves_the_row_alone() {
    let temp = TempDir::new().expect("tempdir");
    let store = kinbase::private::PrivateStore::open_personal(temp.path()).expect("store");
    let mut observation = kinbase::model::Observation {
        observation_id: "obs_1".to_owned(),
        source_kind: "repo_code".to_owned(),
        source_identity: "source".to_owned(),
        native_id: "src/lib.rs".to_owned(),
        content_digest: "0".repeat(64),
        disposition: "current".to_owned(),
        observed_at: "2026-09-08T12:00:00.000Z".to_owned(),
        body_ref: format!("sha256:{}", "0".repeat(64)),
        lifecycle: "observed".to_owned(),
        branch: Some("main".to_owned()),
        ..Default::default()
    };
    assert!(store.insert_observation(&observation).expect("insert"));
    // Git accepts a branch name with a C1 control; the canonical rule does not.
    observation.branch = Some("feature\u{85}x".to_owned());
    assert!(store.update_observation(&observation).is_err());
    let stored = store
        .all_observations()
        .expect("observations")
        .into_iter()
        .find(|row| row.observation_id == "obs_1")
        .expect("the row is still readable");
    assert_eq!(stored.branch.as_deref(), Some("main"));
}

#[test]
fn a_torn_sessions_ledger_still_lets_a_session_end() {
    let temp = TempDir::new().expect("tempdir");
    let home = temp.path().join("home");
    let state = temp.path().join("state");
    let repo = temp.path().join("repo");
    for directory in [&home, &state, &repo] {
        fs::create_dir_all(directory).expect("dir");
    }
    let personal = state.join("kinbase").join("codebase-personal");
    fs::create_dir_all(&personal).expect("personal root");
    fs::write(personal.join("sessions.jsonl"), b"{\"a\":1").expect("torn tail");
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_kinbase"))
            .current_dir(&repo)
            .args(args)
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("XDG_STATE_HOME", &state)
            .env_remove("KINBASE_COMPANY_URL")
            .output_alone()
            .expect("run kinbase")
    };
    let started = run(&["session", "start", "--host", "codex", "--json"]);
    assert!(
        started.status.success(),
        "{}",
        String::from_utf8_lossy(&started.stderr)
    );
    let session: Value = serde_json::from_slice(&started.stdout).expect("json");
    let session_id = session["session_id"].as_str().expect("session id");
    let ended = run(&["session", "end", session_id, "--json"]);
    assert!(
        ended.status.success(),
        "{}",
        String::from_utf8_lossy(&ended.stderr)
    );
    assert!(String::from_utf8_lossy(&started.stderr).contains("torn-ledger-tail"));
}

#[test]
fn a_skipped_line_is_reported_without_its_contents() {
    let temp = TempDir::new().expect("tempdir");
    let home = temp.path().join("home");
    let state = temp.path().join("state");
    let repo = temp.path().join("repo");
    for directory in [&home, &state, &repo] {
        fs::create_dir_all(directory).expect("dir");
    }
    let personal = state.join("kinbase").join("codebase-personal");
    fs::create_dir_all(&personal).expect("personal root");
    // The canonical text rule refuses a control character and its message
    // names the field that holds it.
    fs::write(
        personal.join("sessions.jsonl"),
        "{\"guest_Wilhelmina\":\"x\\u0085y\"}\n",
    )
    .expect("ledger");
    let output = Command::new(env!("CARGO_BIN_EXE_kinbase"))
        .current_dir(&repo)
        .args(["session", "end", "session_absent", "--json"])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_STATE_HOME", &state)
        .env_remove("KINBASE_COMPANY_URL")
        .output_alone()
        .expect("run kinbase");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unreadable-ledger-rows"), "{stderr}");
    assert!(!stderr.contains("Wilhelmina"), "{stderr}");
}
