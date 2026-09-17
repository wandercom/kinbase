//! Adapters read what they are given, say what they could not read, and a
//! source keeps one identity however its path is typed.

use kinbase::crypto::PrivateKey;
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn private_write(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent");
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .expect("open private file");
    file.write_all(bytes).expect("write private file");
}

fn quoted(path: &Path) -> String {
    format!("\"{}\"", path.display())
}

/// One machine: a user config, a Company root, a Personal ledger, and any
/// number of certified repositories sharing them.
struct Machine {
    root: TempDir,
    home: PathBuf,
    config_home: PathBuf,
    state_home: PathBuf,
    personal: PathBuf,
    root_key: PrivateKey,
}

impl Machine {
    fn new() -> Self {
        let root = TempDir::new().expect("temporary root");
        let home = root.path().join("home");
        let config_home = root.path().join("config-home");
        let state_home = root.path().join("state-home");
        let personal = root.path().join("personal");
        let config = config_home.join("kinbase");
        for directory in [&home, &config, &personal, &state_home] {
            fs::create_dir_all(directory).expect("create directory");
        }
        let root_key = PrivateKey::generate();
        private_write(
            &config.join("root-public.key"),
            format!("{}\n", root_key.public().to_hex()).as_bytes(),
        );
        private_write(&config.join("facts.token"), b"facts-token\n");
        private_write(
            &config.join("config.toml"),
            format!(
                "schema_version = \"1\"\n\n[personal]\ndata_root = {}\n\n[company]\nurl = \"http://127.0.0.1:1\"\nfacts_token_file = {}\nroot_public_key_file = {}\ncache_root = {}\nmaintainer_key_file = {}\n",
                quoted(&personal),
                quoted(&config.join("facts.token")),
                quoted(&config.join("root-public.key")),
                quoted(&root.path().join("company-cache")),
                quoted(&config.join("maintainer.key")),
            )
            .as_bytes(),
        );
        let snapshot = json!({
            "schema": "kinbase-snapshot/1",
            "company_id": "company-test",
            "cursor": "1000",
            "authority_cursor": "1000",
            "revocation_cursor": "1000",
            "client_nonce": "ingest-adapters-offline-cache",
            "issued_at": "2026-09-08T12:00:00.000Z",
            "revocation_valid_until": "2030-01-01T00:00:00.000Z",
            "fact_valid_until": "2030-01-01T00:00:00.000Z",
            "registry": [{
                "authority_id": "company-steward",
                "scope": "company:root",
                "public_key": root_key.public().to_hex(),
                "status": "active"
            }],
            "revocations": [], "facts": [], "unknowns": [], "relaxations": [],
            "certificates": [], "fact_versions": {}
        });
        kinbase::company::cache::Cache::open(&root.path().join("company-cache"))
            .expect("open authority cache")
            .store_snapshot(
                &root_key
                    .sign_document("receipt", &snapshot)
                    .expect("sign snapshot"),
                &root_key.public(),
                "2026-09-08T12:00:00.000Z",
            )
            .expect("store fresh authority snapshot");
        Machine {
            root,
            home,
            config_home,
            state_home,
            personal,
            root_key,
        }
    }

    fn repository(&self, name: &str, uuid: &str) -> PathBuf {
        let repo = self.root.path().join(name);
        let git = Command::new("git")
            .args(["init", "--initial-branch=main"])
            .arg(&repo)
            .output()
            .expect("git init");
        assert!(git.status.success());
        let certificate = self.root.path().join(format!("{name}-certificate.json"));
        let unsigned = json!({
            "schema": "kinbase-repo-certificate/1",
            "repository_uuid": uuid,
            "issued_at": "2026-09-07T12:00:00.000Z",
            "company_id": "company-test"
        });
        private_write(
            &certificate,
            kinbase::json::canonical_text(
                &self
                    .root_key
                    .sign_document("repo-certificate", &unsigned)
                    .expect("sign certificate"),
            )
            .as_bytes(),
        );
        let init = self.kinbase(
            &repo,
            &[
                "repo",
                "init",
                "--repo",
                &repo.display().to_string(),
                "--certificate",
                &certificate.display().to_string(),
                "--json",
            ],
        );
        assert!(
            init.status.success(),
            "repo init: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        repo
    }

    fn kinbase(&self, cwd: &Path, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_kinbase"))
            .current_dir(cwd)
            .args(args)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.config_home)
            .env("XDG_STATE_HOME", &self.state_home)
            .env_remove("KINBASE_COMPANY_URL")
            .output()
            .expect("run kinbase")
    }

    fn ingest(&self, repo: &Path, kind: &str, source: &str) -> Value {
        let output = self.kinbase(
            repo,
            &[
                "ingest",
                kind,
                source,
                "--repo",
                &repo.display().to_string(),
                "--json",
            ],
        );
        assert!(
            output.status.success(),
            "ingest {kind} {source}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("ingest receipt is JSON")
    }

    fn ledger(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.personal.join("kinbase-personal.sqlite3"))
            .expect("open ledger")
    }
}

fn tickets(repo: &Path, lines: &[Value]) {
    let exports = repo.join("exports");
    fs::create_dir_all(&exports).expect("exports");
    let body: String = lines.iter().map(|line| format!("{line}\n")).collect();
    fs::write(exports.join("tickets.jsonl"), body).expect("tickets");
}

fn lifecycles(machine: &Machine, identity: &str) -> Vec<(String, String)> {
    let ledger = machine.ledger();
    let mut statement = ledger
        .prepare(
            "SELECT native_id, lifecycle FROM observations WHERE source_identity=?1 ORDER BY native_id, lifecycle",
        )
        .expect("prepare");
    statement
        .query_map([identity], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("query")
        .map(|row| row.expect("row"))
        .collect()
}

const REPO_A: &str = "01234567-89ab-cdef-0123-456789abcdef";
const REPO_B: &str = "fedcba98-7654-3210-fedc-ba9876543210";

fn ticket(id: &str) -> Value {
    json!({"id": id, "title": format!("Ticket {id}"), "body": "Body text.", "state": "completed"})
}

#[test]
fn a_source_keeps_one_identity_however_its_path_is_typed() {
    let machine = Machine::new();
    let repo = machine.repository("repo-a", REPO_A);
    tickets(&repo, &[ticket("ENG-1"), ticket("ENG-2")]);
    let first = machine.ingest(&repo, "issue_tracker", "exports");
    assert_eq!(first["observation_count"], 2);
    for spelling in [
        "./exports".to_owned(),
        "exports/".to_owned(),
        repo.join("exports").display().to_string(),
    ] {
        let again = machine.ingest(&repo, "issue_tracker", &spelling);
        assert_eq!(
            again["source_identity"], first["source_identity"],
            "{spelling}"
        );
        assert_eq!(again["observation_count"], 0, "{spelling}");
        assert_eq!(again["idempotent_count"], 2, "{spelling}");
    }
}

#[test]
fn rows_under_the_typed_spelling_move_to_the_source_identity() {
    let machine = Machine::new();
    let repo = machine.repository("repo-a", REPO_A);
    tickets(&repo, &[ticket("ENG-1"), ticket("ENG-2")]);
    let first = machine.ingest(&repo, "issue_tracker", "./exports");
    let identity = first["source_identity"]
        .as_str()
        .expect("identity")
        .to_owned();
    // What an earlier kinbase recorded: the typed spelling, hashed.
    let legacy = {
        use sha2::{Digest, Sha256};
        format!("source:issue_tracker:{:x}", Sha256::digest(b"./exports"))
    };
    machine
        .ledger()
        .execute(
            "UPDATE observations SET source_identity=?1 WHERE source_identity=?2",
            [&legacy, &identity],
        )
        .expect("rewind to the legacy identity");
    let again = machine.ingest(&repo, "issue_tracker", "./exports");
    assert_eq!(again["source_identity_adopted"]["adopted"], 2, "{again}");
    assert_eq!(again["observation_count"], 0, "no second copy: {again}");
    assert_eq!(again["idempotent_count"], 2);
    assert!(lifecycles(&machine, &legacy).is_empty());
}

#[test]
fn one_repository_never_retires_another_repositorys_records() {
    let machine = Machine::new();
    let a = machine.repository("repo-a", REPO_A);
    let b = machine.repository("repo-b", REPO_B);
    tickets(&a, &[ticket("ENG-1"), ticket("ENG-2")]);
    tickets(&b, &[ticket("ENG-1"), ticket("ENG-2")]);
    let in_b = machine.ingest(&b, "issue_tracker", "exports");
    machine.ingest(&a, "issue_tracker", "exports");
    tickets(&a, &[ticket("ENG-1")]);
    let a_again = machine.ingest(&a, "issue_tracker", "exports");
    assert_eq!(
        a_again["changed_dispositions"]
            .as_array()
            .expect("changes")
            .len(),
        1
    );
    let b_identity = in_b["source_identity"].as_str().expect("identity");
    assert!(
        lifecycles(&machine, b_identity)
            .iter()
            .all(|(_, lifecycle)| lifecycle == "observed"),
        "{:?}",
        lifecycles(&machine, b_identity)
    );
}

#[test]
fn a_record_that_left_its_export_is_retracted_not_absent() {
    let machine = Machine::new();
    let repo = machine.repository("repo-a", REPO_A);
    tickets(&repo, &[ticket("ENG-1"), ticket("ENG-2")]);
    let first = machine.ingest(&repo, "issue_tracker", "exports");
    tickets(&repo, &[ticket("ENG-1")]);
    machine.ingest(&repo, "issue_tracker", "exports");
    let rows = lifecycles(&machine, first["source_identity"].as_str().unwrap());
    assert!(
        rows.contains(&("issue_tracker:ENG-2".to_owned(), "retracted".to_owned())),
        "{rows:?}"
    );
}

#[test]
fn a_wrong_format_export_is_refused_and_retires_nothing() {
    let machine = Machine::new();
    let repo = machine.repository("repo-a", REPO_A);
    tickets(&repo, &[ticket("ENG-1")]);
    let first = machine.ingest(&repo, "issue_tracker", "exports");
    // A pretty-printed array: every line fails to parse.
    fs::write(
        repo.join("exports").join("tickets.jsonl"),
        serde_json::to_string_pretty(&json!([ticket("ENG-1")])).unwrap(),
    )
    .unwrap();
    let refused = machine.kinbase(
        &repo,
        &[
            "ingest",
            "issue_tracker",
            "exports",
            "--repo",
            &repo.display().to_string(),
            "--json",
        ],
    );
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stdout).contains("none is a record"));
    let rows = lifecycles(&machine, first["source_identity"].as_str().unwrap());
    assert_eq!(
        rows,
        vec![("issue_tracker:ENG-1".to_owned(), "observed".to_owned())]
    );
}

#[test]
fn skipped_lines_are_counted_and_a_byte_order_mark_is_not_a_line() {
    let machine = Machine::new();
    let repo = machine.repository("repo-a", REPO_A);
    let exports = repo.join("exports");
    fs::create_dir_all(&exports).unwrap();
    fs::write(
        exports.join("tickets.jsonl"),
        format!(
            "\u{feff}{}\nnot json\n{}\n{}\n",
            ticket("ENG-1"),
            json!({"title": "no id"}),
            ticket("ENG-2")
        ),
    )
    .unwrap();
    let receipt = machine.ingest(&repo, "issue_tracker", "exports");
    assert_eq!(receipt["observation_count"], 2, "{receipt}");
    assert_eq!(
        receipt["skipped_source_records"],
        json!({"issue_tracker: line has no string id": 1, "issue_tracker: line is not JSON": 1})
    );
}

#[test]
fn a_record_outside_the_canonical_model_is_set_aside_not_fatal() {
    let machine = Machine::new();
    let repo = machine.repository("repo-a", REPO_A);
    tickets(
        &repo,
        &[ticket("ENG-1"), ticket("ENG-\u{85}2"), ticket("ENG-3")],
    );
    let receipt = machine.ingest(&repo, "issue_tracker", "exports");
    assert_eq!(receipt["observation_count"], 2, "{receipt}");
    assert_eq!(receipt["noncanonical_count"], 1);
}

#[test]
fn a_bidi_mark_in_a_thread_is_folded_not_fatal() {
    let machine = Machine::new();
    let repo = machine.repository("repo-a", REPO_A);
    let threads = repo.join("threads");
    fs::create_dir_all(&threads).unwrap();
    let thread = json!({
        "id": "T-1",
        "channel": "general",
        "messages": [{"author": "a", "author_kind": "human", "text": "مرحبا\u{61c} the deploy is frozen"}]
    });
    fs::write(threads.join("slack.jsonl"), format!("{thread}\n")).unwrap();
    let receipt = machine.ingest(&repo, "chat_thread", "threads");
    assert_eq!(receipt["observation_count"], 1, "{receipt}");
}

#[test]
fn two_result_files_with_one_name_are_two_runs() {
    let machine = Machine::new();
    let repo = machine.repository("repo-a", REPO_A);
    let runs = repo.join("runs");
    let write = |directory: &str, exit: i64| {
        fs::create_dir_all(runs.join(directory)).unwrap();
        fs::write(
            runs.join(directory).join("result.json"),
            json!({"schema": "kinbase-command-result/1", "command": ["cargo", "test", directory], "exit_code": exit, "stdout": "done"}).to_string(),
        )
        .unwrap();
    };
    write("run1", 0);
    let first = machine.ingest(&repo, "repo_tests", "runs");
    assert_eq!(first["observation_count"], 1, "{first}");
    // A second run with the same file name arrives later.
    write("run0", 1);
    let second = machine.ingest(&repo, "repo_tests", "runs");
    assert_eq!(second["observation_count"], 1, "{second}");
    machine.ingest(&repo, "repo_tests", "runs");
    let rows = lifecycles(&machine, first["source_identity"].as_str().unwrap());
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(
        rows.iter().all(|(_, lifecycle)| lifecycle == "observed"),
        "{rows:?}"
    );
}

#[test]
fn a_typed_claude_prompt_is_read_and_a_torn_line_is_skipped() {
    let machine = Machine::new();
    let repo = machine.repository("repo-a", REPO_A);
    let transcripts = repo.join("transcripts");
    fs::create_dir_all(&transcripts).unwrap();
    let prompt = json!({"type": "user", "uuid": "u1", "timestamp": "2026-09-08T12:00:00.000Z",
        "message": {"role": "user", "content": "Keep the scheduler retries bounded."}});
    fs::write(
        transcripts.join("session.jsonl"),
        format!("{prompt}\n{{\"type\":\"assistant\",\"mess"),
    )
    .unwrap();
    // One oversized transcript does not stop the others.
    fs::write(transcripts.join("huge.jsonl"), vec![b' '; 1024 * 1024 + 1]).unwrap();
    let receipt = machine.ingest(&repo, "claude_jsonl", "transcripts");
    assert_eq!(receipt["observation_count"], 1, "{receipt}");
    assert_eq!(
        receipt["skipped_source_records"]["claude_jsonl: line is not JSON"],
        1
    );
    let role: String = machine
        .ledger()
        .query_row(
            "SELECT json_extract(record, '$.attributes.role') FROM observations WHERE source_kind='claude_jsonl'",
            [],
            |row| row.get(0),
        )
        .expect("role");
    assert_eq!(role, "user");
}

#[test]
fn only_standing_shareable_kindex_nodes_reach_the_codebase_ledger() {
    let machine = Machine::new();
    let repo = machine.repository("repo-a", REPO_A);
    let store = repo.join("kindex-export");
    fs::create_dir_all(&store).unwrap();
    let db = rusqlite::Connection::open(store.join("kindex.db")).unwrap();
    db.execute_batch(
        "CREATE TABLE nodes (id TEXT PRIMARY KEY, type TEXT, title TEXT, content TEXT, extra TEXT,
             created_at TEXT, prov_source TEXT, status TEXT, audience TEXT);
         INSERT INTO nodes VALUES ('n1', 'decision', 'Shared', 'Team decision.', '{}', '2026-09-01T00:00:00.000Z', '', 'active', 'team');
         INSERT INTO nodes VALUES ('n2', 'decision', 'Mine', 'Private note.', '{}', '2026-09-01T00:00:00.000Z', '', 'active', 'private');
         INSERT INTO nodes VALUES ('n3', 'decision', 'Unreviewed', 'Candidate.', '{}', '2026-09-01T00:00:00.000Z', '', 'candidate', 'team');",
    )
    .unwrap();
    drop(db);
    let receipt = machine.ingest(&repo, "kindex", "kindex-export");
    assert_eq!(receipt["observation_count"], 1, "{receipt}");
    assert_eq!(
        receipt["skipped_source_records"],
        json!({"kindex: node is not active": 1, "kindex: audience is not team or public": 1})
    );
}
