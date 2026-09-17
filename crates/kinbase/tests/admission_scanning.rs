//! Every shared-store write is scanned, whichever path admits it.
//!
//! Bulk admission (`corpus admit`) signed ingested ticket text into the
//! repository's `.kin` after de-identification alone, which removes opaque
//! codes and nothing else; the session path scanned, but against an empty
//! registry, and read a scanner error as clean.

use kinbase::crypto::PrivateKey;
use kinbase::scanner::{Registry, scan, scanner_with};
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

// Synthetic values only: a documented example cloud key, a reserved-TLD
// address, and a made-up registered name.
const REGISTERED_NAME: &str = "Wilhelmina Fairweather-Quist";
const EXAMPLE_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
const ADDRESS: &str = "ops.lead@corp.test";
const PASSWORD: &str = "hunter2hunter2";

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

struct World {
    _root: TempDir,
    home: PathBuf,
    config_home: PathBuf,
    state_home: PathBuf,
    repo: PathBuf,
    tickets: PathBuf,
}

impl World {
    fn kinbase(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_kinbase"))
            .current_dir(&self.repo)
            .args(args)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.config_home)
            .env("XDG_STATE_HOME", &self.state_home)
            .env_remove("KINBASE_COMPANY_URL")
            .output()
            .expect("run kinbase")
    }
}

fn certified_world() -> World {
    let root = TempDir::new().expect("temporary root");
    let home = root.path().join("home");
    let config_home = root.path().join("config-home");
    let state_home = root.path().join("state-home");
    let config = config_home.join("kinbase");
    let personal = root.path().join("personal");
    let repo = root.path().join("repository");
    // Ingest reads only sources inside the repository.
    let tickets = repo.join("exports");
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
        &config.join("identifiers.txt"),
        format!("{REGISTERED_NAME}\n").as_bytes(),
    );
    private_write(
        &config.join("config.toml"),
        format!(
            "schema_version = \"1\"\n\n[personal]\ndata_root = {}\n\n[company]\nurl = \"http://127.0.0.1:1\"\nfacts_token_file = {}\nroot_public_key_file = {}\ncache_root = {}\nmaintainer_key_file = {}\n\n[scanner]\nforbidden_identifier_file = {}\n",
            quoted(&personal),
            quoted(&config.join("facts.token")),
            quoted(&config.join("root-public.key")),
            quoted(&root.path().join("company-cache")),
            quoted(&config.join("maintainer.key")),
            quoted(&config.join("identifiers.txt")),
        )
        .as_bytes(),
    );
    let git = Command::new("git")
        .args(["init", "--initial-branch=main"])
        .arg(&repo)
        .output()
        .expect("git init");
    assert!(git.status.success());
    let unsigned = json!({
        "schema": "kinbase-repo-certificate/1",
        "repository_uuid": "01234567-89ab-cdef-0123-456789abcdef",
        "issued_at": "2026-09-07T12:00:00.000Z",
        "company_id": "company-test"
    });
    let certificate = root.path().join("certificate.json");
    private_write(
        &certificate,
        kinbase::json::canonical_text(
            &root_key
                .sign_document("repo-certificate", &unsigned)
                .expect("sign certificate"),
        )
        .as_bytes(),
    );
    // Ingest is reducer-adjacent and needs a fresh authority snapshot; seed
    // the offline cache the way the certificate tests do.
    let snapshot = json!({
        "schema": "kinbase-snapshot/1",
        "company_id": "company-test",
        "cursor": "1000",
        "authority_cursor": "1000",
        "revocation_cursor": "1000",
        "client_nonce": "admission-scanning-offline-cache",
        "issued_at": "2026-09-08T12:00:00.000Z",
        "revocation_valid_until": "2030-01-01T00:00:00.000Z",
        "fact_valid_until": "2030-01-01T00:00:00.000Z",
        "registry": [{
            "authority_id": "company-steward",
            "scope": "company:root",
            "public_key": root_key.public().to_hex(),
            "status": "active"
        }],
        "revocations": [],
        "facts": [],
        "unknowns": [],
        "relaxations": [],
        "certificates": [],
        "fact_versions": {}
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
    let world = World {
        home,
        config_home,
        state_home,
        repo,
        tickets,
        _root: root,
    };
    fs::create_dir_all(&world.tickets).expect("create export directory");
    let repo_arg = world.repo.display().to_string();
    let init = world.kinbase(&[
        "repo",
        "init",
        "--repo",
        &repo_arg,
        "--certificate",
        &certificate.display().to_string(),
        "--json",
    ]);
    assert!(
        init.status.success(),
        "repo init: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    world
}

fn event_bytes(repo: &Path) -> String {
    fn walk(path: &Path, into: &mut String) {
        for entry in fs::read_dir(path).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, into);
            } else if let Ok(text) = fs::read_to_string(&path) {
                into.push_str(&text);
            }
        }
    }
    let mut all = String::new();
    walk(&repo.join(".kin").join("events"), &mut all);
    all
}

#[test]
fn bulk_admission_withholds_what_the_scanner_blocks() {
    let world = certified_world();
    let tickets = [
        json!({"id": "ENG-1", "title": "Scheduler retries", "body": "The scheduler retries at most three times before paging.", "state": "completed", "creator_kind": "human"}),
        json!({"id": "ENG-2", "title": "Lock reset", "body": format!("Reported by {ADDRESS}; password: {PASSWORD}; key {EXAMPLE_KEY}"), "state": "completed", "creator_kind": "human"}),
        json!({"id": "ENG-3", "title": "Guest follow-up", "body": format!("{REGISTERED_NAME} asked about the door code window."), "state": "completed", "creator_kind": "human"}),
    ];
    let lines: String = tickets.iter().map(|ticket| format!("{ticket}\n")).collect();
    fs::write(world.tickets.join("eng.jsonl"), lines).expect("write tickets");
    let repo_arg = world.repo.display().to_string();
    let ingest = world.kinbase(&[
        "ingest",
        "issue_tracker",
        &world.tickets.display().to_string(),
        "--repo",
        &repo_arg,
        "--json",
    ]);
    assert!(
        ingest.status.success(),
        "ingest: {}",
        String::from_utf8_lossy(&ingest.stderr)
    );
    // A document is scanned whole before the classifier sees it; one holding
    // a registered name is withheld whole.
    let documents = world.repo.join("docs-export");
    fs::create_dir_all(&documents).expect("create document export");
    fs::write(
        documents.join("notes.jsonl"),
        format!(
            "{}\n",
            json!({"id": "DOC-1", "title": "Guest notes", "body": format!("{REGISTERED_NAME} prefers the late checkout window.")})
        ),
    )
    .expect("write documents");
    let ingest = world.kinbase(&[
        "ingest",
        "document",
        &documents.display().to_string(),
        "--repo",
        &repo_arg,
        "--json",
    ]);
    assert!(
        ingest.status.success(),
        "document ingest: {}",
        String::from_utf8_lossy(&ingest.stderr)
    );
    let admit = world.kinbase(&[
        "corpus", "admit", "--store", "codebase", "--repo", &repo_arg, "--json",
    ]);
    assert!(
        admit.status.success(),
        "admit: {}",
        String::from_utf8_lossy(&admit.stderr)
    );
    let report: Value = serde_json::from_slice(&admit.stdout).expect("admit report is JSON");
    assert_eq!(report["admitted"], 1, "{report}");
    // Two tickets at admission, and the document before it was classified.
    assert_eq!(report["withheld_for_privacy"], 3, "{report}");
    let written = event_bytes(&world.repo);
    assert!(
        written.contains("The scheduler retries"),
        "the clean ticket is admitted"
    );
    for value in [
        REGISTERED_NAME,
        EXAMPLE_KEY,
        ADDRESS,
        PASSWORD,
        "ENG-2",
        "ENG-3",
    ] {
        assert!(!written.contains(value), "{value} reached .kin/events");
    }
}

#[test]
fn a_registered_name_blocks_every_shared_destination() {
    let registry = Registry::from_values(Vec::new(), vec![REGISTERED_NAME.to_owned()]);
    let atom = kinbase::classify::atomize(
        "issue_tracker",
        "ENG-3",
        &format!("{REGISTERED_NAME} asked about the door code window."),
        "ticket",
        8_000,
        "obs_1",
        "sha256:0",
        Some("01234567-89ab-cdef-0123-456789abcdef"),
        &registry,
    );
    assert!(atom.hard_blocked);
    assert!(
        atom.eligible_destinations.is_empty(),
        "{:?}",
        atom.eligible_destinations
    );
    let unregistered = kinbase::classify::atomize(
        "issue_tracker",
        "ENG-3",
        &format!("{REGISTERED_NAME} asked about the door code window."),
        "ticket",
        8_000,
        "obs_1",
        "sha256:0",
        Some("01234567-89ab-cdef-0123-456789abcdef"),
        &Registry::default(),
    );
    assert!(
        !unregistered.hard_blocked,
        "the name is only known through the registry"
    );
}

#[test]
fn case_folding_that_changes_byte_length_does_not_break_the_scan() {
    // Lowercasing "İ" adds a byte; the bearer detector sliced the original
    // text at an offset found in the lowered copy and panicked, and the
    // resulting error was read as "no taints".
    let text = format!("İ bearer é and key {EXAMPLE_KEY}");
    let result = scan(&text, &Registry::default()).expect("the scan completes");
    assert!(result.hard_block);
    assert!(scanner_with(&text, &Registry::default()).hard_block);
}
