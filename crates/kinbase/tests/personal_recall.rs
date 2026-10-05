//! `kinbase recall` keeps the principal's question Personal: the projection it
//! makes for team knowledge raises no question and logs nothing, and a
//! projection withheld by a blocking Unknown releases no shared statement.

mod support;

use kinbase::crypto::PrivateKey;
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use support::SpawnAlone;
use tempfile::TempDir;

const CANARY: &str = "canary-7f3a: should I tell my manager about the offer from Initech";
const STATEMENT: &str = "Scheduler diagnosis keeps the v1 wire format until the migration lands.";

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

/// A base directory whose whole ancestry the executable rules accept.
fn verified_base() -> PathBuf {
    [
        std::env::var_os("KINBASE_TEST_VERIFIED_DIR").map(PathBuf::from),
        Some(std::env::temp_dir()),
        std::env::var_os("HOME").map(PathBuf::from),
        Some(PathBuf::from(env!("CARGO_MANIFEST_DIR"))),
    ]
    .into_iter()
    .flatten()
    .filter_map(|dir| dir.canonicalize().ok())
    .find(|dir| {
        dir.ancestors().all(|ancestor| {
            fs::symlink_metadata(ancestor).is_ok_and(|metadata| {
                ancestor == Path::new("/")
                    || (!metadata.file_type().is_symlink()
                        && metadata.permissions().mode() & 0o022 == 0)
            })
        })
    })
    .expect("a directory the executable rules accept")
}

struct World {
    _root: TempDir,
    home: PathBuf,
    config_home: PathBuf,
    personal: PathBuf,
    repo: PathBuf,
    shared: Vec<PathBuf>,
}

fn kinbase(world: &World, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kinbase"))
        .current_dir(&world.repo)
        .args(args)
        .env("HOME", &world.home)
        .env("XDG_CONFIG_HOME", &world.config_home)
        .env("XDG_STATE_HOME", world.home.join("state"))
        .env_remove("KINBASE_COMPANY_URL")
        .output_alone()
        .expect("run kinbase")
}

fn fact(repository_uuid: &str, statement: &str) -> kinbase::model::FactEvent {
    kinbase::model::FactEvent {
        schema: "kinbase-event/1".to_owned(),
        event_id: "event_recall_fact".to_owned(),
        store_kind: "codebase".to_owned(),
        authority_id: "root-steward".to_owned(),
        authority_scope: format!("codebase:{repository_uuid}"),
        repository_id: Some(repository_uuid.to_owned()),
        fact_id: "fact_recall_fact".to_owned(),
        logical_key: "logical_recall_fact".to_owned(),
        atom_kind: "constraint".to_owned(),
        scope: "recall corpus".to_owned(),
        statement: statement.to_owned(),
        evidence_refs: Vec::new(),
        asserted_at: "2026-09-08T12:00:00.000Z".to_owned(),
        effective_from: "2026-09-08T12:00:00.000Z".to_owned(),
        effective_until: None,
        disposition: "approved".to_owned(),
        distortion: kinbase::model::Distortion {
            trigger: "scheduler diagnosis wire format".to_owned(),
            loss_if_absent: 8000,
            rationale: "recall proof".to_owned(),
        },
        parents: Vec::new(),
        supersedes: Vec::new(),
        redundancy_with: Vec::new(),
        complements: Vec::new(),
        company_refs: Vec::new(),
        authority_snapshot_cursor: "0".to_owned(),
        confidence: kinbase::model::Bp(9000),
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

/// A certified repository holding one Codebase fact and, when `blocked`, an
/// open architecture Unknown that blocks every dependent decision; a user
/// config whose Personal Kindex is a pinned fake that records what it is asked
/// and the team knowledge it is given.
fn world(blocked: bool) -> World {
    world_with(blocked, true)
}

fn world_with(blocked: bool, team_knowledge: bool) -> World {
    let root = TempDir::new_in(verified_base()).expect("temporary root");
    let home = root.path().join("home");
    let config_home = root.path().join("config-home");
    let kinbase_config = config_home.join("kinbase");
    let cache_root = root.path().join("company-cache");
    let personal = root.path().join("personal");
    let repo = root.path().join("repository");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(&kinbase_config).expect("create config directory");

    let kin = root.path().join("bin").join("kin");
    let body = concat!(
        "#!/bin/sh\n",
        "root=; context=; previous=\n",
        "for arg in \"$@\"; do case \"$previous\" in --data-dir) root=$arg ;; --context-file) context=$arg ;; esac; previous=$arg; done\n",
        "case \"$1\" in\n",
        "ask) printf '%s\\n' \"$@\" > \"$root/asked\"; if [ -n \"$context\" ]; then cat \"$context\" > \"$root/team\"; fi; echo answered ;;\n",
        "esac\n",
    );
    fs::create_dir_all(kin.parent().unwrap()).expect("create bin");
    fs::write(&kin, body).expect("write fake kin");
    fs::set_permissions(&kin, fs::Permissions::from_mode(0o755)).expect("chmod fake kin");

    let root_key = PrivateKey::generate();
    private_write(
        &kinbase_config.join("root-public.key"),
        format!("{}\n", root_key.public().to_hex()).as_bytes(),
    );
    private_write(&kinbase_config.join("facts.token"), b"facts-token\n");
    private_write(
        &kinbase_config.join("config.toml"),
        format!(
            "schema_version = \"1\"\n\n[personal]\ndata_root = {}\nkindex_executable = {}\nkindex_executable_sha256 = \"{}\"\nkindex_team_knowledge = {}\n\n[company]\nurl = \"http://127.0.0.1:1\"\nfacts_token_file = {}\nroot_public_key_file = {}\ncache_root = {}\n",
            quoted(&personal),
            quoted(&kin),
            kinbase::hash::sha256_bytes(body.as_bytes()),
            team_knowledge,
            quoted(&kinbase_config.join("facts.token")),
            quoted(&kinbase_config.join("root-public.key")),
            quoted(&cache_root)
        )
        .as_bytes(),
    );

    let git = Command::new("git")
        .args(["init", "--initial-branch=main", &repo.display().to_string()])
        .output_alone()
        .expect("run git init");
    assert!(
        git.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&git.stderr)
    );

    let repository_uuid = "01234567-89ab-cdef-0123-456789abcdef";
    let certificate = root.path().join("certificate.json");
    let unsigned = json!({
        "schema": "kinbase-repo-certificate/1",
        "repository_uuid": repository_uuid,
        "issued_at": "2026-09-08T12:00:00.000Z",
        "company_id": "company-test"
    });
    let signed = root_key
        .sign_document("repo-certificate", &unsigned)
        .expect("sign certificate");
    private_write(
        &certificate,
        kinbase::json::canonical_text(&signed).as_bytes(),
    );
    let world = World {
        shared: vec![
            repo.clone(),
            cache_root.clone(),
            home.clone(),
            config_home.clone(),
        ],
        _root: root,
        home,
        config_home,
        personal,
        repo,
    };
    let init = kinbase(
        &world,
        &[
            "repo",
            "init",
            "--repo",
            &world.repo.display().to_string(),
            "--certificate",
            &certificate.display().to_string(),
            "--json",
        ],
    );
    assert!(
        init.status.success(),
        "repo init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let snapshot = json!({
        "schema": "kinbase-snapshot/1",
        "company_id": "company-test",
        "cursor": "1000",
        "authority_cursor": "1000",
        "revocation_cursor": "1000",
        "client_nonce": "recall-offline-cache",
        "issued_at": "2026-09-08T12:00:00.000Z",
        "revocation_valid_until": "2030-01-01T00:00:00.000Z",
        "fact_valid_until": "2030-01-01T00:00:00.000Z",
        "registry": [
            {"authority_id": "company-steward", "scope": "company:root",
             "public_key": root_key.public().to_hex(), "status": "active"},
            {"authority_id": "chief-architect", "scope": "architecture:scheduler",
             "public_key": root_key.public().to_hex(), "status": "active", "question_kind": "architecture"}
        ],
        "revocations": [], "facts": [], "unknowns": [], "relaxations": [], "certificates": [],
        "fact_versions": {}
    });
    let signed = root_key
        .sign_document("receipt", &snapshot)
        .expect("sign snapshot");
    let mut cache =
        kinbase::company::cache::Cache::open(&cache_root).expect("open authority cache");
    cache
        .store_snapshot(&signed, &root_key.public(), "2026-09-08T12:00:00.000Z")
        .expect("store authority snapshot");

    let mut documents = Vec::new();
    let mut event = fact(repository_uuid, STATEMENT);
    event.sign(&root_key).expect("sign fact");
    documents.push(event.document());
    if blocked {
        let mut unknown = kinbase::model::UnknownEvent::new(
            "codebase",
            Some(repository_uuid),
            "chief-architect",
            "architecture:scheduler/diagnosis",
            "architecture_scheduler_diagnosis",
            "architecture:scheduler/diagnosis",
            "which compatibility invariant constrains the change",
            "chief-architect",
            "chief-architect",
            "Which compatibility invariant constrains extending the scheduler diagnosis path?",
            9000,
            "2026-09-08T12:00:00.000Z",
            "2026-09-09T12:00:00.000Z",
            "24h",
            "0",
        );
        unknown.sign(&root_key).expect("sign unknown");
        documents.push(unknown.document());
    }
    let mut relative_paths = Vec::new();
    for document in documents {
        let bytes = kinbase::json::canonical_bytes(&document);
        let digest = kinbase::hash::sha256_bytes(&bytes);
        let relative = format!("{}/{}/{}.json", &digest[..2], &digest[2..4], &digest[4..]);
        private_write(&world.repo.join(".kin/events").join(&relative), &bytes);
        relative_paths.push(format!(".kin/events/{relative}"));
    }
    let add = Command::new("git")
        .current_dir(&world.repo)
        .args(["add", ".gitattributes", ".kin/kinbase.toml"])
        .args(&relative_paths)
        .output_alone()
        .expect("git add");
    assert!(
        add.status.success(),
        "git add failed: {}",
        String::from_utf8_lossy(&add.stderr)
    );
    let commit = Command::new("git")
        .current_dir(&world.repo)
        .env("GIT_AUTHOR_NAME", "recall")
        .env("GIT_AUTHOR_EMAIL", "recall@example.invalid")
        .env("GIT_COMMITTER_NAME", "recall")
        .env("GIT_COMMITTER_EMAIL", "recall@example.invalid")
        .args(["commit", "-m", "recall corpus"])
        .output_alone()
        .expect("git commit");
    assert!(
        commit.status.success(),
        "git commit failed: {}",
        String::from_utf8_lossy(&commit.stderr)
    );
    world
}

/// Every file outside the Personal root whose bytes contain `needle`.
fn files_containing(world: &World, needle: &str) -> Vec<PathBuf> {
    fn walk(dir: &Path, needle: &[u8], skip: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.starts_with(skip) {
                continue;
            }
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                continue;
            };
            if metadata.is_dir() {
                walk(&path, needle, skip, out);
            } else if metadata.is_file()
                && fs::read(&path)
                    .is_ok_and(|bytes| bytes.windows(needle.len()).any(|w| w == needle))
            {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    for dir in &world.shared {
        walk(dir, needle.as_bytes(), &world.personal, &mut out);
    }
    out
}

fn recall(world: &World, question: &str) -> Value {
    let output = kinbase(world, &["recall", "--question", question, "--json"]);
    assert!(
        output.status.success(),
        "recall failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("recall receipt is JSON")
}

#[test]
fn a_private_question_with_a_blocking_unknown_is_recorded_nowhere_shared() {
    let world = world(true);
    let receipt = recall(&world, CANARY);
    assert_eq!(receipt["answer"], "answered", "{receipt}");
    assert_eq!(receipt["team"]["projection_state"], "withheld", "{receipt}");
    assert_eq!(receipt["team_facts"], 0, "{receipt}");
    assert_eq!(
        files_containing(&world, "canary-7f3a"),
        Vec::<PathBuf>::new()
    );
    let questions = kinbase(&world, &["questions", "list", "--json"]);
    assert!(!String::from_utf8_lossy(&questions.stdout).contains("canary-7f3a"));
    // The Personal Kindex was asked, and told team guidance is withheld
    // rather than given the blocked statement.
    assert!(
        fs::read_to_string(world.personal.join("asked"))
            .unwrap()
            .contains("canary-7f3a")
    );
    let team = fs::read_to_string(world.personal.join("team")).unwrap();
    assert!(
        team.contains("withheld") && !team.contains(STATEMENT),
        "{team}"
    );

    // The same text as an ordinary projection does raise a question: the
    // check above would have seen it.
    let project = kinbase(
        &world,
        &[
            "project",
            "--repo",
            &world.repo.display().to_string(),
            "--task",
            CANARY,
            "--decision",
            CANARY,
            "--json",
        ],
    );
    assert!(
        project.status.success(),
        "project failed: {}",
        String::from_utf8_lossy(&project.stderr)
    );
    assert!(!files_containing(&world, "canary-7f3a").is_empty());
}

#[test]
fn an_unblocked_projection_releases_annotated_statements() {
    let world = world(false);
    let receipt = recall(&world, "scheduler diagnosis wire format migration");
    assert_eq!(
        receipt["team"]["projection_state"], "projected",
        "{receipt}"
    );
    assert_eq!(receipt["team_facts"], 1, "{receipt}");
    let team = fs::read_to_string(world.personal.join("team")).unwrap();
    let lines: Vec<&str> = team.lines().collect();
    // The snapshot is weeks old and the Company is unreachable: said first.
    assert!(
        lines[0].contains("cached authority snapshot") && lines[0].contains("CACHE_EXPIRED"),
        "{team}"
    );
    assert_eq!(
        receipt["team"]["authority_refresh"], "withheld",
        "{receipt}"
    );
    // The statement keeps its governance.
    assert_eq!(
        lines[1],
        format!(
            "[high distortion compatibility invariant; codebase constraint; standing: present; provenance: unknown] {STATEMENT}"
        )
    );
    assert_eq!(
        files_containing(&world, "scheduler diagnosis wire format migration"),
        Vec::<PathBuf>::new()
    );
}

#[test]
fn a_failed_kindex_hand_off_is_reported_in_text_output() {
    let world = world(false);
    let transcripts = world.repo.join("transcripts");
    fs::create_dir_all(&transcripts).unwrap();
    fs::write(
        transcripts.join("s.jsonl"),
        r#"{"type":"user","timestamp":"2026-10-03T09:00:00.000Z","message":{"role":"user","content":"I bought a red kayak."}}"#,
    )
    .unwrap();
    // The pinned Kindex no longer matches its digest: the hand-off is refused.
    let kin = world.personal.parent().unwrap().join("bin").join("kin");
    fs::write(&kin, "#!/bin/sh\nexit 0\n").unwrap();
    let output = kinbase(
        &world,
        &[
            "ingest",
            "claude_jsonl",
            &transcripts.display().to_string(),
            "--repo",
            &world.repo.display().to_string(),
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("status: ingested"), "{stdout}\n{stderr}");
    assert!(
        stderr.contains("warning: Personal Kindex hand-off failed"),
        "{stdout}\n{stderr}"
    );
}

#[test]
fn without_team_knowledge_recall_projects_nothing() {
    let world = world_with(false, false);
    let receipt = recall(&world, "scheduler diagnosis wire format migration");
    assert_eq!(
        receipt["team"]["projection_state"], "not_requested",
        "{receipt}"
    );
    assert_eq!(receipt["team_facts"], 0);
    assert_eq!(receipt["processors"], serde_json::json!([]));
    assert!(!world.personal.join("team").exists());
}

#[test]
fn a_removed_transcript_source_is_retracted_from_kindex() {
    let world = world(false);
    let transcripts = world.repo.join("transcripts");
    fs::create_dir_all(&transcripts).unwrap();
    fs::write(
        transcripts.join("s.jsonl"),
        r#"{"type":"user","timestamp":"2026-10-03T09:00:00.000Z","message":{"role":"user","content":"I bought a red kayak."}}"#,
    )
    .unwrap();
    let ingest = || -> Value {
        let output = kinbase(
            &world,
            &[
                "ingest",
                "claude_jsonl",
                &transcripts.display().to_string(),
                "--repo",
                &world.repo.display().to_string(),
                "--json",
            ],
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("ingest receipt is JSON")
    };
    let first = ingest();
    assert_eq!(first["personal_kindex"]["conversations"], 1, "{first}");
    fs::remove_dir_all(&transcripts).unwrap();
    let second = ingest();
    assert_eq!(
        second["personal_kindex"]["retracted_removed"], 1,
        "{second}"
    );
}
