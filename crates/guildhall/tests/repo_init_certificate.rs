use guildhall::crypto::PrivateKey;
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::time::SystemTime;
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

fn mode(path: &Path) -> u32 {
    fs::metadata(path).expect("stat path").permissions().mode() & 0o777
}

fn modified(path: &Path) -> SystemTime {
    fs::metadata(path)
        .expect("stat path")
        .modified()
        .expect("modification time")
}

fn quoted(path: &Path) -> String {
    format!("\"{}\"", path.display())
}

fn run_init(
    home: &Path,
    config_home: &Path,
    repo: &Path,
    certificate: &Path,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_guildhall"))
        .current_dir(repo)
        .args([
            "repo",
            "init",
            "--repo",
            &repo.display().to_string(),
            "--certificate",
            &certificate.display().to_string(),
            "--json",
        ])
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", config_home)
        .env_remove("GUILDHALL_COMPANY_URL")
        .output()
        .expect("run guildhall repo init")
}

fn run_status(home: &Path, config_home: &Path, repo: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_guildhall"))
        .current_dir(repo)
        .args(["status", "--repo", &repo.display().to_string(), "--json"])
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", config_home)
        .env_remove("GUILDHALL_COMPANY_URL")
        .output()
        .expect("run guildhall status")
}

fn signed_certificate(root: &PrivateKey, repository_uuid: &str, issued_at: &str) -> Vec<u8> {
    let unsigned = json!({
        "schema": "guildhall-repo-certificate/1",
        "repository_uuid": repository_uuid,
        "issued_at": issued_at,
        "company_id": "company-test"
    });
    let signed = root
        .sign_document("repo-certificate", &unsigned)
        .expect("sign certificate");
    guildhall::json::canonical_text(&signed).into_bytes()
}

fn expected_worktree_paths() -> Vec<String> {
    vec![
        ".gitattributes".to_owned(),
        ".kin/config".to_owned(),
        ".kin/events/".to_owned(),
        ".kin/local/".to_owned(),
        ".kin/manifests/".to_owned(),
    ]
}

fn visible_worktree_paths(repo: &Path) -> Vec<String> {
    fn walk(root: &Path, current: &Path, output: &mut Vec<String>) {
        for entry in fs::read_dir(current).expect("read worktree") {
            let entry = entry.expect("worktree entry");
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == ".git" {
                continue;
            }
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().display().to_string();
            if path.is_dir() {
                output.push(format!("{relative}/"));
                walk(root, &path, output);
            } else {
                output.push(relative);
            }
        }
    }
    let mut output = Vec::new();
    walk(repo, repo, &mut output);
    output.sort();
    output
}

#[test]
fn repo_init_caches_certificate_outside_worktree() {
    let root = TempDir::new().expect("temporary root");
    let home = root.path().join("home");
    let config_home = root.path().join("config-home");
    let guildhall_config = config_home.join("guildhall");
    let cache_root = root.path().join("company-cache");
    let personal_root = root.path().join("personal");
    let repo = root.path().join("repository");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(&guildhall_config).expect("create config directory");
    fs::create_dir_all(&personal_root).expect("create personal root");

    let root_key = PrivateKey::generate();
    let root_public_key_file = guildhall_config.join("root-public.key");
    let facts_token_file = guildhall_config.join("facts.token");
    private_write(
        &root_public_key_file,
        format!("{}\n", root_key.public().to_hex()).as_bytes(),
    );
    private_write(&facts_token_file, b"facts-token\n");
    let user_config = guildhall_config.join("config.toml");
    private_write(
        &user_config,
        format!(
            "schema_version = \"1\"\n\n[personal]\ndata_root = {}\n\n[company]\nurl = \"http://127.0.0.1:1\"\nfacts_token_file = {}\nroot_public_key_file = {}\ncache_root = {}\n",
            quoted(&personal_root),
            quoted(&facts_token_file),
            quoted(&root_public_key_file),
            quoted(&cache_root)
        )
        .as_bytes(),
    );

    let git = Command::new("git")
        .arg("init")
        .arg("--initial-branch=main")
        .arg(&repo)
        .output()
        .expect("run git init");
    assert!(
        git.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&git.stderr)
    );

    let repository_uuid = "01234567-89ab-cdef-0123-456789abcdef";
    let certificate_file = root.path().join("certificate.json");
    let certificate_bytes =
        signed_certificate(&root_key, repository_uuid, "2026-09-07T12:00:00.000Z");
    private_write(&certificate_file, &certificate_bytes);

    let first = run_init(&home, &config_home, &repo, &certificate_file);
    assert!(
        first.status.success(),
        "first repo init failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let receipt: Value = serde_json::from_slice(&first.stdout).expect("first receipt is JSON");
    assert_eq!(receipt["status"], "repo-initialized");
    assert_eq!(receipt["repository_uuid"], repository_uuid);
    assert_eq!(
        receipt["certificate_cached_path"],
        "repositories/01234567-89ab-cdef-0123-456789abcdef/certificate.json"
    );
    assert_eq!(
        receipt["worktree_paths_written"]
            .as_array()
            .expect("worktree path list")
            .iter()
            .map(|value| value.as_str().expect("worktree path").to_owned())
            .collect::<Vec<_>>(),
        expected_worktree_paths()
    );
    assert_eq!(
        receipt["gitattributes_lines_added"],
        json!([
            ".kin/events/** -text -diff -merge",
            ".kin/manifests/** -text -diff -merge"
        ])
    );

    let cached_certificate = cache_root
        .join("repositories")
        .join(repository_uuid)
        .join("certificate.json");
    assert_eq!(
        fs::read(&cached_certificate).expect("read cached certificate"),
        certificate_bytes
    );
    assert_eq!(mode(&cache_root), 0o700);
    assert_eq!(mode(&cache_root.join("repositories")), 0o700);
    assert_eq!(mode(cached_certificate.parent().unwrap()), 0o700);
    assert_eq!(mode(&cached_certificate), 0o600);
    assert_eq!(
        visible_worktree_paths(&repo),
        vec![
            ".gitattributes".to_owned(),
            ".kin/".to_owned(),
            ".kin/config".to_owned(),
            ".kin/events/".to_owned(),
            ".kin/local/".to_owned(),
            ".kin/manifests/".to_owned()
        ]
    );
    assert!(!repo.join(".kin/certificate.json").exists());
    let exclude = fs::read_to_string(repo.join(".git/info/exclude")).expect("read git exclude");
    assert!(exclude.lines().any(|line| line.trim() == ".kin/local/"));

    let cache = guildhall::company::cache::Cache::open(&cache_root).expect("open cache");
    let (resolved, digest) = cache
        .certificate(repository_uuid)
        .expect("resolve cached certificate")
        .expect("cached certificate exists");
    assert_eq!(resolved["repository_uuid"], repository_uuid);
    assert_eq!(
        digest,
        guildhall::json::digest(&serde_json::from_slice::<Value>(&certificate_bytes).unwrap())
    );

    let certificate_before = modified(&cached_certificate);
    let config_before = modified(&repo.join(".kin/config"));
    let attributes_before = modified(&repo.join(".gitattributes"));
    let second = run_init(&home, &config_home, &repo, &certificate_file);
    assert!(
        second.status.success(),
        "idempotent repo init failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second_receipt: Value =
        serde_json::from_slice(&second.stdout).expect("second receipt is JSON");
    assert_eq!(second_receipt["worktree_paths_written"], json!([]));
    assert_eq!(second_receipt["gitattributes_lines_added"], json!([]));
    assert_eq!(modified(&cached_certificate), certificate_before);
    assert_eq!(modified(&repo.join(".kin/config")), config_before);
    assert_eq!(modified(&repo.join(".gitattributes")), attributes_before);

    fs::remove_file(&cached_certificate).expect("remove cached certificate");
    let uncertified = run_status(&home, &config_home, &repo);
    assert_eq!(uncertified.status.code(), Some(2));
    let uncertified_lines = String::from_utf8_lossy(&uncertified.stdout).lines().count();
    assert_eq!(uncertified_lines, 1, "status stdout must be one JSON line");
    let uncertified_status: Value =
        serde_json::from_slice(&uncertified.stdout).expect("uncertified status is JSON");
    assert_eq!(uncertified_status["trusted_fact_count"], 0);
    assert_eq!(uncertified_status["error"]["code"], "REPO_UNCERTIFIED");
    assert!(uncertified_status["error"]["remediation"]
        .as_str()
        .expect("status remediation")
        .contains("repo init --repo"));
    assert_eq!(
        uncertified_status["unknowns"]
            .as_array()
            .expect("status unknowns")
            .iter()
            .filter(|unknown| unknown["kind"] == "certificate")
            .count(),
        1
    );
    private_write(&cached_certificate, &certificate_bytes);

    let replacement_file = root.path().join("certificate-replacement.json");
    let replacement_bytes =
        signed_certificate(&root_key, repository_uuid, "2026-09-07T12:00:01.000Z");
    private_write(&replacement_file, &replacement_bytes);
    let replacement = run_init(&home, &config_home, &repo, &replacement_file);
    assert_eq!(replacement.status.code(), Some(4));
    let replacement_error: Value =
        serde_json::from_slice(&replacement.stderr).expect("replacement error is JSON");
    assert_eq!(replacement_error["error"]["code"], "FOREIGN_REPO_EVENTS");
    assert_eq!(fs::read(&cached_certificate).unwrap(), certificate_bytes);

    let foreign_uuid = "fedcba98-7654-3210-fedc-ba9876543210";
    let foreign_file = root.path().join("certificate-foreign.json");
    private_write(
        &foreign_file,
        &signed_certificate(&root_key, foreign_uuid, "2026-09-07T12:00:02.000Z"),
    );
    let foreign = run_init(&home, &config_home, &repo, &foreign_file);
    assert_eq!(foreign.status.code(), Some(4));
    let foreign_error: Value =
        serde_json::from_slice(&foreign.stderr).expect("foreign error is JSON");
    assert_eq!(foreign_error["error"]["code"], "FOREIGN_REPO_EVENTS");
    assert_eq!(fs::read(&cached_certificate).unwrap(), certificate_bytes);

    let config_text = fs::read_to_string(repo.join(".kin/config")).expect("read .kin/config");
    let config = guildhall::codebase::RepoConfig::parse(&config_text).expect("parse .kin/config");
    assert_eq!(config.repository_uuid_hint, repository_uuid);
    assert_eq!(config.schema_version, "guildhall-repo/1");
}

#[test]
fn packet11_hooks_dispatch_returns_identical_canonical_facts_for_both_hosts() {
    let root = TempDir::new().expect("temporary root");
    let home = root.path().join("home");
    let config_home = root.path().join("config-home");
    let guildhall_config = config_home.join("guildhall");
    let cache_root = root.path().join("company-cache");
    let personal_root = root.path().join("personal");
    let repo = root.path().join("repository");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(&guildhall_config).expect("create config directory");
    fs::create_dir_all(&personal_root).expect("create personal root");

    let root_key = PrivateKey::generate();
    let root_public_key_file = guildhall_config.join("root-public.key");
    let facts_token_file = guildhall_config.join("facts.token");
    private_write(
        &root_public_key_file,
        format!("{}\n", root_key.public().to_hex()).as_bytes(),
    );
    private_write(&facts_token_file, b"facts-token\n");
    private_write(
        &guildhall_config.join("config.toml"),
        format!(
            "schema_version = \"1\"\n\n[personal]\ndata_root = {}\n\n[company]\nurl = \"http://127.0.0.1:1\"\nfacts_token_file = {}\nroot_public_key_file = {}\ncache_root = {}\n",
            quoted(&personal_root),
            quoted(&facts_token_file),
            quoted(&root_public_key_file),
            quoted(&cache_root)
        )
        .as_bytes(),
    );

    let git = Command::new("git")
        .arg("init")
        .arg("--initial-branch=main")
        .arg(&repo)
        .output()
        .expect("run git init");
    assert!(
        git.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&git.stderr)
    );

    let repository_uuid = "01234567-89ab-cdef-0123-456789abcdef";
    let certificate_file = root.path().join("certificate.json");
    private_write(
        &certificate_file,
        &signed_certificate(&root_key, repository_uuid, "2026-09-08T12:00:00.000Z"),
    );
    let init = run_init(&home, &config_home, &repo, &certificate_file);
    assert!(
        init.status.success(),
        "repo init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let mut event = guildhall::model::FactEvent {
        schema: "guildhall-event/1".to_owned(),
        event_id: "event_packet11_hook".to_owned(),
        store_kind: "codebase".to_owned(),
        authority_id: "root-steward".to_owned(),
        authority_scope: format!("codebase:{repository_uuid}"),
        repository_id: Some(repository_uuid.to_owned()),
        fact_id: "fact_packet11_hook".to_owned(),
        logical_key: "logical_packet11_hook".to_owned(),
        atom_kind: "constraint".to_owned(),
        scope: "packet 11 hook dispatch".to_owned(),
        statement: "The packet 11 hook corpus carries one certified canonical fact.".to_owned(),
        evidence_refs: Vec::new(),
        asserted_at: "2026-09-08T12:00:00.000Z".to_owned(),
        effective_from: "2026-09-08T12:00:00.000Z".to_owned(),
        effective_until: None,
        disposition: "approved".to_owned(),
        distortion: guildhall::model::Distortion {
            trigger: "dispatch SessionStart with a certified corpus".to_owned(),
            loss_if_absent: 9000,
            rationale: "packet 11 host parity check".to_owned(),
        },
        parents: Vec::new(),
        supersedes: Vec::new(),
        redundancy_with: Vec::new(),
        complements: Vec::new(),
        company_refs: Vec::new(),
        authority_snapshot_cursor: "0".to_owned(),
        confidence: guildhall::model::Bp(9000),
        unresolved_uncertainty: None,
        signer: String::new(),
        signature: String::new(),
        raw: None,
    };
    event.sign(&root_key).expect("sign packet 11 fact");
    let event_bytes = guildhall::json::canonical_bytes(&event.document());
    let digest = guildhall::hash::sha256_bytes(&event_bytes);
    let relative = format!("{}/{}/{}.json", &digest[..2], &digest[2..4], &digest[4..]);
    let event_path = repo.join(".kin/events").join(&relative);
    private_write(&event_path, &event_bytes);

    let git = Command::new("git")
        .current_dir(&repo)
        .args([
            "add",
            ".gitattributes",
            ".kin/config",
            &format!(".kin/events/{relative}"),
        ])
        .output()
        .expect("stage packet 11 corpus");
    assert!(
        git.status.success(),
        "git add failed: {}",
        String::from_utf8_lossy(&git.stderr)
    );
    let git = Command::new("git")
        .current_dir(&repo)
        .env("GIT_AUTHOR_NAME", "packet11")
        .env("GIT_AUTHOR_EMAIL", "packet11@example.invalid")
        .env("GIT_COMMITTER_NAME", "packet11")
        .env("GIT_COMMITTER_EMAIL", "packet11@example.invalid")
        .args(["commit", "-m", "packet11 certified corpus"])
        .output()
        .expect("commit packet 11 corpus");
    assert!(
        git.status.success(),
        "git commit failed: {}",
        String::from_utf8_lossy(&git.stderr)
    );

    let status = run_status(&home, &config_home, &repo);
    assert!(!status.stdout.is_empty(), "status emitted no receipt");
    let status: Value = serde_json::from_slice(&status.stdout).expect("status receipt is JSON");
    assert_eq!(status["status"], "certified");
    assert_eq!(status["trusted_fact_count"], 1);

    let dispatch = |host: &str| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_guildhall"))
            .current_dir(&repo)
            .args(["hooks", "dispatch", host, "SessionStart", "--json"])
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &config_home)
            .env_remove("GUILDHALL_COMPANY_URL")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn hooks dispatch");
        child
            .stdin
            .take()
            .expect("hooks dispatch stdin")
            .write_all(format!("{{\"cwd\":{}}}", quoted(&repo)).as_bytes())
            .expect("write hooks dispatch stdin");
        child.wait_with_output().expect("run hooks dispatch")
    };

    let codex = dispatch("codex");
    assert!(
        codex.status.success(),
        "codex dispatch failed: {}",
        String::from_utf8_lossy(&codex.stderr)
    );
    let codex: Value =
        serde_json::from_slice(&codex.stdout).expect("codex dispatch receipt is JSON");
    let claude = dispatch("claude");
    assert!(
        claude.status.success(),
        "claude dispatch failed: {}",
        String::from_utf8_lossy(&claude.stderr)
    );
    let claude: Value =
        serde_json::from_slice(&claude.stdout).expect("claude dispatch receipt is JSON");

    assert_eq!(codex["status"], "verified");
    assert_eq!(claude["status"], "verified");
    assert!(!codex["canonical_facts"]
        .as_array()
        .expect("codex facts")
        .is_empty());
    assert_eq!(codex["canonical_facts"], claude["canonical_facts"]);
    assert_eq!(
        guildhall::json::canonical_text(&codex["canonical_facts"]),
        guildhall::json::canonical_text(&claude["canonical_facts"])
    );
}
#[allow(clippy::too_many_arguments)]
fn packet11_project_fact(
    repository_uuid: &str,
    event_id: &str,
    fact_id: &str,
    logical_key: &str,
    atom_kind: &str,
    statement: &str,
    trigger: &str,
    loss_if_absent: u16,
    effective_until: Option<&str>,
) -> guildhall::model::FactEvent {
    guildhall::model::FactEvent {
        schema: "guildhall-event/1".to_owned(),
        event_id: event_id.to_owned(),
        store_kind: "codebase".to_owned(),
        authority_id: "root-steward".to_owned(),
        authority_scope: format!("codebase:{repository_uuid}"),
        repository_id: Some(repository_uuid.to_owned()),
        fact_id: fact_id.to_owned(),
        logical_key: logical_key.to_owned(),
        atom_kind: atom_kind.to_owned(),
        scope: "packet 11 projector corpus".to_owned(),
        statement: statement.to_owned(),
        evidence_refs: Vec::new(),
        asserted_at: "2026-09-08T12:00:00.000Z".to_owned(),
        effective_from: "2026-09-08T12:00:00.000Z".to_owned(),
        effective_until: effective_until.map(str::to_owned),
        disposition: "approved".to_owned(),
        distortion: guildhall::model::Distortion {
            trigger: trigger.to_owned(),
            loss_if_absent,
            rationale: "packet 11 projector proof".to_owned(),
        },
        parents: Vec::new(),
        supersedes: Vec::new(),
        redundancy_with: Vec::new(),
        complements: Vec::new(),
        company_refs: Vec::new(),
        authority_snapshot_cursor: "0".to_owned(),
        confidence: guildhall::model::Bp(9000),
        unresolved_uncertainty: None,
        signer: String::new(),
        signature: String::new(),
        raw: None,
    }
}

#[test]
fn packet11_project_exposes_candidates_gain_and_query_selected_ids() {
    let root = TempDir::new().expect("temporary root");
    let home = root.path().join("home");
    let config_home = root.path().join("config-home");
    let guildhall_config = config_home.join("guildhall");
    let cache_root = root.path().join("company-cache");
    let personal_root = root.path().join("personal");
    let repo = root.path().join("repository");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(&guildhall_config).expect("create config directory");
    fs::create_dir_all(&personal_root).expect("create personal root");

    let root_key = PrivateKey::generate();
    private_write(
        &guildhall_config.join("root-public.key"),
        format!("{}\n", root_key.public().to_hex()).as_bytes(),
    );
    private_write(&guildhall_config.join("facts.token"), b"facts-token\n");
    private_write(
        &guildhall_config.join("config.toml"),
        format!(
            "schema_version = \"1\"\n\n[personal]\ndata_root = {}\n\n[company]\nurl = \"http://127.0.0.1:1\"\nfacts_token_file = {}\nroot_public_key_file = {}\ncache_root = {}\n",
            quoted(&personal_root),
            quoted(&guildhall_config.join("facts.token")),
            quoted(&guildhall_config.join("root-public.key")),
            quoted(&cache_root)
        )
        .as_bytes(),
    );

    let git = Command::new("git")
        .args(["init", "--initial-branch=main", &repo.display().to_string()])
        .output()
        .expect("run git init");
    assert!(
        git.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&git.stderr)
    );

    let repository_uuid = "01234567-89ab-cdef-0123-456789abcdef";
    let certificate_file = root.path().join("certificate.json");
    private_write(
        &certificate_file,
        &signed_certificate(&root_key, repository_uuid, "2026-09-08T12:00:00.000Z"),
    );
    let init = run_init(&home, &config_home, &repo, &certificate_file);
    assert!(
        init.status.success(),
        "repo init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    // Packet 12: projection is reducer-invoking, so it requires a fresh
    // authority snapshot. Seed the offline cache with the same steward root
    // used for this test's certificate and codebase facts.
    let unsigned_snapshot = json!({
        "schema": "guildhall-snapshot/1",
        "company_id": "company-test",
        "cursor": "1000",
        "authority_cursor": "1000",
        "revocation_cursor": "1000",
        "client_nonce": "packet12-offline-cache",
        "issued_at": "2026-09-08T12:00:00.000Z",
        "revocation_valid_until": "2030-01-01T00:00:00.000Z",
        "fact_valid_until": "2030-01-01T00:00:00.000Z",
        "registry": [
            {
                "authority_id": "company-steward",
                "scope": "company:root",
                "public_key": root_key.public().to_hex(),
                "status": "active"
            },
            {
                "authority_id": "repository-maintainer",
                "scope": format!("codebase:{repository_uuid}"),
                "public_key": root_key.public().to_hex(),
                "status": "active"
            }
        ],
        "revocations": [],
        "facts": [],
        "unknowns": [],
        "relaxations": [],
        "certificates": [],
        "fact_versions": {}
    });
    let signed_snapshot = root_key
        .sign_document("receipt", &unsigned_snapshot)
        .expect("sign authority snapshot");
    let mut cache = guildhall::company::cache::Cache::open(&cache_root).expect("open authority cache");
    cache
        .store_snapshot(&signed_snapshot, &root_key.public(), "2026-09-08T12:00:00.000Z")
        .expect("store fresh authority snapshot");

    let mut facts = vec![
        packet11_project_fact(
            repository_uuid,
            "event_packet11_invariant",
            "fact_packet11_invariant",
            "logical_packet11_invariant",
            "constraint",
            "Session observe must terminate when the classifier process emits more than one pipe buffer.",
            "classifier process emits more than one pipe buffer",
            9000,
            None,
        ),
        packet11_project_fact(
            repository_uuid,
            "event_packet11_paraphrase",
            "fact_packet11_paraphrase",
            "logical_packet11_paraphrase",
            "constraint",
            "Session observe must terminate when the classifier process emits more than one pipe buffer.",
            "classifier process emits more than one pipe buffer",
            4000,
            None,
        ),
        packet11_project_fact(
            repository_uuid,
            "event_packet11_test",
            "fact_packet11_test",
            "logical_packet11_test",
            "test",
            "The packet 11 test runs a two-hundred-observation classifier corpus.",
            "classifier deadlock is unobserved",
            8000,
            None,
        ),
        packet11_project_fact(
            repository_uuid,
            "event_packet11_rationale",
            "fact_packet11_rationale",
            "logical_packet11_rationale",
            "rationale",
            "The packet 11 test and rationale pair prove concurrent child output handling.",
            "classifier proof is incomplete",
            7500,
            None,
        ),
        packet11_project_fact(
            repository_uuid,
            "event_packet11_stale",
            "fact_packet11_stale",
            "logical_packet11_stale",
            "constraint",
            "This packet 11 fact expired before the projection clock.",
            "stale fact is projected",
            5000,
            Some("2026-09-07T12:00:00.000Z"),
        ),
        packet11_project_fact(
            repository_uuid,
            "event_packet11_conflict_a",
            "fact_packet11_conflict_a",
            "logical_packet11_conflict",
            "decision",
            "Conflict fact A uses the packet 11 shared logical key.",
            "conflicting fact is hidden",
            6000,
            None,
        ),
        packet11_project_fact(
            repository_uuid,
            "event_packet11_conflict_b",
            "fact_packet11_conflict_b",
            "logical_packet11_conflict",
            "decision",
            "Conflict fact B uses the packet 11 shared logical key.",
            "conflicting fact is hidden",
            6100,
            None,
        ),
    ];
    let mut unknown = guildhall::model::UnknownEvent::new(
        "codebase",
        Some(repository_uuid),
        "root-steward",
        &format!("codebase:{repository_uuid}"),
        "logical_packet11_unknown",
        "packet 11 projector corpus",
        "packet 11 planted unknown must be visible",
        "repository-maintainer",
        "root-steward",
        "Which packet 11 residue still blocks the projector proof?",
        7000,
        "2026-09-08T12:00:00.000Z",
        "2026-09-09T12:00:00.000Z",
        "24h",
        "0",
    );
    unknown.sign(&root_key).expect("sign packet 11 unknown");

    let mut relative_paths = Vec::new();
    for fact in &mut facts {
        fact.sign(&root_key).expect("sign packet 11 fact");
        let bytes = guildhall::json::canonical_bytes(&fact.document());
        let digest = guildhall::hash::sha256_bytes(&bytes);
        let relative = format!("{}/{}/{}.json", &digest[..2], &digest[2..4], &digest[4..]);
        private_write(&repo.join(".kin/events").join(&relative), &bytes);
        relative_paths.push(format!(".kin/events/{relative}"));
    }
    let unknown_bytes = guildhall::json::canonical_bytes(&unknown.document());
    let digest = guildhall::hash::sha256_bytes(&unknown_bytes);
    let relative = format!("{}/{}/{}.json", &digest[..2], &digest[2..4], &digest[4..]);
    private_write(&repo.join(".kin/events").join(&relative), &unknown_bytes);
    relative_paths.push(format!(".kin/events/{relative}"));

    let git = Command::new("git")
        .current_dir(&repo)
        .arg("add")
        .arg(".gitattributes")
        .arg(".kin/config")
        .args(&relative_paths)
        .output()
        .expect("stage packet 11 projector corpus");
    assert!(
        git.status.success(),
        "git add failed: {}",
        String::from_utf8_lossy(&git.stderr)
    );
    let git = Command::new("git")
        .current_dir(&repo)
        .env("GIT_AUTHOR_NAME", "packet11")
        .env("GIT_AUTHOR_EMAIL", "packet11@example.invalid")
        .env("GIT_COMMITTER_NAME", "packet11")
        .env("GIT_COMMITTER_EMAIL", "packet11@example.invalid")
        .args(["commit", "-m", "packet 11 projector corpus"])
        .output()
        .expect("commit packet 11 projector corpus");
    assert!(
        git.status.success(),
        "git commit failed: {}",
        String::from_utf8_lossy(&git.stderr)
    );

    let project = Command::new(env!("CARGO_BIN_EXE_guildhall"))
        .current_dir(&repo)
        .args([
            "project",
            "--repo",
            &repo.display().to_string(),
            "--task",
            "prove classifier termination and projector transparency",
            "--decision",
            "packet 11 projector release",
            "--as-of",
            "2026-09-08T12:00:00.000Z",
            "--json",
        ])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config_home)
        .env_remove("GUILDHALL_COMPANY_URL")
        .output()
        .expect("run guildhall project");
    assert!(
        project.status.success(),
        "project failed: {}",
        String::from_utf8_lossy(&project.stderr)
    );
    let result: Value = serde_json::from_slice(&project.stdout).expect("project receipt is JSON");

    let selected_ids: Vec<&str> = result["selected"]
        .as_array()
        .expect("selected array")
        .iter()
        .filter_map(|fact| fact["fact_id"].as_str())
        .collect();
    assert_eq!(selected_ids.first(), Some(&"fact_packet11_invariant"));
    assert!(!selected_ids.contains(&"fact_packet11_paraphrase"));
    assert!(
        result["selection_trace"]
            .as_array()
            .expect("selection trace")
            .iter()
            .any(|entry| entry["marginal_terms"]["complementarity_gain"]
                .as_i64()
                .unwrap_or_default()
                > 0),
        "test and rationale pair must have positive complementarity"
    );

    let candidates = result["candidates"].as_array().expect("candidate array");
    assert!(
        candidates.len() >= 8,
        "projector omitted ingested candidates: {candidates:?}"
    );
    let roles: std::collections::BTreeSet<_> = candidates
        .iter()
        .filter_map(|candidate| candidate["role"].as_str())
        .collect();
    for expected in ["current", "stale", "conflict", "unknown"] {
        assert!(
            roles.contains(expected),
            "missing candidate role {expected}: {candidates:?}"
        );
    }
    assert!(
        candidates
            .iter()
            .all(|candidate| candidate["reason"].is_string()),
        "every candidate needs a reason: {candidates:?}"
    );

    let status = run_status(&home, &config_home, &repo);
    assert!(!status.stdout.is_empty(), "status emitted no receipt");
    let status: Value = serde_json::from_slice(&status.stdout).expect("status receipt is JSON");
    let query_log = status["query_log"].as_array().expect("query log array");
    let selected_query = query_log
        .iter()
        .rev()
        .find(|row| row["declared_use"].as_str() == Some("packet 11 projector release"))
        .expect("project query log row");
    let logged_selected_ids: Vec<&str> = selected_query["selected_ids"]
        .as_array()
        .expect("query log selected_ids")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        logged_selected_ids, selected_ids,
        "query log selected_ids must match the projection"
    );
}
