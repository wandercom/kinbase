use guildhall::crypto::PrivateKey;
use serde_json::{Value, json};
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
    fs::metadata(path)
        .expect("stat path")
        .permissions()
        .mode()
        & 0o777
}

fn modified(path: &Path) -> SystemTime {
    fs::metadata(path).expect("stat path").modified().expect("modification time")
}

fn quoted(path: &Path) -> String {
    format!("\"{}\"", path.display())
}

fn run_init(home: &Path, config_home: &Path, repo: &Path, certificate: &Path) -> std::process::Output {
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
    private_write(&root_public_key_file, format!("{}\n", root_key.public().to_hex()).as_bytes());
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
    assert!(git.status.success(), "git init failed: {}", String::from_utf8_lossy(&git.stderr));

    let repository_uuid = "01234567-89ab-cdef-0123-456789abcdef";
    let certificate_file = root.path().join("certificate.json");
    let certificate_bytes = signed_certificate(&root_key, repository_uuid, "2026-09-07T12:00:00.000Z");
    private_write(&certificate_file, &certificate_bytes);

    let first = run_init(&home, &config_home, &repo, &certificate_file);
    assert!(first.status.success(), "first repo init failed: {}", String::from_utf8_lossy(&first.stderr));
    let receipt: Value = serde_json::from_slice(&first.stdout).expect("first receipt is JSON");
    assert_eq!(receipt["status"], "repo-initialized");
    assert_eq!(receipt["repository_uuid"], repository_uuid);
    assert_eq!(receipt["certificate_cached_path"], "repositories/01234567-89ab-cdef-0123-456789abcdef/certificate.json");
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
    assert_eq!(fs::read(&cached_certificate).expect("read cached certificate"), certificate_bytes);
    assert_eq!(mode(&cache_root), 0o700);
    assert_eq!(mode(&cache_root.join("repositories")), 0o700);
    assert_eq!(mode(cached_certificate.parent().unwrap()), 0o700);
    assert_eq!(mode(&cached_certificate), 0o600);
    assert_eq!(visible_worktree_paths(&repo), vec![
        ".gitattributes".to_owned(),
        ".kin/".to_owned(),
        ".kin/config".to_owned(),
        ".kin/events/".to_owned(),
        ".kin/local/".to_owned(),
        ".kin/manifests/".to_owned()
    ]);
    assert!(!repo.join(".kin/certificate.json").exists());
    let exclude = fs::read_to_string(repo.join(".git/info/exclude")).expect("read git exclude");
    assert!(!exclude.contains(".kin/local/"));

    let cache = guildhall::company::cache::Cache::open(&cache_root).expect("open cache");
    let (resolved, digest) = cache
        .certificate(repository_uuid)
        .expect("resolve cached certificate")
        .expect("cached certificate exists");
    assert_eq!(resolved["repository_uuid"], repository_uuid);
    assert_eq!(digest, guildhall::json::digest(&serde_json::from_slice::<Value>(&certificate_bytes).unwrap()));

    let certificate_before = modified(&cached_certificate);
    let config_before = modified(&repo.join(".kin/config"));
    let attributes_before = modified(&repo.join(".gitattributes"));
    let second = run_init(&home, &config_home, &repo, &certificate_file);
    assert!(second.status.success(), "idempotent repo init failed: {}", String::from_utf8_lossy(&second.stderr));
    let second_receipt: Value = serde_json::from_slice(&second.stdout).expect("second receipt is JSON");
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
    let uncertified_status: Value = serde_json::from_slice(&uncertified.stdout).expect("uncertified status is JSON");
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
    let replacement_bytes = signed_certificate(&root_key, repository_uuid, "2026-09-07T12:00:01.000Z");
    private_write(&replacement_file, &replacement_bytes);
    let replacement = run_init(&home, &config_home, &repo, &replacement_file);
    assert_eq!(replacement.status.code(), Some(4));
    let replacement_error: Value = serde_json::from_slice(&replacement.stderr).expect("replacement error is JSON");
    assert_eq!(replacement_error["error"]["code"], "FOREIGN_REPO_EVENTS");
    assert_eq!(fs::read(&cached_certificate).unwrap(), certificate_bytes);

    let foreign_uuid = "fedcba98-7654-3210-fedc-ba9876543210";
    let foreign_file = root.path().join("certificate-foreign.json");
    private_write(&foreign_file, &signed_certificate(&root_key, foreign_uuid, "2026-09-07T12:00:02.000Z"));
    let foreign = run_init(&home, &config_home, &repo, &foreign_file);
    assert_eq!(foreign.status.code(), Some(4));
    let foreign_error: Value = serde_json::from_slice(&foreign.stderr).expect("foreign error is JSON");
    assert_eq!(foreign_error["error"]["code"], "FOREIGN_REPO_EVENTS");
    assert_eq!(fs::read(&cached_certificate).unwrap(), certificate_bytes);

    let config_text = fs::read_to_string(repo.join(".kin/config")).expect("read .kin/config");
    let config = guildhall::codebase::RepoConfig::parse(&config_text).expect("parse .kin/config");
    assert_eq!(config.repository_uuid_hint, repository_uuid);
    assert_eq!(config.schema_version, "guildhall-repo/1");
}
