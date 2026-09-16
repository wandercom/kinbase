//! Regression probes for two ledger-shaped failures found in a live install:
//! a hook install that replaced every host hook list, and Personal readers
//! that failed a whole read on one unreadable row.
//!
//! Roles collapsed: the lane that wrote the fix wrote these probes. They pin
//! the shape of the defect; they do not establish oracle independence.

use kinbase::private::PrivateStore;
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn fake_host(bin: &Path, name: &str, version: &str) {
    fs::create_dir_all(bin).expect("bin dir");
    let path = bin.join(name);
    fs::write(&path, format!("#!/bin/sh\necho '{version}'\n")).expect("write fake host");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod fake host");
}

fn plan(home: &Path, bin: &Path, host: &str, cwd: &Path) -> Value {
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_kinbase"))
        .current_dir(cwd)
        .args(["hooks", "plan", host, "--json"])
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_STATE_HOME", home.join(".state"))
        .env("PATH", path)
        .env_remove("KINBASE_COMPANY_URL")
        .output()
        .expect("run hooks plan");
    assert!(
        output.status.success(),
        "plan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("plan JSON")
}

fn planned_content(plan: &Value) -> String {
    plan["files"][0]["content"]
        .as_str()
        .expect("plan content")
        .to_owned()
}

fn commands(document: &Value, event: &str) -> Vec<String> {
    document["hooks"][event]
        .as_array()
        .expect("event array")
        .iter()
        .flat_map(|entry| entry["hooks"].as_array().cloned().unwrap_or_default())
        .filter_map(|handler| handler["command"].as_str().map(str::to_owned))
        .collect()
}

fn own(commands: &[String], host: &str, event: &str) -> usize {
    commands
        .iter()
        .filter(|command| command.ends_with(&format!(" hooks dispatch {host} {event}")))
        .count()
}

#[test]
fn claude_plan_keeps_foreign_handlers_and_replaces_only_its_own() {
    let temp = TempDir::new().expect("tempdir");
    let home = temp.path().join("home");
    let bin = temp.path().join("bin");
    let repo = temp.path().join("repo");
    fs::create_dir_all(&repo).expect("repo");
    fake_host(&bin, "claude", "2.1.272");
    let settings = home.join(".claude").join("settings.json");
    fs::create_dir_all(settings.parent().expect("parent")).expect("claude dir");
    let existing = json!({
        "model": "opus",
        "hooks": {
            "SessionEnd": [{"matcher": "", "hooks": [
                {"type": "command", "command": "python3 ~/archive.py --hook", "timeout": 30000}
            ]}],
            "Stop": [{"matcher": "", "hooks": [
                {"type": "command", "command": "/usr/local/bin/stop.sh"}
            ]}],
            "SessionStart": [{"hooks": [
                {"type": "command", "command": "'/old/build/kinbase' hooks dispatch claude SessionStart"}
            ]}],
            "PreCompact": []
        }
    });
    fs::write(&settings, existing.to_string()).expect("write settings");

    let first = plan(&home, &bin, "claude", &repo);
    let document: Value = serde_json::from_str(&planned_content(&first)).expect("planned settings");
    assert_eq!(document["model"], "opus");
    let session_end = commands(&document, "SessionEnd");
    assert!(
        session_end.contains(&"python3 ~/archive.py --hook".to_owned()),
        "foreign SessionEnd handler dropped: {session_end:?}"
    );
    assert_eq!(
        document["hooks"]["SessionEnd"][0]["hooks"][0]["timeout"], 30000,
        "foreign handler must be preserved byte for byte"
    );
    assert!(commands(&document, "Stop").contains(&"/usr/local/bin/stop.sh".to_owned()));
    let session_start = commands(&document, "SessionStart");
    assert_eq!(
        session_start.len(),
        1,
        "stale dispatcher replaced, not stacked: {session_start:?}"
    );
    assert!(!session_start[0].contains("/old/build/"));
    for event in [
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PreCompact",
        "Stop",
        "SessionEnd",
    ] {
        assert_eq!(
            own(&commands(&document, event), "claude", event),
            1,
            "{event}"
        );
    }

    // Applying the planned bytes and planning again changes nothing.
    fs::write(&settings, planned_content(&first)).expect("apply plan");
    let second = plan(&home, &bin, "claude", &repo);
    assert_eq!(planned_content(&second), planned_content(&first));
}

#[test]
fn codex_plan_keeps_foreign_handlers_and_replaces_only_its_own() {
    let temp = TempDir::new().expect("tempdir");
    let home = temp.path().join("home");
    let bin = temp.path().join("bin");
    let repo = temp.path().join("repo");
    fs::create_dir_all(&repo).expect("repo");
    fake_host(&bin, "codex", "0.50.0");
    let config = home.join(".codex").join("config.toml");
    fs::create_dir_all(config.parent().expect("parent")).expect("codex dir");
    fs::write(
        &config,
        "model = \"gpt\"\n\n[hooks]\nStop = [\n  { type = \"command\", command = \"/usr/local/bin/stop.sh\" },\n  { type = \"command\", command = \"'/old/build/kinbase' hooks dispatch codex Stop\" },\n]\n",
    )
    .expect("write config");

    let first = plan(&home, &bin, "codex", &repo);
    let table: toml::Value = planned_content(&first).parse().expect("planned toml");
    assert_eq!(table["model"].as_str(), Some("gpt"));
    let stop: Vec<String> = table["hooks"]["Stop"]
        .as_array()
        .expect("Stop array")
        .iter()
        .filter_map(|handler| handler["command"].as_str().map(str::to_owned))
        .collect();
    assert!(
        stop.contains(&"/usr/local/bin/stop.sh".to_owned()),
        "foreign Stop handler dropped: {stop:?}"
    );
    assert_eq!(own(&stop, "codex", "Stop"), 1, "{stop:?}");
    assert!(!stop.iter().any(|command| command.contains("/old/build/")));

    fs::write(&config, planned_content(&first)).expect("apply plan");
    let second = plan(&home, &bin, "codex", &repo);
    assert_eq!(planned_content(&second), planned_content(&first));
}

fn personal_store(root: &Path) -> PrivateStore {
    fs::create_dir_all(root).expect("personal root");
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).expect("chmod root");
    PrivateStore::open_personal(root).expect("open personal store")
}

fn poison(root: &Path, session: &str, record: &str) {
    let raw = rusqlite::Connection::open(root.join("kinbase-personal.sqlite3")).expect("open raw");
    raw.execute(
        "INSERT INTO query_log(session_id, record, logged_at) VALUES (?1, ?2, '2026-01-01T00:00:00.000Z')",
        rusqlite::params![session, record],
    )
    .expect("poison row");
}

#[test]
fn query_log_reads_past_unreadable_rows() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("personal");
    let store = personal_store(&root);
    store
        .log_query(Some("session-a"), &json!({"declared_use": "first"}))
        .expect("log first");
    // The exact poison found in a live store: an empty record column.
    poison(&root, "", "");
    poison(&root, "x", "{not json");
    store
        .log_query(Some("session-b"), &json!({"declared_use": "second"}))
        .expect("log second");
    let rows = store.query_log(None).expect("read past poison");
    let uses: Vec<&str> = rows
        .iter()
        .filter_map(|row| row["declared_use"].as_str())
        .collect();
    assert_eq!(uses, vec!["first", "second"]);
}

#[test]
fn query_log_refuses_a_blank_record_and_a_free_text_session() {
    let temp = TempDir::new().expect("tempdir");
    let store = personal_store(&temp.path().join("personal"));
    // A control character fails the canonical text rule; this used to store "".
    let blank = store.log_query(None, &json!({"task": "line one\nline two"}));
    assert!(
        blank.is_err(),
        "a record that cannot be serialised is refused, not blanked"
    );
    let sentence = store.log_query(
        Some("Follow the recorded direction for this ticket"),
        &json!({"ok": true}),
    );
    assert!(
        sentence.is_err(),
        "a sentence is not a host session identifier"
    );
    assert!(store.query_log(None).expect("read").is_empty());
}

#[test]
fn status_survives_a_poisoned_query_log_and_signals_the_skip() {
    let temp = TempDir::new().expect("tempdir");
    let home = temp.path().join("home");
    let config_home = home.join(".config");
    let personal = temp.path().join("personal");
    let store = personal_store(&personal);
    drop(store);
    poison(&personal, "", "");
    let config = config_home.join("kinbase").join("config.toml");
    fs::create_dir_all(config.parent().expect("parent")).expect("config dir");
    fs::write(
        &config,
        format!(
            "schema_version = \"1\"\n\n[personal]\ndata_root = \"{}\"\n",
            personal.display()
        ),
    )
    .expect("write config");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).expect("chmod config");
    let repo = temp.path().join("repo");
    fs::create_dir_all(&repo).expect("repo");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(&repo)
            .status()
            .expect("git init")
            .success()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_kinbase"))
        .current_dir(&repo)
        .args(["status", "--as-of", "2026-09-15T12:00:00.000Z", "--json"])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_STATE_HOME", home.join(".state"))
        .env_remove("KINBASE_COMPANY_URL")
        .output()
        .expect("run status");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "status must not fail on one bad row: {stderr}"
    );
    assert!(
        stderr.contains("unreadable-ledger-rows"),
        "the skip must be signalled, never silent: {stderr}"
    );
}
