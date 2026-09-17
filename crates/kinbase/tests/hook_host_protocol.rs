//! A hook installs where the host reads it, answers in the host's shape, and
//! hands prompts to the session they belong to.
//!
//! - install/plan/doctor wrote `$HOME/.claude` even when `CLAUDE_CONFIG_DIR`
//!   named the directory the host reads, and refused a settings file with a
//!   float or a multi-line command as "not strict JSON";
//! - a re-fired Stop (`stop_hook_active`) checkpointed again;
//! - a prompt was recorded as `hook:UserPromptSubmit`, which Stop never
//!   counts and nothing classifies.
//!
//! Roles collapsed: the lane that wrote the fix wrote these probes.

use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

struct World {
    home: PathBuf,
    personal: PathBuf,
    repo: PathBuf,
    bin: PathBuf,
}

fn world(temp: &TempDir) -> World {
    let home = temp.path().join("home");
    let personal = temp.path().join("personal");
    fs::create_dir_all(&personal).expect("personal");
    fs::set_permissions(&personal, fs::Permissions::from_mode(0o700)).expect("chmod");
    let config = home.join(".config").join("kinbase").join("config.toml");
    fs::create_dir_all(config.parent().expect("parent")).expect("config dir");
    fs::write(
        &config,
        format!(
            "schema_version = \"1\"\n\n[personal]\ndata_root = \"{}\"\n",
            personal.display()
        ),
    )
    .expect("config");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).expect("chmod config");
    let repo = temp.path().join("repo");
    fs::create_dir_all(&repo).expect("repo");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(&repo)
            .status()
            .expect("git")
            .success()
    );
    let bin = temp.path().join("bin");
    fs::create_dir_all(&bin).expect("bin");
    let claude = bin.join("claude");
    fs::write(&claude, "#!/bin/sh\necho '2.1.272'\n").expect("fake claude");
    fs::set_permissions(&claude, fs::Permissions::from_mode(0o755)).expect("chmod claude");
    World {
        home,
        personal,
        repo,
        bin,
    }
}

fn kinbase(world: &World, args: &[&str], envs: &[(&str, &Path)], stdin: &[u8]) -> Output {
    use std::io::Write as _;
    let path = format!(
        "{}:{}",
        world.bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut command = Command::new(env!("CARGO_BIN_EXE_kinbase"));
    command
        .current_dir(&world.repo)
        .args(args)
        .env("HOME", &world.home)
        .env("XDG_CONFIG_HOME", world.home.join(".config"))
        .env("XDG_STATE_HOME", world.home.join(".state"))
        .env("PATH", path)
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("CODEX_HOME")
        .env_remove("KINBASE_COMPANY_URL")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        command.env(key, value);
    }
    let mut child = command.spawn().expect("spawn kinbase");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin)
        .expect("stdin");
    child.wait_with_output().expect("output")
}

fn ok(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("JSON output")
}

#[test]
fn install_writes_where_claude_config_dir_points() {
    let temp = TempDir::new().expect("tempdir");
    let world = world(&temp);
    let config_dir = temp.path().join("claude-config");
    let plan = ok(&kinbase(
        &world,
        &["hooks", "plan", "claude", "--json"],
        &[("CLAUDE_CONFIG_DIR", &config_dir)],
        b"",
    ));
    let settings = config_dir.join("settings.json");
    assert_eq!(
        plan["files"][0]["resolved_path"],
        settings.display().to_string()
    );
    assert_eq!(
        plan["files"][0]["path"],
        settings.display().to_string(),
        "outside HOME: absolute"
    );
    ok(&kinbase(
        &world,
        &["hooks", "install", "claude", "--json"],
        &[("CLAUDE_CONFIG_DIR", &config_dir)],
        b"",
    ));
    assert!(settings.is_file());
    assert!(!world.home.join(".claude").join("settings.json").exists());
    let doctor = kinbase(
        &world,
        &["doctor", "--json"],
        &[("CLAUDE_CONFIG_DIR", &config_dir)],
        b"",
    );
    let text = String::from_utf8_lossy(&doctor.stdout);
    assert!(
        text.contains(&settings.display().to_string()),
        "doctor names the file: {text}"
    );

    let default = ok(&kinbase(
        &world,
        &["hooks", "plan", "claude", "--json"],
        &[],
        b"",
    ));
    assert_eq!(default["files"][0]["path"], ".claude/settings.json");
}

#[test]
fn install_keeps_a_settings_file_with_floats_and_multi_line_commands() {
    let temp = TempDir::new().expect("tempdir");
    let world = world(&temp);
    let settings = world.home.join(".claude").join("settings.json");
    fs::create_dir_all(settings.parent().expect("parent")).expect("dir");
    let existing = "{\n  \"model\": \"opus\",\n  \"temperature\": 0.7,\n  \"statusLine\": {\"type\": \"command\", \"command\": \"line one\\nline two \\u202e\"},\n  \"hooks\": {}\n}\n";
    fs::write(&settings, existing).expect("settings");
    ok(&kinbase(
        &world,
        &["hooks", "install", "claude", "--json"],
        &[],
        b"",
    ));
    let written = fs::read_to_string(&settings).expect("settings");
    let document: Value = serde_json::from_str(&written).expect("valid JSON");
    assert_eq!(document["temperature"], json!(0.7));
    assert_eq!(
        document["statusLine"]["command"],
        "line one\nline two \u{202e}"
    );
    let keys: Vec<&String> = document.as_object().expect("object").keys().collect();
    assert_eq!(
        keys,
        ["model", "temperature", "statusLine", "hooks"],
        "key order kept"
    );
    assert!(written.lines().count() > 1, "written for a person to read");
}

#[test]
fn a_refired_stop_does_not_checkpoint_again() {
    let temp = TempDir::new().expect("tempdir");
    let world = world(&temp);
    let stop = json!({
        "session_id": "host-session-9",
        "cwd": world.repo.display().to_string(),
        "hook_event_name": "Stop",
        "stop_hook_active": true
    });
    let output = kinbase(
        &world,
        &["hooks", "dispatch", "claude", "Stop"],
        &[],
        stop.to_string().as_bytes(),
    );
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!world.personal.join("session-checkpoints.jsonl").exists());
}

#[test]
fn a_prompt_reaches_the_sessions_checkpoint() {
    let temp = TempDir::new().expect("tempdir");
    let world = world(&temp);
    let base = json!({"session_id": "host-session-7", "cwd": world.repo.display().to_string()});
    let mut prompt = base.clone();
    prompt["hook_event_name"] = json!("UserPromptSubmit");
    prompt["prompt"] = json!("We decided to keep the retry budget at three attempts.");
    let output = kinbase(
        &world,
        &["hooks", "dispatch", "claude", "UserPromptSubmit"],
        &[],
        prompt.to_string().as_bytes(),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let pending = world.personal.join("pending-observations");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let observed = fs::read_to_string(world.personal.join("observations.jsonl"))
            .map(|text| text.contains("\"source_identity\":\"session:host-session-7\""))
            .unwrap_or(false);
        let drained = fs::read_dir(&pending)
            .map(|entries| entries.count() == 0)
            .unwrap_or(true);
        if observed && drained {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the worker never finished"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let mut stop = base.clone();
    stop["hook_event_name"] = json!("Stop");
    let receipt = ok(&kinbase(
        &world,
        &["hooks", "dispatch", "claude", "Stop", "--json"],
        &[],
        stop.to_string().as_bytes(),
    ));
    assert_eq!(receipt["observation_count"], 1, "{receipt}");
    assert!(
        receipt["atom_count"].as_u64().unwrap_or(0) >= 1,
        "{receipt}"
    );
}
