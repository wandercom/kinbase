//! The classifier child refuses a cloud processor its caller did not
//! authorize, before any session text leaves the machine.

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn the_classifier_refuses_agy_without_its_processor_scope() {
    let home = tempfile::tempdir().expect("temp home");
    let document = r#"{"observations":[{"observation_id":"obs-1","source_kind":"codex_jsonl","source_identity":"source:test","content_digest":"digest","observed_at":"2026-09-08T10:00:00.000Z","disposition":"current","extraction_version":"1","scope":"host-session","body":"The deploy runs on Fridays.","confidence":8000}]}"#;
    let mut child = Command::new(env!("CARGO_BIN_EXE_kinbase"))
        .args(["classifier", "--json", "--model", "agy:default"])
        .env_clear()
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("XDG_STATE_HOME", home.path().join(".state"))
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn kinbase");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(document.as_bytes())
        .expect("write input");
    let output = child.wait_with_output().expect("classifier output");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(5), "{text}");
    assert!(text.contains("PROCESSOR_UNAUTHORIZED"), "{text}");
    assert!(text.contains("processor_scope"), "{text}");
}
