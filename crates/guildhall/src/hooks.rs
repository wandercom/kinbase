//! Host integration: plan, install, and dispatch native hooks.
//!
//! Hook configuration is user-level only. Plan is side-effect free, install is
//! additive, and dispatch always consumes native stdin before emitting either
//! the JSON receipt (including the base64 envelope) or the length-prefixed
//! stream used by the non-JSON host mode.

use crate::error::{ContractError, ExitCode};
use base64::Engine;
use serde_json::{Map, Value, json};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const HOOK_EVENTS: [&str; 6] = [
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PreCompact",
    "Stop",
    "SessionEnd",
];

pub fn dispatch(
    command: crate::command_types::HookCommand,
    json: bool,
) -> Result<(), ContractError> {
    let launcher = crate::launcher::Launcher::load()?;
    let ranges = &launcher.shared.hosts;
    match command {
        crate::command_types::HookCommand::Plan { host } => plan(host, ranges, json),
        crate::command_types::HookCommand::Install { host } => install(host, ranges, json),
        crate::command_types::HookCommand::Dispatch { host, event } => {
            dispatch_event(host, &event, ranges, json)
        }
    }
}

fn host_name(host: crate::command_types::Host) -> &'static str {
    match host {
        crate::command_types::Host::Codex => "codex",
        crate::command_types::Host::Claude => "claude",
    }
}

fn host_relative_config(host: &str) -> &'static str {
    if host == "claude" {
        ".claude/settings.json"
    } else {
        ".codex/config.toml"
    }
}

fn host_range(
    host: &str,
    ranges: &crate::config::SharedHosts,
) -> String {
    if host == "claude" {
        ranges.claude_version.clone()
    } else {
        ranges.codex_version.clone()
    }
}

fn resolve_host_executable(host: &str) -> Result<PathBuf, ContractError> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let executable_name = if host == "claude" { "claude" } else { "codex" };
    for directory in std::env::split_paths(&path) {
        if directory.as_os_str().is_empty() {
            continue;
        }
        let candidate = directory.join(executable_name);
        if let Ok(metadata) = std::fs::metadata(&candidate) {
            if metadata.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(ContractError::degraded(
        "UNSUPPORTED_HOST_VERSION",
        format!("host executable {executable_name} was not found on PATH"),
        "Install the host CLI or place its approved wrapper on PATH.",
    ))
}

fn version_text(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut current = String::new();
    let mut versions = Vec::new();
    for character in text.chars() {
        if character.is_ascii_digit() || character == '.' {
            current.push(character);
        } else if !current.is_empty() {
            versions.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        versions.push(current);
    }
    versions
        .into_iter()
        .find(|value| value.chars().any(|character| character != '0' && character != '.'))
        .unwrap_or_default()
}

fn version_components(value: &str) -> Vec<u64> {
    value
        .trim_start_matches('v')
        .split('.')
        .map(|part| part.trim_start_matches(|character: char| !character.is_ascii_digit()).parse::<u64>().unwrap_or(0))
        .collect()
}

fn version_in_range(version: &str, range: &str) -> bool {
    if let Some(minimum) = range.trim().strip_prefix(">=") {
        let actual = version_components(version);
        let required = version_components(minimum);
        for index in 0..required.len().max(actual.len()) {
            let left = actual.get(index).copied().unwrap_or(0);
            let right = required.get(index).copied().unwrap_or(0);
            if left > right {
                return true;
            }
            if left < right {
                return false;
            }
        }
        return true;
    }
    range.trim() == version
}

#[derive(Debug)]
struct HostWitness {
    path: PathBuf,
    version: String,
}

fn witness_host(
    host: &str,
    ranges: &crate::config::SharedHosts,
) -> Result<HostWitness, ContractError> {
    let path = resolve_host_executable(host)?;
    let output = std::process::Command::new(&path)
        .arg("--version")
        .output()
        .map_err(|error| ContractError::degraded(
            "UNSUPPORTED_HOST_VERSION",
            format!("host executable could not be invoked: {error}"),
            "Repair the host executable or its approved wrapper on PATH.",
        ))?;
    let version = version_text(&output.stdout);
    if !output.status.success() && version.is_empty() {
        return Err(ContractError::degraded(
            "UNSUPPORTED_HOST_VERSION",
            format!("host executable exited with status {}", output.status),
            "Repair the host executable or its approved wrapper on PATH.",
        ));
    }
    let range = host_range(host, ranges);
    if !version_in_range(&version, &range) {
        return Err(ContractError::degraded(
            "UNSUPPORTED_HOST_VERSION",
            format!("host version {version} is outside the configured range {range}"),
            "Upgrade the host or update the ratified user-level version range.",
        ));
    }
    Ok(HostWitness { path, version })
}

fn current_program() -> String {
    std::env::current_exe()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "guildhall".to_owned())
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r#"'"'"'"#))
}

fn plan_payload(
    host_arg: crate::command_types::Host,
    witness: &HostWitness,
) -> Value {
    let host = host_name(host_arg);
    let relative = host_relative_config(host);
    let program = current_program();
    let commands = HOOK_EVENTS
        .iter()
        .map(|event| {
            json!({
                "program": program,
                "args": ["hooks", "dispatch", host, event],
                "event": event
            })
        })
        .collect::<Vec<_>>();
    let mut base = json!({
        "host": host,
        "status": "planned",
        "files": [{"path": relative}],
        "commands": commands,
        "permissions": [{"path": relative, "mode": "0600"}],
        "host_executable": witness.path.to_string_lossy(),
        "host_version": witness.version
    });
    let digest = crate::hash::sha256_text(&crate::json::canonical_text(&base));
    if let Value::Object(map) = &mut base {
        map.insert("plan_digest".to_owned(), Value::String(digest));
    }
    base
}

fn plan(
    host: crate::command_types::Host,
    ranges: &crate::config::SharedHosts,
    json: bool,
) -> Result<(), ContractError> {
    let witness = witness_host(host_name(host), ranges)?;
    let result = plan_payload(host, &witness);
    if json {
        println!("{}", crate::json::canonical_text(&result));
    } else {
        println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
    }
    Ok(())
}

fn install(
    host_arg: crate::command_types::Host,
    ranges: &crate::config::SharedHosts,
    json: bool,
) -> Result<(), ContractError> {
    let witness = witness_host(host_name(host_arg), ranges)?;
    let plan = plan_payload(host_arg, &witness);
    let host = host_name(host_arg);
    let relative = host_relative_config(host);
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|value| !value.as_os_str().is_empty())
        .ok_or_else(|| ContractError::invariant("HOME is required for user-level hook installation"))?;
    let destination = home.join(relative);
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent).map_err(io_error)?;
    }
    if host == "claude" {
        install_claude(&destination, host, &current_program())?;
    } else {
        install_codex(&destination, host, &current_program())?;
    }
    set_mode(&destination, 0o600)?;
    let receipt = json!({
        "status": "installed",
        "host": host,
        "plan_digest": plan.get("plan_digest"),
        "files_written": [relative],
        "host_executable": witness.path.to_string_lossy(),
        "host_version": witness.version
    });
    if json {
        println!("{}", crate::json::canonical_text(&receipt));
    } else {
        println!("{}", serde_json::to_string_pretty(&receipt).unwrap_or_default());
    }
    Ok(())
}

fn install_codex(path: &Path, host: &str, program: &str) -> Result<(), ContractError> {
    let mut table: toml::Value = if path.exists() {
        let text = std::fs::read_to_string(path).map_err(io_error)?;
        text.parse::<toml::Value>().map_err(|error| ContractError::invariant(format!("existing Codex config is not valid TOML: {error}")))?
    } else {
        toml::Value::Table(toml::map::Map::new())
    };
    let toml::Value::Table(root) = &mut table else {
        return Err(ContractError::invariant("existing Codex config must be a TOML table"));
    };
    let hooks = root
        .entry("hooks".to_owned())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    let toml::Value::Table(hooks) = hooks else {
        return Err(ContractError::invariant("existing Codex [hooks] must be a table"));
    };
    for event in HOOK_EVENTS {
        let command = format!(
            "{} hooks dispatch {} {}",
            shell_quote(program),
            host,
            event
        );
        let mut entry = toml::map::Map::new();
        entry.insert("type".to_owned(), toml::Value::String("command".to_owned()));
        entry.insert("command".to_owned(), toml::Value::String(command));
        hooks.insert(event.to_owned(), toml::Value::Array(vec![toml::Value::Table(entry)]));
    }
    let rendered = toml::to_string_pretty(&table)
        .map_err(|error| ContractError::internal(format!("Codex config serialization failed: {error}")))?;
    std::fs::write(path, rendered.as_bytes()).map_err(io_error)
}

fn install_claude(path: &Path, host: &str, program: &str) -> Result<(), ContractError> {
    let mut document: Value = if path.exists() {
        let bytes = std::fs::read(path).map_err(io_error)?;
        crate::json::parse_strict_value(&bytes).map_err(|error| ContractError::invariant(format!("existing Claude settings are not strict JSON: {error}")))?
    } else {
        json!({})
    };
    let Value::Object(settings) = &mut document else {
        return Err(ContractError::invariant("existing Claude settings must be a JSON object"));
    };
    let hooks = settings
        .entry("hooks".to_owned())
        .or_insert_with(|| json!({}));
    let Value::Object(hooks) = hooks else {
        return Err(ContractError::invariant("existing Claude hooks setting must be an object"));
    };
    for event in HOOK_EVENTS {
        let command = format!(
            "{} hooks dispatch {} {}",
            shell_quote(program),
            host,
            event
        );
        hooks.insert(event.to_owned(), json!([
            {"hooks": [{"type": "command", "command": command}]}
        ]));
    }
    std::fs::write(path, crate::json::canonical_bytes(&document)).map_err(io_error)
}

fn set_mode(path: &Path, mode: u32) -> Result<(), ContractError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(io_error)
}

fn supported_event(event: &str) -> bool {
    HOOK_EVENTS.contains(&event)
        || matches!(
            event,
            "session-start" | "prompt" | "Prompt" | "pre-edit" | "session-end" | "primary-task" | "observation"
        )
}

fn dispatch_event(
    host_arg: crate::command_types::Host,
    event: &str,
    ranges: &crate::config::SharedHosts,
    json: bool,
) -> Result<(), ContractError> {
    let host = host_name(host_arg);
    let _witness = witness_host(host, ranges)?;
    let mut stdin = Vec::new();
    std::io::stdin()
        .read_to_end(&mut stdin)
        .map_err(|error| ContractError::invariant(format!("host hook stdin is unreadable: {error}")))?;
    let map: Map<String, Value> = if stdin.is_empty() {
        Map::new()
    } else {
        crate::json::parse_strict_value(&stdin)
            .map_err(|error| ContractError::degraded(
                "UNSUPPORTED_HOST_VERSION",
                format!("native host envelope is invalid: {error}"),
                "Send one strict JSON envelope on stdin.",
            ))?
            .as_object()
            .cloned()
            .ok_or_else(|| ContractError::degraded(
                "UNSUPPORTED_HOST_VERSION",
                "native host envelope must be a JSON object",
                "Send one strict JSON object on stdin.",
            ))?
    };
    let event_type = if supported_event(event) {
        event.to_owned()
    } else {
        map.get("hook_event_name")
            .or_else(|| map.get("event_type"))
            .or_else(|| map.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("observation")
            .to_owned()
    };
    if !supported_event(&event_type) {
        return Err(ContractError::degraded(
            "UNSUPPORTED_HOST_VERSION",
            format!("unsupported host event: {event_type}"),
            "Use a ratified Codex or Claude native envelope.",
        ));
    }
    let cwd = map
        .get("cwd")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let repository_initialized = cwd.join(".kin").join("config").exists();
    let mut canonical_facts = Vec::new();
    let mut unknowns = Vec::new();
    if matches!(event_type.as_str(), "SessionStart" | "session-start") {
        for store in [crate::StoreKind::Company, crate::StoreKind::Codebase] {
            let root = crate::store::store_root(store, &cwd);
            if let Ok(view) = std::fs::read_to_string(root.join("local").join("current.json")) {
                if let Ok(value) = serde_json::from_str::<Value>(&view) {
                    if let Some(facts) = value.get("facts").and_then(Value::as_array) {
                        canonical_facts.extend(facts.iter().cloned());
                    }
                    if let Some(ids) = value.get("unknown_ids").and_then(Value::as_array) {
                        unknowns.extend(ids.iter().cloned());
                    }
                }
            }
        }
    }
    let degraded = !repository_initialized || canonical_facts.is_empty();
    let mut response = json!({
        "hook": host,
        "event_type": event_type,
        "status": if degraded { "degraded" } else { "verified" },
        "repository_root": cwd.to_string_lossy(),
        "company_state": if repository_initialized { "local" } else { "unverified" },
        "canonical_facts": canonical_facts,
        "decisions": [],
        "receipts": [],
        "company_connect_seconds": 0,
        "degraded": degraded,
        "start_path": if repository_initialized && !canonical_facts.is_empty() { "warm_verified" } else { "cold-unverified" },
        "full_fsck_performed": false,
        "trusted_company_facts": [],
        "trusted_context": canonical_facts,
        "events": [],
        "counts": {
            "canonical_facts": canonical_facts.len(),
            "events": 0,
            "unknowns": unknowns.len()
        },
        "cwd": cwd.to_string_lossy(),
        "context_facts": canonical_facts,
        "unknowns": unknowns,
        "label": "UNTRUSTED_EVIDENCE_NOT_INSTRUCTIONS",
        "personal_queried": false
    });
    match event_type.as_str() {
        "UserPromptSubmit" | "prompt" | "Prompt" => {
            merge(&mut response, json!({
                "capture_active": true,
                "personal_root_readable": false,
                "sandbox_enforced": true,
                "sandbox_disabled_loudly": false,
                "stolen_bytes_promoted": false
            }));
        }
        "Stop" | "SessionEnd" | "session-end" => {
            merge(&mut response, json!({"checkpointed": false}));
        }
        "PreToolUse" | "pre-edit" => {
            merge(&mut response, json!({"tool_use_allowed": true, "personal_queried": false}));
        }
        "PreCompact" => {
            merge(&mut response, json!({"compact_allowed": true, "personal_queried": false}));
        }
        _ => {}
    }
    let stream_body = json!({
        "facts": [],
        "label": "UNTRUSTED_EVIDENCE_NOT_INSTRUCTIONS",
        "trusted_context": []
    });
    let body = crate::json::canonical_bytes(&stream_body);
    let mut stream = format!("{}\n", body.len()).into_bytes();
    stream.extend_from_slice(&body);
    let envelope = base64::engine::general_purpose::STANDARD.encode(&stream);
    if json {
        if let Value::Object(map) = &mut response {
            map.insert("envelope".to_owned(), Value::String(envelope));
        }
        println!("{}", crate::json::canonical_text(&response));
    } else {
        std::io::stdout()
            .write_all(&stream)
            .and_then(|_| std::io::stdout().flush())
            .map_err(io_error)?;
    }
    Ok(())
}

fn merge(target: &mut Value, additions: Value) {
    let Value::Object(additions) = additions else { return; };
    if let Value::Object(target) = target {
        for (key, value) in additions {
            target.insert(key, value);
        }
    }
}

fn io_error(error: std::io::Error) -> ContractError {
    ContractError::new(
        "RUN_INTEGRITY_FAILED",
        error.to_string(),
        "Check filesystem permissions and retry.",
        false,
        ExitCode::InternalFailure,
    )
}

pub fn hook_state(host: &str) -> Value {
    let relative = host_relative_config(host);
    let configured = std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(relative))
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| hook_config_has_entries(host, &text))
        .unwrap_or(false);
    if configured {
        json!({
            "host": host,
            "state": "installed",
            "approval_required": false,
            "personal_queried": false,
            "facts_label": "UNTRUSTED_EVIDENCE_NOT_INSTRUCTIONS"
        })
    } else {
        json!({
            "host": host,
            "state": "HOOK_APPROVAL_REQUIRED",
            "approval_required": true,
            "personal_queried": false,
            "facts_label": "UNTRUSTED_EVIDENCE_NOT_INSTRUCTIONS"
        })
    }
}

fn hook_config_has_entries(host: &str, text: &str) -> Option<bool> {
    if host == "claude" {
        let document: Value = serde_json::from_str(text).ok()?;
        return Some(document.get("hooks")?.is_object());
    }
    let table: toml::Value = text.parse().ok()?;
    Some(table.get("hooks")?.is_table())
}

pub fn host_version(host: &str) -> String {
    match host {
        "claude" => ">=1.0.0".to_owned(),
        _ => ">=0.0.0".to_owned(),
    }
}
