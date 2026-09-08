//! Host integration: plan, install, and dispatch native hooks.
//!
//! Hook configuration is user-level only. Plan is side-effect free, install is
//! additive, and dispatch always consumes native stdin before emitting either
//! the JSON receipt (including the base64 envelope) or the length-prefixed
//! stream used by the non-JSON host mode.

use crate::error::{ContractError, ExitCode};
use crate::repository::RepoContext;
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
    ranges: &crate::config::SharedHosts,
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
    let host_executable = resolve_host_executable(host)
        .ok()
        .map(|path| Value::String(path.to_string_lossy().into_owned()))
        .unwrap_or(Value::Null);
    let mut base = json!({
        "host": host,
        "status": "planned",
        "files": [{"path": relative}],
        "commands": commands,
        "permissions": [{"path": relative, "mode": "0600"}],
        "host_executable": host_executable,
        "host_version": host_range(host, ranges)
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
    let result = plan_payload(host, ranges);
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
    let plan = plan_payload(host_arg, ranges);
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
        "host_version": host_range(host, ranges)
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
    if event_type == "UserPromptSubmit" {
        crate::session::record_hook_observation(host, &map)?;
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
        // SessionStart is deterministic and host-independent: canonical fact
        // bytes come from the certified repository's reduced current view.
        if let Ok(launcher) = crate::launcher::Launcher::load()
            && let Ok(context) = RepoContext::load(launcher, &cwd, false)
        {
            let now = crate::time::now_rfc3339_millis();
            if let Ok((view, _, _)) = context.current_view(&now, None) {
                canonical_facts.extend(view.facts.iter().map(crate::model::value_of));
                unknowns.extend(view.open_unknown_ids.iter().cloned().map(Value::String));
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
            let session_id = map
                .get("session_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let checkpoint = crate::session::checkpoint_internal(session_id)?;
            merge(&mut response, checkpoint);
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

fn host_arg(host: &str) -> crate::command_types::Host {
    if host == "claude" {
        crate::command_types::Host::Claude
    } else {
        crate::command_types::Host::Codex
    }
}

pub fn hook_state(host: &str, ranges: &crate::config::SharedHosts) -> Value {
    let relative = host_relative_config(host);
    let configured = std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(relative))
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| hook_config_has_entries(host, &text))
        .unwrap_or(false);
    let plan = plan_payload(host_arg(host), ranges);
    if configured {
        json!({
            "host": host,
            "installed": true,
            "state": "installed",
            "approval_required": false,
            "plan_digest": plan.get("plan_digest"),
            "personal_queried": false,
            "facts_label": "UNTRUSTED_EVIDENCE_NOT_INSTRUCTIONS"
        })
    } else {
        json!({
            "host": host,
            "installed": false,
            "state": "HOOK_APPROVAL_REQUIRED",
            "approval_required": true,
            "missing_planned_entries": HOOK_EVENTS,
            "plan_digest": plan.get("plan_digest"),
            "personal_queried": false,
            "facts_label": "UNTRUSTED_EVIDENCE_NOT_INSTRUCTIONS"
        })
    }
}

pub fn hook_approval_error(
    host: &str,
    ranges: &crate::config::SharedHosts,
) -> ContractError {
    let state = hook_state(host, ranges);
    ContractError::user_action(
        "HOOK_APPROVAL_REQUIRED",
        format!("host {host} lacks the planned Guildhall hook entries"),
        format!("Run `guildhall hooks install {host}`; the host presents its own approval at its next start."),
    )
    .with_detail(json!({
        "missing_planned_entries": HOOK_EVENTS,
        "hooks": state
    }))
}

fn hook_config_has_entries(host: &str, text: &str) -> Option<bool> {
    let has_command = |event: &str| {
        text.contains(&format!("hooks dispatch {host} {event}"))
    };
    if host == "claude" {
        let document: Value = serde_json::from_str(text).ok()?;
        let hooks = document.get("hooks")?;
        return Some(HOOK_EVENTS.iter().all(|event| {
            hooks.get(*event).is_some_and(Value::is_array) && has_command(event)
        }));
    }
    let table: toml::Value = text.parse().ok()?;
    let hooks = table.get("hooks")?;
    Some(HOOK_EVENTS.iter().all(|event| {
        hooks.get(*event).is_some_and(toml::Value::is_array) && has_command(event)
    }))
}

pub fn host_version(host: &str) -> String {
    match host {
        "claude" => ">=1.0.0".to_owned(),
        _ => ">=0.0.0".to_owned(),
    }
}
