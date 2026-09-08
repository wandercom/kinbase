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

fn host_range(host: &str, ranges: &crate::config::SharedHosts) -> String {
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
        .find(|value| {
            value
                .chars()
                .any(|character| character != '0' && character != '.')
        })
        .unwrap_or_default()
}

fn version_components(value: &str) -> Vec<u64> {
    value
        .trim_start_matches('v')
        .split('.')
        .map(|part| {
            part.trim_start_matches(|character: char| !character.is_ascii_digit())
                .parse::<u64>()
                .unwrap_or(0)
        })
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

/// A disposable home for host probes. The host's own scratch files (session
/// locks, patch wrappers) must never land in the user's HOME during a
/// read-only plan or a diagnostic; the probe runs against a throwaway home
/// that is removed afterwards.
struct ScratchHome {
    root: PathBuf,
}

impl ScratchHome {
    fn create() -> Result<Self, ContractError> {
        let root = std::env::temp_dir().join(format!(
            "guildhall-host-probe-{}-{}",
            std::process::id(),
            &crate::crypto::random_token()[..16]
        ));
        crate::paths::ensure_private_dir(&root, "host probe scratch home")?;
        Ok(Self { root })
    }

    fn apply(&self, command: &mut std::process::Command) {
        command
            .env("HOME", &self.root)
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_DATA_HOME", self.root.join("data"))
            .env("XDG_STATE_HOME", self.root.join("state"))
            .env("XDG_CACHE_HOME", self.root.join("cache"))
            .env("CODEX_HOME", self.root.join(".codex"))
            .env("CLAUDE_CONFIG_DIR", self.root.join(".claude"))
            .env_remove("GUILDHALL_COMPANY_URL")
            .stdin(std::process::Stdio::null());
    }
}

impl Drop for ScratchHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn probe_host(host: &str) -> Result<Value, ContractError> {
    let path = resolve_host_executable(host)?;
    let scratch = ScratchHome::create()?;
    let mut command = std::process::Command::new(&path);
    command.arg("--version");
    scratch.apply(&mut command);
    let output = command.output().map_err(|error| {
        ContractError::degraded(
            "UNSUPPORTED_HOST_VERSION",
            format!("host version probe failed: {}", error.kind()),
            "Repair the host executable or its approved wrapper on PATH.",
        )
    })?;
    drop(scratch);
    let version = version_text(&output.stdout);
    if !output.status.success() || version.is_empty() {
        return Err(ContractError::degraded(
            "UNSUPPORTED_HOST_VERSION",
            format!("host version probe exited with {}", output.status),
            "Install a host CLI or approved wrapper that answers `--version`.",
        ));
    }
    Ok(json!({
        "path": path.to_string_lossy(),
        "version": version,
        "invocation": {
            "argv": [path.to_string_lossy(), "--version"],
            "exit_code": output.status.code(),
            "stdout_bytes": output.stdout.len(),
            "stderr_bytes": output.stderr.len(),
            "scratch_home": true
        }
    }))
}

fn user_home() -> Result<PathBuf, ContractError> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|value| !value.as_os_str().is_empty())
        .ok_or_else(|| {
            ContractError::invariant("HOME is required for user-level hook installation")
        })
}

/// The exact bytes `hooks install` would write for the host's user-level
/// config, rendered from the file as it is now. The plan shows them; the
/// installation writes them; nothing else changes.
fn planned_config_content(
    host: &str,
    destination: &Path,
    program: &str,
) -> Result<String, ContractError> {
    if host == "claude" {
        let bytes = render_claude_settings(destination, host, program)?;
        String::from_utf8(bytes)
            .map_err(|_| ContractError::internal("rendered Claude settings are not UTF-8"))
    } else {
        render_codex_config(destination, host, program)
    }
}

fn plan_payload(
    host_arg: crate::command_types::Host,
    ranges: &crate::config::SharedHosts,
) -> Result<Value, ContractError> {
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
    let host_details = probe_host(host)?;
    let destination = user_home()?.join(relative);
    let content = planned_config_content(host, &destination, &program)?;
    let mut base = json!({
        "host_name": host,
        "host": host_details,
        "status": "planned",
        "files": [{
            "path": relative,
            "exists": destination.is_file(),
            "content": content,
            "mode": "0600"
        }],
        "commands": commands,
        "permissions": [{"path": relative, "mode": "0600"}],
        "required_host_version": host_range(host, ranges),
        "approval": "the host presents its own approval at its next start; no bypass exists"
    });
    // The plan is a display document: its file preview carries newlines,
    // which the durable-record text rule would reject.
    let digest = crate::hash::sha256_text(&crate::json::jcs_text(&base));
    if let Value::Object(map) = &mut base {
        map.insert("plan_digest".to_owned(), Value::String(digest));
    }
    Ok(base)
}

fn plan(
    host: crate::command_types::Host,
    ranges: &crate::config::SharedHosts,
    json: bool,
) -> Result<(), ContractError> {
    let result = plan_payload(host, ranges)?;
    if json {
        println!("{}", crate::json::jcs_text(&result));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
    }
    Ok(())
}

fn install(
    host_arg: crate::command_types::Host,
    ranges: &crate::config::SharedHosts,
    json: bool,
) -> Result<(), ContractError> {
    let plan = plan_payload(host_arg, ranges)?;
    let host = host_name(host_arg);
    let relative = host_relative_config(host);
    let destination = user_home()?.join(relative);
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent).map_err(io_error)?;
    }
    // Write exactly the bytes the plan displayed (C9).
    let content = crate::json::get_array(&plan, "files")
        .and_then(|files| files.first())
        .and_then(|file| crate::json::get_str(file, "content"))
        .ok_or_else(|| ContractError::internal("the hook plan carries no file content"))?
        .to_owned();
    std::fs::write(&destination, content.as_bytes()).map_err(io_error)?;
    set_mode(&destination, 0o600)?;
    let receipt = json!({
        "status": "installed",
        "host": host,
        "plan_digest": plan.get("plan_digest"),
        "files_written": [relative],
        "required_host_version": host_range(host, ranges),
        "host": plan.get("host").cloned().unwrap_or(Value::Null)
    });
    if json {
        println!("{}", crate::json::jcs_text(&receipt));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&receipt).unwrap_or_default()
        );
    }
    Ok(())
}

fn render_codex_config(path: &Path, host: &str, program: &str) -> Result<String, ContractError> {
    let mut table: toml::Value = if path.exists() {
        let text = std::fs::read_to_string(path).map_err(io_error)?;
        text.parse::<toml::Value>().map_err(|error| {
            ContractError::invariant(format!("existing Codex config is not valid TOML: {error}"))
        })?
    } else {
        toml::Value::Table(toml::map::Map::new())
    };
    let toml::Value::Table(root) = &mut table else {
        return Err(ContractError::invariant(
            "existing Codex config must be a TOML table",
        ));
    };
    let hooks = root
        .entry("hooks".to_owned())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    let toml::Value::Table(hooks) = hooks else {
        return Err(ContractError::invariant(
            "existing Codex [hooks] must be a table",
        ));
    };
    for event in HOOK_EVENTS {
        let command = format!("{} hooks dispatch {} {}", shell_quote(program), host, event);
        let mut entry = toml::map::Map::new();
        entry.insert("type".to_owned(), toml::Value::String("command".to_owned()));
        entry.insert("command".to_owned(), toml::Value::String(command));
        hooks.insert(
            event.to_owned(),
            toml::Value::Array(vec![toml::Value::Table(entry)]),
        );
    }
    toml::to_string_pretty(&table).map_err(|error| {
        ContractError::internal(format!("Codex config serialization failed: {error}"))
    })
}

fn render_claude_settings(
    path: &Path,
    host: &str,
    program: &str,
) -> Result<Vec<u8>, ContractError> {
    let mut document: Value = if path.exists() {
        let bytes = std::fs::read(path).map_err(io_error)?;
        crate::json::parse_strict_value(&bytes).map_err(|error| {
            ContractError::invariant(format!(
                "existing Claude settings are not strict JSON: {error}"
            ))
        })?
    } else {
        json!({})
    };
    let Value::Object(settings) = &mut document else {
        return Err(ContractError::invariant(
            "existing Claude settings must be a JSON object",
        ));
    };
    let hooks = settings
        .entry("hooks".to_owned())
        .or_insert_with(|| json!({}));
    let Value::Object(hooks) = hooks else {
        return Err(ContractError::invariant(
            "existing Claude hooks setting must be an object",
        ));
    };
    for event in HOOK_EVENTS {
        let command = format!("{} hooks dispatch {} {}", shell_quote(program), host, event);
        hooks.insert(
            event.to_owned(),
            json!([
                {"hooks": [{"type": "command", "command": command}]}
            ]),
        );
    }
    Ok(crate::json::canonical_bytes(&document))
}

fn set_mode(path: &Path, mode: u32) -> Result<(), ContractError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(io_error)
}

fn supported_event(event: &str) -> bool {
    HOOK_EVENTS.contains(&event)
        || matches!(
            event,
            "session-start"
                | "prompt"
                | "Prompt"
                | "pre-edit"
                | "session-end"
                | "primary-task"
                | "observation"
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
    std::io::stdin().read_to_end(&mut stdin).map_err(|error| {
        ContractError::invariant(format!("host hook stdin is unreadable: {error}"))
    })?;
    let map: Map<String, Value> = if stdin.is_empty() {
        Map::new()
    } else {
        crate::json::parse_strict_value(&stdin)
            .map_err(|error| {
                ContractError::degraded(
                    "UNSUPPORTED_HOST_VERSION",
                    format!("native host envelope is invalid: {error}"),
                    "Send one strict JSON envelope on stdin.",
                )
            })?
            .as_object()
            .cloned()
            .ok_or_else(|| {
                ContractError::degraded(
                    "UNSUPPORTED_HOST_VERSION",
                    "native host envelope must be a JSON object",
                    "Send one strict JSON object on stdin.",
                )
            })?
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
    let mut start = StartState::default();
    if matches!(event_type.as_str(), "SessionStart" | "session-start") {
        start = session_start(&cwd, &mut canonical_facts, &mut unknowns);
        // A freshly certified repository has no fact events yet, but SessionStart
        // still needs a deterministic, host-independent canonical payload. The
        // repository identity is already signed-by-certificate configuration and
        // supplies that bootstrap fact without inventing prose or reading the
        // ambient clock.
        if canonical_facts.is_empty() && start.certified {
            if let Ok(text) = std::fs::read_to_string(cwd.join(".kin").join("config"))
                && let Ok(config) = crate::codebase::RepoConfig::parse(&text)
            {
                canonical_facts.push(json!({
                    "schema": "guildhall-repository/1",
                    "logical_key": "guildhall/repository-identity",
                    "atom_kind": "observation",
                    "state": "current",
                    "schema_version": config.schema_version,
                    "repository_uuid": config.repository_uuid_hint,
                    "safe_name": config.safe_name,
                    "statement": "The certified repository identity and schema version are recorded in .kin/config."
                }));
            }
        }
    }
    // `status` speaks for the canonical Codebase context (verified by the
    // out-of-worktree certificate); `degraded` speaks for the Company context,
    // which a cold, invalid, stale or unverifiable cache withholds loudly.
    let context_verified = repository_initialized && start.certified && !canonical_facts.is_empty();
    let degraded = !context_verified || start.degraded;
    let mut response = json!({
        "hook": host,
        "event_type": event_type,
        "status": if context_verified { "verified" } else { "degraded" },
        "repository_root": cwd.to_string_lossy(),
        "repository_uuid": start.repository_uuid,
        "company_state": start.company_state,
        "cache_state": start.cache_state,
        "canonical_facts": canonical_facts,
        "decisions": [],
        "receipts": [],
        "company_connect_seconds": start.company_connect_seconds,
        "company_refresh": start.refresh,
        "degraded": degraded,
        "degraded_reasons": start.degraded_reasons,
        "notices": start.notices,
        "start_path": start.start_path,
        "full_fsck_performed": false,
        "background_verification_started": start.background_started,
        "trusted_company_facts": start.trusted_company_facts,
        "trusted_context": canonical_facts,
        "events": [],
        "counts": {
            "canonical_facts": canonical_facts.len(),
            "trusted_company_facts": start.trusted_company_facts.len(),
            "events": start.event_count,
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
            merge(
                &mut response,
                json!({
                    "capture_active": true,
                    "personal_root_readable": false,
                    "sandbox_enforced": true,
                    "sandbox_disabled_loudly": false,
                    "stolen_bytes_promoted": false
                }),
            );
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
            merge(
                &mut response,
                json!({"tool_use_allowed": true, "personal_queried": false}),
            );
        }
        "PreCompact" => {
            merge(
                &mut response,
                json!({"compact_allowed": true, "personal_queried": false}),
            );
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
        // The host response is a display document (it carries a measured
        // fractional connect time); the durable-record text rule does not
        // apply to it, JCS ordering and escaping do.
        println!("{}", crate::json::jcs_text(&response));
    } else {
        std::io::stdout()
            .write_all(&stream)
            .and_then(|_| std::io::stdout().flush())
            .map_err(io_error)?;
    }
    Ok(())
}

/// What a host start learned from the verified cache and the bounded probe.
#[derive(Debug)]
struct StartState {
    certified: bool,
    repository_uuid: Option<String>,
    company_state: &'static str,
    cache_state: &'static str,
    start_path: &'static str,
    degraded: bool,
    degraded_reasons: Vec<String>,
    notices: Vec<String>,
    company_connect_seconds: Option<f64>,
    refresh: Value,
    background_started: bool,
    trusted_company_facts: Vec<Value>,
    event_count: usize,
}

impl Default for StartState {
    fn default() -> Self {
        Self {
            certified: false,
            repository_uuid: None,
            company_state: "unverified",
            cache_state: "none",
            start_path: "cold-unverified",
            degraded: true,
            degraded_reasons: Vec::new(),
            notices: Vec::new(),
            company_connect_seconds: None,
            refresh: Value::Null,
            background_started: false,
            trusted_company_facts: Vec::new(),
            event_count: 0,
        }
    }
}

/// SessionStart (architecture §9): resolve the Git root and certified
/// identity; project the previously verified cache; probe the configured
/// Company endpoint inside the 250 ms connection budget; hand verification
/// and refresh to a detached background worker. No fact becomes trusted
/// because that work is still running, and a blackholed endpoint cannot
/// hold the host open.
fn session_start(
    cwd: &Path,
    canonical_facts: &mut Vec<Value>,
    unknowns: &mut Vec<Value>,
) -> StartState {
    let mut state = StartState::default();
    let Ok(launcher) = crate::launcher::Launcher::load() else {
        state
            .degraded_reasons
            .push("launcher configuration unavailable".to_owned());
        return state;
    };
    let Ok(repository) = crate::codebase::Repository::discover(cwd) else {
        state
            .degraded_reasons
            .push("no Git repository at the host cwd".to_owned());
        return state;
    };
    let Ok(clock) = crate::repository::recorded_clock(&launcher, &repository) else {
        state
            .degraded_reasons
            .push("no recorded proof clock".to_owned());
        return state;
    };
    // Offline: the previously verified cache is the only Company input here.
    let Ok(context) = RepoContext::load(launcher.clone(), cwd, false, Some(clock.as_str())) else {
        state
            .degraded_reasons
            .push("repository trust context unavailable".to_owned());
        return state;
    };
    state.repository_uuid = context.trust.repository_uuid.clone();
    state.certified = context.trust.certificate_valid;
    let freshness = context.trust.freshness.as_ref().map(|f| f.at(&clock));
    state.cache_state = match freshness.as_ref().map(|f| &f.state) {
        Some(crate::company::cache::CacheState::Warm) => "warm",
        Some(crate::company::cache::CacheState::Cold) => "cold",
        Some(crate::company::cache::CacheState::Invalid) => "invalid",
        None => "none",
    };
    let revocation_fresh = freshness.as_ref().is_some_and(|f| f.revocation_fresh);
    let fact_fresh = freshness.as_ref().is_some_and(|f| f.fact_fresh);
    if !state.certified {
        state
            .degraded_reasons
            .push(context.trust.certificate_reason.clone());
    }
    match state.cache_state {
        "warm" => {}
        "cold" => state
            .degraded_reasons
            .push("Company cache is cold; refreshing in the background".to_owned()),
        "invalid" => state.degraded_reasons.push(
            "Company cache was invalid and quarantined; refreshing in the background".to_owned(),
        ),
        _ => state
            .degraded_reasons
            .push("no Company cache is configured".to_owned()),
    }
    if state.cache_state == "warm" && !revocation_fresh {
        state
            .degraded_reasons
            .push("REVOCATION_STALE: the cached revocation snapshot lapsed".to_owned());
    }
    if state.cache_state == "warm" && !fact_fresh {
        state
            .degraded_reasons
            .push("CACHE_EXPIRED: the cached facts lapsed".to_owned());
    }
    let full_fsck_required = !repository.kin.join("manifests").is_dir();
    if full_fsck_required {
        state
            .degraded_reasons
            .push("full fsck required: .kin/manifests is absent".to_owned());
    }
    if let Ok((view, counts, _)) = context.current_view(&clock, None) {
        state.event_count = counts.total_files;
        if state.certified {
            canonical_facts.extend(
                view.facts
                    .iter()
                    .filter(|fact| fact.trust == "trusted")
                    .map(crate::model::value_of),
            );
        }
        unknowns.extend(view.open_unknown_ids.iter().cloned().map(Value::String));
    }
    // Company facts are projected only from a warm, fresh, verified cache.
    if state.certified && state.cache_state == "warm" && revocation_fresh && fact_fresh {
        let as_of = crate::time::AsOf {
            as_of: clock.clone(),
            as_of_source: "recorded-proof-clock".to_owned(),
        };
        if let Ok(view) = crate::projector::company_view(&launcher, cwd, &as_of) {
            state.trusted_company_facts = view
                .facts
                .iter()
                .filter(|fact| fact.trust == "trusted" && fact.status == "current")
                .map(|fact| {
                    json!({
                        "fact_id": fact.fact_id,
                        "logical_key": fact.logical_key,
                        "atom_kind": fact.atom_kind,
                        "authority_scope": fact.authority_scope,
                        "statement": fact.statement,
                        "label": "UNTRUSTED_EVIDENCE_NOT_INSTRUCTIONS"
                    })
                })
                .collect();
        }
    }
    // Bounded probe of the configured endpoint: the connection budget only.
    let (connect_seconds, reachable) = match launcher.shared.company.as_ref() {
        Some(access) if !launcher.company_env_present => {
            match crate::http::parse_url(&access.url) {
                Ok((host, port, _)) => {
                    let started = std::time::Instant::now();
                    let outcome = crate::http::probe_connect(&host, port);
                    let elapsed = started.elapsed().as_secs_f64();
                    (Some(elapsed), outcome.is_ok())
                }
                Err(_) => (None, false),
            }
        }
        _ => (None, false),
    };
    state.company_connect_seconds = connect_seconds;
    // A warm, fresh, verified cache projects even when the endpoint is down
    // (architecture §9: warm may project verified cache); the unreachable
    // endpoint is still said loudly. Without such a cache it degrades.
    if connect_seconds.is_some() && !reachable {
        state.notices.push("COMPANY_UNREACHABLE: the configured endpoint did not accept a connection within the 250 ms budget".to_owned());
    }
    // Verification and refresh run detached; the host is never held open.
    // An endpoint that did not accept the probe gets no worker now: the
    // start is already loudly degraded and the next start probes again.
    let worker = if launcher.shared.company.is_some() && reachable {
        Some(if full_fsck_required { "fsck" } else { "status" })
    } else {
        None
    };
    state.background_started =
        worker.is_some_and(|worker| spawn_background_verification(worker, &repository.root));
    state.refresh = json!({
        "endpoint_probed": connect_seconds.is_some(),
        "connected_within_budget": reachable,
        "connect_budget_seconds": 0.25,
        "probe_timeout_seconds": 0.2,
        "worker": worker,
        "started": state.background_started
    });
    state.company_state = if !state.certified {
        "unverified"
    } else if state.cache_state == "warm" && revocation_fresh && fact_fresh {
        if reachable {
            "verified-cache"
        } else {
            "verified-cache-unreachable"
        }
    } else if reachable {
        "refreshing"
    } else {
        "unreachable"
    };
    state.start_path = if !state.certified {
        "cold-unverified"
    } else if state.cache_state == "invalid" {
        "invalid-cache"
    } else if state.cache_state == "cold" || state.cache_state == "none" {
        "cold"
    } else if full_fsck_required {
        "full-fsck-required"
    } else {
        "warm_verified"
    };
    state.degraded = !state.certified
        || state.cache_state != "warm"
        || !revocation_fresh
        || !fact_fresh
        || full_fsck_required;
    if state.degraded {
        state.degraded_reasons.extend(state.notices.iter().cloned());
    }
    state
}

/// Start the background verification worker: this executable running a
/// public command against the repository, detached from the host's process
/// group with no inherited descriptors, so the host response never waits.
fn spawn_background_verification(worker: &str, root: &Path) -> bool {
    use std::os::unix::process::CommandExt;
    let Ok(program) = std::env::current_exe() else {
        return false;
    };
    let mut command = std::process::Command::new(program);
    command
        .arg(worker)
        .arg("--repo")
        .arg(root)
        .arg("--json")
        .current_dir(root)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0);
    command.spawn().is_ok()
}

fn merge(target: &mut Value, additions: Value) {
    let Value::Object(additions) = additions else {
        return;
    };
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

/// The host's hook state from its user-level config alone: a diagnostic
/// reads the file and never runs the host (C9).
pub fn hook_state(host: &str, ranges: &crate::config::SharedHosts) -> Value {
    let relative = host_relative_config(host);
    let configured = std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(relative))
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| hook_config_has_entries(host, &text))
        .unwrap_or(false);
    if configured {
        json!({
            "host": host,
            "config": relative,
            "installed": true,
            "state": "installed",
            "approval_required": false,
            "required_host_version": host_range(host, ranges),
            "personal_queried": false,
            "facts_label": "UNTRUSTED_EVIDENCE_NOT_INSTRUCTIONS"
        })
    } else {
        json!({
            "host": host,
            "config": relative,
            "installed": false,
            "state": "HOOK_APPROVAL_REQUIRED",
            "code": "HOOK_APPROVAL_REQUIRED",
            "approval_required": true,
            "missing_planned_entries": HOOK_EVENTS,
            "required_host_version": host_range(host, ranges),
            "remediation": format!("Run `guildhall hooks plan {host}` to review, then `guildhall hooks install {host}`; the host presents its own approval at its next start."),
            "personal_queried": false,
            "facts_label": "UNTRUSTED_EVIDENCE_NOT_INSTRUCTIONS"
        })
    }
}

/// Every ratified host's hook state, for `doctor`.
pub fn doctor_report(ranges: &crate::config::SharedHosts) -> Value {
    json!({
        "codex": hook_state("codex", ranges),
        "claude": hook_state("claude", ranges)
    })
}

pub fn hook_approval_error(host: &str, ranges: &crate::config::SharedHosts) -> ContractError {
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
    let has_command = |event: &str| text.contains(&format!("hooks dispatch {host} {event}"));
    if host == "claude" {
        let document: Value = serde_json::from_str(text).ok()?;
        let hooks = document.get("hooks")?;
        return Some(
            HOOK_EVENTS
                .iter()
                .all(|event| hooks.get(*event).is_some_and(Value::is_array) && has_command(event)),
        );
    }
    let table: toml::Value = text.parse().ok()?;
    let hooks = table.get("hooks")?;
    Some(
        HOOK_EVENTS.iter().all(|event| {
            hooks.get(*event).is_some_and(toml::Value::is_array) && has_command(event)
        }),
    )
}

pub fn host_version(host: &str) -> String {
    match host {
        "claude" => ">=1.0.0".to_owned(),
        _ => ">=0.0.0".to_owned(),
    }
}
