use crate::error::{ContractError, ExitCode};
use serde_json::{Map, Value, json};
use std::io::{IsTerminal, Write};
use std::path::Path;

pub fn dispatch(
    command: crate::command_types::HookCommand,
    json: bool,
) -> Result<(), ContractError> {
    match command {
        crate::command_types::HookCommand::Plan { host } => plan(host, json),
        crate::command_types::HookCommand::Install { host } => install(host, json),
        crate::command_types::HookCommand::Dispatch { host, event } => {
            dispatch_event(host, &event, json)
        }
    }
}

fn host_name(host: crate::command_types::Host) -> &'static str {
    match host {
        crate::command_types::Host::Codex => "codex",
        crate::command_types::Host::Claude => "claude",
    }
}

fn plan_payload(host: crate::command_types::Host) -> Value {
    let host = host_name(host);
    json!({
        "host": host,
        "status": "planned",
        "files": [
            format!(".kin/local/hooks/{host}.json"),
            ".kin/local/hooks/guildhall-dispatch"
        ],
        "commands": [
            {
                "program": std::env::current_exe().unwrap_or_else(|_| "guildhall".into()).to_string_lossy(),
                "args": ["hooks", "dispatch", host, "$EVENT"]
            }
        ],
        "permissions": {
            "config": "0600",
            "executable": "0755",
            "approval": "host-native"
        }
    })
}

fn plan(host: crate::command_types::Host, json: bool) -> Result<(), ContractError> {
    let result = plan_payload(host);
    if json {
        println!("{}", crate::json::canonical_text(&result));
    } else {
        println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
    }
    Ok(())
}

fn install(host_arg: crate::command_types::Host, json: bool) -> Result<(), ContractError> {
    let host = host_name(host_arg);
    let result = plan_payload(host_arg);
    let repo = std::env::current_dir().map_err(io_error)?;
    if !std::io::stdin().is_terminal() {
        return Err(ContractError::new(
            "HOOK_APPROVAL_REQUIRED",
            "interactive host approval is unavailable",
            "Run hooks install from the host's native approval context.",
            false,
            ExitCode::UserActionRequired,
        ));
    }
    println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
    println!("Type 'install {host}' to approve:");
    std::io::stdout().flush().map_err(io_error)?;
    let mut approval = String::new();
    std::io::stdin().read_line(&mut approval).map_err(io_error)?;
    if approval.trim() != format!("install {host}") {
        return Err(ContractError::new(
            "HOOK_APPROVAL_REQUIRED",
            "host approval rejected or malformed",
            "No files were changed; rerun install only through the host approval flow.",
            false,
            ExitCode::UserActionRequired,
        ));
    }
    let directory = repo.join(".kin").join("local").join("hooks");
    std::fs::create_dir_all(&directory).map_err(io_error)?;
    let config_path = directory.join(format!("{host}.json"));
    std::fs::write(&config_path, crate::json::canonical_bytes(&result)).map_err(io_error)?;
    set_mode(&config_path, 0o600)?;
    let executable_path = directory.join("guildhall-dispatch");
    let program = std::env::current_exe().map_err(io_error)?;
    let script = format!(
        "#!/bin/sh\nexec '{}' hooks dispatch {} \"$1\"\n",
        program.to_string_lossy(),
        host
    );
    std::fs::write(&executable_path, script).map_err(io_error)?;
    set_mode(&executable_path, 0o755)?;
    let receipt = json!({
        "status": "installed",
        "host": host,
        "config": ".kin/local/hooks/config",
        "executable": ".kin/local/hooks/guildhall-dispatch"
    });
    if json {
        println!("{}", crate::json::canonical_text(&receipt));
    } else {
        println!("status: installed");
        println!("host: {host}");
    }
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<(), ContractError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(io_error)
}

fn dispatch_event(
    host: crate::command_types::Host,
    event: &str,
    json: bool,
) -> Result<(), ContractError> {
    let host_name = host_name(host);
    let bytes = if Path::new(event).exists() {
        std::fs::read(Path::new(event)).map_err(io_error)?
    } else {
        event.as_bytes().to_vec()
    };
    let map: Map<String, Value> = crate::json::parse_strict_object(&bytes)
        .map_err(|error| ContractError::new("UNSUPPORTED_HOST_VERSION", error, "Use a valid native host envelope.", false, ExitCode::DegradedSafe))?;
    let event_type = map
        .get("event_type")
        .or_else(|| map.get("type"))
        .or_else(|| map.get("hook_event_name"))
        .and_then(Value::as_str)
        .unwrap_or("observation")
        .to_owned();
    if !matches!(
        event_type.as_str(),
        "SessionStart"
            | "session-start"
            | "prompt"
            | "Prompt"
            | "pre-edit"
            | "PreToolUse"
            | "PreCompact"
            | "Stop"
            | "session-end"
            | "primary-task"
            | "observation"
    ) {
        return Err(ContractError::new(
            "UNSUPPORTED_HOST_VERSION",
            format!("unsupported host event: {event_type}"),
            "Use a ratified Codex or Claude native envelope.",
            false,
            ExitCode::DegradedSafe,
        ));
    }
    let repo = std::env::current_dir().map_err(io_error)?;
    let repository_initialized = repo.join(".kin").join("config").exists();
    let mut context_facts = Vec::new();
    let mut unknowns = Vec::new();
    let mut status = "verified".to_owned();
    if !repository_initialized {
        status = "unverified".to_owned();
    } else if matches!(event_type.as_str(), "SessionStart" | "session-start") {
        for store in [crate::StoreKind::Company, crate::StoreKind::Codebase] {
            let root = crate::store::store_root(store, &repo);
            if let Ok(view) = std::fs::read_to_string(root.join("local").join("current.json")) {
                if let Ok(value) = serde_json::from_str::<Value>(&view) {
                    if let Some(facts) = value.get("facts").and_then(Value::as_array) {
                        context_facts.extend(facts.iter().cloned());
                    }
                    if let Some(ids) = value.get("unknown_ids").and_then(Value::as_array) {
                        unknowns.extend(ids.iter().cloned());
                    }
                }
            }
        }
        if context_facts.is_empty() {
            status = "degraded".to_owned();
        }
    }
    let response = json!({
        "hook": host_name,
        "event_type": event_type,
        "status": status,
        "context_facts": context_facts,
        "unknowns": unknowns,
        "label": "UNTRUSTED_EVIDENCE_NOT_INSTRUCTIONS",
        "personal_queried": false
    });
    if json {
        println!("{}", crate::json::canonical_text(&response));
    } else {
        println!("hook: {host_name}");
        println!("event: {event_type}");
        println!("status: {status}");
        println!("label: UNTRUSTED_EVIDENCE_NOT_INSTRUCTIONS");
        println!("personal_queried: false");
    }
    Ok(())
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
