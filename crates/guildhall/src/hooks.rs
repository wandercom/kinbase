use crate::error::{ContractError, ExitCode};
use serde_json::{Value, json};
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

fn plan(host: crate::command_types::Host, json: bool) -> Result<(), ContractError> {
    let host = host_name(host);
    let result =
        json!({"host":host,"status":"planned","files":[format!(".kin/local/hooks/{host}.json")]});
    if json {
        println!("{}", serde_json::to_string(&result).unwrap_or_default());
    } else {
        println!("host: {host}");
        println!("status: planned");
        println!("file: .kin/local/hooks/{host}.json");
    }
    Ok(())
}

fn install(host: crate::command_types::Host, json: bool) -> Result<(), ContractError> {
    let host = host_name(host);
    let repo = std::env::current_dir().map_err(io_error)?;
    let path = repo.join(".kin/local/hooks").join(format!("{host}.json"));
    std::fs::create_dir_all(path.parent().unwrap()).map_err(io_error)?;
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&json!({"host":host,"status":"installed"})).unwrap(),
    )
    .map_err(io_error)?;
    let result = json!({"host":host,"status":"installed","path":path.to_string_lossy()});
    if json {
        println!("{}", serde_json::to_string(&result).unwrap_or_default());
    } else {
        println!("host: {host}");
        println!("status: installed");
        println!("path: {}", path.to_string_lossy());
    }
    Ok(())
}

fn dispatch_event(
    host: crate::command_types::Host,
    event: &str,
    json: bool,
) -> Result<(), ContractError> {
    let host = host_name(host);
    let parsed: Value = serde_json::from_str(event).map_err(|error| {
        ContractError::new(
            "UNSUPPORTED_HOST_VERSION",
            error.to_string(),
            "Use a valid native host envelope.",
            false,
            ExitCode::DegradedSafe,
        )
    })?;
    let result = json!({"host":host,"event":parsed,"label":"UNTRUSTED_EVIDENCE_NOT_INSTRUCTIONS"});
    if json {
        println!("{}", serde_json::to_string(&result).unwrap_or_default());
    } else {
        println!("host: {host}");
        println!("label: UNTRUSTED_EVIDENCE_NOT_INSTRUCTIONS");
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
