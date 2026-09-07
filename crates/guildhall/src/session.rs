use crate::error::{ContractError, ExitCode};
use serde_json::json;
use std::path::Path;
use uuid::Uuid;

pub fn start(repo: &Path, host: crate::HostKind, json: bool) -> Result<(), ContractError> {
    let session_id = format!("session_{}", Uuid::new_v4());
    let host_name = if host == crate::HostKind::Codex {
        "codex"
    } else {
        "claude"
    };
    let record = json!({"session_id":session_id,"host":host_name,"repo":repo.to_string_lossy(),"status":"started"});
    let path = repo.join(".kin/local/sessions.jsonl");
    std::fs::create_dir_all(path.parent().unwrap()).map_err(io_error)?;
    crate::store::append_jsonl(&path, &record).map_err(io_error)?;
    if json {
        println!("{}", serde_json::to_string(&record).unwrap_or_default());
    } else {
        println!("session_id: {session_id}");
        println!("host: {host_name}");
    }
    Ok(())
}

pub fn observe(session: &str, event: &Path, json: bool) -> Result<(), ContractError> {
    let text = std::fs::read_to_string(event).map_err(io_error)?;
    let record = json!({"session_id":session,"event":text,"status":"observed"});
    let repo = std::env::current_dir().map_err(io_error)?;
    let path = repo.join(".kin/local/session-events.jsonl");
    std::fs::create_dir_all(path.parent().unwrap()).map_err(io_error)?;
    crate::store::append_jsonl(&path, &record).map_err(io_error)?;
    if json {
        println!("{}", serde_json::to_string(&record).unwrap_or_default());
    } else {
        println!("session: {session}");
    }
    Ok(())
}

pub fn checkpoint(session: &str, json: bool) -> Result<(), ContractError> {
    let record = json!({"session_id":session,"status":"checkpointed"});
    if json {
        println!("{}", serde_json::to_string(&record).unwrap_or_default());
    } else {
        println!("session: {session}");
    }
    Ok(())
}

pub fn end(session: &str, json: bool) -> Result<(), ContractError> {
    let record = json!({"session_id":session,"status":"ended"});
    if json {
        println!("{}", serde_json::to_string(&record).unwrap_or_default());
    } else {
        println!("session: {session}");
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
