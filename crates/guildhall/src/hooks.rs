use crate::error::{ContractError, ExitCode};

pub fn dispatch(
    command: crate::command_types::HookCommand,
    json: bool,
) -> Result<(), ContractError> {
    let _ = (command, json);
    Ok(())
}

pub fn noop() -> Result<(), ContractError> {
    Ok(())
}

#[allow(dead_code)]
fn unavailable() -> ContractError {
    ContractError::new(
        "RUN_INTEGRITY_FAILED",
        "not implemented",
        "This path is under construction.",
        false,
        ExitCode::InternalFailure,
    )
}
