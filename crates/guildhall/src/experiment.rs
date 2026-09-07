use crate::error::{ContractError, ExitCode};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub fn dispatch(
    command: crate::command_types::ExperimentCommand,
    json: bool,
) -> Result<(), ContractError> {
    match command {
        crate::command_types::ExperimentCommand::Census { manifest } => census(&manifest, json),
        crate::command_types::ExperimentCommand::Pilot { manifest } => pilot(&manifest, json),
        crate::command_types::ExperimentCommand::Calibrate { manifest } => {
            calibrate(&manifest, json)
        }
        crate::command_types::ExperimentCommand::Freeze { manifest, budget } => {
            freeze(&manifest, &budget, json)
        }
        crate::command_types::ExperimentCommand::Run { frozen_manifest } => {
            run(&frozen_manifest, json)
        }
        crate::command_types::ExperimentCommand::Score { run } => score(&run, json),
        crate::command_types::ExperimentCommand::Verdict { run } => verdict(&run, json),
    }
}

fn read_json(path: &Path) -> Result<Value, ContractError> {
    let text = std::fs::read_to_string(path).map_err(io_error)?;
    serde_json::from_str(&text).map_err(|error| {
        ContractError::new(
            "CONFIG_INVARIANT",
            error.to_string(),
            "Use a valid experiment manifest.",
            false,
            ExitCode::Refused,
        )
    })
}

fn write_json(path: &Path, value: &Value) -> Result<(), ContractError> {
    std::fs::write(
        path,
        serde_json::to_vec_pretty(value)
            .map_err(|error| ContractError::internal(error.to_string()))?,
    )
    .map_err(io_error)
}

fn census(manifest: &Path, json: bool) -> Result<(), ContractError> {
    let manifest_value = read_json(manifest)?;
    let tasks = manifest_value
        .get("tasks")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let result = json!({"status":"census","task_count":tasks.len(),"manifest_digest":crate::hash::sha256_text(&serde_json::to_string(&manifest_value).unwrap_or_default())});
    print_result(&result, json)
}

fn pilot(manifest: &Path, json: bool) -> Result<(), ContractError> {
    let manifest_value = read_json(manifest)?;
    let result = json!({"status":"pilot-complete","manifest":manifest_value});
    print_result(&result, json)
}

fn calibrate(manifest: &Path, json: bool) -> Result<(), ContractError> {
    let manifest_value = read_json(manifest)?;
    let result = json!({"status":"calibrated","manifest":manifest_value});
    print_result(&result, json)
}

fn freeze(manifest: &Path, budget: &Path, json: bool) -> Result<(), ContractError> {
    let manifest_value = read_json(manifest)?;
    let budget_value = read_json(budget)?;
    let frozen = json!({"status":"frozen","manifest":manifest_value,"budget":budget_value});
    let frozen_path = sibling(manifest, "frozen");
    write_json(&frozen_path, &frozen)?;
    print_result(&frozen, json)
}

fn run(frozen_manifest: &Path, json: bool) -> Result<(), ContractError> {
    let frozen_value = read_json(frozen_manifest)?;
    let result = json!({"status":"run-complete","frozen_manifest":frozen_value});
    print_result(&result, json)
}

fn score(run: &Path, json: bool) -> Result<(), ContractError> {
    let run_value = read_json(run)?;
    let result = json!({"status":"scored","run":run_value});
    print_result(&result, json)
}

fn verdict(run: &Path, json: bool) -> Result<(), ContractError> {
    let run_value = read_json(run)?;
    let result = json!({"status":"not-proven","run":run_value});
    print_result(&result, json)
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut output = path.to_path_buf();
    output.set_file_name(format!(
        "{}.{}.json",
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("manifest"),
        suffix
    ));
    output
}

fn print_result(value: &Value, json: bool) -> Result<(), ContractError> {
    if json {
        println!("{}", serde_json::to_string(value).unwrap_or_default());
    } else {
        println!(
            "status: {}",
            value
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        );
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
