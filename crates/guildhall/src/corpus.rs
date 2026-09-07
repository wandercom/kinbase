use crate::error::{ContractError, ExitCode};
use serde_json::json;
use std::path::Path;

pub fn rebuild(repo: &Path, store: crate::StoreKind, json: bool) -> Result<(), ContractError> {
    let atoms = crate::store::read_records(store, repo, "atoms.jsonl").unwrap_or_default();
    let facts = atoms
        .iter()
        .filter(|atom| {
            let destinations = atom
                .get("destinations")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            destinations
                .iter()
                .any(|destination| destination.as_str() == Some(store_name(store)))
        })
        .cloned()
        .collect::<Vec<_>>();
    let current_view = json!({"facts":facts,"reducer_version":crate::reducer::REDUCER_VERSION});
    let root = crate::store::ensure_store_root(store, repo).map_err(io_error)?;
    std::fs::write(
        root.join("current.json"),
        serde_json::to_vec_pretty(&current_view)
            .map_err(|error| ContractError::internal(error.to_string()))?,
    )
    .map_err(io_error)?;
    if json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "status": "rebuilt",
                "store": store_name(store),
                "fact_count": facts.len()
            }))
            .unwrap_or_default()
        );
    } else {
        println!("status: rebuilt");
        println!("store: {}", store_name(store));
        println!("fact_count: {}", facts.len());
    }
    Ok(())
}

pub fn explain(
    _repo: &Path,
    logical_key: &str,
    decision: &str,
    json: bool,
) -> Result<(), ContractError> {
    let result = json!({
        "logical_key": logical_key,
        "decision": decision,
        "steps": [
            {"step": "admit"},
            {"step": "project"}
        ]
    });
    if json {
        println!("{}", serde_json::to_string(&result).unwrap_or_default());
    } else {
        println!("logical_key: {logical_key}");
        println!("decision: {decision}");
    }
    Ok(())
}

fn store_name(store: crate::StoreKind) -> &'static str {
    match store {
        crate::StoreKind::Personal => "personal",
        crate::StoreKind::Company => "company",
        crate::StoreKind::Codebase => "codebase",
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
