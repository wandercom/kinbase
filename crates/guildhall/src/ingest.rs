use crate::classify::atomize;
use crate::error::{ContractError, ExitCode};
use crate::hash::sha256_text;
use crate::model::Observation;
use crate::time::now_rfc3339_millis;
use serde_json::json;
use std::path::Path;

pub fn ingest(
    repo: &Path,
    source_kind: &str,
    source: &Path,
    checkpoint: Option<&str>,
    json: bool,
) -> Result<(), ContractError> {
    let bytes = std::fs::read(source).map_err(io_error)?;
    let digest = sha256_text(&String::from_utf8_lossy(&bytes));
    let observation = Observation {
        observation_id: format!("obs_{digest}"),
        source_kind: source_kind.to_owned(),
        source_identity: source.to_string_lossy().into_owned(),
        native_id: source
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("source")
            .to_owned(),
        content_digest: digest,
        repository_id: None,
        revision: None,
        branch: None,
        disposition: "current".to_owned(),
        observed_at: now_rfc3339_millis(),
        asserted_at: None,
        effective_from: None,
        effective_until: None,
        body_ref: source.to_string_lossy().into_owned(),
        extraction_version: crate::classify::EXTRACTION_VERSION.to_owned(),
    };
    let observation_value = serde_json::to_value(&observation)
        .map_err(|error| ContractError::internal(error.to_string()))?;
    let local_dir = repo.join(".kin/local");
    std::fs::create_dir_all(&local_dir).map_err(io_error)?;
    crate::store::append_jsonl(&local_dir.join("observations.jsonl"), &observation_value)
        .map_err(io_error)?;
    let atom = atomize(
        source_kind,
        source.to_string_lossy().as_ref(),
        &String::from_utf8_lossy(&bytes),
        "repository",
        900,
    );
    let atom_value =
        serde_json::to_value(&atom).map_err(|error| ContractError::internal(error.to_string()))?;
    crate::store::append_jsonl(&local_dir.join("atoms.jsonl"), &atom_value).map_err(io_error)?;
    let result = json!({"status":"ingested","observation_count":1,"fact_count":1,"checkpoint":checkpoint,"source_kind":source_kind});
    if json {
        println!("{}", serde_json::to_string(&result).unwrap_or_default());
    } else {
        println!("status: ingested");
        println!("observation_count: 1");
        println!("fact_count: 1");
        println!("source_kind: {source_kind}");
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
