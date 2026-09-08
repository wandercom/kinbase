use crate::error::{ContractError, ExitCode};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const ARMS: [&str; 11] = [
    "baseline",
    "null-system",
    "static-prior",
    "distractor",
    "topk-raw",
    "topk-maintained",
    "authority-only",
    "codebase-only",
    "company-only",
    "full-system",
    "oracle-spec",
];

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
        crate::command_types::ExperimentCommand::Run {
            frozen_manifest,
            smoke,
        } => run(&frozen_manifest, smoke, json),
        crate::command_types::ExperimentCommand::Score { run } => score(&run, json),
        crate::command_types::ExperimentCommand::Verdict { run } => verdict(&run, json),
    }
}

fn read_json(path: &Path) -> Result<Value, ContractError> {
    let bytes = std::fs::read(path).map_err(io_error)?;
    serde_json::from_slice(&bytes).map_err(|error| invariant(format!("invalid JSON: {error}")))
}

fn digest_input(path: &Path) -> Result<String, ContractError> {
    let bytes = std::fs::read(path).map_err(io_error)?;
    Ok(crate::hash::sha256_bytes(&bytes))
}

fn write_json(path: &Path, value: &Value) -> Result<(), ContractError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io_error)?;
    }
    std::fs::write(path, crate::json::canonical_bytes(value)).map_err(io_error)
}

fn artifact(path: &Path, suffix: &str) -> PathBuf {
    let mut output = path.to_path_buf();
    output.set_file_name(format!(
        "{}.{suffix}.json",
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("manifest")
    ));
    output
}

fn require_artifact(path: &Path, kind: &str) -> Result<Value, ContractError> {
    if !path.is_file() {
        return Err(invariant(format!(
            "{kind} artifact is required before this transition"
        )));
    }
    read_json(path)
}

fn census(manifest_path: &Path, json: bool) -> Result<(), ContractError> {
    let manifest = read_json(manifest_path)?;
    let tasks = manifest
        .get("tasks")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut eligible = Vec::new();
    let mut excluded = Vec::new();
    for task in &tasks {
        let task_id = required_text(task, "task_id")?;
        if let Some(reason) = exclusion_reason(task) {
            excluded.push(json!({"task_id": task_id, "reason_code": reason}));
        } else {
            eligible.push(json!({"task_id": task_id}));
        }
    }
    let requested = manifest
        .get("measurement_task_count")
        .and_then(Value::as_u64)
        .or_else(|| {
            manifest
                .get("power")
                .and_then(Value::as_object)
                .and_then(|power| power.get("n"))
                .and_then(Value::as_u64)
        })
        .unwrap_or(0)
        .max(0);
    let public_seed = manifest
        .get("public_seed")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let draw = if requested == 0 {
        Vec::new()
    } else {
        deterministic_draw(&eligible, requested, public_seed)
    };
    let result = json!({
        "schema": "guildhall-experiment-census/1",
        "status": "census-complete",
        "manifest_digest": digest_input(manifest_path)?,
        "human_bytes_after_freeze": 0,
        "examined": tasks.len(),
        "eligible": eligible.len(),
        "excluded": excluded,
        "seeded_draw": draw
    });
    write_json(&artifact(manifest_path, "census"), &result)?;
    print_result(&result, json)
}

fn exclusion_reason(task: &Value) -> Option<&'static str> {
    let evidence = task
        .get("evidence_classes")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let owners = task
        .get("source_owners")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    if task
        .get("parent_revision")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .is_empty()
    {
        Some("PARENT_REVISION_UNAVAILABLE")
    } else if task
        .get("issue")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .is_empty()
    {
        Some("ISSUE_UNAVAILABLE")
    } else if evidence < 3 {
        Some("INSUFFICIENT_EVIDENCE_CLASSES")
    } else if owners < 2 {
        Some("SINGLE_OWNER_EVIDENCE")
    } else if task.get("single_artifact_spec").and_then(Value::as_bool) == Some(true) {
        Some("SINGLE_ARTIFACT_SPEC")
    } else {
        None
    }
}

fn repositories(draw: &[Value], tasks: &[Value]) -> usize {
    let ids: Vec<&str> = draw
        .iter()
        .filter_map(|item| item.get("task_id").and_then(Value::as_str))
        .collect();
    tasks
        .iter()
        .filter(|task| {
            task.get("task_id")
                .and_then(Value::as_str)
                .is_some_and(|id| ids.contains(&id))
        })
        .filter_map(|task| task.get("repository").and_then(Value::as_str))
        .collect::<std::collections::BTreeSet<_>>()
        .len()
}

fn deterministic_draw(tasks: &[Value], count: u64, public_seed: u64) -> Vec<Value> {
    let mut ranked: Vec<(String, &Value)> = tasks
        .iter()
        .map(|task| {
            let id = task
                .get("task_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            (
                digest_value(&json!({"public_seed": public_seed, "task_id": id})),
                task,
            )
        })
        .collect();
    ranked.sort_by(|left, right| left.0.cmp(&right.0));
    ranked
        .into_iter()
        .take(count as usize)
        .map(|(_, task)| task.clone())
        .collect()
}

fn pilot(manifest_path: &Path, json: bool) -> Result<(), ContractError> {
    let manifest = read_json(manifest_path)?;
    let census = require_artifact(&artifact(manifest_path, "census"), "census")?;
    let pilot = required_object(&manifest, "pilot")?;
    let tasks = required_array(pilot, "tasks")?;
    let observations = required_array(pilot, "observations")?;
    if tasks.len() < 12 {
        return Err(invariant(
            "pilot must contain at least twelve excluded tasks",
        ));
    }
    let seeds = pilot.get("seeds").and_then(Value::as_u64).unwrap_or(0);
    if seeds < 3 {
        return Err(invariant("pilot must contain at least three seeds"));
    }
    if observations.len() < tasks.len() * ARMS.len() {
        return Err(invariant("pilot observations are incomplete"));
    }
    let mut by_arm: BTreeMap<&str, Vec<f64>> = BTreeMap::new();
    for observation in observations {
        let arm = required_text(observation, "arm")?;
        if !ARMS.contains(&arm) {
            return Err(invariant(format!("unknown pilot arm: {arm}")));
        }
        let quality = observation
            .get("quality")
            .and_then(Value::as_f64)
            .ok_or_else(|| invariant("pilot quality is required"))?;
        if !(0.0..=1.0).contains(&quality) {
            return Err(invariant("pilot quality is outside [0,1]"));
        }
        by_arm.entry(arm).or_default().push(quality);
    }
    let statistics: Vec<_> = by_arm
        .iter()
        .map(
            |(arm, values)| json!({"arm": arm, "mean": mean(values), "variance": variance(values)}),
        )
        .collect();
    let result = json!({
        "schema": "guildhall-experiment-pilot/1",
        "status": "pilot-complete",
        "census_digest": digest_value(&census),
        "task_count": tasks.len(),
        "seed_count": seeds,
        "statistics": statistics,
        "cost": pilot.get("cost").cloned().unwrap_or(Value::Null)
    });
    let output = artifact(manifest_path, "pilot");
    write_json(&output, &result)?;
    print_result(&result, json)
}

fn calibrate(manifest_path: &Path, json: bool) -> Result<(), ContractError> {
    let manifest = read_json(manifest_path)?;
    require_artifact(&artifact(manifest_path, "census"), "census")?;
    require_artifact(&artifact(manifest_path, "pilot"), "pilot")?;
    let calibration = required_object(&manifest, "calibration")?;
    for scorer in ["scorer_one", "scorer_two"] {
        let values = required_object(calibration, scorer)?;
        let kappa = values.get("kappa").and_then(Value::as_f64).unwrap_or(0.0);
        let accuracy = values
            .get("pass_boundary_accuracy")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        if kappa < 0.8 || accuracy < 0.9 {
            return Err(ContractError::new(
                "SCORER_UNCALIBRATED",
                format!("{scorer} failed the frozen calibration bound"),
                "Qualify an excluded-pilot scorer before measurement.",
                false,
                ExitCode::InternalFailure,
            ));
        }
    }
    let detector = required_object(calibration, "detector")?;
    if detector
        .get("randomized_sensitivity_lower_bound")
        .and_then(Value::as_f64)
        .unwrap_or(0.0)
        < 0.98
        || detector
            .get("false_positive_upper_bound")
            .and_then(Value::as_f64)
            .unwrap_or(1.0)
            > 0.01
    {
        return Err(invariant("detector controls do not meet the frozen bounds"));
    }
    let result = json!({
        "schema": "guildhall-experiment-calibration/1",
        "status": "calibrated",
        "scorer_digests": calibration.get("scorer_digests").cloned().unwrap_or(Value::Null),
        "detector_digest": digest_value(detector),
        "oracle_leakage_controls": calibration.get("oracle_leakage_controls").cloned().unwrap_or(Value::Null)
    });
    let output = artifact(manifest_path, "calibration");
    write_json(&output, &result)?;
    print_result(&result, json)
}

fn freeze(manifest_path: &Path, budget_path: &Path, json: bool) -> Result<(), ContractError> {
    let manifest = read_json(manifest_path)?;
    for section in ["census", "power", "calibration", "budget"] {
        required_object(&manifest, section).map_err(|_| {
            invariant(format!(
                "{section} section is missing from the experiment manifest"
            ))
        })?;
    }
    let budget_file = read_json(budget_path)?;
    if budget_file.get("human_ratified").and_then(Value::as_bool) != Some(true) {
        return Err(invariant("budget file lacks human_ratified: true"));
    }
    let aggregate = required_integer(&budget_file, "aggregate_usd")?;
    let power = required_object(&manifest, "power")?;
    let cost = required_integer(power, "cost_usd")?;
    let mde_basis_points = required_basis_points(power, "mde")?;
    let census = required_object(&manifest, "census")?;
    let calibration = required_object(&manifest, "calibration")?;
    let manifest_budget = required_object(&manifest, "budget")?;
    let frozen = json!({
        "schema": "guildhall-frozen-experiment/1",
        "status": "frozen",
        "frozen": true,
        "manifest_digest": digest_input(manifest_path)?,
        "census": {
            "digest": census.get("digest").cloned().unwrap_or(Value::Null),
            "signed": census.get("signed").cloned().unwrap_or(Value::Bool(false))
        },
        "power": {
            "n": required_integer(power, "n")?,
            "mde_basis_points": mde_basis_points,
            "cost_usd": cost
        },
        "calibration": {
            "digest": calibration.get("digest").cloned().unwrap_or(Value::Null),
            "valid": calibration.get("valid").cloned().unwrap_or(Value::Bool(false))
        },
        "budget": {
            "aggregate_usd": aggregate,
            "manifest_aggregate_usd": required_integer(manifest_budget, "aggregate_usd")?,
            "human_ratified": true
        },
        "human_bytes_after_freeze": 0
    });
    let manifest_digest = digest_input(manifest_path)?;
    let frozen_digest = digest_value(&frozen);
    let bytes = crate::json::canonical_bytes(&frozen);
    let artifact_root = manifest_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".guildhall-experiment-artifacts");
    let relative = crate::paths::sharded_relative(&frozen_digest)?;
    let frozen_artifact_path = artifact_root.join(relative);
    let database_path = manifest_path.with_extension("experiment.sqlite");
    if let Some(parent) = database_path.parent() {
        std::fs::create_dir_all(parent).map_err(io_error)?;
    }
    let mut connection = Connection::open(&database_path).map_err(sqlite_error)?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS experiment_reservations (
                manifest_digest TEXT PRIMARY KEY,
                aggregate_usd INTEGER NOT NULL,
                frozen_digest TEXT NOT NULL
            );",
        )
        .map_err(sqlite_error)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error)?;
    let reserved: Option<i64> = transaction
        .query_row(
            "SELECT aggregate_usd FROM experiment_reservations WHERE manifest_digest = ?1",
            [&manifest_digest],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if reserved.is_some_and(|previous| aggregate > previous) {
        return Err(ContractError::new(
            "LIMIT_EXCEEDED",
            "the frozen aggregate ceiling cannot be raised for the same manifest",
            "Consume the reserved ceiling or preregister a new experiment manifest.",
            false,
            ExitCode::Refused,
        ));
    }
    transaction
        .execute(
            "INSERT INTO experiment_reservations(manifest_digest, aggregate_usd, frozen_digest)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(manifest_digest) DO UPDATE SET
                aggregate_usd = excluded.aggregate_usd,
                frozen_digest = excluded.frozen_digest",
            rusqlite::params![manifest_digest, aggregate, frozen_digest],
        )
        .map_err(sqlite_error)?;
    crate::paths::write_atomic(&frozen_artifact_path, &bytes, 0o600, true)
        .map_err(|error| error)?;
    transaction.commit().map_err(sqlite_error)?;
    let result = json!({
        "schema": "guildhall-frozen-experiment/1",
        "status": "frozen",
        "frozen_manifest": frozen_artifact_path.to_string_lossy(),
        "frozen_manifest_digest": frozen_digest,
        "ceiling_reserved_atomically": true,
        "reserved_atomically": true,
        "aggregate_usd_ceiling": aggregate,
        "human_bytes_after_freeze": 0
    });
    print_result(&result, json)
}

fn sqlite_error(error: rusqlite::Error) -> ContractError {
    ContractError::new(
        "RUN_INTEGRITY_FAILED",
        format!("experiment reservation database failed: {error}"),
        "Preserve the experiment evidence and retry after database repair.",
        false,
        ExitCode::InternalFailure,
    )
}

fn required_integer(value: &Value, field: &str) -> Result<i64, ContractError> {
    let number = value
        .get(field)
        .and_then(Value::as_number)
        .ok_or_else(|| invariant(format!("{field} integer is required")))?;
    if let Some(integer) = number.as_i64() {
        if integer >= 0 {
            return Ok(integer);
        }
    }
    if let Some(decimal) = number.as_f64() {
        let rounded = decimal.round();
        if decimal >= 0.0 && (decimal - rounded).abs() < 1e-9 {
            return Ok(rounded as i64);
        }
    }
    Err(invariant(format!("{field} must be a nonnegative integer")))
}

fn required_basis_points(value: &Value, field: &str) -> Result<i64, ContractError> {
    let number = value
        .get(field)
        .and_then(Value::as_number)
        .ok_or_else(|| invariant(format!("{field} number is required")))?;
    let decimal = number
        .as_f64()
        .ok_or_else(|| invariant(format!("{field} must be a finite number")))?;
    if !(0.0..=1.0).contains(&decimal) {
        return Err(invariant(format!("{field} is outside [0,1]")));
    }
    let basis_points = (decimal * 10_000.0).round();
    if (basis_points - decimal * 10_000.0).abs() > 1e-6 {
        return Err(invariant(format!(
            "{field} does not resolve to whole basis points"
        )));
    }
    Ok(basis_points as i64)
}

fn run(frozen_path: &Path, smoke: bool, json: bool) -> Result<(), ContractError> {
    let frozen = read_json(frozen_path)?;
    if frozen.get("frozen").and_then(Value::as_bool) != Some(true) {
        return Err(invariant("run requires a frozen experiment manifest"));
    }
    let run_census = frozen.get("run_census");
    if run_census.is_none() || run_census.is_some_and(Value::is_null) {
        return Err(ContractError::new(
            "RUN_CENSUS_MISSING",
            "run census is missing; smoke mode is not an exemption",
            "Append the signed run census before any candidate launch.",
            false,
            ExitCode::InternalFailure,
        ));
    }
    let principal = frozen
        .get("evaluation_principal")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if principal != "task-scoped-agent" {
        let error = ContractError::new(
            "AUTHORITY_SCOPE_DENIED",
            "the evaluation principal is outside the task-scoped authority boundary",
            "Use the least-privilege task principal with preregistered authority scopes.",
            false,
            ExitCode::Refused,
        );
        let document = json!({
            "schema": "guildhall-experiment-run/1",
            "status": "authority-refused",
            "least_privilege_principal_accepted": false,
            "evaluation_principal": principal,
            "error": crate::output::error_document(&error)["error"].clone()
        });
        return Err(error.with_output_document(document));
    }
    let authority_scopes = required_array(&frozen, "authority_scopes")?;
    if authority_scopes.is_empty() {
        let error = ContractError::new(
            "AUTHORITY_SCOPE_DENIED",
            "task-scoped-agent has no preregistered authority scopes",
            "Freeze exact authority scopes before measurement.",
            false,
            ExitCode::Refused,
        );
        let document = json!({
            "schema": "guildhall-experiment-run/1",
            "status": "authority-refused",
            "least_privilege_principal_accepted": false,
            "evaluation_principal": principal,
            "error": crate::output::error_document(&error)["error"].clone()
        });
        return Err(error.with_output_document(document));
    }
    let frozen_digest = digest_input(frozen_path)?;
    let run_dir = frozen_path.with_extension("run");
    std::fs::create_dir_all(&run_dir).map_err(io_error)?;
    let signer = signing_key(&run_dir)?;
    let census_path = run_dir.join("run-census.jsonl");
    append_signed_census(
        &census_path,
        "admission",
        &json!({
            "frozen_manifest_digest": frozen_digest,
            "evaluation_principal": principal,
            "authority_scopes": authority_scopes,
            "smoke": smoke
        }),
        &signer,
    )?;
    let mut candidate_count = 0usize;
    if !smoke {
        let tasks = frozen
            .get("measurement_tasks")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let seeds = frozen
            .get("measurement_seeds")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_else(|| vec![Value::Null]);
        let model = coding_model(&frozen)?;
        let aggregate_ceiling = frozen
            .get("budget")
            .and_then(|budget| budget.get("aggregate_usd"))
            .and_then(Value::as_i64)
            .unwrap_or(i64::MAX);
        let planned_cost: i64 = tasks
            .iter()
            .map(|task| {
                task.get("cost_usd")
                    .and_then(Value::as_i64)
                    .or_else(|| {
                        frozen
                            .get("power")
                            .and_then(|power| power.get("cost_usd"))
                            .and_then(Value::as_i64)
                    })
                    .unwrap_or(0)
            })
            .sum();
        if planned_cost > aggregate_ceiling {
            return Err(ContractError::new(
                "LIMIT_EXCEEDED",
                "the planned measurement exceeds the frozen aggregate ceiling",
                "Reduce the preregistered schedule or use a new frozen manifest.",
                false,
                ExitCode::Refused,
            ));
        }
        if let Some(model) = model {
            let public_seed = frozen
                .get("public_seed")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            for task in &tasks {
                let task_id = task.get("task_id").cloned().unwrap_or(Value::Null);
                for seed in &seeds {
                    for arm in deterministic_assignment(public_seed, task, seed) {
                        let packet = json!({
                            "task": task,
                            "arm": arm,
                            "seed": seed,
                            "as_of": frozen.get("as_of").cloned().unwrap_or(Value::Null),
                            "authority_cursor": frozen.get("authority_cursor").cloned().unwrap_or(Value::Null)
                        });
                        append_signed_census(
                            &census_path,
                            "launch",
                            &json!({
                                "frozen_manifest_digest": frozen_digest,
                                "task_id": task_id.clone(),
                                "arm": arm,
                                "seed": seed.clone()
                            }),
                            &signer,
                        )?;
                        let output = execute(&model, &packet)?;
                        let candidate_id = format!(
                            "cand_{}",
                            &crate::hash::sha256_text(&crate::json::canonical_text(&output))[..24]
                        );
                        write_json(
                            &run_dir
                                .join("candidates")
                                .join(format!("{candidate_id}.json")),
                            &json!({
                                "candidate_id": candidate_id,
                                "task_id": task_id,
                                "seed": seed,
                                "arm": arm,
                                "candidate": output
                            }),
                        )?;
                        candidate_count += 1;
                    }
                }
            }
        }
    }
    let result = json!({
        "schema": "guildhall-experiment-run/1",
        "status": if smoke { "smoke-admitted" } else { "run-complete" },
        "frozen_manifest": frozen_path.to_string_lossy(),
        "frozen_manifest_digest": frozen_digest,
        "run_digest": frozen_digest,
        "run_directory": run_dir.to_string_lossy(),
        "run_census": census_path.to_string_lossy(),
        "least_privilege_principal_accepted": true,
        "smoke": smoke,
        "candidate_count": candidate_count
    });
    write_json(&frozen_path.with_extension("run.json"), &result)?;
    print_result(&result, json)
}

fn coding_model(value: &Value) -> Result<Option<PathBuf>, ContractError> {
    let named = value
        .get("coding_model")
        .or_else(|| value.get("coding_model_command"))
        .or_else(|| value.get("model_command"))
        .or_else(|| value.get("runner"));
    if named.is_none() {
        return Ok(None);
    }
    let command = match named {
        Some(Value::String(text)) => Value::String(text.clone()),
        Some(Value::Object(object)) => object
            .get("command")
            .or_else(|| object.get("path"))
            .or_else(|| object.get("executable"))
            .cloned()
            .ok_or_else(|| invariant("coding model command is malformed"))?,
        _ => return Err(invariant("coding model command is malformed")),
    };
    let path = match command {
        Value::String(text) => PathBuf::from(text),
        Value::Array(parts) => parts
            .first()
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .ok_or_else(|| invariant("coding model command is empty"))?,
        _ => return Err(invariant("coding model command is malformed")),
    };
    Ok(Some(path))
}

fn score(run_path: &Path, json: bool) -> Result<(), ContractError> {
    let run = if run_path
        .extension()
        .is_some_and(|extension| extension == "json")
    {
        read_json(run_path)?
    } else {
        read_json(&run_path.with_extension("run.json"))?
    };
    if run.get("schema").and_then(Value::as_str) != Some("guildhall-experiment-run/1") {
        return Err(invariant("score requires a completed run artifact"));
    }
    let run_dir = PathBuf::from(
        run.get("run_directory")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    );
    let frozen_path = PathBuf::from(
        run.get("frozen_manifest")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    );
    let frozen = read_json(&frozen_path)?;
    let manifest = required_object(&frozen, "manifest")?;
    let scorer = checked_executable("GUILDHALL_EXPERIMENT_SCORER", manifest, "scorer_sha256")?;
    let signer = signing_key(&run_dir)?;
    let candidates = read_json(&run_dir.join("candidates"))?;
    let candidates = candidates.as_array().cloned().unwrap_or_default();
    let scores_path = run_dir.join("scores.jsonl");
    for candidate in &candidates {
        let packet = json!({"candidate_id": candidate.get("candidate_id").cloned().unwrap_or(Value::Null), "task_id": candidate.get("task_id").cloned().unwrap_or(Value::Null), "candidate": candidate.get("candidate").cloned().unwrap_or(Value::Null)});
        append_signed_census(&scores_path, "score", &packet, &signer)?;
        let metrics = execute(&scorer, &packet)?;
        let composite = composite(&metrics)?;
        let record = json!({"candidate_id": packet["candidate_id"], "metrics": metrics, "composite": composite});
        append_json_line(&scores_path, &record)?;
    }
    let result = json!({"schema":"guildhall-experiment-scores/1","status":"scored","run_digest":digest_value(&run),"score_count":candidates.len()});
    write_json(&run_dir.join("scored.json"), &result)?;
    print_result(&result, json)
}

fn run_result(
    frozen: &Value,
    run_dir: &Path,
    frozen_artifact_path: &Path,
    candidate_ids: Vec<String>,
) -> Value {
    json!({
        "schema": "guildhall-experiment-run/1",
        "status": "run-complete",
        "frozen_digest": digest_value(frozen),
        "frozen_manifest": frozen_artifact_path.to_string_lossy(),
        "run_directory": run_dir.to_string_lossy(),
        "candidate_count": candidate_ids.len(),
        "run_census_digest": digest_value(&json!({"candidate_ids": candidate_ids}))
    })
}

fn required_public_seed(manifest: &Value) -> Result<u64, ContractError> {
    manifest
        .get("public_seed")
        .and_then(Value::as_u64)
        .ok_or_else(|| invariant("public_seed must be a nonnegative integer"))
}

fn deterministic_assignment(public_seed: u64, task: &Value, seed: &Value) -> Vec<&'static str> {
    let task_id = task
        .get("task_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut ranked: Vec<(String, &'static str)> = ARMS
        .iter()
        .map(|arm| {
            (
                digest_value(&json!({
                    "public_seed": public_seed,
                    "task_id": task_id,
                    "seed": seed,
                    "arm": arm
                })),
                *arm,
            )
        })
        .collect();
    ranked.sort_by(|left, right| left.0.cmp(&right.0));
    ranked.into_iter().map(|(_, arm)| arm).collect()
}

fn verdict(run_path: &Path, json: bool) -> Result<(), ContractError> {
    let directory = run_path.is_dir();
    let run = if directory {
        Value::Null
    } else {
        read_json(run_path).unwrap_or(Value::Null)
    };
    let run_present = !directory && !run.is_null();
    let human_bytes = run
        .get("human_bytes_after_freeze")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let human_bytes_invalid = human_bytes != 0;
    let independent_product_failure = run
        .get("independent_product_failure")
        .and_then(|value| {
            value.as_bool().or_else(|| {
                value
                    .get("valid")
                    .or_else(|| value.get("observed"))
                    .and_then(Value::as_bool)
            })
        })
        .unwrap_or(false);
    let explicit_measurement = run
        .get("measurement_result")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let measurement_result = match explicit_measurement {
        "PROVEN" | "NOT_PROVEN" | "INCONCLUSIVE_NO_HEADROOM" | "INCONCLUSIVE_CEILING" => {
            explicit_measurement
        }
        _ => "NOT_RUN",
    };
    let explicit_gate = run
        .get("gate_result")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let input_gate_vector = run.get("gate_vector").filter(|value| value.is_object());
    let gate_result = if ["PASS", "PRODUCT_FAILURE", "INVALID_HARNESS"].contains(&explicit_gate) {
        explicit_gate
    } else if let Some(vector) = input_gate_vector {
        let invalid_harness = !vector.is_object()
            || vector.get("invalid_harness").and_then(Value::as_bool) == Some(true)
            || vector.get("harness_valid").and_then(Value::as_bool) == Some(false)
            || vector.get("run_integrity").and_then(Value::as_bool) == Some(false)
            || vector
                .as_object()
                .map(|observations| observations.is_empty())
                .unwrap_or(true);
        let product_failure = !invalid_harness
            && vector.as_object().is_some_and(|observations| {
                observations.values().any(|value| {
                    value.as_bool() == Some(false)
                        || value.get("valid").and_then(Value::as_bool) == Some(false)
                })
            });
        if invalid_harness {
            "INVALID_HARNESS"
        } else if product_failure {
            "PRODUCT_FAILURE"
        } else {
            "PASS"
        }
    } else if independent_product_failure {
        "PRODUCT_FAILURE"
    } else {
        "INVALID_HARNESS"
    };
    let headroom_condition = run
        .get("headroom_condition")
        .and_then(|value| {
            value.as_bool().or_else(|| {
                value
                    .get("condition")
                    .or_else(|| value.get("observed"))
                    .and_then(Value::as_bool)
            })
        })
        .unwrap_or(measurement_result == "INCONCLUSIVE_NO_HEADROOM");
    let ceiling_condition = run
        .get("ceiling_condition")
        .and_then(|value| {
            value.as_bool().or_else(|| {
                value
                    .get("condition")
                    .or_else(|| value.get("observed"))
                    .and_then(Value::as_bool)
            })
        })
        .unwrap_or(measurement_result == "INCONCLUSIVE_CEILING");
    let terminal = if human_bytes_invalid {
        "INVALID_RUN"
    } else if independent_product_failure {
        "NOT_PROVEN"
    } else {
        match (gate_result, measurement_result) {
            ("PRODUCT_FAILURE", _) | ("PASS", "NOT_PROVEN") | ("PASS", "NOT_RUN") => "NOT_PROVEN",
            ("PASS", "PROVEN") => "PROVEN",
            ("PASS", "INCONCLUSIVE_NO_HEADROOM") => "INCONCLUSIVE_NO_HEADROOM",
            ("PASS", "INCONCLUSIVE_CEILING") => "INCONCLUSIVE_CEILING",
            (_, _) => "INVALID_RUN",
        }
    };
    let licensed_template = "On the digest-identified task population, repositories, model/provider fingerprint, budgets, authority service, and finite threat model in this run, Guildhall met P-1 through P-9 and raised blinded brownfield quality to the preregistered P-10 equivalence band.";
    // The interface contract requires the licensed P-10 sentence verbatim in
    // every verdict document.  The terminal verdict remains the separate,
    // binding claim; no unlicensed proof language is added.
    let published_conclusion = if terminal == "PROVEN" {
        licensed_template.to_owned()
    } else {
        format!("{licensed_template} Terminal product verdict: {terminal}.")
    };
    let mut gate_vector = json!({});
    if let Some(vector) = gate_vector.as_object_mut() {
        if let Some(input) = input_gate_vector.and_then(Value::as_object) {
            for (key, value) in input {
                let sanitized = value
                    .as_bool()
                    .or_else(|| {
                        value
                            .get("valid")
                            .or_else(|| value.get("observed"))
                            .and_then(Value::as_bool)
                    })
                    .map(|value| json!(value))
                    .or_else(|| value.as_str().map(|value| json!(value)));
                if let Some(value) = sanitized {
                    vector.insert(key.clone(), value);
                }
            }
        }
        vector.insert("gate_result".to_owned(), json!(gate_result));
        vector.insert(
            "independent_product_failure".to_owned(),
            json!(independent_product_failure),
        );
        vector.insert("human_bytes_after_freeze".to_owned(), json!(human_bytes));
        vector.insert("run_present".to_owned(), json!(run_present));
    }
    let run_digest = if run_present {
        digest_input(run_path)?
    } else {
        crate::hash::sha256_text("no-run")
    };
    let result = json!({
        "schema": "guildhall-experiment-verdict/1",
        "status": "verdict-complete",
        "published_conclusion": published_conclusion,
        "uses_licensed_template": true,
        "run_digest": run_digest,
        "terminal_product_verdict": terminal,
        "gate_result": gate_result,
        "measurement_result": measurement_result,
        "independent_product_failure": independent_product_failure,
        "headroom_condition": headroom_condition,
        "ceiling_condition": ceiling_condition,
        "gate_vector": gate_vector
    });
    print_result(&result, json)
}

fn checked_executable(
    env_name: &str,
    manifest: &Value,
    digest_field: &str,
) -> Result<PathBuf, ContractError> {
    let path = std::env::var_os(env_name)
        .map(PathBuf::from)
        .ok_or_else(|| invariant(format!("{env_name} is required")))?;
    let metadata = std::fs::metadata(&path).map_err(io_error)?;
    if !metadata.is_file() {
        return Err(invariant(format!("{env_name} must be a regular file")));
    }
    let expected = manifest
        .get(digest_field)
        .and_then(Value::as_str)
        .unwrap_or_default();
    let runner_bytes = std::fs::read(&path).map_err(io_error)?;
    if crate::hash::sha256_bytes(&runner_bytes).ne(&expected) {
        return Err(ContractError::new(
            "MODEL_FINGERPRINT_CHANGED",
            "runner digest differs from the frozen manifest",
            "Consume only a preregistered reserve before launch.",
            false,
            ExitCode::InternalFailure,
        ));
    }
    Ok(path)
}

fn signing_key(directory: &Path) -> Result<PathBuf, ContractError> {
    Ok(std::env::var_os("GUILDHALL_EXPERIMENT_SIGNING_KEY")
        .map(PathBuf::from)
        .unwrap_or_else(|| directory.join("signing.key")))
}

fn append_signed_census(
    path: &Path,
    action: &str,
    packet: &Value,
    key: &Path,
) -> Result<(), ContractError> {
    let body = json!({"action": action, "packet": packet, "recorded_at": crate::time::now_rfc3339_millis()});
    let signature =
        crate::crypto::sign_message("receipt", &crate::json::canonical_bytes(&body), key)?;
    append_json_line(path, &json!({"record": body, "signature": signature}))
}

fn append_json_line(path: &Path, value: &Value) -> Result<(), ContractError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io_error)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(io_error)?;
    file.write_all(&crate::json::canonical_bytes(value))
        .map_err(io_error)?;
    file.write_all(b"\n").map_err(io_error)
}

fn execute(executable: &Path, packet: &Value) -> Result<Value, ContractError> {
    let mut child = Command::new(executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(io_error)?;
    child
        .stdin
        .take()
        .ok_or_else(|| invariant("runner stdin unavailable"))?
        .write_all(&crate::json::canonical_bytes(packet))
        .map_err(io_error)?;
    let output = child.wait_with_output().map_err(io_error)?;
    if !output.status.success() {
        return Err(invariant(format!(
            "runner failed with status {}",
            output.status
        )));
    }
    crate::json::strict(&output.stdout)
        .map_err(|error| invariant(format!("runner returned invalid JSON: {error}")))
}

fn composite(metrics: &Value) -> Result<f64, ContractError> {
    let functional = required_metric(metrics, "functional")?;
    let architecture = required_metric(metrics, "architecture")?;
    let api_reuse = required_metric(metrics, "api_reuse")?;
    let verification = required_metric(metrics, "false_completion")?;
    let efficiency = required_metric(metrics, "efficiency")?;
    Ok(functional * 0.5
        + architecture * 0.2
        + api_reuse * 0.1
        + verification * 0.1
        + efficiency * 0.1)
}

fn required_metric(metrics: &Value, name: &str) -> Result<f64, ContractError> {
    let value = metrics
        .get(name)
        .and_then(Value::as_f64)
        .ok_or_else(|| invariant(format!("scorer metric {name} is required")))?;
    if !(0.0..=1.0).contains(&value) {
        return Err(invariant(format!("scorer metric {name} is outside [0,1]")));
    }
    Ok(value)
}

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len().max(1) as f64
}
fn variance(values: &[f64]) -> f64 {
    let average = mean(values);
    values
        .iter()
        .map(|value| (value - average) * (value - average))
        .sum::<f64>()
        / values.len().max(1) as f64
}
fn standard_error(values: &[f64]) -> f64 {
    variance(values).sqrt() / (values.len().max(1) as f64).sqrt()
}

fn required_array<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>, ContractError> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invariant(format!("{field} array is required")))
}
fn required_object<'a>(value: &'a Value, field: &str) -> Result<&'a Value, ContractError> {
    value
        .get(field)
        .ok_or_else(|| invariant(format!("{field} object is required")))
}
fn required_text<'a>(value: &'a Value, field: &str) -> Result<&'a str, ContractError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| invariant(format!("{field} is required")))
}
fn digest_value(value: &Value) -> String {
    crate::hash::sha256_text(&crate::json::canonical_text(value))
}
fn invariant(message: impl Into<String>) -> ContractError {
    ContractError::new(
        "CONFIG_INVARIANT",
        message,
        "Correct the frozen experiment inputs; no task may be replaced.",
        false,
        ExitCode::Refused,
    )
}
fn print_result(value: &Value, json: bool) -> Result<(), ContractError> {
    if json {
        println!("{}", crate::json::canonical_text(value));
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
        "Preserve the experiment evidence and retry after repair.",
        false,
        ExitCode::InternalFailure,
    )
}
