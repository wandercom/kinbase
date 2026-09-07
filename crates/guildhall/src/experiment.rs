use crate::error::{ContractError, ExitCode};
use serde_json::{Map, Value, json};
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
        crate::command_types::ExperimentCommand::Run { frozen_manifest } => {
            run(&frozen_manifest, json)
        }
        crate::command_types::ExperimentCommand::Score { run } => score(&run, json),
        crate::command_types::ExperimentCommand::Verdict { run } => verdict(&run, json),
    }
}

fn read_json(path: &Path) -> Result<Value, ContractError> {
    let bytes = std::fs::read(path).map_err(io_error)?;
    crate::json::strict(&bytes).map_err(|error| invariant(error))
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
    let tasks = required_array(&manifest, "tasks")?;
    let mut examined = Vec::new();
    let mut eligible = Vec::new();
    let mut excluded = Vec::new();
    for task in tasks {
        let task_id = required_text(task, "task_id")?;
        examined.push(json!({"task_id": task_id}));
        let reason = exclusion_reason(task);
        if let Some(reason) = reason {
            excluded.push(json!({"task_id": task_id, "reason_code": reason}));
        } else {
            eligible.push(json!({"task_id": task_id}));
        }
    }
    let requested = manifest
        .get("measurement_task_count")
        .and_then(Value::as_u64)
        .unwrap_or(8);
    if eligible.len() < requested.max(8) as usize || repositories(&eligible, &tasks) < 2 {
        return Err(invariant(
            "eligible census is below the two-repository, eight-task floor",
        ));
    }
    let draw = deterministic_draw(&eligible, requested.max(8));
    let result = json!({
        "schema": "guildhall-experiment-census/1",
        "status": "census-complete",
        "manifest_digest": digest_value(&manifest),
        "examined": examined,
        "eligible": eligible,
        "excluded": excluded,
        "drawn": draw,
        "seed": manifest.get("public_seed").cloned().unwrap_or(Value::Null)
    });
    let output = artifact(manifest_path, "census");
    write_json(&output, &result)?;
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

fn deterministic_draw(tasks: &[Value], count: u64) -> Vec<Value> {
    let mut ranked: Vec<(String, &Value)> = tasks
        .iter()
        .map(|task| {
            let id = task
                .get("task_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            (crate::hash::sha256_text(id), task)
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
    let census = require_artifact(&artifact(manifest_path, "census"), "census")?;
    let pilot = require_artifact(&artifact(manifest_path, "pilot"), "pilot")?;
    let calibration = require_artifact(&artifact(manifest_path, "calibration"), "calibration")?;
    let budget = read_json(budget_path)?;
    if budget.get("status").and_then(Value::as_str) != Some("ratified") {
        return Err(invariant("budget is not exact-byte human-ratified"));
    }
    if budget
        .get("founder_receipt")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .is_empty()
        || budget
            .get("validator_receipt")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .is_empty()
    {
        return Err(invariant("budget lacks founder and validator receipts"));
    }
    let arms = required_array(&manifest, "arms")?;
    let arm_names: Vec<&str> = arms.iter().filter_map(Value::as_str).collect();
    if arm_names != ARMS {
        return Err(invariant(
            "manifest does not bind exactly the eleven ratified arms",
        ));
    }
    if pilot.get("status").and_then(Value::as_str) != Some("pilot-complete") {
        return Err(invariant("power and cost results are not frozen"));
    }
    let result = json!({
        "schema": "guildhall-frozen-experiment/1",
        "status": "frozen",
        "manifest": manifest,
        "manifest_digest": digest_value(&manifest),
        "census_digest": digest_value(&census),
        "pilot_digest": digest_value(&pilot),
        "calibration_digest": digest_value(&calibration),
        "budget": budget,
        "budget_digest": digest_value(&budget),
        "human_bytes_after_freeze": 0
    });
    let output = artifact(manifest_path, "frozen");
    write_json(&output, &result)?;
    print_result(&result, json)
}

fn run(frozen_path: &Path, json: bool) -> Result<(), ContractError> {
    let frozen = read_json(frozen_path)?;
    if frozen.get("schema").and_then(Value::as_str) != Some("guildhall-frozen-experiment/1") {
        return Err(invariant("run requires a frozen experiment manifest"));
    }
    let manifest = required_object(&frozen, "manifest")?;
    let tasks = required_array(manifest, "measurement_tasks")?;
    let seeds = required_array(manifest, "measurement_seeds")?;
    if tasks.len() < 8 || seeds.len() < 3 {
        return Err(invariant(
            "measurement schedule is below the preregistered floor",
        ));
    }
    let runner = checked_executable("GUILDHALL_EXPERIMENT_RUNNER", manifest, "runner_sha256")?;
    let signer = signing_key()?;
    let run_dir = frozen_path.with_extension("run");
    std::fs::create_dir_all(run_dir.join("candidates")).map_err(io_error)?;
    let census_path = run_dir.join("run-census.jsonl");
    let mut mapping = Map::new();
    let mut candidate_ids = Vec::new();
    for task in tasks {
        for seed in seeds {
            for arm in ARMS {
                let packet = json!({
                    "task": task,
                    "arm": arm,
                    "seed": seed,
                    "as_of": manifest.get("as_of").cloned().unwrap_or(Value::Null),
                    "authority_cursor": manifest.get("authority_cursor").cloned().unwrap_or(Value::Null)
                });
                append_signed_census(&census_path, "launch", &packet, &signer)?;
                let output = execute(&runner, &packet)?;
                let candidate_id = format!(
                    "cand_{}",
                    &crate::hash::sha256_text(&crate::json::canonical_text(&output))[..24]
                );
                let candidate = json!({
                    "candidate_id": candidate_id,
                    "task_id": task.get("task_id").cloned().unwrap_or(Value::Null),
                    "seed": seed,
                    "candidate": output
                });
                write_json(
                    &run_dir
                        .join("candidates")
                        .join(format!("{candidate_id}.json")),
                    &candidate,
                )?;
                mapping.insert(candidate_id.clone(), json!({"task_id": task.get("task_id").cloned().unwrap_or(Value::Null), "seed": seed, "arm": arm}));
                candidate_ids.push(candidate_id);
            }
        }
    }
    write_json(&run_dir.join("mapping.json"), &Value::Object(mapping))?;
    let result = json!({
        "schema": "guildhall-experiment-run/1",
        "status": "run-complete",
        "frozen_digest": digest_value(&frozen),
        "run_directory": run_dir.to_string_lossy(),
        "candidate_count": candidate_ids.len(),
        "run_census_digest": digest_value(&json!({"candidate_ids": candidate_ids}))
    });
    write_json(&frozen_path.with_extension("run.json"), &result)?;
    print_result(&result, json)
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
    let signer = signing_key()?;
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

fn verdict(run_path: &Path, json: bool) -> Result<(), ContractError> {
    let run = read_json(&run_path)?;
    let run_dir = PathBuf::from(
        run.get("run_directory")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    );
    let scores = read_json(&run_dir.join("scores.jsonl"))?;
    let scores = scores.as_array().cloned().unwrap_or_default();
    let mapping = read_json(&run_dir.join("mapping.json"))?;
    let mut by_task: BTreeMap<String, BTreeMap<&str, Vec<f64>>> = BTreeMap::new();
    for score in &scores {
        let candidate_id = required_text(&score, "candidate_id")?;
        let mapped = mapping
            .get(&candidate_id)
            .ok_or_else(|| invariant("score has no arm mapping"))?;
        let arm = required_text(mapped, "arm")?;
        let task_id = required_text(mapped, "task_id")?;
        by_task
            .entry(task_id.to_owned())
            .or_default()
            .entry(arm)
            .or_default()
            .push(
                score
                    .get("composite")
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0),
            );
    }
    let mut arm_means: BTreeMap<&str, Vec<f64>> = BTreeMap::new();
    for (_, arms) in &by_task {
        for (arm, values) in arms {
            arm_means.entry(arm).or_default().push(mean(values));
        }
    }
    let mean_of = |arm: &str| arm_means.get(arm).map(|values| mean(values)).unwrap_or(0.0);
    let lower = |arm: &str| {
        arm_means
            .get(arm)
            .map(|values| mean(values) - 1.96 * standard_error(values))
            .unwrap_or(0.0)
    };
    let baseline = mean_of("baseline");
    let oracle = mean_of("oracle-spec");
    let full = mean_of("full-system");
    let status = if baseline > 0.85 {
        "INCONCLUSIVE_NO_HEADROOM"
    } else if oracle < 0.9 || lower("full-system") - oracle > 0.05 {
        "INCONCLUSIVE_CEILING"
    } else if full >= 0.9
        && full >= oracle - 0.05
        && full - baseline >= 0.15
        && full - mean_of("null-system") >= 0.15
        && full - mean_of("static-prior") >= 0.1
        && full - mean_of("topk-raw") >= 0.1
        && full - mean_of("topk-maintained") >= 0.1
    {
        "PROVEN"
    } else {
        "NOT_PROVEN"
    };
    let result = json!({"schema":"guildhall-experiment-verdict/1","measurement_result":status,"arm_means":arm_means,"baseline_mean":baseline,"oracle_mean":oracle,"full_system_mean":full,"intention_to_treat":scores.len()});
    write_json(&run_dir.join("verdict.json"), &result)?;
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

fn signing_key() -> Result<PathBuf, ContractError> {
    std::env::var_os("GUILDHALL_EXPERIMENT_SIGNING_KEY")
        .map(PathBuf::from)
        .ok_or_else(|| invariant("GUILDHALL_EXPERIMENT_SIGNING_KEY is required"))
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
