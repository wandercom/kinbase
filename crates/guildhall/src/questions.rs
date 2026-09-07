use crate::error::{ContractError, ExitCode};
use serde_json::{Value, json};
use std::path::Path;

pub fn dispatch(
    command: crate::command_types::QuestionCommand,
    json: bool,
) -> Result<(), ContractError> {
    match command {
        crate::command_types::QuestionCommand::List { owner } => list(owner.as_deref(), json),
        crate::command_types::QuestionCommand::Ask { question_id } => ask(&question_id, json),
        crate::command_types::QuestionCommand::Answer {
            question_id,
            answer_file,
            key_file,
        } => answer(&question_id, &answer_file, &key_file, json),
        crate::command_types::QuestionCommand::Status { question_id } => status(&question_id, json),
    }
}

fn list(owner: Option<&str>, json: bool) -> Result<(), ContractError> {
    let repo = std::env::current_dir().map_err(io_error)?;
    let records = crate::store::read_records(crate::StoreKind::Company, &repo, "questions.jsonl")
        .unwrap_or_default();
    let filtered: Vec<_> = records
        .iter()
        .filter(|record| {
            owner
                .map(|owner| record.get("owner").and_then(Value::as_str) == Some(owner))
                .unwrap_or(true)
        })
        .cloned()
        .collect();
    if json {
        println!(
            "{}",
            serde_json::to_string(&Value::Array(filtered)).unwrap_or_default()
        );
    } else {
        println!("question_count: {}", filtered.len());
    }
    Ok(())
}

fn ask(question_id: &str, json: bool) -> Result<(), ContractError> {
    let repo = std::env::current_dir().map_err(io_error)?;
    let question = json!({
        "question_id": question_id,
        "question": "Please resolve the architectural ambiguity.",
        "owner": "chief-architect",
        "scope": "architecture:demo",
        "status": "open"
    });
    crate::store::append_record(
        crate::StoreKind::Company,
        &repo,
        "questions.jsonl",
        &question,
    )
    .map_err(io_error)?;
    if json {
        println!("{}", serde_json::to_string(&question).unwrap_or_default());
    } else {
        println!("question: {question_id}");
        println!("status: open");
    }
    Ok(())
}

fn answer(
    question_id: &str,
    answer_file: &Path,
    key_file: &Path,
    json: bool,
) -> Result<(), ContractError> {
    let repo = std::env::current_dir().map_err(io_error)?;
    let answer_text = std::fs::read_to_string(answer_file).map_err(io_error)?;
    let signature = crate::crypto::sign(answer_text.as_bytes(), key_file)?;
    let record = json!({
        "question_id": question_id,
        "answer": answer_text,
        "signature": signature,
        "status": "answered"
    });
    crate::store::append_record(crate::StoreKind::Company, &repo, "answers.jsonl", &record)
        .map_err(io_error)?;
    if json {
        println!("{}", serde_json::to_string(&record).unwrap_or_default());
    } else {
        println!("question: {question_id}");
        println!("status: answered");
    }
    Ok(())
}

fn status(question_id: &str, json: bool) -> Result<(), ContractError> {
    let repo = std::env::current_dir().map_err(io_error)?;
    let questions = crate::store::read_records(crate::StoreKind::Company, &repo, "questions.jsonl")
        .unwrap_or_default();
    let answers = crate::store::read_records(crate::StoreKind::Company, &repo, "answers.jsonl")
        .unwrap_or_default();
    let question = questions
        .into_iter()
        .find(|record| record.get("question_id").and_then(Value::as_str) == Some(question_id));
    let answer = answers
        .into_iter()
        .find(|record| record.get("question_id").and_then(Value::as_str) == Some(question_id));
    let result = json!({"question_id":question_id,"question":question,"answer":answer});
    if json {
        println!("{}", serde_json::to_string(&result).unwrap_or_default());
    } else {
        println!("question: {question_id}");
        println!(
            "status: {}",
            if answer.is_some() { "answered" } else { "open" }
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
