//! The Personal store's Kindex (product.md: Personal is Kindex).
//!
//! Host transcripts are Personal by provenance. Kinbase keeps them in its
//! private journal, and with `[personal] kindex_executable` configured it also
//! hands each transcript, as one conversation, to the Kindex graph at the
//! Personal root, where `kinbase recall` answers the principal's own
//! questions from it. Only the launcher and Personal worker hold the Personal
//! root, so both steps run there. Nothing Kindex reads or returns enters a
//! shared store, a projection or a host hook.
//!
//! Kindex runs under the classifier's executable rules: an absolute regular
//! file owned by the effective user, no group/other write anywhere up its
//! directory chain, its pinned SHA-256 rechecked through the descriptor that
//! is executed, and a scrubbed environment plus only the variables the
//! configuration names.

use crate::config::PersonalKindexConfig;
use crate::error::ContractError;
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};

/// One host transcript (Claude Code or Codex JSON Lines) as a Kindex
/// conversation: `{"id", "date", "messages": [{"role", "content", "name"?}]}`.
/// `None` when it holds no message text.
pub fn transcript_conversation(id: &str, text: &str) -> Option<Value> {
    let mut messages = Vec::new();
    let mut date: Option<String> = None;
    for line in text.lines() {
        let Ok(Value::Object(map)) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let kind = map.get("type").and_then(Value::as_str).unwrap_or_default();
        if matches!(kind, "stop" | "session_end") {
            continue;
        }
        let body: &Map<String, Value> = if kind == "response_item" {
            match map.get("payload").and_then(Value::as_object) {
                Some(payload) => payload,
                None => continue,
            }
        } else {
            map.get("message").and_then(Value::as_object).unwrap_or(&map)
        };
        let Some(content) = crate::lifecycle::content_text(body).filter(|t| !t.trim().is_empty())
        else {
            continue;
        };
        let role = body
            .get("role")
            .and_then(Value::as_str)
            .filter(|role| !role.is_empty())
            .unwrap_or(if kind.is_empty() { "user" } else { kind });
        let mut message = json!({ "role": role, "content": content });
        if let Some(name) = body.get("name").and_then(Value::as_str) {
            message["name"] = json!(name);
        }
        messages.push(message);
        if date.is_none() {
            date = map
                .get("timestamp")
                .or_else(|| map.get("ts"))
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
    }
    if messages.is_empty() {
        return None;
    }
    Some(json!({ "id": id, "date": date, "messages": messages }))
}

fn run(cfg: &PersonalKindexConfig, args: Vec<String>) -> Result<Vec<u8>, ContractError> {
    let env: Vec<(String, String)> = cfg
        .env
        .iter()
        .filter_map(|name| std::env::var(name).ok().map(|value| (name.clone(), value)))
        .collect();
    crate::sandbox::run_verified_executable_with_env(
        &cfg.executable,
        &cfg.executable_sha256,
        &args,
        &env,
        &[],
        std::time::Duration::from_secs(cfg.timeout_seconds),
    )
    .map_err(|mut error| {
        error.message = format!("Personal Kindex: {}", error.message);
        error
    })
}

fn common_args(cfg: &PersonalKindexConfig, data_root: &Path) -> Vec<String> {
    let mut args = vec!["--data-dir".to_owned(), data_root.to_string_lossy().into_owned()];
    if let Some(config) = &cfg.config {
        args.push("--config".to_owned());
        args.push(config.to_string_lossy().into_owned());
    }
    args
}

/// Hands the transcripts at `source` to the Personal Kindex graph (and digests
/// them when configured). Returns a receipt with the conversation count.
pub fn hand_off(
    cfg: &PersonalKindexConfig,
    data_root: &Path,
    source: &Path,
) -> Result<Value, ContractError> {
    let mut conversations = Vec::new();
    for path in crate::lifecycle::source_files(source)? {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with(".jsonl") {
            continue;
        }
        let text = std::fs::read_to_string(&path).map_err(|e| ContractError::io("transcript", e))?;
        if let Some(conversation) = transcript_conversation(name.trim_end_matches(".jsonl"), &text) {
            conversations.push(conversation);
        }
    }
    if conversations.is_empty() {
        return Ok(json!({ "conversations": 0 }));
    }
    // A private staging directory inside the Personal root, removed afterwards.
    let staging: PathBuf = data_root.join(".kinbase-handoff").join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(&staging).map_err(|e| ContractError::io("Kindex hand-off staging", e))?;
    let result = (|| {
        for (index, conversation) in conversations.iter().enumerate() {
            std::fs::write(
                staging.join(format!("{index:06}.json")),
                serde_json::to_vec(conversation).unwrap_or_default(),
            )
            .map_err(|e| ContractError::io("Kindex hand-off", e))?;
        }
        let mut args = vec!["ingest".to_owned(), "conversations".to_owned(), "--directory".to_owned()];
        args.push(staging.to_string_lossy().into_owned());
        args.extend(common_args(cfg, data_root));
        run(cfg, args)?;
        if cfg.digest {
            let mut args = vec!["digest".to_owned()];
            args.extend(common_args(cfg, data_root));
            run(cfg, args)?;
        }
        Ok(json!({ "conversations": conversations.len(), "digested": cfg.digest }))
    })();
    let _ = std::fs::remove_dir_all(&staging);
    result
}

/// Answers the principal's question from the Personal Kindex graph, with
/// `team` (statements of the shared facts a projection selected for the
/// question) as shared knowledge alongside it. Shared facts may flow into the
/// Personal side; nothing flows back.
pub fn recall(
    cfg: &PersonalKindexConfig,
    data_root: &Path,
    question: &str,
    as_of: Option<&str>,
    team: &[String],
) -> Result<String, ContractError> {
    let mut args = vec!["ask".to_owned()];
    args.extend(common_args(cfg, data_root));
    if let Some(as_of) = as_of {
        args.push("--as-of".to_owned());
        args.push(as_of.to_owned());
    }
    let staging = data_root.join(".kinbase-handoff");
    let team_file = (!team.is_empty()).then(|| staging.join(format!("team-{}.txt", uuid::Uuid::new_v4())));
    if let Some(path) = &team_file {
        std::fs::create_dir_all(&staging).map_err(|e| ContractError::io("Kindex team knowledge", e))?;
        let lines: Vec<String> = team.iter().map(|statement| statement.split_whitespace().collect::<Vec<_>>().join(" ")).collect();
        std::fs::write(path, lines.join("\n")).map_err(|e| ContractError::io("Kindex team knowledge", e))?;
        args.push("--context-file".to_owned());
        args.push(path.to_string_lossy().into_owned());
    }
    args.push("--".to_owned());
    args.push(question.to_owned());
    let out = run(cfg, args);
    if let Some(path) = &team_file {
        let _ = std::fs::remove_file(path);
    }
    Ok(String::from_utf8_lossy(&out?).trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_and_codex_lines_become_one_conversation() {
        let text = [
            r#"{"type":"user","timestamp":"2024-03-10T09:00:00.000Z","message":{"role":"user","content":"I bought a red kayak."}}"#,
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"Nice!"}]}}"#,
            r#"{"type":"response_item","payload":{"role":"user","name":"Caroline","content":[{"type":"input_text","text":"Hi Mel"}]}}"#,
            r#"not json"#,
            r#"{"type":"stop"}"#,
        ]
        .join("\n");
        let conversation = transcript_conversation("s1", &text).unwrap();
        assert_eq!(conversation["id"], "s1");
        assert_eq!(conversation["date"], "2024-03-10T09:00:00.000Z");
        let messages = conversation["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0], json!({"role": "user", "content": "I bought a red kayak."}));
        assert_eq!(messages[1]["content"], "Nice!");
        assert_eq!(messages[2], json!({"role": "user", "content": "Hi Mel", "name": "Caroline"}));
    }

    #[test]
    fn a_transcript_without_text_is_no_conversation() {
        assert!(transcript_conversation("s", r#"{"type":"stop"}"#).is_none());
    }
}
