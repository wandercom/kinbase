//! The Personal store's Kindex (product.md: Personal is Kindex).
//!
//! Host transcripts are Personal by provenance. Kinbase keeps them in its
//! private journal, and with `[personal] kindex_executable` configured it also
//! hands what the ingest scan read of each transcript to the Kindex graph at
//! the Personal root, where `kinbase recall` answers the principal's own
//! questions from it. Only the launcher and Personal worker hold the Personal
//! root, so both steps run there. Nothing Kindex reads or returns enters a
//! shared store, a projection or a host hook.
//!
//! The hand-off exports the scan's records, so the scan's bounds apply (a
//! transcript over the per-file bound is skipped, a directory over its budget
//! is refused) and nothing is read twice. Each transcript is kept for its
//! retention: a `.retention` sidecar's `private_retention_seconds`, else
//! `[personal] kindex_retention_seconds`, else the private raw-session default,
//! counted from the transcript's last change. Kindex is told when each
//! conversation expires, and a ledger under the Personal root records what was
//! handed over, so a conversation past its retention, or whose transcript is
//! gone from a source that is ingested again, is retracted from Kindex with
//! everything Kindex derived from it.
//!
//! Kindex runs under the classifier's executable rules: an absolute regular
//! file owned by the effective user, no group/other write anywhere up its
//! directory chain, its pinned SHA-256 rechecked through the descriptor that
//! is executed, and a scrubbed environment plus only the variables the
//! configuration names. The Personal root is checked (not a symlink, owned by
//! the effective user, mode 0700) before every invocation.

use crate::config::PersonalKindexConfig;
use crate::error::ContractError;
use crate::lifecycle::SourceRecord;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const HANDOFF_DIR: &str = ".kinbase-handoff";
const LEDGER_FILE: &str = "conversations.json";
const LEDGER_LIMIT: usize = 64 * 1024 * 1024;
const DAY_SECONDS: i64 = 86_400;

/// One transcript line (Claude Code or Codex JSON Lines) as a Kindex message,
/// with the line's timestamp. `None` for a line with no message text.
fn transcript_message(map: &Map<String, Value>) -> Option<(Value, Option<String>)> {
    let kind = map.get("type").and_then(Value::as_str).unwrap_or_default();
    if matches!(kind, "stop" | "session_end") {
        return None;
    }
    let body: &Map<String, Value> = if kind == "response_item" {
        map.get("payload").and_then(Value::as_object)?
    } else {
        map.get("message").and_then(Value::as_object).unwrap_or(map)
    };
    let content = crate::lifecycle::content_text(body).filter(|t| !t.trim().is_empty())?;
    let role = body
        .get("role")
        .and_then(Value::as_str)
        .filter(|role| !role.is_empty())
        .unwrap_or(if kind.is_empty() { "user" } else { kind });
    let mut message = json!({ "role": role, "content": content });
    if let Some(name) = body.get("name").and_then(Value::as_str) {
        message["name"] = json!(name);
    }
    let timestamp = map
        .get("timestamp")
        .or_else(|| map.get("ts"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Some((message, timestamp))
}

/// The host's own session id on a transcript line, when it carries one.
fn native_session_id(map: &Map<String, Value>) -> Option<String> {
    map.get("sessionId")
        .or_else(|| map.get("session_id"))
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .map(str::to_owned)
}

fn day_of(timestamp: &str) -> Option<String> {
    let day = timestamp.get(..10)?;
    chrono::NaiveDate::parse_from_str(day, "%Y-%m-%d")
        .ok()
        .map(|_| day.to_owned())
}

fn day_of_seconds(seconds: i64) -> String {
    chrono::DateTime::from_timestamp(seconds, 0)
        .map(|time| time.date_naive().to_string())
        .unwrap_or_default()
}

/// A transcript's lines as Kindex conversations, one per calendar day its
/// messages carry: a session resumed on later days keeps each message under
/// its own date instead of the session's first. A message without a timestamp
/// joins the day before it (or the first day). Each conversation's id is
/// `{base}#{day}`, or `{base}#undated` when no line has a date.
pub fn transcript_segments<'a>(base: &str, lines: impl IntoIterator<Item = &'a str>) -> Vec<Value> {
    // (day, its first timestamp, its messages), in order of first appearance.
    let mut days: Vec<(String, Option<String>, Vec<Value>)> = Vec::new();
    let mut current: Option<usize> = None;
    let mut lead: Vec<Value> = Vec::new();
    for line in lines {
        let Ok(Value::Object(map)) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some((message, timestamp)) = transcript_message(&map) else {
            continue;
        };
        match timestamp.as_deref().and_then(day_of) {
            Some(day) => {
                let index = match days.iter().position(|(known, _, _)| *known == day) {
                    Some(index) => index,
                    None => {
                        days.push((day, timestamp.clone(), Vec::new()));
                        days.len() - 1
                    }
                };
                // Lines before the first dated one belong to its day.
                days[index].2.append(&mut lead);
                days[index].2.push(message);
                current = Some(index);
            }
            None => match current {
                Some(index) => days[index].2.push(message),
                None => lead.push(message),
            },
        }
    }
    let mut segments: Vec<Value> = days
        .into_iter()
        .map(|(day, first, messages)| json!({"id": format!("{base}#{day}"), "date": first, "messages": messages}))
        .collect();
    if segments.is_empty() && !lead.is_empty() {
        segments
            .push(json!({"id": format!("{base}#undated"), "date": Value::Null, "messages": lead}));
    }
    segments.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    segments
}

/// What the ledger keeps for one handed-off transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LedgerEntry {
    /// The transcript file, canonical.
    path: String,
    /// Unix seconds past which it is retracted.
    deadline: i64,
    /// The Kindex conversation ids it was handed over as.
    segments: Vec<String>,
}

type Ledger = BTreeMap<String, LedgerEntry>;

/// What one hand-off sends to Kindex and the ledger it leaves.
#[derive(Debug, Default)]
struct Plan {
    entries: Vec<Value>,
    ledger: Ledger,
    conversations: usize,
    transcripts: usize,
    expired: usize,
    removed: usize,
}

fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path)
        .or_else(|_| std::path::absolute(path))
        .unwrap_or_else(|_| path.to_path_buf())
}

/// The conversation identity of one transcript: the host's session id (the
/// file name when the transcript has none) and a digest of the transcript's
/// canonical path, so equal file names in different directories, or a session
/// id reused by another host, never share a conversation.
fn conversation_base(path: &Path, session: Option<&str>) -> String {
    let stem = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.trim_end_matches(".jsonl"))
        .unwrap_or("transcript");
    let digest = crate::hash::sha256_text(&path.to_string_lossy());
    format!("{}@{}", session.unwrap_or(stem), &digest[..16])
}

fn retract(entries: &mut Vec<Value>, segments: &[String]) {
    entries.extend(
        segments
            .iter()
            .map(|id| json!({ "id": id, "retracted": true })),
    );
}

/// Plans a hand-off of `records` (one scan of `source`), given what the
/// ledger says earlier hand-offs sent. `present` is every transcript file the
/// source holds now, scanned or not, canonical.
fn plan(
    default_retention: i64,
    records: &[SourceRecord],
    source: &Path,
    present: &BTreeSet<PathBuf>,
    mut ledger: Ledger,
    now: i64,
) -> Plan {
    let mut out = Plan::default();
    let today = day_of_seconds(now);
    let mut by_file: BTreeMap<
        PathBuf,
        (
            std::sync::Arc<crate::lifecycle::TranscriptOrigin>,
            Vec<&SourceRecord>,
        ),
    > = BTreeMap::new();
    for record in records {
        let Some(origin) = &record.transcript else {
            continue;
        };
        if record.disposition == "terminal" {
            continue;
        }
        by_file
            .entry(canonical(&origin.path))
            .or_insert_with(|| (origin.clone(), Vec::new()))
            .1
            .push(record);
    }
    let mut handled: BTreeSet<String> = BTreeSet::new();
    for (path, (origin, file_records)) in &by_file {
        let lines: Vec<String> = file_records
            .iter()
            .map(|record| String::from_utf8_lossy(&record.content).into_owned())
            .collect();
        let session = lines.iter().find_map(|line| {
            serde_json::from_str::<Value>(line)
                .ok()
                .and_then(|value| value.as_object().and_then(native_session_id))
        });
        let base = conversation_base(path, session.as_deref());
        handled.insert(base.clone());
        let retention = origin
            .declared_retention_seconds
            .unwrap_or(default_retention);
        let deadline = origin.modified.unwrap_or(now).saturating_add(retention);
        // Kindex expires by day and keeps a node through its expiry day, so the
        // last day is the one before the deadline's: never kept past it.
        let expires = day_of_seconds(deadline - DAY_SECONDS);
        let previous = ledger.remove(&base);
        if deadline <= now || expires < today {
            out.expired += 1;
            if let Some(previous) = previous {
                retract(&mut out.entries, &previous.segments);
            }
            continue;
        }
        let mut segments = transcript_segments(&base, lines.iter().map(String::as_str));
        if segments.is_empty() {
            if let Some(previous) = previous {
                retract(&mut out.entries, &previous.segments);
            }
            continue;
        }
        let ids: Vec<String> = segments
            .iter()
            .filter_map(|segment| segment["id"].as_str().map(str::to_owned))
            .collect();
        if let Some(previous) = previous {
            let stale: Vec<String> = previous
                .segments
                .into_iter()
                .filter(|id| !ids.contains(id))
                .collect();
            retract(&mut out.entries, &stale);
        }
        for segment in &mut segments {
            segment["expires"] = json!(expires);
        }
        out.conversations += segments.len();
        out.transcripts += 1;
        out.entries.extend(segments);
        ledger.insert(
            base,
            LedgerEntry {
                path: path.to_string_lossy().into_owned(),
                deadline,
                segments: ids,
            },
        );
    }
    // Earlier hand-offs: past retention, or their transcript is gone from
    // this source.
    let scope = canonical(source);
    let mut kept = Ledger::new();
    for (base, entry) in ledger {
        if handled.contains(&base) {
            kept.insert(base, entry);
            continue;
        }
        let path = PathBuf::from(&entry.path);
        if entry.deadline <= now {
            out.expired += 1;
            retract(&mut out.entries, &entry.segments);
        } else if path.starts_with(&scope) && !present.contains(&path) {
            out.removed += 1;
            retract(&mut out.entries, &entry.segments);
        } else {
            kept.insert(base, entry);
        }
    }
    out.ledger = kept;
    out
}

/// The Personal root, checked before Kindex is given it: not a symlink (a
/// trailing separator would resolve one), created if missing, owned by the
/// effective user and mode 0700. Returns its canonical path.
pub(crate) fn protect_root(data_root: &Path) -> Result<PathBuf, ContractError> {
    use std::os::unix::fs::MetadataExt;
    let root: PathBuf = data_root.components().collect();
    crate::paths::ensure_private_dir(&root, "Personal data root")?;
    let metadata = std::fs::symlink_metadata(&root)
        .map_err(|error| ContractError::unreadable("Personal data root", &error))?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.uid() != euid {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            "Personal data root is not a directory owned by the current user",
            "Point [personal] data_root at a directory you own; it is kept at mode 0700.",
        ));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            "Personal data root is readable or writable by others",
            format!("Run `chmod 0700 {}` and retry.", root.display()),
        ));
    }
    std::fs::canonicalize(&root)
        .map_err(|error| ContractError::unreadable("Personal data root", &error))
}

/// The hand-off directory under the Personal root, private and not a symlink.
fn handoff_dir(root: &Path) -> Result<PathBuf, ContractError> {
    let dir = root.join(HANDOFF_DIR);
    crate::paths::ensure_private_dir(&dir, "Kindex hand-off directory")?;
    Ok(dir)
}

fn load_ledger(dir: &Path) -> Result<Ledger, ContractError> {
    let path = dir.join(LEDGER_FILE);
    if std::fs::symlink_metadata(&path).is_err() {
        return Ok(Ledger::new());
    }
    let bytes = crate::paths::read_bounded(&path, LEDGER_LIMIT, "Kindex hand-off ledger")?;
    serde_json::from_slice(&bytes).map_err(|error| {
        ContractError::refused(
            "CONFIG_INVARIANT",
            format!("Kindex hand-off ledger is unreadable ({error})"),
            "Restore or remove the ledger under the Personal root's .kinbase-handoff directory.",
        )
    })
}

fn save_ledger(dir: &Path, ledger: &Ledger) -> Result<(), ContractError> {
    let bytes =
        serde_json::to_vec(ledger).map_err(|error| ContractError::internal(error.to_string()))?;
    crate::paths::write_atomic(&dir.join(LEDGER_FILE), &bytes, 0o600, false).map(|_| ())
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

fn common_args(cfg: &PersonalKindexConfig, root: &Path) -> Vec<String> {
    let mut args = vec!["--data-dir".to_owned(), root.to_string_lossy().into_owned()];
    if let Some(config) = &cfg.config {
        args.push("--config".to_owned());
        args.push(config.to_string_lossy().into_owned());
    }
    args
}

/// Sends `entries` (conversations and retractions) to Kindex through a private
/// staging directory under the hand-off directory, removed afterwards.
fn ingest(
    cfg: &PersonalKindexConfig,
    root: &Path,
    dir: &Path,
    entries: &[Value],
) -> Result<(), ContractError> {
    let staging = dir.join(uuid::Uuid::new_v4().to_string());
    crate::paths::ensure_private_dir(&staging, "Kindex hand-off staging")?;
    let result = (|| {
        for (index, entry) in entries.iter().enumerate() {
            let bytes = serde_json::to_vec(entry)
                .map_err(|error| ContractError::internal(error.to_string()))?;
            crate::paths::write_atomic(
                &staging.join(format!("{index:06}.json")),
                &bytes,
                0o600,
                false,
            )?;
        }
        let mut args = vec![
            "ingest".to_owned(),
            "conversations".to_owned(),
            "--directory".to_owned(),
        ];
        args.push(staging.to_string_lossy().into_owned());
        args.extend(common_args(cfg, root));
        run(cfg, args).map(|_| ())
    })();
    let _ = std::fs::remove_dir_all(&staging);
    result
}

fn seconds(now: &str) -> Result<i64, ContractError> {
    crate::time::parse_rfc3339_millis(now)
        .map(|time| time.timestamp())
        .map_err(ContractError::invariant)
}

/// Hands one scan of host transcripts at `source` to the Personal Kindex graph
/// (and digests them when configured), and retracts what is past retention or
/// gone from the source. Returns a receipt.
pub fn hand_off(
    cfg: &PersonalKindexConfig,
    data_root: &Path,
    source: &Path,
    records: &[SourceRecord],
    now: &str,
) -> Result<Value, ContractError> {
    let now = seconds(now)?;
    let root = protect_root(data_root)?;
    let dir = handoff_dir(&root)?;
    let ledger = load_ledger(&dir)?;
    let present: BTreeSet<PathBuf> = crate::lifecycle::source_files(source)
        .unwrap_or_default()
        .into_iter()
        .filter(|path| path.to_str().is_some_and(|name| name.ends_with(".jsonl")))
        .map(|path| canonical(&path))
        .collect();
    let default_retention = cfg
        .retention_seconds
        .unwrap_or(crate::lifecycle::PRIVATE_RAW_RETENTION_SECONDS);
    let plan = plan(default_retention, records, source, &present, ledger, now);
    let receipt = json!({
        "conversations": plan.conversations,
        "transcripts": plan.transcripts,
        "retracted_expired": plan.expired,
        "retracted_removed": plan.removed,
        "digested": cfg.digest && plan.conversations > 0
    });
    if plan.entries.is_empty() {
        save_ledger(&dir, &plan.ledger)?;
        return Ok(receipt);
    }
    ingest(cfg, &root, &dir, &plan.entries)?;
    save_ledger(&dir, &plan.ledger)?;
    if cfg.digest && plan.conversations > 0 {
        let mut args = vec!["digest".to_owned()];
        args.extend(common_args(cfg, &root));
        run(cfg, args)?;
    }
    Ok(receipt)
}

/// Retracts the conversations whose retention has passed. Returns how many.
fn purge_expired(
    cfg: &PersonalKindexConfig,
    root: &Path,
    dir: &Path,
    now: i64,
) -> Result<usize, ContractError> {
    let ledger = load_ledger(dir)?;
    let (due, kept): (Ledger, Ledger) = ledger
        .into_iter()
        .partition(|(_, entry)| entry.deadline <= now);
    if due.is_empty() {
        return Ok(0);
    }
    let mut entries = Vec::new();
    for entry in due.values() {
        retract(&mut entries, &entry.segments);
    }
    ingest(cfg, root, dir, &entries)?;
    save_ledger(dir, &kept)?;
    Ok(due.len())
}

/// Answers the principal's question from the Personal Kindex graph, with
/// `team` (shared knowledge a projection released for the question, one item
/// per line, annotated) alongside it. Shared facts may flow into the Personal
/// side; nothing flows back. Conversations past their retention are retracted
/// first.
pub fn recall(
    cfg: &PersonalKindexConfig,
    data_root: &Path,
    question: &str,
    as_of: Option<&str>,
    team: &[String],
    now: &str,
) -> Result<String, ContractError> {
    let root = protect_root(data_root)?;
    let dir = handoff_dir(&root)?;
    purge_expired(cfg, &root, &dir, seconds(now)?)?;
    let mut args = vec!["ask".to_owned()];
    args.extend(common_args(cfg, &root));
    if let Some(as_of) = as_of {
        args.push("--as-of".to_owned());
        args.push(as_of.to_owned());
    }
    let team_file =
        (!team.is_empty()).then(|| dir.join(format!("team-{}.txt", uuid::Uuid::new_v4())));
    if let Some(path) = &team_file {
        let lines: Vec<String> = team
            .iter()
            .map(|item| item.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect();
        crate::paths::write_atomic(path, lines.join("\n").as_bytes(), 0o600, false)?;
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

/// The shared knowledge a projection releases to recall, and what recall
/// reports about it. A withheld projection releases no statements, only a
/// note that team guidance is blocked; a released statement keeps the
/// governance it carries (role, kind, store, standing, provenance, the paths
/// it governs), and a degraded authority snapshot is stated.
#[derive(Debug, Default, PartialEq)]
pub struct TeamKnowledge {
    pub items: Vec<String>,
    pub facts: usize,
    pub report: Value,
}

pub fn team_knowledge(result: &Value, statements: &BTreeMap<String, String>) -> TeamKnowledge {
    let state = result["projection_state"].as_str().unwrap_or("projected");
    let policy = result["degraded_policy"].as_str().unwrap_or_default();
    let refresh = &result["brief"]["authority_refresh"];
    let mut report = json!({
        "projection_state": state,
        "degraded_policy": policy,
        "authority_refresh": refresh["status"].as_str().unwrap_or("unknown"),
    });
    if state == "withheld" {
        report["facts"] = json!(0);
        return TeamKnowledge {
            items: vec![
                "Team guidance for this question is withheld: an open question or a degraded safety \
                 dependency blocks the shared projection. Answer from the user's own conversations \
                 and say that team guidance is pending."
                    .to_owned(),
            ],
            facts: 0,
            report,
        };
    }
    let mut items = Vec::new();
    if refresh["status"].as_str() == Some("withheld") {
        items.push(format!(
            "The team knowledge below comes from a cached authority snapshot; the refresh was withheld ({}). \
             It may be out of date.",
            refresh["code"].as_str().unwrap_or("unavailable")
        ));
    }
    if policy == "reversible_sandbox_only_experiment" {
        items.push(
            "Team knowledge is degraded for this question: treat it as guidance for reversible \
             experiments only."
                .to_owned(),
        );
    }
    let mut facts = 0;
    for selected in result["selected"].as_array().into_iter().flatten() {
        let Some(statement) = selected["fact_id"]
            .as_str()
            .and_then(|id| statements.get(id))
        else {
            continue;
        };
        let mut notes = vec![
            selected["role"]
                .as_str()
                .unwrap_or("fact")
                .replace('_', " "),
            format!(
                "{} {}",
                selected["store_kind"].as_str().unwrap_or("shared"),
                selected["atom_kind"].as_str().unwrap_or("fact")
            ),
            format!(
                "standing: {}",
                selected["standing"].as_str().unwrap_or("unknown")
            ),
            format!(
                "provenance: {}",
                selected["provenance"].as_str().unwrap_or("unknown")
            ),
        ];
        let governs: Vec<&str> = selected["governs_paths"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        if !governs.is_empty() {
            notes.push(format!("governs: {}", governs.join(", ")));
        }
        items.push(format!("[{}] {statement}", notes.join("; ")));
        facts += 1;
    }
    report["facts"] = json!(facts);
    TeamKnowledge {
        items,
        facts,
        report,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::TranscriptOrigin;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    const NOW: i64 = 1_791_000_000; // 2026-10-03

    fn segments(base: &str, lines: &[&str]) -> Vec<Value> {
        transcript_segments(base, lines.iter().copied())
    }

    #[test]
    fn claude_and_codex_lines_become_messages() {
        let lines = [
            r#"{"type":"user","timestamp":"2024-03-10T09:00:00.000Z","message":{"role":"user","content":"I bought a red kayak."}}"#,
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"Nice!"}]}}"#,
            r#"{"type":"response_item","payload":{"role":"user","name":"Caroline","content":[{"type":"input_text","text":"Hi Mel"}]}}"#,
            r#"not json"#,
            r#"{"type":"stop"}"#,
        ];
        let out = segments("s1", &lines);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["id"], "s1#2024-03-10");
        assert_eq!(out[0]["date"], "2024-03-10T09:00:00.000Z");
        let messages = out[0]["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(
            messages[0],
            json!({"role": "user", "content": "I bought a red kayak."})
        );
        assert_eq!(messages[1]["content"], "Nice!");
        assert_eq!(
            messages[2],
            json!({"role": "user", "content": "Hi Mel", "name": "Caroline"})
        );
    }

    #[test]
    fn a_transcript_without_text_is_no_conversation() {
        assert!(segments("s", &[r#"{"type":"stop"}"#]).is_empty());
    }

    #[test]
    fn a_resumed_session_keeps_each_message_under_its_own_date() {
        let lines = [
            r#"{"type":"user","message":{"role":"user","content":"before any date"}}"#,
            r#"{"type":"user","timestamp":"2024-03-10T23:50:00.000Z","message":{"role":"user","content":"day one"}}"#,
            r#"{"type":"assistant","message":{"role":"assistant","content":"reply on day one"}}"#,
            r#"{"type":"user","timestamp":"2024-03-12T08:00:00.000Z","message":{"role":"user","content":"resumed on day three"}}"#,
            r#"{"type":"assistant","timestamp":"2024-03-12T08:00:05.000Z","message":{"role":"assistant","content":"reply on day three"}}"#,
        ];
        let out = segments("s", &lines);
        assert_eq!(
            out.iter()
                .map(|s| s["id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["s#2024-03-10", "s#2024-03-12"]
        );
        let contents = |i: usize| -> Vec<String> {
            out[i]["messages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m["content"].as_str().unwrap().to_owned())
                .collect()
        };
        assert_eq!(
            contents(0),
            ["before any date", "day one", "reply on day one"]
        );
        assert_eq!(contents(1), ["resumed on day three", "reply on day three"]);
        assert_eq!(out[1]["date"], "2024-03-12T08:00:00.000Z");
    }

    #[test]
    fn an_undated_transcript_is_one_undated_conversation() {
        let out = segments(
            "s",
            &[r#"{"type":"user","message":{"role":"user","content":"hi"}}"#],
        );
        assert_eq!(out[0]["id"], "s#undated");
        assert_eq!(out[0]["date"], Value::Null);
    }

    fn record(path: &Path, line: &str, modified: i64, declared: Option<i64>) -> SourceRecord {
        let mut record = SourceRecord::new("n", "u");
        record.content = line.as_bytes().to_vec();
        record.transcript = Some(Arc::new(TranscriptOrigin {
            path: path.to_path_buf(),
            modified: Some(modified),
            declared_retention_seconds: declared,
        }));
        record
    }

    const LINE: &str = r#"{"type":"user","sessionId":"sess-1","timestamp":"2026-10-03T09:00:00.000Z","message":{"role":"user","content":"hello"}}"#;

    #[test]
    fn identical_file_names_in_different_directories_are_different_conversations() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a/s.jsonl"), dir.path().join("b/s.jsonl"));
        for path in [&a, &b] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, LINE).unwrap();
        }
        let records = vec![record(&a, LINE, NOW, None), record(&b, LINE, NOW, None)];
        let present = [canonical(&a), canonical(&b)].into_iter().collect();
        let out = plan(86_400, &records, dir.path(), &present, Ledger::new(), NOW);
        let ids: BTreeSet<&str> = out
            .entries
            .iter()
            .filter_map(|e| e["id"].as_str())
            .collect();
        assert_eq!(ids.len(), 2, "{ids:?}");
        assert!(ids.iter().all(|id| id.starts_with("sess-1@")));
        assert_eq!(out.ledger.len(), 2);
    }

    #[test]
    fn conversations_carry_their_retention_and_expired_ones_are_retracted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.jsonl");
        std::fs::write(&path, LINE).unwrap();
        let present = [canonical(&path)].into_iter().collect();
        // Kept for 30 days from its last change: Kindex is told the last day.
        let fresh = plan(
            30 * 86_400,
            &[record(&path, LINE, NOW, None)],
            dir.path(),
            &present,
            Ledger::new(),
            NOW,
        );
        assert_eq!(
            fresh.entries[0]["expires"],
            day_of_seconds(NOW + 29 * 86_400)
        );
        // A sidecar's declared retention wins over the configured one.
        let declared = plan(
            30 * 86_400,
            &[record(&path, LINE, NOW, Some(3 * 86_400))],
            dir.path(),
            &present,
            Ledger::new(),
            NOW,
        );
        assert_eq!(
            declared.entries[0]["expires"],
            day_of_seconds(NOW + 2 * 86_400)
        );
        // Later, past retention: the same transcript is retracted, not resent.
        let later = NOW + 31 * 86_400;
        let expired = plan(
            30 * 86_400,
            &[record(&path, LINE, NOW, None)],
            dir.path(),
            &present,
            fresh.ledger.clone(),
            later,
        );
        assert_eq!(expired.expired, 1);
        assert_eq!(
            expired.entries,
            vec![json!({"id": fresh.entries[0]["id"], "retracted": true})]
        );
        assert!(expired.ledger.is_empty());
        // Past retention with no transcript in the scan at all: retracted too.
        let swept = plan(
            30 * 86_400,
            &[],
            Path::new("/elsewhere"),
            &BTreeSet::new(),
            fresh.ledger,
            later,
        );
        assert_eq!(swept.expired, 1);
        assert_eq!(swept.entries[0]["retracted"], true);
    }

    #[test]
    fn a_transcript_gone_from_its_source_is_retracted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.jsonl");
        std::fs::write(&path, LINE).unwrap();
        let present: BTreeSet<PathBuf> = [canonical(&path)].into_iter().collect();
        let first = plan(
            86_400 * 30,
            &[record(&path, LINE, NOW, None)],
            dir.path(),
            &present,
            Ledger::new(),
            NOW,
        );
        // Ingesting another source leaves it alone.
        let other = plan(
            86_400 * 30,
            &[],
            Path::new("/elsewhere"),
            &BTreeSet::new(),
            first.ledger.clone(),
            NOW,
        );
        assert!(other.entries.is_empty() && other.ledger.len() == 1);
        // The same source without it: retracted.
        let gone = plan(
            86_400 * 30,
            &[],
            dir.path(),
            &BTreeSet::new(),
            first.ledger,
            NOW,
        );
        assert_eq!(gone.removed, 1);
        assert_eq!(gone.entries[0]["retracted"], true);
    }

    #[test]
    fn a_day_no_longer_in_the_transcript_is_retracted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.jsonl");
        let mut ledger = Ledger::new();
        let base = conversation_base(&canonical(&path), Some("sess-1"));
        std::fs::write(&path, LINE).unwrap();
        ledger.insert(
            base.clone(),
            LedgerEntry {
                path: canonical(&path).to_string_lossy().into_owned(),
                deadline: NOW + 86_400 * 30,
                segments: vec![format!("{base}#2026-09-01"), format!("{base}#2026-10-03")],
            },
        );
        let present = [canonical(&path)].into_iter().collect();
        let out = plan(
            86_400 * 30,
            &[record(&path, LINE, NOW, None)],
            dir.path(),
            &present,
            ledger,
            NOW,
        );
        assert!(
            out.entries
                .contains(&json!({"id": format!("{base}#2026-09-01"), "retracted": true}))
        );
        assert!(
            out.entries
                .iter()
                .any(|e| e["id"] == format!("{base}#2026-10-03") && e["messages"].is_array())
        );
    }

    #[test]
    fn an_oversized_transcript_is_never_read_or_exported() {
        // The scan skips a transcript over the per-file bound, so it yields no
        // records, and the hand-off exports only the scan's records.
        let dir = tempfile::tempdir().unwrap();
        let line = format!("{LINE}\n");
        std::fs::write(
            dir.path().join("big.jsonl"),
            line.repeat(1024 * 1024 / line.len() + 2),
        )
        .unwrap();
        std::fs::write(dir.path().join("small.jsonl"), &line).unwrap();
        let scan = crate::lifecycle::scan_transcripts(
            "claude_jsonl",
            dir.path(),
            "2026-10-03T09:00:00.000Z",
        )
        .unwrap();
        assert_eq!(scan.skipped.values().sum::<usize>(), 1);
        assert!(!scan.records.is_empty());
        assert!(
            scan.records.iter().all(|r| r
                .transcript
                .as_ref()
                .unwrap()
                .path
                .ends_with("small.jsonl"))
        );
        let present = [
            canonical(&dir.path().join("small.jsonl")),
            canonical(&dir.path().join("big.jsonl")),
        ]
        .into_iter()
        .collect();
        let out = plan(
            86_400,
            &scan.records,
            dir.path(),
            &present,
            Ledger::new(),
            NOW,
        );
        assert_eq!(out.transcripts, 1);
        assert!(
            out.ledger
                .values()
                .all(|entry| entry.path.ends_with("small.jsonl"))
        );
    }

    #[test]
    fn the_personal_root_is_created_private() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("personal");
        let canonical_root = protect_root(&root).unwrap();
        assert_eq!(
            std::fs::metadata(&canonical_root)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn a_permissive_personal_root_is_tightened() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("personal");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
        protect_root(&root).unwrap();
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn a_symlinked_personal_root_is_refused_with_or_without_a_trailing_separator() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = dir.path().join("personal");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(protect_root(&link).is_err());
        let mut trailing = link.into_os_string();
        trailing.push("/");
        assert!(protect_root(Path::new(&trailing)).is_err());
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn a_symlinked_handoff_directory_is_never_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let root = protect_root(&dir.path().join("personal")).unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join(HANDOFF_DIR)).unwrap();
        assert!(handoff_dir(&root).is_err());
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    }

    fn selected(fact_id: &str) -> Value {
        json!({"fact_id": fact_id, "role": "ratified_ruling", "store_kind": "company", "atom_kind": "decision",
               "standing": "ratified", "provenance": "human", "governs_paths": ["src/pay"]})
    }

    #[test]
    fn a_withheld_projection_releases_no_statements() {
        let result = json!({"projection_state": "withheld", "degraded_policy": "block_dependent_decision",
                            "selected": [selected("f1")], "brief": {"authority_refresh": {"status": "ok"}}});
        let statements = BTreeMap::from([("f1".to_owned(), "Use the ledger service.".to_owned())]);
        let team = team_knowledge(&result, &statements);
        assert_eq!(team.facts, 0);
        assert!(
            team.items
                .iter()
                .all(|item| !item.contains("ledger service"))
        );
        assert!(team.items[0].contains("withheld"));
        assert_eq!(team.report["projection_state"], "withheld");
    }

    #[test]
    fn released_statements_keep_their_governance() {
        let result = json!({"projection_state": "projected", "degraded_policy": "block_dependent_decision",
                            "selected": [selected("f1")], "brief": {"authority_refresh": {"status": "ok"}}});
        let statements = BTreeMap::from([("f1".to_owned(), "Use the ledger service.".to_owned())]);
        let team = team_knowledge(&result, &statements);
        assert_eq!(team.facts, 1);
        assert_eq!(
            team.items,
            [
                "[ratified ruling; company decision; standing: ratified; provenance: human; governs: src/pay] Use the ledger service."
            ]
        );
    }

    #[test]
    fn a_degraded_projection_says_so() {
        let result = json!({"projection_state": "projected", "degraded_policy": "reversible_sandbox_only_experiment",
                            "selected": [selected("f1")],
                            "brief": {"authority_refresh": {"status": "withheld", "code": "CACHE_EXPIRED"}}});
        let statements = BTreeMap::from([("f1".to_owned(), "Use the ledger service.".to_owned())]);
        let team = team_knowledge(&result, &statements);
        assert!(
            team.items[0].contains("cached authority snapshot")
                && team.items[0].contains("CACHE_EXPIRED")
        );
        assert!(team.items[1].contains("reversible experiments only"));
        assert_eq!(team.facts, 1);
        assert_eq!(team.report["authority_refresh"], "withheld");
    }

    /// A directory whose whole ancestry the executable rules accept.
    fn verified_base() -> PathBuf {
        [
            std::env::var_os("KINBASE_TEST_VERIFIED_DIR").map(PathBuf::from),
            Some(std::env::temp_dir()),
            std::env::var_os("HOME").map(PathBuf::from),
            Some(PathBuf::from(env!("CARGO_MANIFEST_DIR"))),
        ]
        .into_iter()
        .flatten()
        .filter_map(|dir| dir.canonicalize().ok())
        .find(|dir| {
            dir.ancestors().all(|ancestor| {
                std::fs::symlink_metadata(ancestor).is_ok_and(|metadata| {
                    ancestor == Path::new("/")
                        || (!metadata.file_type().is_symlink()
                            && metadata.permissions().mode() & 0o022 == 0)
                })
            })
        })
        .expect("a directory the executable rules accept")
    }

    /// A pinned fake `kin`: `ingest` copies the staged conversations to
    /// `<data-dir>/received/`, `digest` is counted, `ask` prints its context file.
    fn fake_kindex(dir: &Path, retention_seconds: Option<i64>) -> PersonalKindexConfig {
        let body = concat!(
            "#!/bin/sh\n",
            "case \"$1\" in\n",
            "ingest) mkdir -p \"$6/received\" && cp \"$4\"/*.json \"$6/received/\" && ls -ld \"$4\" > \"$6/staging-mode\" ;;\n",
            "digest) echo digest >> \"$3/digests\" ;;\n",
            "ask) if [ \"$4\" = --context-file ]; then cat \"$5\"; fi ;;\n",
            "esac\n",
        );
        let executable = dir.join("kin");
        std::fs::write(&executable, body).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        PersonalKindexConfig {
            executable,
            executable_sha256: crate::hash::sha256_bytes(body.as_bytes()),
            env: Vec::new(),
            config: None,
            timeout_seconds: 30,
            digest: true,
            retention_seconds,
        }
    }

    fn received(root: &Path) -> Vec<Value> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(root.join("received"))
            .map(|dir| dir.flatten().map(|entry| entry.path()).collect())
            .unwrap_or_default();
        files.sort();
        let out = files
            .iter()
            .map(|path| serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap())
            .collect();
        let _ = std::fs::remove_dir_all(root.join("received"));
        out
    }

    #[test]
    fn hand_off_sends_the_scan_protects_the_root_and_retracts_past_retention() {
        let base = tempfile::TempDir::new_in(verified_base()).unwrap();
        let cfg = fake_kindex(base.path(), Some(2 * 86_400));
        let source = base.path().join("transcripts");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("s.jsonl"), LINE).unwrap();
        let root = base.path().join("personal");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        let now = crate::time::now_rfc3339_millis();
        let scan = crate::lifecycle::scan_transcripts("claude_jsonl", &source, &now).unwrap();

        let receipt = hand_off(&cfg, &root, &source, &scan.records, &now).unwrap();
        assert_eq!(receipt["conversations"], 1, "{receipt}");
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let sent = received(&root);
        assert_eq!(sent.len(), 1);
        assert!(sent[0]["id"].as_str().unwrap().starts_with("sess-1@"));
        assert!(sent[0]["expires"].is_string());
        assert!(
            std::fs::read_to_string(root.join("staging-mode"))
                .unwrap()
                .starts_with("drwx------")
        );
        assert_eq!(
            std::fs::read_to_string(root.join("digests")).unwrap(),
            "digest\n"
        );
        let ledger = std::fs::metadata(root.join(HANDOFF_DIR).join(LEDGER_FILE)).unwrap();
        assert_eq!(ledger.permissions().mode() & 0o777, 0o600);

        // Three days later the transcript is past its retention: recall
        // retracts it from Kindex before it answers.
        let later =
            crate::time::format_rfc3339_millis(chrono::Utc::now() + chrono::Duration::days(3));
        recall(&cfg, &root, "what did I say?", None, &[], &later).unwrap();
        let retracted = received(&root);
        assert_eq!(
            retracted,
            vec![json!({"id": sent[0]["id"], "retracted": true})]
        );
        assert!(load_ledger(&root.join(HANDOFF_DIR)).unwrap().is_empty());
    }

    #[test]
    fn recall_passes_team_knowledge_through_a_private_file() {
        let base = tempfile::TempDir::new_in(verified_base()).unwrap();
        let cfg = fake_kindex(base.path(), None);
        let root = base.path().join("personal");
        let answer = recall(
            &cfg,
            &root,
            "why the ledger?",
            None,
            &["[ratified ruling] Use the\nledger.".to_owned()],
            &crate::time::now_rfc3339_millis(),
        )
        .unwrap();
        assert_eq!(answer, "[ratified ruling] Use the ledger.");
        let leftovers: Vec<_> = std::fs::read_dir(root.join(HANDOFF_DIR))
            .unwrap()
            .flatten()
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }
}
