//! Adapter seams reported by diagnostics (architecture §1 and §11).

use serde_json::{Value, json};

pub const SOURCE_KINDS: [&str; 12] = [
    "codex_jsonl",
    "claude_jsonl",
    "repo_code",
    "repo_tests",
    "git_history",
    "docs_adr",
    "github_export",
    "runtime_evidence",
    "kindex",
    "authority_answer",
    // Issue trackers are where the *why* lives, and they link outward to the pull
    // request that carries the code and to the documents and threads that argued
    // it. That makes a ticket the natural spine of the association graph.
    "issue_tracker",
    // A pull request is the only artifact that ties a stated intent to the exact
    // lines that changed. Its diff hunks are where code anchors come from.
    "pull_request",
];

/// Report the exact Kindex 0.36 seam this product reserves and supports.
/// This is a diagnostic, not an admission decision; the ingest command still
/// verifies every planted event independently.
pub fn kindex_seam_conformance() -> Value {
    json!({
        "native_schema": "kindex/0.36.0-export",
        "nodes_columns": ["id", "node_type", "title", "content", "payload", "created_at"],
        "edges_columns": ["src", "dst", "relationship", "reason"],
        "source_kinds": SOURCE_KINDS,
        "reserved_paths": crate::codebase::RESERVED_PATHS,
        "legacy_collision_policy": "refuse-without-bytes",
        "event_schema": crate::model::EVENT_SCHEMA,
        "disposition": "verified-seam"
    })
}
