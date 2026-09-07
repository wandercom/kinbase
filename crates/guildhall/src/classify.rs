use crate::model::Atom;
use crate::scanner::scanner;
use sha2::{Digest, Sha256};

pub const EXTRACTION_VERSION: &str = "guildhall-extract/1";

pub fn atomize(
    source_kind: &str,
    native_id: &str,
    statement: &str,
    scope: &str,
    confidence: u16,
) -> Atom {
    let taints = scanner(statement).taints;
    let mut destinations = Vec::new();
    match source_kind {
        "codex_jsonl" | "claude_jsonl" => destinations.push("personal".to_owned()),
        "company" | "authority_answer" => destinations.push("company".to_owned()),
        "repo_code" | "repo_tests" | "docs_adr" | "git_history" | "github_export"
        | "runtime_evidence" | "kindex" => destinations.push("codebase".to_owned()),
        _ => {}
    }
    if taints.iter().any(|taint| taint.hard_block()) {
        destinations.clear();
    }
    Atom {
        atom_id: format!(
            "atom_{:x}",
            Sha256::digest(format!("{source_kind}\0{native_id}\0{statement}").as_bytes())
        ),
        statement: statement.to_owned(),
        scope: scope.to_owned(),
        atom_kind: infer_kind(statement),
        confidence,
        provenance: source_kind.to_owned(),
        taints: taints
            .iter()
            .map(|taint| taint.as_str().to_owned())
            .collect(),
        destinations,
        unresolved_uncertainty: (confidence < 600).then(|| {
            "low-confidence atom was retained as evidence, not trusted direction".to_owned()
        }),
    }
}

fn infer_kind(statement: &str) -> String {
    let lower = statement.to_lowercase();
    if lower.contains("must") || lower.contains("required") {
        "constraint".to_owned()
    } else if lower.contains('?') {
        "question".to_owned()
    } else if lower.contains("use ") || lower.contains("choose ") {
        "decision".to_owned()
    } else {
        "observation".to_owned()
    }
}
