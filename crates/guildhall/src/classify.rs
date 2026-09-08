use crate::model::Atom;
use crate::scanner::{ScanResult, Taint, scanner};
use sha2::{Digest, Sha256};

pub const EXTRACTION_VERSION: &str = "guildhall-extract/1";

pub fn source_kind_is_supported(source_kind: &str) -> bool {
    matches!(
        source_kind,
        "codex_jsonl"
            | "claude_jsonl"
            | "repo_code"
            | "repo_tests"
            | "git_history"
            | "docs_adr"
            | "github_export"
            | "runtime_evidence"
            | "kindex"
            | "authority_answer"
    )
}

pub fn atomize(
    source_kind: &str,
    native_id: &str,
    statement: &str,
    scope: &str,
    confidence: u16,
    observation_id: &str,
    source_digest: &str,
    repository_id: Option<&str>,
) -> Atom {
    let scan: ScanResult = scanner(statement);
    let hard_block = scan.taints.iter().any(|taint| taint.hard_block());
    let mut destinations = Vec::new();
    match source_kind {
        "codex_jsonl" | "claude_jsonl" => {
            destinations.push("personal".to_owned());
            if !hard_block && confidence >= 600 {
                let lower = statement.to_lowercase();
                if lower.contains("architecture") || lower.contains("company policy") {
                    destinations.push("company".to_owned());
                }
                if let Some(repository_id) = repository_id {
                    if lower.contains("repository")
                        || lower.contains("codebase")
                        || lower.contains("test")
                    {
                        destinations.push(format!("codebase:{repository_id}"));
                    }
                }
            }
        }
        "company" | "authority_answer" => {
            if !hard_block {
                destinations.push("company".to_owned());
            }
        }
        "repo_code" | "repo_tests" | "git_history" | "docs_adr" | "github_export"
        | "runtime_evidence" | "kindex" => {
            if !hard_block {
                if let Some(repository_id) = repository_id {
                    destinations.push(format!("codebase:{repository_id}"));
                }
            }
        }
        _ => {}
    }
    if confidence < 600 {
        destinations.retain(|destination| destination == "personal");
    }
    destinations.dedup();
    Atom {
        atom_id: format!(
            "atom_{:x}",
            Sha256::digest(
                format!("{source_kind}\0{native_id}\0{observation_id}\0{statement}").as_bytes()
            )
        ),
        observation_id: observation_id.to_owned(),
        source_kind: source_kind.to_owned(),
        source_digest: source_digest.to_owned(),
        statement: statement.to_owned(),
        atom_kind: infer_kind(statement),
        scope: scope.to_owned(),
        confidence,
        provenance: source_kind.to_owned(),
        taints: scan
            .taints
            .iter()
            .map(|taint| taint.as_str().to_owned())
            .collect(),
        hard_blocked: hard_block,
        proposed_destinations: destinations.clone(),
        eligible_destinations: destinations,
        demoted_destinations: Vec::new(),
        unresolved_uncertainty: (confidence < 600).then(|| {
            "low-confidence atom was retained as evidence, not trusted direction".to_owned()
        }),
        extractor: EXTRACTION_VERSION.to_owned(),
        scanner_version: crate::scanner::SCANNER_VERSION.to_owned(),
        scan_findings: scan.findings,
        repository_id: repository_id.map(str::to_owned),
        revision: None,
        disposition: None,
        effective_until: None,
        origin_trust: None,
        environment_id: None,
        supersedes_hint: Vec::new(),
    }
}

pub fn provenance_taint(source_kind: &str) -> Option<Taint> {
    match source_kind {
        "codex_jsonl" | "claude_jsonl" => Some(Taint::PersonalSession),
        "company" | "authority_answer" => Some(Taint::CompanyConfidential),
        "repo_code" | "repo_tests" | "git_history" | "docs_adr" | "github_export"
        | "runtime_evidence" | "kindex" => Some(Taint::Codebase),
        _ => None,
    }
}

fn infer_kind(statement: &str) -> String {
    let lower = statement.to_lowercase();
    if lower.contains('?') {
        "question".to_owned()
    } else if lower.contains("must") || lower.contains("required") || lower.contains("never") {
        "constraint".to_owned()
    } else if lower.contains("because") || lower.contains("rationale") {
        "rationale".to_owned()
    } else if lower.contains("use ") || lower.contains("choose ") || lower.contains("decide") {
        "decision".to_owned()
    } else {
        "observation".to_owned()
    }
}
