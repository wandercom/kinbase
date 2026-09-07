use guildhall::classify::atomize;
use guildhall::hash::sha256_text;
use guildhall::json::canonical_text;
use guildhall::scanner::hard_blocked;
use serde_json::json;

#[test]
fn canonical_json_is_deterministic_and_taint_blocks_shared_output() {
    let value = json!({"b": 1, "a": 2});
    assert_eq!(canonical_text(&value), r#"{"a":2,"b":1}"#);
    assert_eq!(
        sha256_text(&canonical_text(&value)),
        sha256_text(r#"{"a":2,"b":1}"#)
    );
    assert!(hard_blocked("my api_key is guildhall-canary"));
    let atom = atomize(
        "codex_jsonl",
        "1",
        "my api_key",
        "personal",
        900,
        "obs_test",
        "digest_test",
        None,
    );
    assert_eq!(atom.destinations, vec!["personal".to_owned()]);
}

#[test]
fn codebase_atoms_use_repository_bound_destination() {
    let atom = atomize(
        "repo_code",
        "line:1",
        "Scheduler diagnosis must use deployed lookahead.",
        "scheduler/diagnosis",
        9000,
        "obs_test",
        "digest_test",
        Some("018f"),
    );
    assert_eq!(atom.destinations, vec!["codebase:018f".to_owned()]);
    assert_eq!(atom.atom_kind, "constraint");
}

#[test]
fn low_confidence_shared_atoms_are_demoted() {
    let atom = atomize(
        "repo_code",
        "line:1",
        "maybe use a workaround",
        "repository",
        500,
        "obs_test",
        "digest_test",
        Some("018f"),
    );
    assert!(atom.destinations.is_empty());
    assert!(atom.unresolved_uncertainty.is_some());
}
