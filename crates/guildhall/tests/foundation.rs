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
    assert!(
        atomize("codex_jsonl", "1", "my api_key", "personal", 900)
            .destinations
            .is_empty()
    );
}
