//! The authority registry moves forward only, and a registry republication
//! withdraws exactly what it stopped warranting: a dropped entry retires its
//! scope, and only a key no entry lists any more is revoked outright. Driven
//! through a running `kinbase company serve` with signed requests.

mod support;

use kinbase::company::client::Client;
use kinbase::company::db::CompanyDb;
use kinbase::config::TokenRecord;
use kinbase::crypto::PrivateKey;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use support::SpawnAlone;
use tempfile::TempDir;

const TOKEN: &str = "facts-registry-publication";

struct Service {
    _temp: TempDir,
    child: Child,
    root: PrivateKey,
    client: Client,
    sqlite: PathBuf,
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Service {
    /// A service whose only credential is the facts token: registry
    /// publication is authorised by the steward signature (ruling C6).
    fn start() -> Self {
        let temp = TempDir::new().expect("temporary root");
        let root = PrivateKey::generate();
        let root_path = temp.path().join("company-root.key");
        let token_path = temp.path().join("facts.token");
        let config_path = temp.path().join("kinbased.toml");
        let sqlite = temp.path().join("company.sqlite");
        root.save_new(&root_path, "Company root key")
            .expect("save root key");
        kinbase::crypto::write_0600(&token_path, TOKEN.as_bytes(), "facts token")
            .expect("write token");
        // A port the kernel just handed out and released; the service binds
        // it a moment later.
        let port = TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("free port")
            .port();
        let config = format!(
            r#"schema_version = "1"
company_id = "company-demo"
sqlite_path = "{db}"
bind = "127.0.0.1:{port}"
root_key_file = "{root_key}"
facts_token_file = "{token}"
auth_failures_per_minute = 100
default_fact_freshness_seconds = 900
candidate_lifetime_seconds = 900
clock_skew_seconds = 300
nonce_retention_seconds = 1300
"#,
            db = sqlite.display(),
            root_key = root_path.display(),
            token = token_path.display(),
        );
        kinbase::crypto::write_0600(&config_path, config.as_bytes(), "service config")
            .expect("write config");
        let mut child = Command::new(env!("CARGO_BIN_EXE_kinbase"))
            .args(["company", "serve", "--config"])
            .arg(&config_path)
            .arg("--json")
            .env("HOME", temp.path())
            .env("XDG_CONFIG_HOME", temp.path().join("config"))
            .env("XDG_STATE_HOME", temp.path().join("state"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn_alone()
            .expect("start company service");
        let mut banner = String::new();
        BufReader::new(child.stdout.take().expect("service stdout"))
            .read_line(&mut banner)
            .expect("read banner");
        assert!(banner.contains("company-serving"), "banner: {banner}");
        let client = Client::new(
            &format!("http://127.0.0.1:{port}"),
            TokenRecord {
                token: TOKEN.to_owned(),
            },
            PrivateKey::generate(),
            Some(root.public()),
            temp.path().join("client-cache"),
            false,
        )
        .expect("client");
        Service {
            _temp: temp,
            child,
            root,
            client,
            sqlite,
        }
    }

    fn db(&self) -> CompanyDb {
        CompanyDb::open(&self.sqlite).expect("open company store")
    }

    fn registry(&self, cursor: Option<&str>, entries: Vec<Value>) -> Value {
        let mut document = json!({"schema": kinbase::model::REGISTRY_SCHEMA, "entries": entries});
        if let Some(cursor) = cursor {
            document["authority_cursor"] = Value::String(cursor.to_owned());
        }
        self.root
            .sign_document("authority-registry-entry", &document)
            .expect("sign registry")
    }

    fn steward(&self) -> Value {
        entry("company-steward", "company:root", &self.root)
    }

    /// Status and body of one registry publication.
    fn publish(&self, document: &Value) -> (u16, Value) {
        let response = self
            .client
            .post("/authority-registry", document)
            .expect("post registry");
        (response.status, response.body)
    }

    fn code(&self, document: &Value) -> (u16, String) {
        let (status, body) = self.publish(document);
        (status, error_code(&body))
    }

    fn post_fact(&self, fact: &Value) -> (u16, Value) {
        let response = self.client.post("/facts", fact).expect("post fact");
        (response.status, response.body)
    }

    /// Facts the service projects as current; `/facts` also lists every
    /// other admitted event with the status it was evaluated to.
    fn current_fact_ids(&self) -> Vec<String> {
        let body = self.client.get_ok("/facts").expect("read facts");
        let mut ids: Vec<String> = body["facts"]
            .as_array()
            .expect("facts array")
            .iter()
            .filter(|fact| fact["status"] == "current")
            .filter_map(|fact| fact["fact_id"].as_str().map(str::to_owned))
            .collect();
        ids.sort();
        ids
    }

    /// Keys revoked outright, and (key, scope) pairs revoked for one scope.
    fn revocations(&self) -> (Vec<String>, Vec<(String, String)>) {
        let body = self
            .client
            .get_ok("/revocations")
            .expect("read revocations");
        let mut keys = Vec::new();
        let mut scoped = Vec::new();
        for document in body["revocations"].as_array().expect("revocations") {
            let key = document["revoked_key"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            match document["revoked_scope"].as_str() {
                Some(scope) => scoped.push((key, scope.to_owned())),
                None => keys.push(key),
            }
        }
        keys.sort();
        keys.dedup();
        scoped.sort();
        scoped.dedup();
        (keys, scoped)
    }
}

fn error_code(body: &Value) -> String {
    body["error"]["code"]
        .as_str()
        .or_else(|| body["code"].as_str())
        .unwrap_or_default()
        .to_owned()
}

fn entry(authority_id: &str, scope: &str, key: &PrivateKey) -> Value {
    json!({
        "authority_id": authority_id,
        "scope": scope,
        "public_key": key.public().to_hex(),
        "channel": "company:root",
        "capabilities": ["answer"]
    })
}

/// A Company fact `key` signs as `authority_id` in `scope`.
fn fact(key: &PrivateKey, authority_id: &str, scope: &str, statement: &str) -> Value {
    let fact_id = kinbase::model::fact_id("company", scope, statement);
    let asserted_at = kinbase::time::now_rfc3339_millis();
    let document = json!({
        "schema": kinbase::model::EVENT_SCHEMA,
        "event_id": kinbase::model::event_id(
            &fact_id,
            &kinbase::hash::sha256_text(statement),
            &asserted_at,
            authority_id,
        ),
        "store_kind": "company",
        "authority_id": authority_id,
        "authority_scope": scope,
        "fact_id": fact_id,
        "logical_key": kinbase::model::logical_key("company", scope, statement),
        "atom_kind": "decision",
        "scope": scope,
        "statement": statement,
        "evidence_refs": ["registry-publication-test"],
        "asserted_at": asserted_at,
        "effective_from": asserted_at,
        "disposition": "accepted",
        "distortion": {"trigger": "a scheduling or storage change", "loss_if_absent": 7500, "rationale": "the owner decided it"},
        "parents": [],
        "supersedes": [],
        "redundancy_with": [],
        "complements": [],
        "company_refs": [],
        "authority_snapshot_cursor": "0",
        "confidence": 9000,
        "unresolved_uncertainty": null
    });
    key.sign_document("fact-event", &document)
        .expect("sign fact")
}

#[test]
fn an_old_registry_posted_again_revokes_nothing() {
    let service = Service::start();
    let steward = service.steward();
    let architect = PrivateKey::generate();
    let first = service.registry(Some("1000"), vec![steward.clone()]);
    let second = service.registry(
        Some("1001"),
        vec![
            steward,
            entry("chief-architect", "architecture:scheduling", &architect),
        ],
    );
    assert_eq!(service.publish(&first).0, 201);
    assert_eq!(service.publish(&second).0, 201);
    let events_before = service.db().cursor().expect("cursor");

    assert_eq!(service.code(&first), (409, "APPROVAL_REPLAY".to_owned()));
    assert_eq!(
        service.db().cursor().expect("cursor"),
        events_before,
        "no event was written"
    );
    assert_eq!(service.revocations(), (Vec::new(), Vec::new()));
    let registry = service
        .client
        .get_ok("/authority-registry")
        .expect("read registry");
    assert!(
        registry.to_string().contains(&architect.public().to_hex()),
        "{registry}"
    );
    assert_eq!(
        service
            .db()
            .audit_records("registry-publication-refused")
            .expect("audit")
            .len(),
        1,
        "the refused replay is on record"
    );
}

#[test]
fn a_superseded_document_at_the_current_cursor_is_not_current() {
    // History from before the forward-only rule can hold two documents at one
    // authority cursor; only the newer one is current.
    let service = Service::start();
    let steward = service.steward();
    let first = service.registry(Some("1000"), vec![steward.clone()]);
    let second = service.registry(
        Some("1000"),
        vec![
            steward,
            entry("maintainer", "codebase:x", &PrivateKey::generate()),
        ],
    );
    let db = service.db();
    for document in [&first, &second] {
        db.append_event(
            &format!("registry_{}", &kinbase::json::digest(document)[..40]),
            "authority-registry-entry",
            "registry",
            document,
            "",
            "verified",
            None,
        )
        .expect("write history row")
        .expect("history row is new");
    }
    assert_eq!(service.code(&first), (409, "APPROVAL_REPLAY".to_owned()));
    assert_eq!(service.publish(&second).0, 200);
}

#[test]
fn the_current_registry_posted_again_is_the_same_receipt() {
    let service = Service::start();
    let document = service.registry(Some("1000"), vec![service.steward()]);
    let (created, receipt) = service.publish(&document);
    assert_eq!(created, 201, "{receipt}");
    let events_before = service.db().cursor().expect("cursor");
    // Long enough that a receipt stamped with the retry's own clock differs.
    std::thread::sleep(std::time::Duration::from_millis(20));
    let (again, retried) = service.publish(&document);
    assert_eq!(again, 200, "{retried}");
    assert_eq!(retried, receipt, "the retry returns the original receipt");
    assert_eq!(service.db().cursor().expect("cursor"), events_before);
}

#[test]
fn a_registry_must_advance_its_cursor() {
    let service = Service::start();
    let steward = service.steward();
    assert_eq!(
        service
            .publish(&service.registry(Some("1000"), vec![steward.clone()]))
            .0,
        201
    );
    let same_cursor = service.registry(
        Some("1000"),
        vec![
            steward.clone(),
            entry("maintainer", "codebase:x", &PrivateKey::generate()),
        ],
    );
    assert_eq!(
        service.code(&same_cursor),
        (409, "APPROVAL_REPLAY".to_owned())
    );
    let older = service.registry(Some("999"), vec![steward.clone()]);
    assert_eq!(service.code(&older), (409, "APPROVAL_REPLAY".to_owned()));
    assert_eq!(
        service.code(&service.registry(None, vec![steward])),
        (400, "CONFIG_INVARIANT".to_owned())
    );
}

#[test]
fn a_dropped_scope_withdraws_what_it_warranted_and_nothing_else() {
    let service = Service::start();
    let steward = service.steward();
    let architect = PrivateKey::generate();
    let hex = architect.public().to_hex();
    let both = service.registry(
        Some("1000"),
        vec![
            steward.clone(),
            entry("chief-architect", "architecture:scheduling", &architect),
            entry("chief-architect", "architecture:storage", &architect),
        ],
    );
    assert_eq!(service.publish(&both).0, 201);
    let scheduling = fact(
        &architect,
        "chief-architect",
        "architecture:scheduling",
        "Jobs are scheduled by the queue, never by cron.",
    );
    let storage = fact(
        &architect,
        "chief-architect",
        "architecture:storage",
        "Blobs are stored content-addressed.",
    );
    for document in [&scheduling, &storage] {
        let (status, receipt) = service.post_fact(document);
        assert_eq!(status, 201, "{receipt}");
    }
    let scheduling_id = scheduling["fact_id"].as_str().unwrap().to_owned();
    let storage_id = storage["fact_id"].as_str().unwrap().to_owned();
    let mut both_ids = vec![scheduling_id.clone(), storage_id.clone()];
    both_ids.sort();
    assert_eq!(service.current_fact_ids(), both_ids);

    // Storage leaves the registry; the key keeps scheduling.
    let one = service.registry(
        Some("1001"),
        vec![
            steward.clone(),
            entry("chief-architect", "architecture:scheduling", &architect),
        ],
    );
    assert_eq!(service.publish(&one).0, 201);
    assert_eq!(
        service.revocations(),
        (
            Vec::new(),
            vec![(hex.clone(), "architecture:storage".to_owned())]
        ),
        "the entry is revoked, not the key"
    );
    assert_eq!(
        service.current_fact_ids(),
        vec![scheduling_id.clone()],
        "the storage fact had only the dropped scope behind it"
    );
    let apologies = service
        .client
        .get_ok("/unknowns")
        .expect("read unknowns")
        .to_string();
    assert!(apologies.contains(&storage_id), "{apologies}");
    assert!(!apologies.contains(&scheduling_id), "{apologies}");
    let (status, refused) = service.post_fact(&fact(
        &architect,
        "chief-architect",
        "architecture:storage",
        "Blobs are stored by path.",
    ));
    assert_eq!(
        (status, error_code(&refused).as_str()),
        (403, "AUTHORITY_WRONG_SCOPE")
    );
    let (status, receipt) = service.post_fact(&fact(
        &architect,
        "chief-architect",
        "architecture:scheduling",
        "Retries back off exponentially.",
    ));
    assert_eq!(
        status, 201,
        "the key still speaks for scheduling: {receipt}"
    );

    // No entry lists the key any more: now the key itself is revoked.
    let none = service.registry(Some("1002"), vec![steward]);
    assert_eq!(service.publish(&none).0, 201);
    assert_eq!(service.revocations().0, vec![hex]);
    assert!(
        service.current_fact_ids().is_empty(),
        "every fact the key alone warranted withdraws"
    );
}
