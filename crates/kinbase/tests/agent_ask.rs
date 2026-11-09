//! Company briefs with no git repo and no recorded proof clock.
//! `oidc_support::Gate` has no API-key gate. The store checks the facts bearer
//! (`Authorization: Bearer`, oidc.rs) plus a client-key request signature
//! (spec/architecture.md). These probes use `company init` / `company serve`.
mod support;
use kinbase::company::client::Client;
use kinbase::config::TokenRecord;
use kinbase::crypto::PrivateKey;
use serde_json::{Value, json};
use std::{fs, io::{BufRead, BufReader, Read, Write}, net::TcpStream, os::unix::fs::PermissionsExt, path::{Path, PathBuf}, process::{Child, Command, Output, Stdio}, time::Duration};
use support::SpawnAlone;
use tempfile::TempDir;
const TOKEN: &str = "facts-agent-ask";
const QUESTION: &str = "widgetforge";
const STANDING: &str = "present";
const PROVENANCE: &str = "human";
struct Fact { key: &'static str, scope: &'static str, statement: &'static str, section: &'static str, heading: &'static str }
const FACTS: [Fact; 3] = [
    Fact { key: "architecture/widgetforge", scope: "architecture:widgetforge", statement: "widgetforge rulings stay binding", section: "rulings", heading: "RULINGS" },
    Fact { key: "ownership/widgetforge", scope: "ownership:widgetforge", statement: "widgetforge ownership sits with the steward", section: "ownership", heading: "OWNERSHIP" },
    Fact { key: "ticket/widgetforge", scope: "ticket:widgetforge", statement: "widgetforge ticket records the migration", section: "past_work", heading: "PAST WORK" },
];
struct Store {
    _temp: TempDir,
    home: PathBuf, config_home: PathBuf, state_home: PathBuf, personal: PathBuf, scratch: PathBuf,
    child: Child, port: u16, root: PrivateKey, client: Client,
    as_of: String,
}

impl Drop for Store {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); }
}
fn kinbase_at(home: &Path, config: &Path, state: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kinbase"));
    command.env("HOME", home).env("XDG_CONFIG_HOME", config).env("XDG_STATE_HOME", state)
        .env_remove("KINBASE_COMPANY_URL").env_remove("KINBASE_CLIENT_KEY_FD");
    command
}
fn isolated(git: bool) -> (TempDir, PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
    let temp = TempDir::new().expect("temp");
    let (home, config, state, personal, work) = (
        temp.path().join("home"), temp.path().join("config"), temp.path().join("state"),
        temp.path().join("personal"), temp.path().join("work"),
    );
    for dir in [&home, &config.join("kinbase"), &state, &personal, &work] {
        fs::create_dir_all(dir).expect("dir");
    }
    fs::set_permissions(&personal, fs::Permissions::from_mode(0o700)).expect("mode");
    if git {
        assert!(Command::new("git").args(["init", "-q"]).current_dir(&work).status_alone().unwrap().success());
    }
    (temp, home, config, state, personal, work)
}

impl Store {
    fn boot(matches_root: bool) -> Self {
        let (temp, home, config_home, state_home, personal, scratch) = isolated(false);
        let company_root = PrivateKey::generate();
        let root_path = temp.path().join("company-root.key");
        let token_path = temp.path().join("facts.token");
        let service_config = temp.path().join("kinbased.toml");
        company_root.save_new(&root_path, "Company root key").expect("root key");
        kinbase::crypto::write_0600(&token_path, TOKEN.as_bytes(), "facts token").expect("token");
        let port = std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).expect("port").port();
        let service = format!("schema_version = \"1\"\ncompany_id = \"company-demo\"\nsqlite_path = \"{}\"\nbind = \"127.0.0.1:{port}\"\nroot_key_file = \"{}\"\nfacts_token_file = \"{}\"\nauth_failures_per_minute = 1000\ndefault_fact_freshness_seconds = 3600\ncandidate_lifetime_seconds = 900\nclock_skew_seconds = 300\nnonce_retention_seconds = 1300\n", temp.path().join("company.sqlite").display(), root_path.display(), token_path.display());
        kinbase::crypto::write_0600(&service_config, service.as_bytes(), "service config").expect("service");
        let init = kinbase_at(&home, &config_home, &state_home).args(["company", "init", "--config"]).arg(&service_config).output_alone().expect("init");
        assert!(init.status.success(), "company init: {}{}", out(&init.stdout), out(&init.stderr));
        let mut child = kinbase_at(&home, &config_home, &state_home)
            .args(["company", "serve", "--config"]).arg(&service_config).arg("--json")
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null())
            .spawn_alone().expect("serve");
        let mut banner = String::new();
        BufReader::new(child.stdout.take().expect("stdout")).read_line(&mut banner).expect("banner");
        assert!(banner.contains("company-serving"), "{banner}");
        let client = Client::new(&format!("http://127.0.0.1:{port}"), TokenRecord { token: TOKEN.to_owned() }, PrivateKey::generate(), Some(company_root.public()), temp.path().join("poster-cache"), false).expect("client");
        let hex = if matches_root { company_root.public().to_hex() } else { PrivateKey::generate().public().to_hex() };
        write_user_config(&config_home.join("kinbase"), &personal, &temp.path().join("cache"), &token_path, &format!("http://127.0.0.1:{port}"), Some(&hex));
        Self { as_of: kinbase::time::now_rfc3339_millis(), _temp: temp, home, config_home, state_home, personal, scratch, child, port, root: company_root, client }
    }
    fn plant(&self) {
        let architect = PrivateKey::generate();
        let mut entries = vec![authority("company-steward", "company:root", &self.root)];
        for fact in &FACTS {
            entries.push(authority("chief-architect", fact.scope, &architect));
        }
        let registry = self.root.sign_document("authority-registry-entry", &json!({"schema": kinbase::model::REGISTRY_SCHEMA, "authority_cursor": "1000", "entries": entries})).expect("sign registry");
        let posted = self.client.post("/authority-registry", &registry).expect("post registry");
        assert_eq!(posted.status, 201, "{}", posted.body);
        for fact in &FACTS {
            let posted = self.client.post("/facts", &signed_fact(&architect, fact, &self.as_of)).expect("post fact");
            assert_eq!(posted.status, 201, "{}", posted.body);
        }
    }
    fn ask(&self, json: bool, as_of: Option<&str>) -> Output {
        let mut args = vec!["ask", QUESTION];
        if let Some(as_of) = as_of {
            args.extend(["--as-of", as_of]);
        }
        if json {
            args.push("--json");
        }
        kinbase_at(&self.home, &self.config_home, &self.state_home).current_dir(&self.scratch).args(&args).output_alone().expect("ask")
    }
}
fn write_user_config(dir: &Path, personal: &Path, cache: &Path, token: &Path, url: &str, root_hex: Option<&str>) {
    let client = dir.join("client.key");
    PrivateKey::generate().save_new(&client, "client key").expect("client key");
    let mut body = format!("schema_version = \"1\"\n\n[personal]\ndata_root = \"{}\"\n\n[company]\nurl = \"{url}\"\nfacts_token_file = \"{}\"\nclient_key_file = \"{}\"\ncache_root = \"{}\"\n", personal.display(), token.display(), client.display(), cache.display());
    if let Some(hex) = root_hex {
        let root_file = dir.join("root-public.key");
        kinbase::crypto::write_0600(&root_file, format!("{hex}\n").as_bytes(), "root public").expect("root public");
        body.push_str(&format!("root_public_key_file = \"{}\"\n", root_file.display()));
    }
    kinbase::crypto::write_0600(&dir.join("config.toml"), body.as_bytes(), "user config").expect("config");
}
fn authority(id: &str, scope: &str, key: &PrivateKey) -> Value {
    json!({"authority_id": id, "scope": scope, "public_key": key.public().to_hex(), "channel": "company:root", "capabilities": ["answer"]})
}
fn signed_fact(key: &PrivateKey, fact: &Fact, at: &str) -> Value {
    let fact_id = kinbase::model::fact_id("company", fact.scope, fact.statement);
    key.sign_document("fact-event", &json!({
        "schema": kinbase::model::EVENT_SCHEMA,
        "event_id": kinbase::model::event_id(&fact_id, &kinbase::hash::sha256_text(fact.statement), at, "chief-architect"),
        "store_kind": "company", "authority_id": "chief-architect", "authority_scope": fact.scope,
        "fact_id": fact_id, "logical_key": fact.key, "atom_kind": "decision", "scope": fact.scope,
        "statement": fact.statement, "evidence_refs": ["agent-ask"], "asserted_at": at, "effective_from": at,
        "disposition": "accepted", "authority_snapshot_cursor": "0", "confidence": 9000, "unresolved_uncertainty": null,
        "distortion": {"trigger": "a scheduling or storage change", "loss_if_absent": 7500, "rationale": "the owner decided it"},
        "parents": [], "supersedes": [], "redundancy_with": [], "complements": [], "company_refs": [],
        "standing": STANDING, "provenance": PROVENANCE
    })).expect("sign fact")
}
fn out(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
fn fact_line(fact: &Fact) -> String {
    format!("- [{}] ({STANDING}, {PROVENANCE}) {}", fact.key, fact.statement)
}
fn section<'a>(text: &'a str, heading: &str) -> Vec<&'a str> {
    let lines: Vec<_> = text.lines().collect();
    let start = lines.iter().position(|line| *line == heading).expect(heading);
    lines[start + 1..].iter().copied().take_while(|line| !matches!(*line, "RULINGS" | "OWNERSHIP" | "PAST WORK")).filter(|line| !line.is_empty()).collect()
}
fn personal_quiet(personal: &Path) {
    let Ok(connection) = rusqlite::Connection::open(personal.join("kinbase-personal.sqlite3")) else { return };
    for (sql, what) in [("SELECT COUNT(*) FROM meta WHERE key LIKE 'proof-clock:%'", "proof clock"), ("SELECT COUNT(*) FROM query_log", "query log")] {
        let rows: i64 = connection.query_row(sql, [], |row| row.get(0)).unwrap_or(0);
        assert_eq!(rows, 0, "ask recorded a {what}");
    }
}
fn brief(output: &Output) -> Value {
    let raw = out(&output.stdout);
    assert!(output.status.success(), "json ask failed: {raw}{}", out(&output.stderr));
    let line = raw.trim();
    assert!(!line.contains('\n'), "json brief is not one line: {line}");
    serde_json::from_str(line).expect("one json object")
}
fn error_field(output: &Output, name: &str) -> String {
    let value: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    value.get(name).and_then(Value::as_str).or_else(|| value.get("error").and_then(|e| e.get(name)).and_then(Value::as_str)).unwrap_or("").to_owned()
}

#[test]
fn ask_in_a_clean_home_and_nongit_dir_groups_company_facts_and_records_nothing() {
    let store = Store::boot(true);
    store.plant();
    assert!(!store.scratch.join(".git").exists(), "cwd is a git worktree");
    // `ask QUESTION` with no flag. Facts were admitted at boot, so the later
    // wall-clock instant still includes them.
    let text = store.ask(false, None);
    let rendered = out(&text.stdout);
    assert!(text.status.success(), "text ask failed: {rendered}{}", out(&text.stderr));
    assert_eq!(rendered.lines().filter(|line| matches!(*line, "RULINGS" | "OWNERSHIP" | "PAST WORK")).collect::<Vec<_>>(), ["RULINGS", "OWNERSHIP", "PAST WORK"]);
    let open = brief(&store.ask(true, None));
    let pinned = brief(&store.ask(true, Some(&store.as_of)));
    assert_eq!(pinned["as_of"], store.as_of);
    assert_ne!(open["as_of_source"], pinned["as_of_source"], "no-flag and --as-of share a clock source");
    assert!(pinned["authority_refresh"]["status"].as_str().is_some_and(|status| !status.is_empty()), "{pinned}");
    assert!(pinned.get("candidates").is_none() && pinned.get("selection_trace").is_none(), "{pinned}");
    for fact in &FACTS {
        let expected = fact_line(fact);
        assert_eq!(section(&rendered, fact.heading), [expected.as_str()]);
        let row = &pinned[fact.section][0];
        assert_eq!(
            (row["logical_key"].as_str(), row["standing"].as_str(), row["provenance"].as_str(), row["statement"].as_str()),
            (Some(fact.key), Some(STANDING), Some(PROVENANCE), Some(fact.statement))
        );
    }
    personal_quiet(&store.personal);
}

#[test]
fn ask_prints_no_brief_when_the_company_root_does_not_verify() {
    let store = Store::boot(false);
    store.plant();
    let output = store.ask(true, Some(&store.as_of));
    let rendered = format!("{}{}", out(&output.stdout), out(&output.stderr));
    assert!(!output.status.success(), "{rendered}");
    assert!(!rendered.contains("RULINGS") && !rendered.contains("widgetforge rulings"), "{rendered}");
    let code = error_field(&output, "code");
    assert!(kinbase::error::CODES.contains(&code.as_str()), "{rendered}");
    assert_eq!(output.status.code(), Some(kinbase::error::exit_for(&code)), "{rendered}");
}

#[test]
fn project_as_of_on_an_uncertified_git_worktree_needs_no_recorded_proof_clock() {
    // spec/cli.md: `project --repo PATH --task --decision`, exit 2 outside a
    // Git worktree. A certificate is not in that synopsis, so this worktree
    // is uncertified. The failure under test is the missing proof clock.
    let (_temp, home, config_home, state_home, personal, repo) = isolated(true);
    kinbase::crypto::write_0600(&config_home.join("kinbase/config.toml"), format!("schema_version = \"1\"\n\n[personal]\ndata_root = \"{}\"\n", personal.display()).as_bytes(), "config").expect("config");
    let repo_arg = repo.display().to_string();
    let output = kinbase_at(&home, &config_home, &state_home).current_dir(&repo).args(["project", "--repo", &repo_arg, "--task", QUESTION, "--decision", "read", "--as-of", "2026-11-09T12:00:00.000Z", "--json"]).output_alone().expect("project");
    let rendered = format!("{}{}", out(&output.stdout), out(&output.stderr));
    assert!(!rendered.contains("no recorded proof clock"), "{rendered}");
    assert!(output.status.success(), "{rendered}");
    assert_eq!(serde_json::from_slice::<Value>(&output.stdout).expect("json")["as_of"], "2026-11-09T12:00:00.000Z");
}

#[test]
fn company_config_without_root_public_key_file_is_config_invariant() {
    let (temp, home, config_home, state_home, personal, repo) = isolated(true);
    let dir = config_home.join("kinbase");
    kinbase::crypto::write_0600(&dir.join("facts.token"), TOKEN.as_bytes(), "token").expect("token");
    write_user_config(&dir, &personal, &temp.path().join("cache"), &dir.join("facts.token"), "http://127.0.0.1:1", None);
    let output = kinbase_at(&home, &config_home, &state_home).current_dir(&repo).args(["doctor", "--json"]).output_alone().expect("doctor");
    let rendered = format!("{}{}", out(&output.stdout), out(&output.stderr));
    assert_eq!(output.status.code(), Some(kinbase::error::exit_for("CONFIG_INVARIANT")), "{rendered}");
    assert_eq!(error_field(&output, "code"), "CONFIG_INVARIANT", "{rendered}");
    assert!(error_field(&output, "message").contains("root_public_key_file"), "{rendered}");
}

#[test]
fn a_facts_bearer_without_a_request_signature_is_refused() {
    // unauthenticated_pressure.rs refuses a peer with no credential. This
    // presents the facts bearer and no signature. An unbound signature is not
    // minted here: no test helper exposes the request's canonical bytes.
    let store = Store::boot(true);
    let address = format!("127.0.0.1:{}", store.port);
    let mut stream = TcpStream::connect(&address).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    write!(stream, "GET /facts HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n").expect("write");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let response = String::from_utf8_lossy(&response);
    assert!(response.contains(" 401 "), "unsigned bearer was not refused: {response}");
}
