//! What an unauthenticated peer can make the Company service do. On a
//! loopback bind the peer set was the operator's own processes; with
//! `allow_non_loopback` the peer set is whatever can reach the port, so the
//! work done before a credential is examined is now an attack surface.
//!
//! Two things have to hold. Arriving at the port must not drive a Company
//! root-key signature or a ledger write, and it must not be able to take
//! every serving thread away from the real clients.

mod support;

use kinbase::company::client::Client;
use kinbase::company::db::CompanyDb;
use kinbase::company::server::MAX_CONCURRENT_CONNECTIONS;
use kinbase::config::TokenRecord;
use kinbase::crypto::PrivateKey;
use serde_json::json;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use support::SpawnAlone;
use tempfile::TempDir;

const TOKEN: &str = "facts-unauthenticated-pressure";

struct Service {
    _temp: TempDir,
    child: Child,
    port: u16,
    root: PrivateKey,
    sqlite: PathBuf,
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Service {
    fn start(extra: &str) -> Self {
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
        let port = std::net::TcpListener::bind("127.0.0.1:0")
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
auth_failures_per_minute = 1000
default_fact_freshness_seconds = 900
candidate_lifetime_seconds = 900
clock_skew_seconds = 300
nonce_retention_seconds = 1300
{extra}"#,
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
        Service {
            _temp: temp,
            child,
            port,
            root,
            sqlite,
        }
    }

    fn address(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    fn db(&self) -> CompanyDb {
        CompanyDb::open(&self.sqlite).expect("open company store")
    }

    fn client(&self, key: PrivateKey) -> Client {
        Client::new(
            &format!("http://127.0.0.1:{}", self.port),
            TokenRecord {
                token: TOKEN.to_owned(),
            },
            key,
            Some(self.root.public()),
            self._temp.path().join("client-cache"),
            false,
        )
        .expect("client")
    }

    fn event_count(&self) -> i64 {
        self.db()
            .connection
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .expect("count events")
    }

    fn observation_status(&self) -> String {
        self.db()
            .connection
            .query_row("SELECT status FROM manifest_observations", [], |row| {
                row.get(0)
            })
            .expect("read observation status")
    }

    /// One observation whose freshness window closed long ago, so the
    /// periodic obligations have work waiting: retiring it signs a
    /// `fact-event` with the Company root key and appends it to the ledger.
    fn plant_lapsed_observation(&self) {
        self.db()
            .insert_manifest_observation(
                &json!({
                    "repository_uuid": "01234567-89ab-cdef-0123-456789abcdef",
                    "branch": "main",
                    "observed_default_branch_revision": "lineage-head-1",
                    "event_count": 2,
                    "merkle_root": "merkle-1",
                    "event_digests": ["digest-1", "digest-2"],
                    "observed_at": "2020-01-01T00:00:00.000Z",
                    "fresh_until": "2020-01-01T01:00:00.000Z"
                }),
                1,
            )
            .expect("plant a lapsed observation");
    }
}

/// One GET on the socket. `extra_headers` is `Name: value\r\n` lines, or empty.
/// The signed client cannot omit its signature.
fn http_get(address: &str, route: &str, extra_headers: &str) -> String {
    let mut stream = TcpStream::connect(address).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let request = format!(
        "GET {route} HTTP/1.1\r\nHost: {address}\r\n{extra_headers}Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).expect("write request");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).to_string()
}

#[test]
fn an_unauthenticated_request_drives_no_root_key_signature() {
    let service = Service::start("");
    service.plant_lapsed_observation();
    let before = service.event_count();

    for route in ["/status", "/facts", "/events"] {
        let response = http_get(&service.address(), route, "");
        assert!(
            response.contains(" 401 "),
            "{route} answered an unauthenticated peer with something other than a refusal: {response}",
        );
    }

    assert_eq!(
        service.event_count(),
        before,
        "an unauthenticated peer appended a signed event to the ledger",
    );
    assert_eq!(
        service.observation_status(),
        "current",
        "an unauthenticated peer drove the periodic obligations to write",
    );

    // The obligations are deferred, not dropped: the first authenticated
    // request still pays them, which is what makes the assertions above a
    // statement about authentication rather than about deleted behaviour.
    service
        .client(PrivateKey::generate())
        .get_ok("/facts")
        .expect("authenticated read");
    assert_eq!(
        service.observation_status(),
        "historical",
        "the lapsed observation was never retired for an authenticated caller",
    );
    assert!(
        service.event_count() > before,
        "the retirement event was never signed for an authenticated caller",
    );
}

#[test]
fn the_connection_ceiling_refuses_a_peer_that_sends_nothing() {
    let service = Service::start("");
    let address = service.address();
    // Sockets that connect and then say nothing. Each one costs the service a
    // thread parked on the read timeout, which is the whole cost an
    // unauthenticated peer can impose before a credential is read.
    let mut held: Vec<TcpStream> = (0..MAX_CONCURRENT_CONNECTIONS)
        .map(|_| TcpStream::connect(&address).expect("hold a connection"))
        .collect();

    // A connection is only counted once the accept loop has taken it, so the
    // probe repeats until the ceiling is reached; a probe that is served
    // instead of refused is itself one more silent peer, so the loop
    // converges. The deadline stays well inside the five-second read timeout
    // that would otherwise start releasing the held sockets.
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut refusal = String::new();
    while Instant::now() < deadline {
        let mut probe = TcpStream::connect(&address).expect("probe connection");
        probe
            .set_read_timeout(Some(Duration::from_millis(250)))
            .expect("probe read timeout");
        let mut response = Vec::new();
        let _ = probe.read_to_end(&mut response);
        if !response.is_empty() {
            refusal = String::from_utf8_lossy(&response).to_string();
            break;
        }
        held.push(probe);
    }

    assert!(
        refusal.contains(" 503 "),
        "the service kept accepting silent connections past its ceiling of {MAX_CONCURRENT_CONNECTIONS} (last probe: {refusal:?})",
    );
    assert!(
        refusal.contains("LIMIT_EXCEEDED"),
        "the ceiling refusal was not the typed envelope: {refusal}",
    );
}

// cites: PLAT-4881 (per-token ceilings; R-17 still accepts a second key).
fn second_key_facts(extra: &str) -> (u16, String) {
    let service = Service::start(extra);
    let a = service.client(PrivateKey::generate());
    let b = service.client(PrivateKey::generate());
    a.get_ok("/facts").expect("inside the ceiling");
    a.get_ok("/facts").expect("inside the ceiling");
    let response = b.get("/facts").expect("answered");
    (
        response.status,
        response.body["error"]["code"].as_str().unwrap_or("").into(),
    )
}

#[test]
fn read_volume_budget_is_per_token_across_client_keys() {
    let (status, code) = second_key_facts("read_volume_per_hour = 2\nrequests_per_minute = 1000\n");
    assert_eq!((status, code.as_str()), (429, "LIMIT_EXCEEDED"));
}

#[test]
fn request_rate_budget_is_per_token_across_client_keys() {
    let (status, code) = second_key_facts("requests_per_minute = 2\nread_volume_per_hour = 1000\n");
    assert_eq!((status, code.as_str()), (429, "LIMIT_EXCEEDED"));
}

#[test]
fn a_second_client_key_is_accepted_on_a_fresh_token_budget() {
    let service = Service::start("read_volume_per_hour = 1000\nrequests_per_minute = 1000\n");
    let a = service.client(PrivateKey::generate());
    let b = service.client(PrivateKey::generate());
    assert_eq!(a.get("/status").expect("key A").status, 200);
    assert_eq!(b.get("/status").expect("key B").status, 200);
}

#[test]
fn a_token_without_a_verifying_signature_is_refused() {
    let service = Service::start("read_volume_per_hour = 1000\nrequests_per_minute = 1000\n");
    let response = http_get(
        &service.address(),
        "/status",
        &format!("Authorization: Bearer {TOKEN}\r\n"),
    );
    assert!(
        response.contains(" 401 ") && response.contains("AUTHORITY_SCOPE_DENIED"),
        "{response}"
    );
}
