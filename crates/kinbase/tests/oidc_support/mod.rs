//! In-process OIDC provider, browser stub, and TLS gateway. Synthetic values only.
#![allow(dead_code)]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use kinbase::crypto::PrivateKey;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{BufRead as _, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

use crate::support::SpawnAlone;

pub const EMAIL: &str = "ada@example.invalid";
pub const CLIENT_ID: &str = "client-synth";
pub const SECRET: &str = "csec-synth-4nW8-bT";
pub const CODE: &str = "code-synth-9pL3-aQ";
pub const FACTS: &str = "facts-synth-2mX6-cR";
pub const SEEDED_REFRESH: &str = "rfr-synth-7kQ2-mZ";
const ADMIN: &str = "admin-synth-8qY1-dS";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    Off,
    Proxy,
    KeepAuth,
    Plain401,
    Untrusted,
    WrongName,
    Truncate,
    Reframe,
    Pass,
}

#[derive(Clone, Copy)]
pub enum Frame {
    Length,
    Chunked,
    Eof,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Apply {
    All,
    Refresh,
    Code,
}

#[derive(Clone)]
pub struct Script {
    pub login_ttl: u64,
    pub refresh_ttl: u64,
    pub omit_refresh: bool,
    pub omit_id: bool,
    pub omit_email: bool,
    pub omit_exp: bool,
    pub oauth_error: Option<String>,
    pub error_description: Option<String>,
    pub http_status: Option<u16>,
    pub non_json: bool,
    pub discovery_issuer: Option<String>,
    pub token_endpoint: Option<String>,
    pub offline_access: bool,
    pub hold_refresh: bool,
    pub apply: Apply,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            login_ttl: 60,
            refresh_ttl: 3600,
            omit_refresh: false,
            omit_id: false,
            omit_email: false,
            omit_exp: false,
            oauth_error: None,
            error_description: None,
            http_status: None,
            non_json: false,
            discovery_issuer: None,
            token_endpoint: None,
            offline_access: false,
            hold_refresh: false,
            apply: Apply::All,
        }
    }
}

#[derive(Clone)]
struct Counts {
    refresh_calls: usize,
    discovery_calls: usize,
    accepts: usize,
    http_bytes: usize,
    forms: Vec<String>,
    content_types: Vec<String>,
    refresh_tokens_seen: Vec<String>,
    authz: Vec<String>,
    facts_headers: Vec<String>,
    upstream_status: Vec<u16>,
    upstream_bodies: Vec<String>,
    forwarded_authz: Vec<String>,
    latest_id: String,
    current_refresh: String,
    issued_ids: Vec<String>,
    issued_refresh: Vec<String>,
    code_refresh: String,
}

struct Inner {
    counts: Mutex<Counts>,
    script: Mutex<Script>,
    frames: Mutex<VecDeque<Frame>>,
    release: Mutex<bool>,
    release_cv: Condvar,
    entered: Mutex<usize>,
    entered_cv: Condvar,
}

#[derive(Clone)]
pub struct Cfg {
    pub provider: bool,
    pub company: bool,
    pub certify: bool,
    pub issuer: bool,
    pub client_id: bool,
    pub secret: bool,
    pub issuer_override: Option<String>,
    pub allow_non_loopback: Option<bool>,
    pub company_url: Option<String>,
    pub gate: Gate,
    pub client_facts: String,
}

impl Cfg {
    pub fn oidc() -> Self {
        Self {
            provider: true,
            company: true,
            certify: false,
            issuer: true,
            client_id: true,
            secret: false,
            issuer_override: None,
            allow_non_loopback: None,
            company_url: None,
            gate: Gate::Proxy,
            client_facts: FACTS.to_owned(),
        }
    }

    /// No provider, company server, or gateway. Set an issuer when the row still configures OIDC.
    pub fn quiet(mut self) -> Self {
        self.provider = false;
        self.company = false;
        self.gate = Gate::Off;
        self
    }

    pub fn at(mut self, url: &str) -> Self {
        self.company_url = Some(url.to_owned());
        self
    }

    pub fn issuer_is(mut self, issuer: &str) -> Self {
        self.issuer_override = Some(issuer.to_owned());
        self
    }

    pub fn allow(mut self, allow: bool) -> Self {
        self.allow_non_loopback = Some(allow);
        self
    }

    pub fn parts(mut self, issuer: bool, client: bool, secret: bool) -> Self {
        self.issuer = issuer;
        self.client_id = client;
        self.secret = secret;
        self
    }
}

pub struct View {
    pub refresh_calls: usize,
    pub discovery_calls: usize,
    pub accepts: usize,
    pub http_bytes: usize,
    pub forms: Vec<String>,
    pub content_types: Vec<String>,
    pub refresh_tokens_seen: Vec<String>,
    pub authz: Vec<String>,
    pub facts_headers: Vec<String>,
    pub upstream_status: Vec<u16>,
    pub upstream_bodies: Vec<String>,
    pub forwarded_authz: Vec<String>,
    pub latest_id: String,
    pub code_refresh: String,
}

pub struct Rig {
    _tmp: TempDir,
    home: PathBuf,
    config_home: PathBuf,
    repo: PathBuf,
    state_home: PathBuf,
    client_tmp: PathBuf,
    bin: PathBuf,
    pub argv_log: PathBuf,
    pub http_log: PathBuf,
    cert_pem: PathBuf,
    provider: String,
    pub gateway: String,
    pub company: String,
    upstream: String,
    inner: Arc<Inner>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    service: Mutex<Option<Child>>,
    root_key: PrivateKey,
}

impl Rig {
    pub fn boot(cfg: Cfg) -> Self {
        let tmp = TempDir::new().expect("temp");
        let root = tmp.path().to_path_buf();
        let home = root.join("home");
        let config_home = root.join("config");
        let state_home = root.join("state");
        let client_tmp = root.join("client-tmp");
        let repo = root.join("repo");
        let bin = root.join("bin");
        for dir in [&home, &config_home, &state_home, &client_tmp, &repo, &bin] {
            fs::create_dir_all(dir).expect("dir");
        }
        let inner = Arc::new(Inner {
            counts: Mutex::new(Counts {
                refresh_calls: 0,
                discovery_calls: 0,
                accepts: 0,
                http_bytes: 0,
                forms: Vec::new(),
                content_types: Vec::new(),
                refresh_tokens_seen: Vec::new(),
                authz: Vec::new(),
                facts_headers: Vec::new(),
                upstream_status: Vec::new(),
                upstream_bodies: Vec::new(),
                forwarded_authz: Vec::new(),
                latest_id: String::new(),
                current_refresh: SEEDED_REFRESH.to_owned(),
                issued_ids: Vec::new(),
                issued_refresh: Vec::new(),
                code_refresh: String::new(),
            }),
            script: Mutex::new(Script::default()),
            frames: Mutex::new(VecDeque::new()),
            release: Mutex::new(false),
            release_cv: Condvar::new(),
            entered: Mutex::new(0),
            entered_cv: Condvar::new(),
        });
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut threads = Vec::new();
        let root_key = PrivateKey::generate();
        let (mut service, mut company, mut upstream) = (None, String::new(), String::new());
        if cfg.company {
            let (child, port) = serve_company(&root, &root_key);
            service = Some(child);
            company = format!("http://127.0.0.1:{port}");
            upstream = format!("127.0.0.1:{port}");
        }
        let mut gateway = String::new();
        if cfg.gate != Gate::Off {
            let (port, handle) = listen(cfg.gate, &upstream, &inner, &stop);
            threads.push(handle);
            gateway = match cfg.gate {
                Gate::Reframe | Gate::Pass => format!("http://127.0.0.1:{port}"),
                _ => format!("https://127.0.0.1:{port}"),
            };
        }
        let mut provider = String::new();
        if cfg.provider {
            let (port, handle) = listen_provider(&inner, &stop);
            threads.push(handle);
            provider = format!("http://127.0.0.1:{port}");
        }
        let rig = Rig {
            argv_log: root.join("browser.argv"),
            http_log: root.join("browser.http"),
            cert_pem: fixture("ca.pem"),
            home,
            config_home,
            repo,
            state_home,
            client_tmp,
            bin,
            provider,
            gateway,
            company,
            upstream,
            inner,
            stop,
            threads: Mutex::new(threads),
            service: Mutex::new(service),
            root_key,
            _tmp: tmp,
        };
        rig.write_browser("good");
        if cfg.certify {
            rig.write_config(&Cfg {
                company_url: Some("http://127.0.0.1:1".into()),
                ..cfg.clone()
            });
            rig.certify();
        } else {
            git_init(&rig.repo);
        }
        rig.write_config(&cfg);
        rig
    }

    pub fn set_script(&self, script: Script) {
        *self.inner.script.lock().expect("script") = script;
    }

    pub fn script_mut<F: FnOnce(&mut Script)>(&self, f: F) {
        f(&mut self.inner.script.lock().expect("script"));
    }

    pub fn set_frames(&self, frames: &[Frame]) {
        *self.inner.frames.lock().expect("frames") = frames.iter().copied().collect();
    }

    pub fn view(&self) -> View {
        let c = self.inner.counts.lock().expect("counts");
        View {
            refresh_calls: c.refresh_calls,
            discovery_calls: c.discovery_calls,
            accepts: c.accepts,
            http_bytes: c.http_bytes,
            forms: c.forms.clone(),
            content_types: c.content_types.clone(),
            refresh_tokens_seen: c.refresh_tokens_seen.clone(),
            authz: c.authz.clone(),
            facts_headers: c.facts_headers.clone(),
            upstream_status: c.upstream_status.clone(),
            upstream_bodies: c.upstream_bodies.clone(),
            forwarded_authz: c.forwarded_authz.clone(),
            latest_id: c.latest_id.clone(),
            code_refresh: c.code_refresh.clone(),
        }
    }

    pub fn oidc_path(&self) -> PathBuf {
        self.config_home.join("kinbase").join("oidc.json")
    }

    pub fn write_bytes(&self, bytes: &[u8]) {
        private_write(&self.oidc_path(), bytes);
    }

    pub fn seed(&self, refresh: &str, ttl: u64) -> String {
        let id = jwt(Some(epoch() + ttl), Some(EMAIL));
        private_write(
            &self.oidc_path(),
            format!(r#"{{"refresh_token":"{refresh}","id_token":"{id}"}}"#).as_bytes(),
        );
        let mut c = self.inner.counts.lock().expect("counts");
        c.current_refresh = refresh.to_owned();
        c.latest_id = id.clone();
        id
    }

    pub fn write_browser(&self, mode: &str) {
        let script = browser_script(mode, &self.argv_log, &self.http_log);
        for name in ["xdg-open", "open"] {
            let path = self.bin.join(name);
            fs::write(&path, &script).expect("browser");
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
        }
    }

    pub fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Output {
        let path = format!(
            "{}:{}",
            self.bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_kinbase"));
        cmd.current_dir(&self.repo)
            .args(args)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.config_home)
            .env("XDG_STATE_HOME", &self.state_home)
            .env("TMPDIR", &self.client_tmp)
            .env("SSL_CERT_FILE", &self.cert_pem)
            .env("PATH", path)
            .env_remove("KINBASE_COMPANY_URL")
            .env_remove("SSL_CERT_DIR")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(bytes) = stdin {
            cmd.stdin(Stdio::piped());
            let mut child = cmd.spawn_alone().expect("spawn");
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(bytes)
                .expect("stdin");
            child.wait_with_output().expect("wait")
        } else {
            cmd.output_alone().expect("run")
        }
    }

    pub fn login(&self, json_mode: bool) -> Output {
        if json_mode {
            self.run(&["auth", "login", "--json"], None)
        } else {
            self.run(&["auth", "login"], None)
        }
    }

    pub fn status(&self) -> Output {
        self.run(
            [
                "status",
                "--repo",
                &self.repo.display().to_string(),
                "--json",
            ]
            .as_slice(),
            None,
        )
    }

    pub fn issue(&self, url: &str) -> Output {
        self.run(
            [
                "repo",
                "issue",
                "--repo",
                &self.repo.display().to_string(),
                "--company",
                url,
                "--json",
            ]
            .as_slice(),
            None,
        )
    }

    pub fn session_start(&self) -> Output {
        let cwd = self.repo.display().to_string();
        self.run(
            &["hooks", "dispatch", "claude", "SessionStart", "--json"],
            Some(format!(r#"{{"cwd":"{cwd}"}}"#).as_bytes()),
        )
    }

    pub fn arm_hold(&self) {
        self.script_mut(|s| s.hold_refresh = true);
        *self.inner.release.lock().expect("rel") = false;
        *self.inner.entered.lock().expect("entered") = 0;
    }

    pub fn wait_refresh_entered(&self) {
        let mut n = self.inner.entered.lock().expect("entered");
        let start = std::time::Instant::now();
        while *n < 1 {
            let left = Duration::from_secs(8).saturating_sub(start.elapsed());
            let (guard, timeout) = self.inner.entered_cv.wait_timeout(n, left).expect("wait");
            n = guard;
            if timeout.timed_out() && *n < 1 {
                panic!("refresh never reached the provider");
            }
        }
    }

    /// Both children are already spawned; hold the first refresh for one further second.
    pub fn release_after_overlap(&self) {
        thread::sleep(Duration::from_secs(1));
        self.release_hold();
    }

    pub fn leaks(&self, blobs: &[&str]) -> Vec<String> {
        let needles = {
            let c = self.inner.counts.lock().expect("counts");
            let mut raw = Vec::new();
            raw.extend(c.issued_ids.iter().cloned());
            raw.extend(c.issued_refresh.iter().cloned());
            raw.push(CODE.to_owned());
            raw.push(FACTS.to_owned());
            raw.push(SECRET.to_owned());
            raw.push(SEEDED_REFRESH.to_owned());
            raw.push(c.code_refresh.clone());
            for form in &c.forms {
                if let Some(ver) = form_get(form, "code_verifier") {
                    raw.push(ver);
                }
            }
            let mut out = BTreeSet::new();
            for item in raw {
                if item.len() < 8 {
                    continue;
                }
                if item.contains('.') {
                    for seg in item.split('.') {
                        if seg.len() >= 12 {
                            out.insert(seg.to_owned());
                        }
                    }
                }
                if item.len() >= 12 {
                    out.insert(item[..12].to_owned());
                }
                out.insert(item);
            }
            out
        };
        let mut hits = Vec::new();
        for blob in blobs {
            if needles
                .iter()
                .any(|n| !n.is_empty() && blob.contains(n.as_str()))
            {
                hits.push("output contains a secret".to_owned());
                return hits;
            }
        }
        let mut files = BTreeSet::new();
        for root in [
            &self.home,
            &self.config_home,
            &self.state_home,
            &self.client_tmp,
            &self.repo,
        ] {
            walk(root, &mut files);
        }
        for path in files {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if matches!(
                name,
                "oidc.json" | "facts.token" | "admin.token" | "client.secret"
            ) {
                continue;
            }
            let Ok(bytes) = fs::read(&path) else { continue };
            let text = String::from_utf8_lossy(&bytes);
            if needles.iter().any(|n| text.contains(n)) {
                hits.push(format!("{} contains a secret", path.display()));
                break;
            }
        }
        hits
    }

    fn release_hold(&self) {
        *self.inner.release.lock().expect("rel") = true;
        self.inner.release_cv.notify_all();
    }

    fn write_config(&self, cfg: &Cfg) {
        let dir = self.config_home.join("kinbase");
        fs::create_dir_all(&dir).expect("config dir");
        let personal = self.home.join("personal");
        fs::create_dir_all(&personal).expect("personal");
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&personal, fs::Permissions::from_mode(0o700)).ok();
        let root_pub = dir.join("root-public.key");
        private_write(
            &root_pub,
            format!("{}\n", self.root_key.public().to_hex()).as_bytes(),
        );
        let facts = dir.join("facts.token");
        private_write(&facts, cfg.client_facts.as_bytes());
        let admin = dir.join("admin.token");
        private_write(&admin, ADMIN.as_bytes());
        let client_key = dir.join("client.key");
        let maintainer = dir.join("maintainer.key");
        if !client_key.exists() {
            PrivateKey::generate()
                .save_new(&client_key, "client key")
                .expect("client key");
        }
        if !maintainer.exists() {
            PrivateKey::generate()
                .save_new(&maintainer, "maintainer key")
                .expect("maintainer key");
        }
        let secret = dir.join("client.secret");
        private_write(&secret, SECRET.as_bytes());
        let company_url = cfg
            .company_url
            .clone()
            .unwrap_or_else(|| self.gateway.clone());
        let mut body = format!(
            "schema_version = \"1\"\n\n[personal]\ndata_root = \"{}\"\n\n[company]\nurl = \"{company_url}\"\nfacts_token_file = \"{}\"\nroot_public_key_file = \"{}\"\ncache_root = \"{}\"\nclient_key_file = \"{}\"\nmaintainer_key_file = \"{}\"\nadmin_token_file = \"{}\"\n",
            personal.display(),
            facts.display(),
            root_pub.display(),
            self.home.join("cache").display(),
            client_key.display(),
            maintainer.display(),
            admin.display(),
        );
        if let Some(allow) = cfg.allow_non_loopback {
            body.push_str(&format!("allow_non_loopback = {allow}\n"));
        }
        if cfg.issuer {
            let issuer = cfg
                .issuer_override
                .clone()
                .unwrap_or_else(|| self.provider.clone());
            body.push_str(&format!("oidc_issuer = \"{issuer}\"\n"));
        }
        if cfg.client_id {
            body.push_str(&format!("oidc_client_id = \"{CLIENT_ID}\"\n"));
        }
        if cfg.secret {
            body.push_str(&format!(
                "oidc_client_secret_file = \"{}\"\n",
                secret.display()
            ));
        }
        private_write(&dir.join("config.toml"), body.as_bytes());
    }

    fn certify(&self) {
        git_init(&self.repo);
        let repository_uuid = "01234567-89ab-cdef-0123-456789abcdef";
        let unsigned = json!({
            "schema": "kinbase-repo-certificate/1",
            "repository_uuid": repository_uuid,
            "issued_at": "2026-09-08T12:00:00.000Z",
            "company_id": "company-test"
        });
        let signed = self
            .root_key
            .sign_document("repo-certificate", &unsigned)
            .expect("sign certificate");
        let certificate = self._tmp.path().join("certificate.json");
        private_write(
            &certificate,
            kinbase::json::canonical_text(&signed).as_bytes(),
        );
        let init = self.run(
            &[
                "repo",
                "init",
                "--repo",
                &self.repo.display().to_string(),
                "--certificate",
                &certificate.display().to_string(),
                "--json",
            ],
            None,
        );
        assert!(init.status.success(), "repo init: {}", stderr(&init));
        let mut event = packet_event(repository_uuid);
        event.sign(&self.root_key).expect("sign fact");
        let bytes = kinbase::json::canonical_bytes(&event.document());
        let digest = kinbase::hash::sha256_bytes(&bytes);
        let relative = format!("{}/{}/{}.json", &digest[..2], &digest[2..4], &digest[4..]);
        private_write(&self.repo.join(".kin/events").join(&relative), &bytes);
        let add = Command::new("git")
            .current_dir(&self.repo)
            .args([
                "add",
                ".gitattributes",
                ".kin/kinbase.toml",
                &format!(".kin/events/{relative}"),
            ])
            .output_alone()
            .expect("git add");
        assert!(add.status.success(), "git add");
        let commit = Command::new("git")
            .current_dir(&self.repo)
            .env("GIT_AUTHOR_NAME", "oidc")
            .env("GIT_AUTHOR_EMAIL", "oidc@example.invalid")
            .env("GIT_COMMITTER_NAME", "oidc")
            .env("GIT_COMMITTER_EMAIL", "oidc@example.invalid")
            .args(["commit", "-m", "certified corpus"])
            .output_alone()
            .expect("git commit");
        assert!(commit.status.success(), "git commit: {}", stderr(&commit));
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.release_hold();
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for addr in [
            self.gateway
                .trim_start_matches("https://")
                .trim_start_matches("http://"),
            self.provider.trim_start_matches("http://"),
        ] {
            if !addr.is_empty() {
                let _ = TcpStream::connect(addr);
            }
        }
        for thread in self.threads.lock().expect("threads").drain(..) {
            let _ = thread.join();
        }
        if let Some(child) = self.service.lock().expect("service").as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn git_init(repo: &Path) {
    let git = Command::new("git")
        .args(["init", "-q", "--initial-branch=main"])
        .current_dir(repo)
        .env("GIT_AUTHOR_NAME", "oidc")
        .env("GIT_AUTHOR_EMAIL", "oidc@example.invalid")
        .output_alone()
        .expect("git init");
    assert!(git.status.success(), "git init");
}

fn serve_company(root: &Path, root_key: &PrivateKey) -> (Child, u16) {
    let root_path = root.join("company-root.key");
    let token_path = root.join("facts.token");
    let config_path = root.join("kinbased.toml");
    root_key
        .save_new(&root_path, "Company root key")
        .expect("root key");
    kinbase::crypto::write_0600(&token_path, FACTS.as_bytes(), "facts token").expect("token");
    let port = TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("port")
        .port();
    let config = format!(
        "schema_version = \"1\"\ncompany_id = \"company-demo\"\nsqlite_path = \"{}\"\nbind = \"127.0.0.1:{port}\"\nroot_key_file = \"{}\"\nfacts_token_file = \"{}\"\nauth_failures_per_minute = 1000\ndefault_fact_freshness_seconds = 900\ncandidate_lifetime_seconds = 900\nclock_skew_seconds = 300\nnonce_retention_seconds = 1300\n",
        root.join("company.sqlite").display(),
        root_path.display(),
        token_path.display(),
    );
    kinbase::crypto::write_0600(&config_path, config.as_bytes(), "service config").expect("cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_kinbase"))
        .args(["company", "serve", "--config"])
        .arg(&config_path)
        .arg("--json")
        .env("HOME", root)
        .env("XDG_CONFIG_HOME", root.join("svc-config"))
        .env("XDG_STATE_HOME", root.join("svc-state"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn_alone()
        .expect("serve");
    let mut banner = String::new();
    std::io::BufReader::new(child.stdout.take().expect("stdout"))
        .read_line(&mut banner)
        .expect("banner");
    assert!(banner.contains("company-serving"), "banner: {banner}");
    (child, port)
}

fn listen(
    gate: Gate,
    upstream: &str,
    inner: &Arc<Inner>,
    stop: &Arc<std::sync::atomic::AtomicBool>,
) -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("gateway bind");
    let port = listener.local_addr().expect("addr").port();
    let upstream = upstream.to_owned();
    let inner = Arc::clone(inner);
    let stop = Arc::clone(stop);
    let handle = thread::spawn(move || {
        for incoming in listener.incoming() {
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            let Ok(tcp) = incoming else { break };
            inner.counts.lock().expect("counts").accepts += 1;
            let inner = Arc::clone(&inner);
            let upstream = upstream.clone();
            thread::spawn(move || gateway_conn(tcp, gate, &upstream, &inner));
        }
    });
    (port, handle)
}

fn listen_provider(
    inner: &Arc<Inner>,
    stop: &Arc<std::sync::atomic::AtomicBool>,
) -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("provider bind");
    let port = listener.local_addr().expect("addr").port();
    let base = format!("http://127.0.0.1:{port}");
    let inner = Arc::clone(inner);
    let stop = Arc::clone(stop);
    let handle = thread::spawn(move || {
        for incoming in listener.incoming() {
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            let Ok(tcp) = incoming else { break };
            let inner = Arc::clone(&inner);
            let base = base.clone();
            thread::spawn(move || provider_conn(tcp, &base, &inner));
        }
    });
    (port, handle)
}

fn gateway_conn(mut tcp: TcpStream, gate: Gate, upstream: &str, inner: &Inner) {
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
    if gate == Gate::Reframe {
        let req = read_http(&mut tcp);
        note_request(inner, &req);
        let frame = inner
            .frames
            .lock()
            .expect("frames")
            .pop_front()
            .unwrap_or(Frame::Length);
        let raw = forward(upstream, &req);
        let (status, mut body) = split_response(&raw);
        if body.first() == Some(&b'{') {
            body.splice(1..1, std::iter::repeat(b' ').take(256 * 1024));
        }
        let _ = tcp.write_all(&reframe(&status, &body, frame));
        return;
    }
    if gate == Gate::Pass {
        let req = read_http(&mut tcp);
        note_request(inner, &req);
        let raw = forward(upstream, &req);
        inner
            .counts
            .lock()
            .expect("counts")
            .upstream_status
            .push(status_code(&raw));
        let _ = tcp.write_all(&raw);
        return;
    }
    let (cert, key) = match gate {
        Gate::Untrusted => ("untrusted.crt.der", "untrusted.key.der"),
        Gate::WrongName => ("wrong-name.crt.der", "wrong-name.key.der"),
        _ => ("gateway.crt.der", "gateway.key.der"),
    };
    let mut conn = match rustls::ServerConnection::new(identity(cert, key)) {
        Ok(conn) => conn,
        Err(_) => return,
    };
    let req = read_http(&mut rustls::Stream::new(&mut conn, &mut tcp));
    note_request(inner, &req);
    if req.is_empty() {
        return;
    }
    if gate == Gate::Truncate {
        let raw = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"status\":\"certified\"}";
        let mut stream = rustls::Stream::new(&mut conn, &mut tcp);
        let _ = stream.write_all(raw.as_bytes());
        let _ = stream.flush();
        return;
    }
    let response = if gate == Gate::Plain401 || !bearer_ok(inner, &req) {
        plain_401()
    } else {
        let stripped;
        let outbound: &[u8] = if gate == Gate::KeepAuth {
            &req
        } else {
            stripped = strip_authorization(&req);
            &stripped
        };
        if gate == Gate::KeepAuth {
            let head = String::from_utf8_lossy(req_head(outbound));
            if let Some(value) = header(&head, "authorization") {
                inner
                    .counts
                    .lock()
                    .expect("counts")
                    .forwarded_authz
                    .push(value);
            }
        }
        let raw = forward(upstream, outbound);
        let status = status_code(&raw);
        let (_, body) = split_response(&raw);
        let mut counts = inner.counts.lock().expect("counts");
        counts.upstream_status.push(status);
        counts
            .upstream_bodies
            .push(String::from_utf8_lossy(&body).into_owned());
        if raw.is_empty() { plain_401() } else { raw }
    };
    {
        let mut stream = rustls::Stream::new(&mut conn, &mut tcp);
        let _ = stream.write_all(&response);
        let _ = stream.flush();
    }
    conn.send_close_notify();
    while conn.wants_write() {
        if conn.write_tls(&mut tcp).is_err() {
            break;
        }
    }
}

fn provider_conn(mut tcp: TcpStream, base: &str, inner: &Inner) {
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(8)));
    let req = read_http(&mut tcp);
    if req.is_empty() {
        return;
    }
    let head = String::from_utf8_lossy(&req);
    let path = head
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/");
    if path.ends_with("/.well-known/openid-configuration") {
        inner.counts.lock().expect("counts").discovery_calls += 1;
        let script = inner.script.lock().expect("script").clone();
        let issuer = script
            .discovery_issuer
            .clone()
            .unwrap_or_else(|| base.to_owned());
        let token = script
            .token_endpoint
            .clone()
            .unwrap_or_else(|| format!("{base}/token"));
        let mut scopes = vec!["openid".to_owned(), "email".to_owned()];
        if script.offline_access {
            scopes.push("offline_access".to_owned());
        }
        let body = json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": token,
            "scopes_supported": scopes,
        })
        .to_string();
        let _ = write_http(&mut tcp, 200, "application/json", &body);
        return;
    }
    if path.ends_with("/token") {
        token_endpoint(&mut tcp, &req, inner);
        return;
    }
    let _ = write_http(&mut tcp, 404, "text/plain", "nope");
}

fn token_endpoint(tcp: &mut TcpStream, req: &[u8], inner: &Inner) {
    let head = String::from_utf8_lossy(req_head(req));
    let content_type = header(&head, "content-type").unwrap_or_default();
    let body_text = String::from_utf8_lossy(&req_body(req)).into_owned();
    {
        let mut c = inner.counts.lock().expect("counts");
        c.content_types.push(content_type.clone());
        c.forms.push(body_text.clone());
    }
    if !content_type
        .to_ascii_lowercase()
        .starts_with("application/x-www-form-urlencoded")
    {
        let _ = write_http(
            tcp,
            415,
            "application/json",
            r#"{"error":"invalid_request"}"#,
        );
        return;
    }
    let refresh = form_get(&body_text, "grant_type").as_deref() == Some("refresh_token");
    if refresh {
        let presented = form_get(&body_text, "refresh_token").unwrap_or_default();
        let mut c = inner.counts.lock().expect("counts");
        c.refresh_calls += 1;
        c.refresh_tokens_seen.push(presented);
    }
    let script = inner.script.lock().expect("script").clone();
    let applies = match script.apply {
        Apply::All => true,
        Apply::Refresh => refresh,
        Apply::Code => !refresh,
    };
    if refresh && script.hold_refresh {
        *inner.entered.lock().expect("entered") += 1;
        inner.entered_cv.notify_all();
        let mut rel = inner.release.lock().expect("rel");
        while !*rel {
            rel = inner.release_cv.wait(rel).expect("wait release");
        }
    }
    if applies {
        if let Some(status) = script.http_status {
            if status >= 500 {
                let _ = write_http(
                    tcp,
                    status,
                    "application/json",
                    r#"{"error":"server_error"}"#,
                );
                return;
            }
        }
        if script.non_json {
            let _ = write_http(tcp, 200, "text/plain", "not-json");
            return;
        }
        if let Some(error) = &script.oauth_error {
            let mut doc = json!({"error": error});
            if let Some(desc) = &script.error_description {
                doc["error_description"] = json!(desc);
            }
            let _ = write_http(tcp, 400, "application/json", &doc.to_string());
            return;
        }
    }
    if refresh {
        let presented = form_get(&body_text, "refresh_token").unwrap_or_default();
        if presented != inner.counts.lock().expect("counts").current_refresh {
            let _ = write_http(tcp, 400, "application/json", r#"{"error":"invalid_grant"}"#);
            return;
        }
    } else if form_get(&body_text, "code").as_deref() != Some(CODE) {
        let _ = write_http(tcp, 400, "application/json", r#"{"error":"invalid_grant"}"#);
        return;
    }
    let ttl = if refresh {
        script.refresh_ttl
    } else {
        script.login_ttl
    };
    let email = if applies && script.omit_email {
        None
    } else {
        Some(EMAIL)
    };
    let exp = if applies && script.omit_exp {
        None
    } else {
        Some(epoch() + ttl)
    };
    let id = if applies && script.omit_id {
        None
    } else {
        Some(jwt(exp, email))
    };
    let mut doc = json!({});
    if let Some(id) = &id {
        doc["id_token"] = json!(id);
    }
    {
        let mut c = inner.counts.lock().expect("counts");
        if let Some(id) = &id {
            if exp.is_some() {
                c.latest_id = id.clone();
            }
            c.issued_ids.push(id.clone());
        }
        if !(applies && script.omit_refresh) {
            let issued = format!("rfr-issued-{}-synth", c.issued_refresh.len());
            doc["refresh_token"] = json!(issued);
            c.current_refresh = issued.clone();
            c.issued_refresh.push(issued);
            if !refresh {
                c.code_refresh = c.current_refresh.clone();
            }
        }
    }
    let _ = write_http(tcp, 200, "application/json", &doc.to_string());
}

fn note_request(inner: &Inner, req: &[u8]) {
    if req.is_empty() {
        return;
    }
    let mut c = inner.counts.lock().expect("counts");
    c.http_bytes += req.len();
    let head = String::from_utf8_lossy(req_head(req));
    if let Some(v) = header(&head, "authorization") {
        c.authz.push(v);
    }
    if let Some(v) = header(&head, "x-kinbase-token") {
        c.facts_headers.push(v);
    }
}

fn bearer_ok(inner: &Inner, req: &[u8]) -> bool {
    let head = String::from_utf8_lossy(req_head(req));
    let Some(token) =
        header(&head, "authorization").and_then(|v| v.strip_prefix("Bearer ").map(str::to_owned))
    else {
        return false;
    };
    let latest = inner.counts.lock().expect("counts").latest_id.clone();
    !latest.is_empty() && token == latest && exp_future(&token)
}

fn exp_future(token: &str) -> bool {
    let Some(payload) = token.split('.').nth(1) else {
        return false;
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(payload) else {
        return false;
    };
    serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|v| v["exp"].as_u64())
        .is_some_and(|exp| exp > epoch())
}

fn strip_authorization(req: &[u8]) -> Vec<u8> {
    let end = header_end(req).unwrap_or(req.len());
    let head = String::from_utf8_lossy(&req[..end]);
    let kept: Vec<&str> = head
        .split("\r\n")
        .filter(|line| !line.is_empty() && !line.to_ascii_lowercase().starts_with("authorization:"))
        .collect();
    let mut out = kept.join("\r\n").into_bytes();
    out.extend_from_slice(b"\r\n\r\n");
    if end < req.len() {
        out.extend_from_slice(&req[end..]);
    }
    out
}

fn forward(upstream: &str, req: &[u8]) -> Vec<u8> {
    let Ok(mut tcp) = TcpStream::connect(upstream) else {
        return Vec::new();
    };
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
    if tcp.write_all(req).is_err() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    let _ = tcp.read_to_end(&mut buf);
    buf
}

fn reframe(status: &str, body: &[u8], frame: Frame) -> Vec<u8> {
    let status = if status.is_empty() {
        "HTTP/1.1 200 OK"
    } else {
        status
    };
    match frame {
        Frame::Length => {
            let mut out = format!("{status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
            out.extend_from_slice(body);
            out
        }
        Frame::Chunked => {
            let mut out = format!("{status}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{len:x}\r\n", len = body.len()).into_bytes();
            out.extend_from_slice(body);
            out.extend_from_slice(b"\r\n0\r\n\r\n");
            out
        }
        Frame::Eof => {
            let mut out =
                format!("{status}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n")
                    .into_bytes();
            out.extend_from_slice(body);
            out
        }
    }
}

fn split_response(raw: &[u8]) -> (String, Vec<u8>) {
    let Some(end) = header_end(raw) else {
        return (String::new(), Vec::new());
    };
    let head = String::from_utf8_lossy(&raw[..end]).into_owned();
    let status = head
        .lines()
        .next()
        .unwrap_or("")
        .trim_end_matches('\r')
        .to_owned();
    let mut body = raw[end..].to_vec();
    if let Some(n) = header(&head, "content-length").and_then(|v| v.parse().ok()) {
        if body.len() > n {
            body.truncate(n);
        }
    }
    (status, body)
}

fn status_code(raw: &[u8]) -> u16 {
    String::from_utf8_lossy(req_head(raw))
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn plain_401() -> Vec<u8> {
    b"HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\nContent-Length: 13\r\nConnection: close\r\n\r\nnot-a-kinbase".to_vec()
}

fn identity(cert: &str, key: &str) -> std::sync::Arc<rustls::ServerConfig> {
    let cert = rustls::pki_types::CertificateDer::from(fs::read(fixture(cert)).expect("cert"));
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        fs::read(fixture(key)).expect("key"),
    ));
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    std::sync::Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("tls12")
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("identity"),
    )
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/oidc")
        .join(name)
}

fn read_http(reader: &mut impl Read) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        if buf.len() > 2_000_000 {
            break;
        }
        match reader.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(end) = header_end(&buf) {
                    let head = String::from_utf8_lossy(&buf[..end]);
                    let need = header(&head, "content-length")
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(0);
                    if buf.len() >= end + need {
                        break;
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    buf
}

fn header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn header(head: &str, name: &str) -> Option<String> {
    head.split("\r\n").find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim().to_owned())
    })
}

fn req_head(req: &[u8]) -> &[u8] {
    header_end(req).map(|n| &req[..n]).unwrap_or(req)
}

fn req_body(req: &[u8]) -> &[u8] {
    header_end(req).map(|n| &req[n..]).unwrap_or(b"")
}

fn write_http(
    sock: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    sock.write_all(
        format!("HTTP/1.1 {status} x\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes(),
    )
}

pub fn form_get(body: &str, key: &str) -> Option<String> {
    body.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (url_decode(k) == key).then(|| url_decode(v))
    })
}

pub fn url_decode(input: &str) -> String {
    let plus = input.replace('+', " ");
    let bytes = plus.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&plus[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn query(url: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let Some(qs) = url.split_once('?').map(|(_, q)| q) else {
        return map;
    };
    for pair in qs.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        map.insert(url_decode(k), url_decode(v));
    }
    map
}

pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

pub fn assert_code(output: &Output, code: &str) {
    let text = stdout(output);
    assert!(
        text.contains(&format!("\"code\":\"{code}\""))
            || text.contains(&format!("\"code\": \"{code}\""))
            || text.contains(&format!("{code}:")),
        "missing {code}\nstdout: {text}\nstderr: {}",
        stderr(output)
    );
}

pub fn login_url(output: &Output) -> String {
    for line in stderr(output).lines() {
        let line = line.trim();
        if line.starts_with("http://") || line.starts_with("https://") {
            return line.to_owned();
        }
        if let Ok(value) = serde_json::from_str::<Value>(line) {
            if value["diagnostic"] == "login_url" {
                return value["detail"]["url"].as_str().unwrap_or("").to_owned();
            }
        }
    }
    String::new()
}

pub fn mode_bits(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).expect("stat").permissions().mode() & 0o777
}

fn epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn jwt(exp: Option<u64>, email: Option<&str>) -> String {
    let header = b64(br#"{"alg":"none","kid":"synthetic-oidc"}"#);
    let mut payload = serde_json::Map::new();
    if let Some(exp) = exp {
        payload.insert("exp".into(), json!(exp));
    }
    if let Some(email) = email {
        payload.insert("email".into(), json!(email));
    }
    let body = b64(&serde_json::to_vec(&Value::Object(payload)).expect("payload"));
    let sig = b64(b"sig-synth-5tH7-eU-not-real-signature");
    format!("{header}.{body}.{sig}")
}

fn private_write(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("parent");
    }
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .expect("open");
    file.write_all(bytes).expect("write");
}

fn walk(root: &Path, out: &mut BTreeSet<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some(".git") {
                continue;
            }
            walk(&path, out);
        } else {
            out.insert(path);
        }
    }
}

fn browser_script(mode: &str, argv: &Path, http: &Path) -> String {
    format!(
        r#"#!/bin/bash
printf '%s\n' "$1" >> "{argv}"
url="$1"
decode() {{
  local v="$1"
  v="${{v//+/ }}"
  printf -v v '%b' "${{v//%/\\x}}"
  printf '%s' "$v"
}}
qs="${{url#*?}}"
redir=""
state=""
IFS='&' read -ra parts <<< "$qs"
for p in "${{parts[@]}}"; do
  k="${{p%%=*}}"
  raw="${{p#*=}}"
  v="$(decode "$raw")"
  case "$k" in
    redirect_uri) redir="$v" ;;
    state) state="$raw" ;;
  esac
done
rest="${{redir#http://}}"
hp="${{rest%%/*}}"
host="${{hp%%:*}}"
port="${{hp##*:}}"
get() {{
  exec 3<>"/dev/tcp/${{host}}/${{port}}"
  printf 'GET %s HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n\r\n' "$1" "$host" "$port" >&3
  resp="$(cat <&3 || true)"
  exec 3<&-
  exec 3>&-
  printf '%s\n----\n' "$resp" >> "{http}"
}}
code="{code}"
case "{mode}" in
  good) get "/callback?code=${{code}}&state=${{state}}" ;;
  bad-state)
    get "/callback?code=${{code}}&state=tampered-state"
    get "/callback?code=${{code}}&state=${{state}}"
    ;;
  missing-state)
    get "/callback?code=${{code}}"
    get "/callback?code=${{code}}&state=${{state}}"
    ;;
  error) get "/callback?error=access_denied&state=${{state}}" ;;
  no-code) get "/callback?state=${{state}}" ;;
  other)
    get "/not-callback"
    get "/callback?code=${{code}}&state=${{state}}"
    ;;
  idle)
    exec 4<>"/dev/tcp/${{host}}/${{port}}"
    get "/callback?code=${{code}}&state=${{state}}"
    exec 4<&-
    exec 4>&-
    ;;
esac
"#,
        argv = argv.display(),
        http = http.display(),
        code = CODE,
        mode = mode,
    )
}

fn packet_event(repository_uuid: &str) -> kinbase::model::FactEvent {
    kinbase::model::FactEvent {
        schema: "kinbase-event/1".to_owned(),
        event_id: "event_oidc_status".to_owned(),
        store_kind: "codebase".to_owned(),
        authority_id: "root-steward".to_owned(),
        authority_scope: format!("codebase:{repository_uuid}"),
        repository_id: Some(repository_uuid.to_owned()),
        fact_id: "fact_oidc_status".to_owned(),
        logical_key: "logical_oidc_status".to_owned(),
        atom_kind: "constraint".to_owned(),
        scope: "oidc status corpus".to_owned(),
        statement: "The oidc status corpus carries one certified canonical fact.".to_owned(),
        evidence_refs: Vec::new(),
        asserted_at: "2026-09-08T12:00:00.000Z".to_owned(),
        effective_from: "2026-09-08T12:00:00.000Z".to_owned(),
        effective_until: None,
        disposition: "approved".to_owned(),
        distortion: kinbase::model::Distortion {
            trigger: "oidc status reaches the store".to_owned(),
            loss_if_absent: 9000,
            rationale: "oidc request proof".to_owned(),
        },
        parents: Vec::new(),
        supersedes: Vec::new(),
        redundancy_with: Vec::new(),
        complements: Vec::new(),
        company_refs: Vec::new(),
        authority_snapshot_cursor: "0".to_owned(),
        confidence: kinbase::model::Bp(9000),
        standing: kinbase::model::default_standing_pub(),
        provenance: kinbase::model::default_provenance_pub(),
        governs_paths: Vec::new(),
        anchors: Vec::new(),
        unresolved_uncertainty: None,
        signer: String::new(),
        signature: String::new(),
        raw: None,
    }
}

pub fn json_code(body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| {
            v["error"]["code"]
                .as_str()
                .or_else(|| v["code"].as_str())
                .map(str::to_owned)
        })
        .unwrap_or_default()
}
