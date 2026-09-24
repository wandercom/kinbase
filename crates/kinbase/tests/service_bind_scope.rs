//! The proof binds loopback so a laptop deployment cannot be reached by anyone
//! but its operator. A managed deployment is reached through a cluster Service
//! and takes that isolation from the network policy instead, so the rule is an
//! opt-out rather than a constant.
//!
//! What has to hold is that the opt-out is opt-out: a config that does not
//! mention it keeps refusing a routable bind, because the failure mode of
//! getting this wrong is a Company store answering the open internet.

mod support;

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use support::SpawnAlone;
use tempfile::TempDir;

fn service_config(directory: &Path, bind: &str, allow: Option<bool>) -> std::path::PathBuf {
    let path = directory.join("kinbased.toml");
    let mut body = format!(
        "schema_version = \"1\"\n\
         company_id = \"bind-scope\"\n\
         sqlite_path = \"{dir}/company.sqlite3\"\n\
         bind = \"{bind}\"\n\
         root_key_file = \"{dir}/company-root.key\"\n\
         facts_token_file = \"{dir}/facts.token\"\n\
         auth_failures_per_minute = 10\n\
         default_fact_freshness_seconds = 3600\n\
         candidate_lifetime_seconds = 900\n\
         clock_skew_seconds = 300\n\
         nonce_retention_seconds = 604800\n",
        dir = directory.display(),
    );
    if let Some(allow) = allow {
        body.push_str(&format!("allow_non_loopback = {allow}\n"));
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(body.as_bytes()).unwrap();
    path
}

fn init(directory: &Path, bind: &str, allow: Option<bool>) -> (bool, String) {
    let config = service_config(directory, bind, allow);
    let output = Command::new(env!("CARGO_BIN_EXE_kinbase"))
        .args(["company", "init", "--config"])
        .arg(&config)
        .output_alone()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    (output.status.success(), text)
}

fn scratch() -> TempDir {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    temp
}

#[test]
fn a_config_that_does_not_mention_the_flag_still_refuses_a_routable_bind() {
    let temp = scratch();
    let (succeeded, text) = init(temp.path(), "0.0.0.0:8421", None);
    assert!(!succeeded, "a routable bind was accepted by default: {text}");
    assert!(
        text.contains("bind must be a loopback address"),
        "refused for the wrong reason: {text}",
    );
}

#[test]
fn the_flag_set_false_is_the_same_as_absent() {
    let temp = scratch();
    let (succeeded, text) = init(temp.path(), "0.0.0.0:8421", Some(false));
    assert!(!succeeded, "allow_non_loopback = false accepted a routable bind: {text}");
}

#[test]
fn a_routable_bind_is_accepted_only_when_the_flag_asks_for_it() {
    let temp = scratch();
    let (succeeded, text) = init(temp.path(), "0.0.0.0:8421", Some(true));
    assert!(succeeded, "allow_non_loopback = true still refused: {text}");
}

#[test]
fn a_loopback_bind_needs_no_flag() {
    let temp = scratch();
    let (succeeded, text) = init(temp.path(), "127.0.0.1:8421", None);
    assert!(succeeded, "the default deployment shape was refused: {text}");
}


// The config gate alone is not the rule a request meets. The transport parses
// the endpoint again on every call, so a client could be configured for a
// routable store and then refused at the socket -- which reads as an outage
// rather than as a rule. These cover the client end to end.

fn user_config(temp: &TempDir, url: &str, allow: Option<bool>) -> std::path::PathBuf {
    let config = temp.path().join("config-home").join("kinbase");
    let personal = temp.path().join("personal");
    for directory in [&config, &personal] {
        fs::create_dir_all(directory).unwrap();
    }
    fs::set_permissions(&personal, fs::Permissions::from_mode(0o700)).unwrap();
    let root = kinbase::crypto::PrivateKey::generate();
    let write = |path: &Path, bytes: &[u8]| {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
    };
    write(
        &config.join("root-public.key"),
        format!("{}\n", root.public().to_hex()).as_bytes(),
    );
    write(&config.join("facts.token"), b"facts-token\n");
    write(&config.join("admin.token"), b"admin-token\n");
    let mut body = format!(
        "schema_version = \"1\"\n\n[personal]\ndata_root = \"{personal}\"\n\n\
         [company]\nurl = \"{url}\"\nfacts_token_file = \"{token}\"\n\
         root_public_key_file = \"{root_file}\"\ncache_root = \"{cache}\"\n\
         client_key_file = \"{client}\"\nmaintainer_key_file = \"{maintainer}\"\n\
         admin_token_file = \"{admin}\"\n",
        personal = personal.display(),
        url = url,
        token = config.join("facts.token").display(),
        root_file = config.join("root-public.key").display(),
        cache = temp.path().join("company-cache").display(),
        client = config.join("client.key").display(),
        maintainer = config.join("maintainer.key").display(),
        admin = config.join("admin.token").display(),
    );
    if let Some(allow) = allow {
        body.push_str(&format!("allow_non_loopback = {allow}\n"));
    }
    write(&config.join("config.toml"), body.as_bytes());
    temp.path().join("config-home")
}

/// `repo issue` is the shortest path that actually builds a Company client, so
/// it is the one command that witnesses both the config rule and the socket
/// rule. `status` on an uncertified repository returns before either.
fn issue_against(url: &str, allow: Option<bool>) -> String {
    let temp = scratch();
    let config_home = user_config(&temp, url, allow);
    let repo = temp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(&repo)
            .status_alone()
            .unwrap()
            .success()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_kinbase"))
        .current_dir(&repo)
        .args(["repo", "issue", "--repo", ".", "--company", url])
        .env("HOME", temp.path())
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_STATE_HOME", temp.path().join("state-home"))
        .env_remove("KINBASE_COMPANY_URL")
        .output_alone()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).to_string() + &String::from_utf8_lossy(&output.stderr)
}

#[test]
fn a_routable_company_url_is_refused_by_default() {
    let text = issue_against("http://kinbase.kinbase.svc.cluster.local:8421", None);
    assert!(
        text.contains("loopback"),
        "a routable Company URL was accepted by default: {text}",
    );
}

#[test]
fn a_routable_company_url_reaches_the_socket_when_the_flag_asks_for_it() {
    // RFC 5737 TEST-NET-1, reserved for documentation and routed nowhere, so the
    // connection attempt times out. Asserting the timeout rather than the absence
    // of a refusal is the point: an endpoint rule that still rejected this, or any
    // earlier return, would not reach the socket at all, and a test that only says
    // "no loopback error" passes for both of those reasons.
    let text = issue_against("http://192.0.2.1:8421", Some(true));
    assert!(
        text.contains("COMPANY_UNREACHABLE"),
        "the request never reached the socket: {text}",
    );
    assert!(
        !text.contains("loopback"),
        "the transport still refused a permitted endpoint: {text}",
    );
}

#[test]
fn a_non_boolean_flag_is_malformed_configuration_rather_than_false() {
    let temp = scratch();
    let path = service_config(temp.path(), "127.0.0.1:8421", None);
    let text = fs::read_to_string(&path).unwrap() + "allow_non_loopback = \"true\"\n";
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    file.write_all(text.as_bytes()).unwrap();
    drop(file);
    let output = Command::new(env!("CARGO_BIN_EXE_kinbase"))
        .args(["company", "init", "--config"])
        .arg(&path)
        .output_alone()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "a quoted boolean was accepted: {text}");
    assert!(
        text.contains("must be a boolean"),
        "refused for the wrong reason: {text}",
    );
}
