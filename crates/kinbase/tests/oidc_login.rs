//! Login, the callback, and what must never be stored or printed.

mod oidc_support;
mod support;

use oidc_support::*;
use serde_json::Value;
use std::fs;
use std::process::Output;

const PRIOR: &[u8] = br#"{"refresh_token":"prior-refresh-synth","id_token":"prior.id.token"}"#;

fn assert_authorize(url: &str, scope: &str) {
    let q = query(url);
    for (key, value) in [
        ("response_type", "code"),
        ("scope", scope),
        ("client_id", CLIENT_ID),
        ("code_challenge_method", "S256"),
        ("access_type", "offline"),
        ("prompt", "consent"),
    ] {
        assert_eq!(q.get(key).map(String::as_str), Some(value), "{url}");
    }
    assert!(q.get("state").is_some_and(|s| !s.is_empty()), "{url}");
    assert!(
        q.get("code_challenge").is_some_and(|s| !s.is_empty()),
        "{url}"
    );
    let redir = q.get("redirect_uri").map(String::as_str).unwrap_or("");
    assert!(
        redir.starts_with("http://127.0.0.1:") && redir.ends_with("/callback"),
        "{redir}"
    );
}

fn assert_session(path: &std::path::Path) {
    assert_eq!(mode_bits(path), 0o600);
    let value: Value = serde_json::from_slice(&fs::read(path).expect("oidc.json")).expect("json");
    let mut keys: Vec<_> = value.as_object().expect("object").keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, ["id_token", "refresh_token"]);
}

#[test]
fn login_then_request_refreshes_once_and_reaches_the_store() {
    let mut cfg = Cfg::oidc();
    cfg.certify = true;
    let rig = Rig::boot(cfg);
    let plain = rig.login(false);
    assert!(plain.status.success(), "{}", stderr(&plain));
    assert_eq!(stdout(&plain), format!("signed in as {EMAIL}\n"));
    assert_authorize(&login_url(&plain), "openid email");
    assert_eq!(rig.view().refresh_calls, 0);
    assert_session(&rig.oidc_path());

    let status = rig.status();
    assert!(status.status.success(), "{}", stderr(&status));
    let body: Value = serde_json::from_slice(&status.stdout).expect("status json");
    assert_eq!(body["status"], "certified");
    let view = rig.view();
    assert_eq!(view.refresh_calls, 1);
    assert!(
        view.discovery_calls >= 2,
        "discovery {}",
        view.discovery_calls
    );
    assert!(
        view.upstream_status.contains(&200),
        "{:?}",
        view.upstream_status
    );
    assert!(
        view.facts_headers.iter().any(|h| h == FACTS),
        "{:?}",
        view.facts_headers
    );
    let latest = view.latest_id.clone();
    assert!(
        view.authz.iter().any(|h| h == &format!("Bearer {latest}")),
        "{:?}",
        view.authz
    );
    let saved: Value = serde_json::from_slice(&fs::read(rig.oidc_path()).unwrap()).unwrap();
    assert_eq!(saved["id_token"], view.latest_id);
    assert_eq!(mode_bits(&rig.oidc_path()), 0o600);

    let json_login = rig.login(true);
    assert!(json_login.status.success(), "{}", stderr(&json_login));
    assert_eq!(stdout(&json_login).lines().count(), 1);
    let doc: Value = serde_json::from_str(stdout(&json_login).trim()).expect("json stdout");
    assert_eq!(doc["signed_in_as"], EMAIL);
    assert_eq!(doc.as_object().unwrap().len(), 1);
    let err = stderr(&json_login);
    let line = err
        .lines()
        .find(|line| line.contains("login_url"))
        .expect("diagnostic");
    let diag: Value = serde_json::from_str(line).expect("diagnostic json");
    assert_eq!(diag["diagnostic"], "login_url");
    assert_eq!(diag["detail"]["url"], login_url(&json_login));
    assert!(diag.get("at").is_some());
}

#[test]
fn a_bad_callback_stores_nothing() {
    // mode, token-endpoint fault, login completes, marker in the callback response, error code
    let rows: &[(&str, &str, bool, &str, &str)] = &[
        ("bad-state", "", true, "400", ""),
        ("missing-state", "", true, "400", ""),
        ("error", "", false, "", "AUTHORITY_SCOPE_DENIED"),
        ("no-code", "", false, "", "AUTHORITY_SCOPE_DENIED"),
        ("good", "invalid_grant", false, "", "AUTHORITY_SCOPE_DENIED"),
        ("good", "500", false, "", "COMPANY_UNREACHABLE"),
        ("other", "", true, "404", ""),
        ("idle", "", true, "", ""),
    ];
    for (mode, fault, completes, mark, code) in rows {
        let rig = Rig::boot(Cfg::oidc());
        rig.write_bytes(PRIOR);
        rig.write_browser(mode);
        if !fault.is_empty() {
            let mut script = Script::default();
            script.apply = Apply::Code;
            if *fault == "500" {
                script.http_status = Some(500);
            } else {
                script.oauth_error = Some((*fault).to_owned());
            }
            rig.set_script(script);
        }
        let out = rig.login(false);
        if !mark.is_empty() {
            let http = fs::read_to_string(&rig.http_log).unwrap_or_default();
            assert!(http.contains(mark), "{mode} callback log:\n{http}");
        }
        if *completes {
            assert!(out.status.success(), "{mode}: {}", stderr(&out));
            assert_eq!(stdout(&out), format!("signed in as {EMAIL}\n"));
        } else {
            assert_code(&out, code);
            if *code == "AUTHORITY_SCOPE_DENIED" {
                assert_eq!(out.status.code(), Some(4), "{mode} exit");
            }
            assert_eq!(fs::read(rig.oidc_path()).expect("prior"), PRIOR, "{mode}");
            if *fault == "invalid_grant" {
                assert!(
                    stdout(&out).contains("Run `kinbase auth login`"),
                    "{}",
                    stdout(&out)
                );
            }
        }
    }
}

#[test]
fn login_needs_a_refresh_token_an_email_and_the_right_client_auth() {
    let refuse = |mutate: fn(&mut Script)| {
        let rig = Rig::boot(Cfg::oidc());
        rig.write_bytes(PRIOR);
        let mut script = Script::default();
        mutate(&mut script);
        rig.set_script(script);
        let out = rig.login(false);
        assert_code(&out, "AUTHORITY_SCOPE_DENIED");
        assert_eq!(out.status.code(), Some(4));
        assert_eq!(fs::read(rig.oidc_path()).unwrap(), PRIOR);
    };
    refuse(|s| s.omit_refresh = true);
    refuse(|s| s.omit_email = true);

    let mut cfg = Cfg::oidc();
    cfg.secret = true;
    let rig = Rig::boot(cfg);
    let out = rig.login(false);
    assert!(out.status.success(), "{}", stderr(&out));
    let form = rig
        .view()
        .forms
        .into_iter()
        .find(|f| f.contains("authorization_code"))
        .expect("code grant");
    assert_eq!(form_get(&form, "client_secret").as_deref(), Some(SECRET));

    let rig = Rig::boot(Cfg::oidc());
    let out = rig.login(false);
    assert!(out.status.success(), "{}", stderr(&out));
    let form = rig
        .view()
        .forms
        .into_iter()
        .find(|f| f.contains("authorization_code"))
        .expect("code grant");
    assert_eq!(form_get(&form, "client_secret"), None, "{form}");
    assert_authorize(&login_url(&out), "openid email");

    let rig = Rig::boot(Cfg::oidc());
    rig.script_mut(|s| s.offline_access = true);
    let out = rig.login(false);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_authorize(&login_url(&out), "openid email offline_access");
}

#[test]
fn no_token_reaches_argv_output_or_logs() {
    let scrub = |rig: &Rig, out: &Output| {
        let argv = fs::read_to_string(&rig.argv_log).unwrap_or_default();
        let hits = rig.leaks(&[stdout(out).as_str(), stderr(out).as_str(), argv.as_str()]);
        assert!(hits.is_empty(), "{hits:?}\n{}", stderr(out));
    };
    let mut cfg = Cfg::oidc();
    cfg.certify = true;
    let rig = Rig::boot(cfg);
    let plain = rig.login(false);
    assert!(plain.status.success(), "{}", stderr(&plain));
    scrub(&rig, &plain);
    let status = rig.status();
    scrub(&rig, &status);
    let json_login = rig.login(true);
    scrub(&rig, &json_login);

    let rig = Rig::boot(Cfg::oidc());
    rig.write_bytes(PRIOR);
    rig.script_mut(|s| s.omit_refresh = true);
    scrub(&rig, &rig.login(false));
    let rig = Rig::boot(Cfg::oidc());
    rig.write_bytes(PRIOR);
    rig.script_mut(|s| s.omit_email = true);
    scrub(&rig, &rig.login(false));

    let rig = Rig::boot(Cfg::oidc());
    rig.write_bytes(PRIOR);
    rig.write_browser("error");
    scrub(&rig, &rig.login(false));

    let mut cfg = Cfg::oidc();
    cfg.certify = true;
    let rig = Rig::boot(cfg);
    rig.seed(SEEDED_REFRESH, 60);
    rig.script_mut(|s| s.oauth_error = Some("invalid_grant".into()));
    scrub(&rig, &rig.status());
    let rig = Rig::boot({
        let mut cfg = Cfg::oidc();
        cfg.certify = true;
        cfg
    });
    rig.seed(SEEDED_REFRESH, 60);
    rig.script_mut(|s| s.http_status = Some(500));
    scrub(&rig, &rig.status());
    let rig = Rig::boot({
        let mut cfg = Cfg::oidc();
        cfg.certify = true;
        cfg
    });
    rig.seed(SEEDED_REFRESH, 60);
    rig.script_mut(|s| {
        s.oauth_error = Some("invalid_client".into());
        s.error_description = Some("desc-synth-marker".into());
    });
    let out = rig.status();
    assert!(
        !stdout(&out).contains("desc-synth-marker"),
        "{}",
        stdout(&out)
    );
    scrub(&rig, &out);

    let mut cfg = Cfg::oidc();
    cfg.gate = Gate::Plain401;
    let rig = Rig::boot(cfg);
    rig.seed(SEEDED_REFRESH, 3600);
    let url = rig.gateway.clone();
    scrub(&rig, &rig.issue(&url));
}
