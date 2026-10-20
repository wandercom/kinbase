//! Company transport: headers, URL rules, TLS, framing, SessionStart.

mod oidc_support;
mod support;

use oidc_support::*;
use serde_json::Value;
use std::fs;

fn mask(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        if let Ok(mut value) = serde_json::from_str::<Value>(line) {
            if let Some(obj) = value.as_object_mut() {
                obj.remove("evidence_id");
                if let Some(err) = obj.get_mut("error").and_then(|e| e.as_object_mut()) {
                    err.remove("evidence_id");
                }
            }
            out.push_str(&value.to_string());
        } else if line.starts_with("evidence_id:") {
            out.push_str("evidence_id:");
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

#[test]
fn requests_without_a_session_fail_before_connecting() {
    let mut cfg = Cfg::oidc();
    cfg.certify = true;
    let rig = Rig::boot(cfg);
    let before = rig.view().http_bytes;
    let status = rig.status();
    assert_code(&status, "AUTHORITY_SCOPE_DENIED");
    assert!(
        stdout(&status).contains("Run `kinbase auth login`"),
        "{}",
        stdout(&status)
    );
    let url = rig.gateway.clone();
    let issue = rig.issue(&url);
    assert_code(&issue, "AUTHORITY_SCOPE_DENIED");
    assert_eq!(issue.status.code(), Some(4));
    assert!(
        stdout(&issue).contains("Run `kinbase auth login`"),
        "{}",
        stdout(&issue)
    );
    let view = rig.view();
    assert_eq!(view.http_bytes, before);
    assert_eq!(view.accepts, 0);
    assert!(view.authz.is_empty());
}

#[test]
fn a_gateway_401_asks_for_login() {
    let mut cfg = Cfg::oidc();
    cfg.gate = Gate::Plain401;
    let rig = Rig::boot(cfg);
    rig.seed(SEEDED_REFRESH, 3600);
    let before = fs::read(rig.oidc_path()).unwrap();
    let url = rig.gateway.clone();
    let out = rig.issue(&url);
    assert_code(&out, "AUTHORITY_SCOPE_DENIED");
    assert_eq!(out.status.code(), Some(4));
    assert!(
        stdout(&out).contains("Run `kinbase auth login`"),
        "{}",
        stdout(&out)
    );
    assert_eq!(fs::read(rig.oidc_path()).unwrap(), before);

    let mut cfg = Cfg::oidc();
    cfg.client_facts = "wrong-facts-synth-ZZ".into();
    let rig = Rig::boot(cfg);
    rig.seed(SEEDED_REFRESH, 3600);
    let before = fs::read(rig.oidc_path()).unwrap();
    let url = rig.gateway.clone();
    let out = rig.issue(&url);
    let body = rig
        .view()
        .upstream_bodies
        .last()
        .cloned()
        .unwrap_or_default();
    let code = json_code(&body);
    assert!(!code.is_empty(), "server body: {body}");
    assert_code(&out, &code);
    if !body.contains("kinbase auth login") {
        assert!(
            !stdout(&out).contains("Run `kinbase auth login`"),
            "{}",
            stdout(&out)
        );
    }
    assert_eq!(fs::read(rig.oidc_path()).unwrap(), before);
}

#[test]
fn the_store_reads_the_facts_token_from_its_own_header() {
    let mut cfg = Cfg::oidc();
    cfg.gate = Gate::KeepAuth;
    cfg.certify = true;
    let rig = Rig::boot(cfg);
    let login = rig.login(false);
    assert!(login.status.success(), "{}", stderr(&login));
    let status = rig.status();
    assert!(status.status.success(), "{}", stderr(&status));
    let body: Value = serde_json::from_slice(&status.stdout).expect("status");
    assert_eq!(body["status"], "certified");
    let view = rig.view();
    assert!(
        view.forwarded_authz.iter().any(|header| {
            header
                .strip_prefix("Bearer ")
                .is_some_and(|token| token == view.latest_id && token != FACTS)
        }),
        "{:?}",
        view.forwarded_authz
    );
    assert!(
        view.facts_headers.iter().any(|header| header == FACTS),
        "{:?}",
        view.facts_headers
    );
    assert!(
        view.upstream_status.contains(&200),
        "{:?}",
        view.upstream_status
    );

    let mut cfg = Cfg::oidc().parts(false, false, false);
    cfg.provider = false;
    cfg.gate = Gate::Pass;
    cfg.certify = true;
    let rig = Rig::boot(cfg);
    let status = rig.status();
    assert!(status.status.success(), "{}", stderr(&status));
    let body: Value = serde_json::from_slice(&status.stdout).expect("status");
    assert_eq!(body["status"], "certified");
    let view = rig.view();
    assert!(!view.authz.is_empty(), "{:?}", view.authz);
    assert!(
        view.authz
            .iter()
            .all(|header| header == &format!("Bearer {FACTS}")),
        "{:?}",
        view.authz
    );
    assert!(view.facts_headers.is_empty(), "{:?}", view.facts_headers);
    assert!(
        view.upstream_status.contains(&200),
        "{:?}",
        view.upstream_status
    );
}

#[test]
fn oidc_config_and_endpoint_rules() {
    let issued = |cfg: Cfg, url: &str| {
        let rig = Rig::boot(cfg);
        rig.issue(url)
    };
    let logged = |cfg: Cfg| Rig::boot(cfg).login(false);
    let quiet = |issuer: &str| Cfg::oidc().quiet().issuer_is(issuer);

    let out = issued(
        quiet("http://127.0.0.1:9").at("http://127.0.0.1:9"),
        "http://127.0.0.1:9",
    );
    assert_code(&out, "AUTHORITY_SCOPE_DENIED");

    let out = issued(
        quiet("https://idp.invalid/realms/t")
            .allow(true)
            .at("http://192.0.2.1:9"),
        "http://192.0.2.1:9",
    );
    assert_code(&out, "CONFIG_INVARIANT");
    assert_eq!(out.status.code(), Some(4));

    let https = quiet("https://idp.invalid/realms/t").at("https://192.0.2.1:9");
    assert_code(
        &issued(https.clone(), "https://192.0.2.1:9"),
        "CONFIG_INVARIANT",
    );
    assert_code(
        &issued(https.allow(true), "https://192.0.2.1:9"),
        "AUTHORITY_SCOPE_DENIED",
    );

    assert_code(
        &logged(quiet("http://idp.invalid/realms/t").at("http://127.0.0.1:9")),
        "CONFIG_INVARIANT",
    );
    let out = logged(quiet("https://idp.invalid/realms/t").at("http://127.0.0.1:9"));
    assert_code(&out, "COMPANY_UNREACHABLE");
    assert!(
        !stdout(&out).contains("CONFIG_INVARIANT"),
        "{}",
        stdout(&out)
    );

    let rig = Rig::boot(Cfg::oidc());
    rig.script_mut(|s| s.discovery_issuer = Some("https://not-the-issuer.example".into()));
    assert_code(&rig.login(false), "CONFIG_INVARIANT");
    let rig = Rig::boot(Cfg::oidc());
    rig.script_mut(|s| s.token_endpoint = Some("http://10.1.2.3/token".into()));
    assert_code(&rig.login(false), "CONFIG_INVARIANT");

    for (issuer, client, secret) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let out = logged(
            Cfg::oidc()
                .quiet()
                .parts(issuer, client, secret)
                .issuer_is("https://idp.invalid/realms/t")
                .at("http://127.0.0.1:9"),
        );
        assert_code(&out, "CONFIG_INVARIANT");
        assert_eq!(out.status.code(), Some(4));
    }

    let out = logged(
        Cfg::oidc()
            .quiet()
            .parts(false, false, false)
            .at("http://127.0.0.1:9"),
    );
    assert_code(&out, "CONFIG_INVARIANT");
    assert_eq!(out.status.code(), Some(4));

    let out = issued(
        Cfg::oidc()
            .quiet()
            .parts(false, false, false)
            .allow(true)
            .at("http://192.0.2.1:9"),
        "http://192.0.2.1:9",
    );
    assert_code(&out, "COMPANY_UNREACHABLE");
    assert!(!stdout(&out).contains("loopback"), "{}", stdout(&out));
}

#[test]
fn an_untrusted_gateway_certificate_sends_no_token() {
    for gate in [Gate::Untrusted, Gate::WrongName] {
        let mut cfg = Cfg::oidc();
        cfg.gate = gate;
        let rig = Rig::boot(cfg);
        rig.seed(SEEDED_REFRESH, 3600);
        let url = rig.gateway.clone();
        let out = rig.issue(&url);
        assert_code(&out, "COMPANY_UNREACHABLE");
        assert_eq!(rig.view().http_bytes, 0, "{url}");
    }
}

#[test]
fn chunked_and_unframed_responses_parse() {
    let mut cfg = Cfg::oidc();
    cfg.gate = Gate::Reframe;
    cfg.issuer = false;
    cfg.client_id = false;
    cfg.provider = false;
    let rig = Rig::boot(cfg);
    let url = rig.gateway.clone();
    let mut seen = Vec::new();
    for frame in [Frame::Chunked, Frame::Eof, Frame::Length] {
        rig.set_frames(&[frame, frame, frame, frame, frame, frame, frame, frame]);
        let out = rig.issue(&url);
        seen.push(mask(&(stdout(&out) + &stderr(&out))));
    }
    assert_eq!(seen[0], seen[1], "chunked vs eof");
    assert_eq!(seen[1], seen[2], "eof vs framed");

    let mut cfg = Cfg::oidc();
    cfg.gate = Gate::Truncate;
    cfg.issuer = false;
    cfg.client_id = false;
    cfg.provider = false;
    let rig = Rig::boot(cfg);
    let url = rig.gateway.clone();
    assert_code(&rig.issue(&url), "COMPANY_UNREACHABLE");

    let rig = Rig::boot(Cfg::oidc());
    assert!(rig.login(false).status.success(), "login");
    let types = rig.view().content_types;
    assert!(
        types.iter().any(|t| t
            .to_ascii_lowercase()
            .starts_with("application/x-www-form-urlencoded")),
        "{types:?}"
    );
}

#[test]
fn session_start_without_a_session_asks_for_login() {
    let mut cfg = Cfg::oidc();
    cfg.certify = true;
    let rig = Rig::boot(cfg);
    let out = rig.session_start();
    assert!(out.status.success(), "{}", stderr(&out));
    let value: Value = serde_json::from_slice(&out.stdout).expect("session json");
    assert!(
        value["notices"]
            .to_string()
            .contains("run kinbase auth login"),
        "{value}"
    );
    assert_eq!(value["background_verification_started"], false);
    assert_eq!(value["company_refresh"]["started"], false);

    let mut cfg = Cfg::oidc()
        .quiet()
        .allow(true)
        .issuer_is("https://idp.invalid/realms/t")
        .at("https://company.invalid");
    cfg.certify = true;
    let rig = Rig::boot(cfg);
    rig.seed(SEEDED_REFRESH, 3600);
    let out = rig.session_start();
    assert!(out.status.success(), "{}", stderr(&out));
    let value: Value = serde_json::from_slice(&out.stdout).expect("session json");
    assert_eq!(value["background_verification_started"], true);
    assert_eq!(value["company_refresh"]["started"], true);
    assert_ne!(value["company_state"], "unreachable");
}
