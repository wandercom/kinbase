//! Refresh outcomes, including the failures that must not send a token.

mod oidc_support;
mod support;

use oidc_support::*;
use serde_json::Value;
use std::fs;

fn certified() -> Rig {
    let mut cfg = Cfg::oidc();
    cfg.certify = true;
    Rig::boot(cfg)
}

fn saved_refresh(rig: &Rig) -> String {
    let value: Value =
        serde_json::from_slice(&fs::read(rig.oidc_path()).expect("oidc.json")).unwrap();
    value["refresh_token"].as_str().unwrap_or("").to_owned()
}

#[test]
fn refresh_outcomes_follow_the_provider() {
    let rig = certified();
    rig.seed(SEEDED_REFRESH, 60);
    rig.script_mut(|s| s.refresh_ttl = 60);
    let first = rig.status();
    assert!(first.status.success(), "{}", stderr(&first));
    let rotated = saved_refresh(&rig);
    assert_ne!(rotated, SEEDED_REFRESH);
    let second = rig.status();
    assert!(second.status.success(), "{}", stderr(&second));
    assert_eq!(
        rig.view().refresh_tokens_seen,
        vec![SEEDED_REFRESH.to_owned(), rotated]
    );
    let view = rig.view();
    assert!(view.discovery_calls >= view.refresh_calls);
    assert!(view.discovery_calls >= 2, "{}", view.discovery_calls);

    let rig = certified();
    rig.seed(SEEDED_REFRESH, 60);
    rig.script_mut(|s| {
        s.omit_refresh = true;
        s.refresh_ttl = 60;
    });
    assert!(rig.status().status.success(), "first keep");
    assert_eq!(saved_refresh(&rig), SEEDED_REFRESH);
    assert!(rig.status().status.success(), "second keep");
    assert_eq!(
        rig.view().refresh_tokens_seen,
        vec![SEEDED_REFRESH.to_owned(), SEEDED_REFRESH.to_owned()]
    );

    let rows: [(&str, fn(&mut Script)); 3] = [
        ("invalid_grant", |s| {
            s.oauth_error = Some("invalid_grant".into())
        }),
        ("no_id", |s| s.omit_id = true),
        ("no_exp", |s| s.omit_exp = true),
    ];
    for (label, mutate) in rows {
        let rig = certified();
        rig.seed(SEEDED_REFRESH, 60);
        rig.script_mut(mutate);
        let out = rig.status();
        assert_code(&out, "AUTHORITY_SCOPE_DENIED");
        assert!(
            stdout(&out).contains("Run `kinbase auth login`"),
            "{label}: {}",
            stdout(&out)
        );
        assert!(!rig.oidc_path().exists(), "{label} kept the session");
    }

    let rig = certified();
    rig.seed(SEEDED_REFRESH, 60);
    rig.script_mut(|s| {
        s.hold_refresh = true;
        s.oauth_error = Some("invalid_grant".into());
        s.apply = Apply::Refresh;
    });
    rig.arm_hold();
    std::thread::scope(|scope| {
        let status = scope.spawn(|| rig.status());
        rig.wait_refresh_entered();
        let login = scope.spawn(|| rig.login(false));
        rig.release_after_overlap();
        let login = login.join().expect("login");
        let _status = status.join().expect("status");
        assert!(login.status.success(), "{}", stderr(&login));
        assert_eq!(saved_refresh(&rig), rig.view().code_refresh);
    });
}

#[test]
fn refresh_failures_keep_the_session_and_send_nothing() {
    let keep =
        |cfg: Cfg, mutate: fn(&mut Script), code: &str, echo: Option<&str>, hidden: &[&str]| {
            let rig = {
                let mut cfg = cfg;
                cfg.certify = true;
                Rig::boot(cfg)
            };
            rig.seed(SEEDED_REFRESH, 60);
            let before = fs::read(rig.oidc_path()).unwrap();
            let seen = rig.view().http_bytes;
            rig.script_mut(mutate);
            let out = rig.status();
            assert_code(&out, code);
            if code == "CONFIG_INVARIANT" || code == "AUTHORITY_SCOPE_DENIED" {
                assert_eq!(out.status.code(), Some(4), "{code}");
            }
            assert_eq!(fs::read(rig.oidc_path()).unwrap(), before);
            assert_eq!(rig.view().http_bytes, seen, "sent a company request");
            let text = stdout(&out) + &stderr(&out);
            if let Some(echo) = echo {
                assert!(text.contains(echo), "{text}");
            }
            for secret in hidden {
                assert!(!text.contains(secret), "{text}");
            }
        };

    keep(
        Cfg::oidc(),
        |s| s.token_endpoint = Some("http://127.0.0.1:1/token".into()),
        "COMPANY_UNREACHABLE",
        None,
        &[],
    );
    keep(
        Cfg::oidc(),
        |s| s.http_status = Some(502),
        "COMPANY_UNREACHABLE",
        None,
        &[],
    );
    keep(
        Cfg::oidc(),
        |s| s.non_json = true,
        "COMPANY_UNREACHABLE",
        None,
        &[],
    );

    let mut down = Cfg::oidc();
    down.provider = false;
    down.issuer_override = Some("http://127.0.0.1:1".into());
    keep(down, |_| {}, "COMPANY_UNREACHABLE", None, &[]);

    keep(
        Cfg::oidc(),
        |s| s.token_endpoint = Some("http://10.1.2.3/token".into()),
        "CONFIG_INVARIANT",
        None,
        &[],
    );
    keep(
        Cfg::oidc(),
        |s| s.discovery_issuer = Some("https://not-the-issuer.example".into()),
        "CONFIG_INVARIANT",
        None,
        &[],
    );
    keep(
        Cfg::oidc(),
        |s| {
            s.oauth_error = Some("invalid_client".into());
            s.error_description = Some("desc-synth-marker".into());
        },
        "CONFIG_INVARIANT",
        Some("invalid_client"),
        &["desc-synth-marker", SEEDED_REFRESH],
    );
    keep(
        Cfg::oidc(),
        |s| s.oauth_error = Some("Not_Valid".into()),
        "CONFIG_INVARIANT",
        None,
        &["Not_Valid"],
    );
}

#[test]
fn two_processes_refresh_once() {
    let rig = certified();
    rig.seed(SEEDED_REFRESH, 60);
    rig.arm_hold();
    std::thread::scope(|scope| {
        let first = scope.spawn(|| rig.status());
        let second = scope.spawn(|| rig.status());
        rig.wait_refresh_entered();
        rig.release_after_overlap();
        let first = first.join().expect("first");
        let second = second.join().expect("second");
        assert!(first.status.success(), "{}", stderr(&first));
        assert!(second.status.success(), "{}", stderr(&second));
        let a: Value = serde_json::from_slice(&first.stdout).expect("json");
        let b: Value = serde_json::from_slice(&second.stdout).expect("json");
        assert_eq!(a["status"], "certified");
        assert_eq!(b["status"], "certified");
    });
    assert_eq!(rig.view().refresh_calls, 1);
}
