//! Deterministic secret/identifier/correlation scanners (architecture §5,
//! threat model "Hard-blocking taint"). Hard-block assignment is
//! deterministic for registered canaries/identifiers, credential formats,
//! explicit secret fields, and configured source classes. Detection runs
//! over NFC/NFD, case, hex, base64, percent, JSON-escape, whitespace and
//! delimiter (fragmentation) views. Any detector error fails closed.
//! Findings never contain the matched bytes.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use unicode_normalization::UnicodeNormalization;

pub const SCANNER_VERSION: &str = "guildhall-scanner/2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum Taint {
    Secret,
    Credential,
    ConfiguredCanary,
    ForbiddenIdentifier,
    PersonalSession,
    CompanyConfidential,
    Codebase,
    Public,
}

impl Taint {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Credential => "credential",
            Self::ConfiguredCanary => "configured-canary",
            Self::ForbiddenIdentifier => "forbidden-identifier",
            Self::PersonalSession => "personal-session",
            Self::CompanyConfidential => "company-confidential",
            Self::Codebase => "codebase",
            Self::Public => "public",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "secret" => Some(Self::Secret),
            "credential" => Some(Self::Credential),
            "configured-canary" => Some(Self::ConfiguredCanary),
            "forbidden-identifier" => Some(Self::ForbiddenIdentifier),
            "personal-session" => Some(Self::PersonalSession),
            "company-confidential" => Some(Self::CompanyConfidential),
            "codebase" => Some(Self::Codebase),
            "public" => Some(Self::Public),
            _ => None,
        }
    }

    /// Hard-blocking for every shared destination; cannot be approved.
    pub fn hard_block(self) -> bool {
        matches!(
            self,
            Self::Secret | Self::Credential | Self::ConfiguredCanary | Self::ForbiddenIdentifier
        )
    }

    /// Approval-gating provenance: may yield a minimized shared candidate
    /// only through eligibility, scanning, and exact-byte approval.
    pub fn approval_gating(self) -> bool {
        matches!(self, Self::PersonalSession | Self::CompanyConfidential)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub detector: String,
    pub family: String,
    pub taint: Taint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scanner_version: String,
    pub hard_block: bool,
    pub taints: Vec<Taint>,
    pub findings: Vec<Finding>,
    pub views_examined: usize,
}

/// The registered canary and forbidden-identifier sets. Raw values live only
/// in the launcher/Personal boundary; shared processes receive digests of
/// normalized values (see [`canary_digest`]).
#[derive(Debug, Clone, Default)]
pub struct Registry {
    pub canaries: Vec<String>,
    pub canary_digests: BTreeSet<String>,
    pub identifiers: Vec<String>,
}

impl Registry {
    pub fn from_values(canaries: Vec<String>, identifiers: Vec<String>) -> Self {
        let canary_digests = canaries.iter().map(|value| canary_digest(value)).collect();
        Self {
            canaries,
            canary_digests,
            identifiers,
        }
    }

    pub fn digests_only(digests: &[String], identifiers: &[String]) -> Self {
        Self {
            canaries: Vec::new(),
            canary_digests: digests.iter().cloned().collect(),
            identifiers: identifiers.to_vec(),
        }
    }
}

/// Normalization used for registry digests: NFC, lowercase, alphanumerics
/// only (so delimiter, whitespace, and case transformations collapse).
pub fn squeeze(value: &str) -> String {
    value
        .nfc()
        .collect::<String>()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect()
}

pub fn canary_digest(value: &str) -> String {
    crate::hash::sha256_text(&format!("guildhall-canary/1\0{}", squeeze(value)))
}

/// Every deterministic view of the text that a detector examines.
fn views(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut out: Vec<(String, String)> = Vec::new();
    let nfc: String = text.nfc().collect();
    let nfd: String = text.nfd().collect();
    out.push(("raw".to_owned(), text.to_owned()));
    out.push(("nfc".to_owned(), nfc.clone()));
    out.push(("nfd".to_owned(), nfd));
    out.push(("lower".to_owned(), nfc.to_lowercase()));
    out.push(("squeezed".to_owned(), squeeze(text)));
    let mut decoded = Vec::new();
    for token in tokens(text) {
        if token.len() >= 16 && token.bytes().all(|b| b.is_ascii_hexdigit()) && token.len() % 2 == 0
        {
            if let Some(bytes) = crate::hash::hex_decode(&token.to_lowercase()) {
                if let Ok(value) = String::from_utf8(bytes) {
                    decoded.push(("hex".to_owned(), value));
                }
            }
        }
        if token.len() >= 16 {
            let attempts: [(&str, Result<Vec<u8>, base64::DecodeError>); 3] = [
                ("base64", STANDARD.decode(token.as_bytes())),
                ("base64-nopad", STANDARD_NO_PAD.decode(token.as_bytes())),
                ("base64-url", URL_SAFE_NO_PAD.decode(token.as_bytes())),
            ];
            for (name, attempt) in attempts {
                if let Ok(bytes) = attempt {
                    if let Ok(value) = String::from_utf8(bytes) {
                        if value.chars().all(|c| !c.is_control()) {
                            decoded.push((name.to_owned(), value));
                        }
                    }
                }
            }
        }
    }
    if text.contains('%') {
        decoded.push(("percent".to_owned(), percent_decode(text)));
    }
    if text.contains("\\u") || text.contains("\\x") {
        decoded.push(("json-escape".to_owned(), json_unescape(text)));
    }
    if text.contains("&#") {
        decoded.push(("html-entity".to_owned(), html_unescape(text)));
    }
    for (name, value) in decoded {
        out.push((format!("{name}:squeezed"), squeeze(&value)));
        out.push((
            format!("{name}:lower"),
            value.nfc().collect::<String>().to_lowercase(),
        ));
        out.push((name, value));
    }
    Ok(out)
}

fn tokens(text: &str) -> Vec<String> {
    text.split(|c: char| {
        !(c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_')
    })
    .filter(|token| !token.is_empty())
    .map(str::to_owned)
    .collect()
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(pair) = std::str::from_utf8(&bytes[index + 1..index + 3]) {
                if let Ok(value) = u8::from_str_radix(pair, 16) {
                    out.push(value);
                    index += 3;
                    continue;
                }
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn json_unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '\\' && index + 1 < chars.len() {
            match chars[index + 1] {
                'u' if index + 5 < chars.len() => {
                    let hex: String = chars[index + 2..index + 6].iter().collect();
                    if hex.len() == 4 {
                        if let Ok(unit) = u16::from_str_radix(&hex, 16) {
                            if (0xd800..=0xdbff).contains(&unit)
                                && index + 11 < chars.len()
                                && chars[index + 6] == '\\'
                                && chars[index + 7] == 'u'
                            {
                                let low: String = chars[index + 8..index + 12].iter().collect();
                                if let Ok(low_unit) = u16::from_str_radix(&low, 16) {
                                    if let Some(Ok(c)) = char::decode_utf16([unit, low_unit]).next()
                                    {
                                        out.push(c);
                                        index += 12;
                                        continue;
                                    }
                                }
                            }
                            if let Some(c) = char::from_u32(u32::from(unit)) {
                                out.push(c);
                                index += 6;
                                continue;
                            }
                        }
                    }
                }
                'x' if index + 3 < chars.len() => {
                    let hex: String = chars[index + 2..index + 4].iter().collect();
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        out.push(byte as char);
                        index += 4;
                        continue;
                    }
                }
                'n' => {
                    out.push('\n');
                    index += 2;
                    continue;
                }
                't' => {
                    out.push('\t');
                    index += 2;
                    continue;
                }
                '"' | '\\' | '/' => {
                    out.push(chars[index + 1]);
                    index += 2;
                    continue;
                }
                _ => {}
            }
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}

fn html_unescape(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("&#") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let (is_hex, body) = if let Some(stripped) = after.strip_prefix('x') {
            (true, stripped)
        } else {
            (false, after)
        };
        if let Some(end) = body.find(';') {
            let digits = &body[..end];
            let code = if is_hex {
                u32::from_str_radix(digits, 16).ok()
            } else {
                digits.parse::<u32>().ok()
            };
            if let Some(c) = code.and_then(char::from_u32) {
                out.push(c);
                rest = &body[end + 1..];
                continue;
            }
        }
        out.push_str("&#");
        rest = after;
    }
    out.push_str(rest);
    out
}

fn add(findings: &mut Vec<Finding>, detector: &str, family: &str, taint: Taint) {
    let finding = Finding {
        detector: detector.to_owned(),
        family: family.to_owned(),
        taint,
    };
    if !findings.contains(&finding) {
        findings.push(finding);
    }
}

/// Run every deterministic detector. `Err` means a detector failed and the
/// caller must treat the input as hard-blocked (fail closed).
pub fn scan(text: &str, registry: &Registry) -> Result<ScanResult, String> {
    let result = std::panic::catch_unwind(|| scan_inner(text, registry));
    match result {
        Ok(inner) => inner,
        Err(_) => Err("scanner panicked; failing closed".to_owned()),
    }
}

fn scan_inner(text: &str, registry: &Registry) -> Result<ScanResult, String> {
    let mut findings = Vec::new();
    let all_views = views(text)?;
    // 1. registered canaries: exact and every reversible transformation,
    //    plus the frozen partial rule (any 16-char window of a >= 20-char
    //    squeezed canary).
    for canary in &registry.canaries {
        let squeezed = squeeze(canary);
        if squeezed.is_empty() {
            continue;
        }
        let lower = canary.nfc().collect::<String>().to_lowercase();
        let hex_form = crate::hash::hex_string(canary.as_bytes());
        let base64_forms = [
            STANDARD.encode(canary.as_bytes()),
            STANDARD_NO_PAD.encode(canary.as_bytes()),
            URL_SAFE_NO_PAD.encode(canary.as_bytes()),
        ];
        let percent_form: String = canary.bytes().map(|b| format!("%{b:02X}")).collect();
        let json_form: String = canary
            .encode_utf16()
            .map(|unit| format!("\\u{unit:04x}"))
            .collect();
        for (family, view) in &all_views {
            let view_lower = view.to_lowercase();
            if view.contains(canary.as_str()) {
                add(
                    &mut findings,
                    "canary-exact",
                    family,
                    Taint::ConfiguredCanary,
                );
            } else if view_lower.contains(&lower) {
                add(
                    &mut findings,
                    "canary-case",
                    family,
                    Taint::ConfiguredCanary,
                );
            }
            if squeeze(view).contains(&squeezed) {
                add(
                    &mut findings,
                    "canary-normalized",
                    family,
                    Taint::ConfiguredCanary,
                );
            }
            if view_lower.contains(&hex_form) {
                add(&mut findings, "canary-hex", family, Taint::ConfiguredCanary);
            }
            if base64_forms.iter().any(|form| view.contains(form.as_str())) {
                add(
                    &mut findings,
                    "canary-base64",
                    family,
                    Taint::ConfiguredCanary,
                );
            }
            if view.to_uppercase().contains(&percent_form) {
                add(
                    &mut findings,
                    "canary-percent",
                    family,
                    Taint::ConfiguredCanary,
                );
            }
            if view_lower.contains(&json_form) {
                add(
                    &mut findings,
                    "canary-json-escape",
                    family,
                    Taint::ConfiguredCanary,
                );
            }
            if squeezed.len() >= 20 {
                let view_squeezed = squeeze(view);
                let chars: Vec<char> = squeezed.chars().collect();
                for window in chars.windows(16) {
                    let piece: String = window.iter().collect();
                    if view_squeezed.contains(&piece) {
                        add(
                            &mut findings,
                            "canary-partial",
                            family,
                            Taint::ConfiguredCanary,
                        );
                        break;
                    }
                }
            }
        }
    }
    // 1b. digest-only registries (shared processes): word-level digests.
    if !registry.canary_digests.is_empty() {
        for (family, view) in &all_views {
            for token in view.split(|c: char| !c.is_alphanumeric()) {
                if token.len() >= 6 && registry.canary_digests.contains(&canary_digest(token)) {
                    add(
                        &mut findings,
                        "canary-digest",
                        family,
                        Taint::ConfiguredCanary,
                    );
                }
            }
            let squeezed = squeeze(view);
            if squeezed.len() >= 6 && registry.canary_digests.contains(&canary_digest(&squeezed)) {
                add(
                    &mut findings,
                    "canary-digest-whole",
                    family,
                    Taint::ConfiguredCanary,
                );
            }
        }
    }
    // 2. registered forbidden identifiers.
    for identifier in &registry.identifiers {
        let squeezed = squeeze(identifier);
        if squeezed.is_empty() {
            continue;
        }
        for (family, view) in &all_views {
            if squeeze(view).contains(&squeezed) {
                add(
                    &mut findings,
                    "identifier-registered",
                    family,
                    Taint::ForbiddenIdentifier,
                );
            }
        }
    }
    // 3. credential formats and explicit secret fields, over decoded views.
    for (family, view) in &all_views {
        credential_formats(view, family, &mut findings);
        secret_fields(view, family, &mut findings);
        identifier_formats(view, family, &mut findings);
        correlation_ids(view, family, &mut findings);
    }
    let mut taints: Vec<Taint> = findings.iter().map(|finding| finding.taint).collect();
    taints.sort();
    taints.dedup();
    let hard_block = taints.iter().any(|taint| taint.hard_block());
    Ok(ScanResult {
        scanner_version: SCANNER_VERSION.to_owned(),
        hard_block,
        taints,
        findings,
        views_examined: all_views.len(),
    })
}

fn credential_formats(view: &str, family: &str, findings: &mut Vec<Finding>) {
    for token in tokens(view) {
        let t = token.as_str();
        let matched = (t.starts_with("AKIA")
            && t.len() == 20
            && t[4..]
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()))
            || (t.starts_with("ghp_") && t.len() >= 30)
            || (t.starts_with("gho_") && t.len() >= 30)
            || (t.starts_with("github_pat_") && t.len() >= 30)
            || (t.starts_with("sk-")
                && t.len() >= 20
                && t[3..]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
            || (t.starts_with("xox")
                && t.len() >= 20
                && t.as_bytes().get(3).is_some_and(|b| b"baprs".contains(b))
                && t.as_bytes().get(4) == Some(&b'-'))
            || (t.starts_with("AIza") && t.len() == 39)
            || (t.starts_with("eyJ") && t.matches('.').count() == 2 && t.len() >= 40)
            || (t.starts_with("glpat-") && t.len() >= 20)
            || (t.starts_with("guildhall_") && t.len() >= 40);
        if matched {
            add(findings, "credential-format", family, Taint::Credential);
        }
    }
    if view.contains("-----BEGIN") && view.contains("PRIVATE KEY-----") {
        add(findings, "private-key-block", family, Taint::Secret);
    }
    let lower = view.to_lowercase();
    if let Some(index) = lower.find("bearer ") {
        let rest = &view[index + 7..];
        let token: String = rest.chars().take_while(|c| !c.is_whitespace()).collect();
        if token.len() >= 20 {
            add(findings, "bearer-token", family, Taint::Credential);
        }
    }
}

fn secret_fields(view: &str, family: &str, findings: &mut Vec<Finding>) {
    let lower = view.to_lowercase();
    for key in [
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "api-key",
        "access_token",
        "refresh_token",
        "private_key",
        "client_secret",
        "auth_token",
    ] {
        let mut search = 0usize;
        while let Some(found) = lower[search..].find(key) {
            let start = search + found + key.len();
            let rest = &lower[start..];
            let trimmed = rest.trim_start();
            if let Some(after) = trimmed
                .strip_prefix(':')
                .or_else(|| trimmed.strip_prefix('='))
            {
                let value: String = after
                    .trim_start()
                    .trim_start_matches(['"', '\''])
                    .chars()
                    .take_while(|c| {
                        !c.is_whitespace() && *c != '"' && *c != '\'' && *c != ',' && *c != ';'
                    })
                    .collect();
                if value.len() >= 6 && value != "<redacted>" && !value.starts_with("${") {
                    add(findings, "secret-field", family, Taint::Secret);
                }
            }
            search = start;
        }
    }
}

fn identifier_formats(view: &str, family: &str, findings: &mut Vec<Finding>) {
    // Social security numbers: ddd-dd-dddd
    let bytes = view.as_bytes();
    for window in bytes.windows(11) {
        if window[3] == b'-'
            && window[6] == b'-'
            && window[..3].iter().all(u8::is_ascii_digit)
            && window[4..6].iter().all(u8::is_ascii_digit)
            && window[7..].iter().all(u8::is_ascii_digit)
        {
            add(
                findings,
                "identifier-ssn-format",
                family,
                Taint::ForbiddenIdentifier,
            );
            break;
        }
    }
    // Email addresses.
    for token in view.split(|c: char| {
        c.is_whitespace()
            || c == '<'
            || c == '>'
            || c == '('
            || c == ')'
            || c == ','
            || c == ';'
            || c == '"'
    }) {
        if let Some((local, domain)) = token.split_once('@') {
            if !local.is_empty()
                && domain.contains('.')
                && local
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".+_-".contains(&b))
                && domain
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
                && !domain.ends_with('.')
                && domain != "example.com"
                && !domain.ends_with(".example")
            {
                add(
                    findings,
                    "identifier-email",
                    family,
                    Taint::ForbiddenIdentifier,
                );
                break;
            }
        }
    }
    // Phone numbers: 10+ digits with separators, e.g. +1 555-123-4567.
    let mut digits = 0usize;
    let mut run = 0usize;
    for c in view.chars() {
        if c.is_ascii_digit() {
            digits += 1;
            run += 1;
        } else if c == '-' || c == ' ' || c == '(' || c == ')' || c == '.' || c == '+' {
            run = 0;
        } else {
            digits = 0;
            run = 0;
        }
        if digits >= 10 && run <= 4 && digits <= 15 && view.contains('-') && view.contains('+') {
            add(
                findings,
                "identifier-phone-format",
                family,
                Taint::ForbiddenIdentifier,
            );
            break;
        }
    }
}

fn correlation_ids(view: &str, family: &str, findings: &mut Vec<Finding>) {
    for marker in [
        "/.codex/sessions/",
        "/.claude/projects/",
        "/sessions/rollout-",
        "transcript_path",
    ] {
        if view.contains(marker) {
            add(
                findings,
                "correlation-transcript-path",
                family,
                Taint::ForbiddenIdentifier,
            );
        }
    }
    for token in tokens(view) {
        let t = token.as_str();
        if (t.starts_with("session_")
            || t.starts_with("obs_")
            || t.starts_with("cand_")
            || t.starts_with("rollout-20"))
            && t.len() >= 24
        {
            add(
                findings,
                "correlation-private-id",
                family,
                Taint::ForbiddenIdentifier,
            );
        }
    }
}

/// Convenience: hard-blocked under an empty registry (formats only).
pub fn hard_blocked(text: &str) -> bool {
    match scan(text, &Registry::default()) {
        Ok(result) => result.hard_block,
        Err(_) => true,
    }
}

pub fn scanner(text: &str) -> ScanResult {
    scan(text, &Registry::default()).unwrap_or_else(|_| ScanResult {
        scanner_version: SCANNER_VERSION.to_owned(),
        hard_block: true,
        taints: Vec::new(),
        findings: Vec::new(),
        views_examined: 0,
    })
}
