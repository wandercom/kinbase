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

pub const SCANNER_VERSION: &str = "kinbase-scanner/2";

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
    pub identifier_digests: BTreeSet<String>,
    /// The word counts registered values span. A digest-only scan hashes
    /// every run of consecutive words of exactly these lengths; hashing single
    /// words and the whole text could never match `alpha bravo` inside a
    /// sentence.
    pub digest_word_counts: BTreeSet<usize>,
}

/// The longest word run a digest-only scan hashes. A longer registered value
/// is still found whole, never by a run; the cap bounds the work.
pub const MAX_DIGEST_WORDS: usize = 32;

impl Registry {
    pub fn from_values(canaries: Vec<String>, identifiers: Vec<String>) -> Self {
        let canary_digests = canaries.iter().map(|value| canary_digest(value)).collect();
        let identifier_digests = identifiers
            .iter()
            .map(|value| identifier_digest(value))
            .collect();
        let digest_word_counts = registered_word_counts(canaries.iter().chain(&identifiers));
        Self {
            canaries,
            canary_digests,
            identifiers,
            identifier_digests,
            digest_word_counts,
        }
    }

    /// A registry for a process that holds no raw values.
    pub fn digests_only(
        canary_digests: &[String],
        identifier_digests: &[String],
        digest_word_counts: &[usize],
    ) -> Self {
        Self {
            canaries: Vec::new(),
            canary_digests: canary_digests.iter().cloned().collect(),
            identifiers: Vec::new(),
            identifier_digests: identifier_digests.iter().cloned().collect(),
            digest_word_counts: digest_word_counts
                .iter()
                .copied()
                .filter(|count| (1..=MAX_DIGEST_WORDS).contains(count))
                .collect(),
        }
    }
}

/// The words of a value as digest matching sees them: maximal alphanumeric
/// runs, each squeezed.
fn digest_words(value: &str) -> Vec<String> {
    value
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(squeeze)
        .filter(|word| !word.is_empty())
        .collect()
}

/// The word counts of registered values a run can match (one through
/// `MAX_DIGEST_WORDS`).
pub fn registered_word_counts<'a>(values: impl Iterator<Item = &'a String>) -> BTreeSet<usize> {
    values
        .map(|value| digest_words(value).len())
        .filter(|count| (1..=MAX_DIGEST_WORDS).contains(count))
        .collect()
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
    crate::hash::sha256_text(&format!("kinbase-canary/1\0{}", squeeze(value)))
}

pub fn identifier_digest(value: &str) -> String {
    crate::hash::sha256_text(&format!("kinbase-identifier/1\0{}", squeeze(value)))
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
    // 1b. digest-only registries (shared processes): every run of a
    //     registered word count, and the whole text. A registry holding the
    //     raw values has already matched them above and below, so it skips
    //     the runs (and their hashing cost).
    let digest_only = registry.canaries.is_empty() && registry.identifiers.is_empty();
    if !registry.canary_digests.is_empty() || !registry.identifier_digests.is_empty() {
        for (family, view) in &all_views {
            let words = if digest_only {
                digest_words(view)
            } else {
                Vec::new()
            };
            for &count in &registry.digest_word_counts {
                for run in words.windows(count) {
                    let joined = run.concat();
                    if joined.len() >= 6
                        && registry.canary_digests.contains(&canary_digest(&joined))
                    {
                        add(
                            &mut findings,
                            "canary-digest",
                            family,
                            Taint::ConfiguredCanary,
                        );
                    }
                    if registry
                        .identifier_digests
                        .contains(&identifier_digest(&joined))
                    {
                        add(
                            &mut findings,
                            "identifier-digest",
                            family,
                            Taint::ForbiddenIdentifier,
                        );
                    }
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
            || (t.starts_with("kinbase_") && t.len() >= 40);
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
    if contains_email(view) {
        add(
            findings,
            "identifier-email",
            family,
            Taint::ForbiddenIdentifier,
        );
    }
    if contains_phone_number(view) {
        add(
            findings,
            "identifier-phone-format",
            family,
            Taint::ForbiddenIdentifier,
        );
    }
}

/// An email address anywhere in `view`, as people write them: after
/// `mailto:` or a label colon, inside brackets or quotes, or ending a
/// sentence. Reserved example domains are not addresses.
fn contains_email(view: &str) -> bool {
    view.split(|c: char| c.is_whitespace() || "<>()[]{},;\"'`|".contains(c))
        .filter_map(|token| token.split_once('@'))
        .any(|(local, domain)| {
            // `mailto:` and `Email:` label the address; a colon after the
            // host (`git@github.com:org/repo`) makes it a remote, and the
            // domain check below refuses it.
            let local = local.rsplit(':').next().unwrap_or_default();
            let local = local.trim_start_matches(|c: char| !c.is_ascii_alphanumeric());
            let domain = domain.trim_end_matches(|c: char| !c.is_ascii_alphanumeric());
            !local.is_empty()
                && local
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".+_-".contains(&b))
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.contains("..")
                && domain
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
                && domain.rsplit('.').next().is_some_and(|tld| {
                    tld.len() >= 2
                        && (tld.bytes().all(|b| b.is_ascii_alphabetic())
                            || tld.strip_prefix("xn--").is_some_and(|label| {
                                !label.is_empty()
                                    && label
                                        .bytes()
                                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                            }))
                })
                && domain != "example.com"
                && !domain.ends_with(".example")
        })
}

/// A phone number in `view`: an E.164 number (`+` then 10 to 15 digits in
/// groups) or a North American number grouped 3-3-4, with or without a
/// leading `1` and parentheses around the area code. The digits must form
/// one written number: a date, a clock time and a timezone offset elsewhere
/// in the text are not added together, and an unformatted ten-digit run (an
/// epoch timestamp) is not a phone number.
fn contains_phone_number(view: &str) -> bool {
    let chars: Vec<char> = view.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        let starts = chars[index].is_ascii_digit() || chars[index] == '+' || chars[index] == '(';
        // Glued to a word before it, directly or through one `-`/`.`
        // (`ABC-123-456-7890` is a ticket, not a phone).
        let joined_to_word = index > 0
            && (chars[index - 1].is_alphanumeric()
                || (index > 1
                    && matches!(chars[index - 1], '-' | '.')
                    && chars[index - 2].is_alphabetic()));
        if !starts {
            index += 1;
            continue;
        }
        if joined_to_word {
            // The whole chained token is an identifier; resuming inside it
            // found `123-456-7890` in `ABC-12-123-456-7890`.
            while index < chars.len()
                && (chars[index].is_alphanumeric() || matches!(chars[index], '-' | '.'))
            {
                index += 1;
            }
            continue;
        }
        let mut end = index;
        while end < chars.len() && (chars[end].is_ascii_digit() || " -.()+".contains(chars[end])) {
            end += 1;
        }
        let next = end;
        // The span ends at its last digit or closing parenthesis; a number
        // glued to letters after it is an identifier, not a phone.
        while end > index && " -.(+".contains(chars[end - 1]) {
            end -= 1;
        }
        // Digits glued to letters after them (`9am`) are not part of the
        // number before them: that group is dropped, not the whole span.
        if end < chars.len() && chars[end].is_alphanumeric() {
            while end > index && chars[end - 1].is_ascii_digit() {
                end -= 1;
            }
            let separated = end > index && " -.".contains(chars[end - 1]);
            while end > index && " -.(+".contains(chars[end - 1]) {
                end -= 1;
            }
            if !separated {
                end = index;
            }
        }
        if end > index && phone_span(&chars[index..end]) {
            return true;
        }
        index = next.max(index + 1);
    }
    false
}

/// Whether one span of digits and separators holds a written phone number.
fn phone_span(span: &[char]) -> bool {
    // Digit groups and the separator text before each.
    let mut groups: Vec<(String, String)> = Vec::new();
    let mut separator = String::new();
    let mut digits = String::new();
    for &c in span {
        if c.is_ascii_digit() {
            digits.push(c);
        } else {
            if !digits.is_empty() {
                groups.push((std::mem::take(&mut separator), std::mem::take(&mut digits)));
            }
            separator.push(c);
        }
    }
    if !digits.is_empty() {
        groups.push((separator, digits));
    }
    let single = |sep: &str| matches!(sep, "-" | "." | " ");
    let chained = |sep: &str| matches!(sep, "-" | ".");
    for (start, (sep, _)) in groups.iter().enumerate() {
        // E.164: a `+` that opens a number (not one glued to the digits
        // before it, as in a timezone offset), then groups joined by single
        // separators until 10 to 15 digits have been written.
        let opens = (start == 0 && sep.trim_start() == "+") || sep.ends_with(" +");
        if opens {
            let mut total = 0usize;
            for (position, (joint, group)) in groups[start..].iter().enumerate() {
                if position > 0 && !single(joint) {
                    break;
                }
                total += group.len();
                if (10..=15).contains(&total) {
                    return true;
                }
                if total > 15 {
                    break;
                }
            }
        }
        // North American 3-3-4, optionally after `1` and with the area code
        // in parentheses. A group chained on by `-` or `.` on either side
        // makes it part of a longer identifier, unless the one before is
        // the country code.
        let Some(window) = groups.get(start..start + 3) else {
            continue;
        };
        let (area_sep, area) = &window[0];
        let (exchange_sep, exchange) = &window[1];
        let (line_sep, line) = &window[2];
        if (area.len(), exchange.len(), line.len()) != (3, 3, 4) {
            continue;
        }
        let parenthesized =
            area_sep.ends_with('(') && matches!(exchange_sep.as_str(), ")" | ") " | ")-");
        if !(parenthesized || single(exchange_sep)) || !single(line_sep) {
            continue;
        }
        // Unparenthesized groups use one separator throughout, and groups
        // split only by spaces ("512 256 1024") count only after a `1`.
        let country_code = start > 0 && groups[start - 1].1 == "1";
        if !parenthesized && (exchange_sep != line_sep || (line_sep == " " && !country_code)) {
            continue;
        }
        let lead = area_sep.trim_end_matches('(');
        let before_ok = start == 0 || !chained(lead) || country_code;
        let after_ok = groups
            .get(start + 3)
            .is_none_or(|(joint, _)| !chained(joint));
        if before_ok && after_ok {
            return true;
        }
    }
    false
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

#[cfg(test)]
mod digest_registry_tests {
    use super::*;

    #[test]
    fn a_digest_only_registry_finds_a_multi_word_value_inside_text() {
        let raw = Registry::from_values(
            vec!["Violet Harbor Lantern".to_owned()],
            vec!["acme payroll".to_owned()],
        );
        let counts: Vec<usize> = raw.digest_word_counts.iter().copied().collect();
        assert_eq!(counts, [2, 3]);
        let digests: Vec<String> = raw.canary_digests.iter().cloned().collect();
        let identifiers: Vec<String> = raw.identifier_digests.iter().cloned().collect();
        let shared = Registry::digests_only(&digests, &identifiers, &counts);
        assert!(shared.canaries.is_empty() && shared.identifiers.is_empty());

        let canary = scan(
            "Deploy notes: violet-harbor lantern moved to prod.",
            &shared,
        )
        .expect("scan");
        assert!(
            canary.taints.contains(&Taint::ConfiguredCanary),
            "{:?}",
            canary.findings
        );
        let identifier = scan("Rotate the Acme Payroll credentials today.", &shared).expect("scan");
        assert!(
            identifier.taints.contains(&Taint::ForbiddenIdentifier),
            "{:?}",
            identifier.findings
        );
        let clean = scan("The harbor lantern is violet.", &shared).expect("scan");
        assert!(
            !clean.taints.contains(&Taint::ConfiguredCanary),
            "{:?}",
            clean.findings
        );
    }
}

#[cfg(test)]
mod digest_work_tests {
    use super::*;

    #[test]
    fn a_long_registered_value_does_not_multiply_the_scan() {
        let long_identifier = (0..100)
            .map(|index| format!("word{index}"))
            .collect::<Vec<_>>()
            .join(" ");
        let text = (0..1000)
            .map(|index| format!("token{index}"))
            .collect::<Vec<_>>()
            .join(" ");
        let raw = Registry::from_values(Vec::new(), vec![long_identifier]);
        assert!(
            raw.digest_word_counts.is_empty(),
            "a 100-word value is never a run"
        );
        let started = std::time::Instant::now();
        scan(&text, &raw).expect("scan");
        let identifiers: Vec<String> = raw.identifier_digests.iter().cloned().collect();
        let shared = Registry::digests_only(&[], &identifiers, &[100, 2]);
        assert_eq!(
            shared
                .digest_word_counts
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            [2]
        );
        scan(&text, &shared).expect("scan");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
    }
}

#[cfg(test)]
mod identifier_tests {
    use super::{contains_email, contains_phone_number};

    #[test]
    fn email_addresses_are_found_as_people_write_them() {
        for text in [
            "Write to alice.smith@acme-corp.io.",
            "Contact: mailto:ops+pager@acme.co!",
            "Email:bob@acme.org",
            "reach me at <carol@acme.dev>",
            "(dave@acme.com)",
            "[erin@acme.net]",
            "'frank@acme.io'",
            "Is it grace@acme.io?",
            "alice@mail.xn--p1ai",
        ] {
            assert!(contains_email(text), "{text}");
        }
        for text in [
            "someone@example.com wrote the fixture",
            "the handler for @mentions in the notifier",
            "user@localhost is the default",
            "a@b.c is not a valid address",
            "decorators like @app.route are fine",
            "npm install @scope/package@1.2.3",
            "git clone git@github.com:acme/app.git",
            "origin ssh://git@github.com/acme/app.git",
        ] {
            assert!(!contains_email(text), "{text}");
        }
    }

    #[test]
    fn phone_numbers_are_found_without_other_punctuation_in_the_text() {
        for text in [
            "Call 555-123-4567 tomorrow",
            "call (555) 123-4567",
            "call (555)123-4567",
            "555.123.4567 is the desk",
            "dial 1 555 123 4567",
            "dial 1-555-123-4567",
            "+1 555 123 4567",
            "+15551234567",
            "+44 20 7946 0958",
            "On 2026-09-17 555-123-4567 called",
            "+1-555-123-4567 9am-5pm",
            "555-123-4567 9am-5pm weekdays",
        ] {
            assert!(contains_phone_number(text), "{text}");
        }
        for text in [
            "Deployed 2026-09-17 10:00 +0000 to prod",
            "at 2026-09-17T10:00:00+00:00",
            "The epoch was 1726567890 then",
            "version 2026.09.17 shipped",
            "ticket ABC-123-456-7890 closed",
            "order 123-456-7890-12 shipped",
            "ids 10.123.456.7890 in the log",
            "PR 4035655462 was merged",
            "retry 3 times over 12 seconds",
            "buffer sizes 512 256 1024 bytes",
            "ranges 555-123.4567 mixed",
            "ticket ABC-12-123-456-7890 closed",
            "build 555-123-4567abc failed",
        ] {
            assert!(!contains_phone_number(text), "{text}");
        }
    }
}
