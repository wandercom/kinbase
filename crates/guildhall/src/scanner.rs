use crate::hash::sha256_text;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Taint {
    Secret,
    Credential,
    Canary,
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
            Self::Canary => "configured-canary",
            Self::ForbiddenIdentifier => "forbidden-identifier",
            Self::PersonalSession => "personal-session",
            Self::CompanyConfidential => "company-confidential",
            Self::Codebase => "codebase",
            Self::Public => "public",
        }
    }

    pub fn hard_block(self) -> bool {
        matches!(
            self,
            Self::Secret | Self::Credential | Self::Canary | Self::ForbiddenIdentifier
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub taints: Vec<Taint>,
    pub findings: Vec<String>,
    pub scanner_version: String,
}

pub fn scanner(text: &str) -> ScanResult {
    let normalized = text.to_lowercase();
    let mut taints = Vec::new();
    let mut findings = Vec::new();
    let markers = [
        ("api_key", Taint::Secret),
        ("apikey", Taint::Secret),
        ("secret", Taint::Secret),
        ("password", Taint::Credential),
        ("bearer ", Taint::Credential),
        ("ghp_", Taint::Credential),
        ("github_pat_", Taint::Credential),
        ("sk-", Taint::Credential),
        ("akia", Taint::Credential),
        ("guildhall-canary", Taint::Canary),
        ("social-security", Taint::ForbiddenIdentifier),
        ("passport-number", Taint::ForbiddenIdentifier),
    ];
    for (marker, taint) in markers {
        if normalized.contains(marker) {
            taints.push(taint);
            findings.push(format!("matched:{marker}"));
        }
    }
    if normalized.contains("personally")
        || normalized.contains("my birthday")
        || normalized.contains("my medical")
    {
        taints.push(Taint::PersonalSession);
    }
    if normalized.contains("company confidential") || normalized.contains("internal only") {
        taints.push(Taint::CompanyConfidential);
    }
    taints.push(Taint::Public);
    taints.sort_by_key(|taint| taint.as_str());
    taints.dedup();
    ScanResult {
        taints,
        findings,
        scanner_version: format!("guildhall-scanner/1:{}", sha256_text("guildhall-scanner/1")),
    }
}

pub fn hard_blocked(text: &str) -> bool {
    scanner(text).taints.iter().any(|taint| taint.hard_block())
}
