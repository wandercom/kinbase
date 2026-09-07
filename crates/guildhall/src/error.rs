use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExitCode {
    Ok = 0,
    UserActionRequired = 2,
    DegradedSafe = 3,
    Refused = 4,
    IntegrityFailure = 5,
    DependencyUnavailable = 6,
    InternalFailure = 70,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContractError {
    pub code: String,
    pub message: String,
    pub remediation: String,
    pub retryable: bool,
    pub evidence_id: String,
}

impl ContractError {
    pub fn new(
        code: &str,
        message: impl Into<String>,
        remediation: impl Into<String>,
        retryable: bool,
        exit: ExitCode,
    ) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
            remediation: remediation.into(),
            retryable,
            evidence_id: format!("err_{:02}", exit as i32),
        }
    }

    pub fn exit(&self) -> i32 {
        match self.code.as_str() {
            "COMPANY_UNREACHABLE" | "CACHE_EXPIRED" | "REVOCATION_STALE" => 6,
            "REPO_UNCERTIFIED" | "APPROVAL_EXPIRED" | "HOOK_APPROVAL_REQUIRED" => 2,
            "PERSONAL_TAINT_BLOCKED"
            | "SIGNATURE_INVALID"
            | "DIGEST_MISMATCH"
            | "PROCESSOR_UNAUTHORIZED" => 5,
            "AUTHORITY_SCOPE_DENIED" | "AUTHORITY_WRONG_SCOPE" | "CONFIG_INVARIANT" => 4,
            _ => 70,
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(
            "RUN_INTEGRITY_FAILED",
            message,
            "Preserve evidence and rerun after repairing the failure.",
            false,
            ExitCode::InternalFailure,
        )
    }
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ContractError {}

pub type Result<T, E = ContractError> = std::result::Result<T, E>;
