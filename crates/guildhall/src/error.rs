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
        let message = message.into();
        let remediation = remediation.into();
        let evidence_source = format!("{}\0{}\0{}\0{}", code, message, remediation, retryable);
        let evidence_id = format!("err_{}", &crate::hash::sha256_text(&evidence_source)[..16]);
        Self {
            code: code.to_owned(),
            message: message.into(),
            remediation: remediation.into(),
            retryable,
            evidence_id,
        }
        .with_exit(exit)
    }

    pub fn exit(&self) -> i32 {
        match self.code.as_str() {
            "COMPANY_UNREACHABLE" => 6,
            "CACHE_EXPIRED" | "REVOCATION_STALE" => 3,
            "REPO_UNCERTIFIED" | "APPROVAL_EXPIRED" | "HOOK_APPROVAL_REQUIRED" => 2,
            "FOREIGN_REPO_EVENTS"
            | "MANIFEST_HEAD_REGRESSION"
            | "LIMIT_EXCEEDED"
            | "APPROVAL_REPLAY"
            | "AUTHORITY_WRONG_SCOPE"
            | "AUTHORITY_SCOPE_DENIED"
            | "CONFIG_INVARIANT" => 4,
            "SIGNATURE_INVALID"
            | "DIGEST_MISMATCH"
            | "PERSONAL_TAINT_BLOCKED"
            | "PROCESSOR_UNAUTHORIZED" => 5,
            "DIGEST_ALGORITHM_UNSUPPORTED"
            | "UNKNOWN_OWNER_UNRESOLVED"
            | "UNSUPPORTED_HOST_VERSION"
            | "UNSUPPORTED_KINDEX_VERSION" => 3,
            "MANIFEST_INCOMPLETE" => 5,
            "MODEL_FINGERPRINT_CHANGED"
            | "ORACLE_LEAKAGE"
            | "SCORER_UNCALIBRATED"
            | "RUN_CENSUS_MISSING"
            | "RUN_INTEGRITY_FAILED" => 70,
            code => {
                let _ = code;
                70
            }
        }
    }

    fn with_exit(mut self, exit: ExitCode) -> Self {
        debug_assert_eq!(i32::from(self.exit()), exit as i32);
        if self.exit() != exit as i32 {
            self.code = "RUN_INTEGRITY_FAILED".to_owned();
            self.message =
                "constructed error uses an exit code inconsistent with the ratified taxonomy"
                    .to_owned();
            self.remediation =
                "Preserve the receipt and report the implementation defect.".to_owned();
            self.retryable = false;
            self.evidence_id = "err_taxonomy_mismatch".to_owned();
        }
        self
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
