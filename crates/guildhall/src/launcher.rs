//! The launcher (architecture §1, §6; cli.md "Configuration"): resolves the
//! user config from `${XDG_CONFIG_HOME:-~/.config}/guildhall/config.toml`
//! only, attests inherited descriptors before any side effect, opens the
//! Personal store for Personal work, and derives the shared configuration
//! that carries no Personal capability.

use crate::company::cache::Cache;
use crate::company::client::Client;
use crate::config::{Mode, SharedConfig, UserConfig};
use crate::crypto::PublicKey;
use crate::error::ContractError;
use crate::private::PrivateStore;
use serde_json::{Value, json};
use std::path::PathBuf;

#[derive(Clone)]
pub struct Launcher {
    pub mode: Mode,
    pub user: Option<UserConfig>,
    pub shared: SharedConfig,
    pub fd_attestation: Value,
    pub company_env_present: bool,
}

pub struct CompanyAccess {
    pub client: Client,
    pub cache: Cache,
    pub root: PublicKey,
    pub url: String,
}

impl Launcher {
    /// Load configuration and attest descriptors. Any inherited Personal or
    /// non-allowlisted descriptor refuses here, before shared work.
    pub fn load() -> Result<Self, ContractError> {
        let user = crate::config::load_user_config()?;
        let personal_root = user.as_ref().map(|user| user.personal.data_root.clone());
        let fd_attestation = crate::sandbox::attest_descriptors(personal_root.as_deref())?;
        let shared = match &user {
            Some(user) => user.shared()?,
            None => crate::config::codebase_only_shared(),
        };
        let company_env_present = std::env::var_os("GUILDHALL_COMPANY_URL").is_some();
        Ok(Self {
            mode: shared.mode,
            user,
            shared,
            fd_attestation,
            company_env_present,
        })
    }

    pub fn principal_id(&self) -> &str {
        &self.shared.principal_id
    }

    pub fn host_instance_id(&self) -> &str {
        &self.shared.host_instance_id
    }

    /// The private store for Personal provenance: the configured Personal
    /// data root, or the host-wide state store in Codebase-only mode.
    pub fn private_store(&self) -> Result<PrivateStore, ContractError> {
        match &self.user {
            Some(user) => PrivateStore::open_personal(&user.personal.data_root),
            None => PrivateStore::open_core(),
        }
    }

    /// The serialized prompt-budget Core store (host-wide).
    pub fn core_store(&self) -> Result<PrivateStore, ContractError> {
        PrivateStore::open_core()
    }

    pub fn personal_root(&self) -> Option<PathBuf> {
        self.user
            .as_ref()
            .map(|user| user.personal.data_root.clone())
    }

    /// Raw canary/identifier registry for the private routing path.
    pub fn scanner_registry(&self) -> Result<crate::scanner::Registry, ContractError> {
        let Some(user) = &self.user else {
            return Ok(crate::scanner::Registry::default());
        };
        let canaries = match &user.scanner.canary_file {
            Some(path) => read_lines(path, "canary registry")?,
            None => Vec::new(),
        };
        let identifiers = match &user.scanner.forbidden_identifier_file {
            Some(path) => read_lines(path, "forbidden identifier registry")?,
            None => Vec::new(),
        };
        Ok(crate::scanner::Registry::from_values(canaries, identifiers))
    }

    /// Company access from the configured endpoint only (C28: an
    /// environment-supplied endpoint is `PROCESSOR_UNAUTHORIZED` and
    /// receives zero bytes).
    pub fn company(&self) -> Result<Option<CompanyAccess>, ContractError> {
        if self.company_env_present {
            return Err(ContractError::new(
                "PROCESSOR_UNAUTHORIZED",
                "GUILDHALL_COMPANY_URL names a processor outside the configured authorization; no bytes were sent",
                "Configure the Company endpoint in the launcher user config; the environment cannot supply a processor.",
                false,
                crate::error::ExitCode::IntegrityFailure,
            )
            .with_detail(json!({"bytes_sent": 0, "shared_work_performed": false})));
        }
        let Some(access) = &self.shared.company else {
            return Ok(None);
        };
        let root = access.root_key()?;
        let cache = Cache::open(&access.cache_root)?;
        let client = Client::new(
            &access.url,
            access.facts_token.clone(),
            access.client_key()?,
            Some(root.clone()),
            access.cache_root.clone(),
        )?;
        Ok(Some(CompanyAccess {
            client,
            cache,
            root,
            url: access.url.clone(),
        }))
    }

    /// Company cache only (no network), for offline/degraded reads.
    pub fn company_cache(&self) -> Result<Option<(Cache, PublicKey)>, ContractError> {
        let Some(access) = &self.shared.company else {
            return Ok(None);
        };
        Ok(Some((Cache::open(&access.cache_root)?, access.root_key()?)))
    }

    pub fn company_port(&self) -> Option<u16> {
        self.shared
            .company
            .as_ref()
            .and_then(|access| crate::http::parse_url(&access.url).ok())
            .map(|(_, port, _)| port)
    }

    /// Capability report for `doctor` (cli.md: every process reports its
    /// granted capability names).
    pub fn capability_report(&self) -> Value {
        let shared_names: Vec<&str> = {
            let mut names = vec!["codebase:read", "codebase:write"];
            if self.shared.company.is_some() {
                names.push("company:read");
                names.push("company:write");
            }
            names
        };
        json!({
            "processes": [
                {
                    "role": "launcher",
                    "granted_capabilities": ["config:read", "personal:open", "shared-config:derive", "sandbox:launch"],
                    "holds_personal_capability": self.user.is_some(),
                    "personal_root_in_serialized_config": false
                },
                {
                    "role": "personal-worker",
                    "granted_capabilities": ["personal:read", "personal:write", "extract", "route", "scan"],
                    "holds_personal_capability": self.user.is_some(),
                    "personal_root_in_serialized_config": false
                },
                {
                    "role": "shared-projector",
                    "granted_capabilities": shared_names,
                    "holds_personal_capability": false,
                    "personal_root_in_serialized_config": serialized_shared_config_mentions_personal(&self.shared, self.personal_root().as_deref())
                },
                {
                    "role": "shared-writer",
                    "granted_capabilities": shared_names,
                    "holds_personal_capability": false,
                    "personal_root_in_serialized_config": serialized_shared_config_mentions_personal(&self.shared, self.personal_root().as_deref())
                }
            ],
            "mode": self.mode,
            "fd_attestation": self.fd_attestation
        })
    }

    pub fn shared_config_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.shared).unwrap_or_default()
    }
}

fn serialized_shared_config_mentions_personal(
    shared: &SharedConfig,
    personal_root: Option<&std::path::Path>,
) -> bool {
    let Some(root) = personal_root else {
        return false;
    };
    let text = serde_json::to_string(shared).unwrap_or_default();
    text.contains(&root.to_string_lossy().to_string())
}

fn read_lines(path: &std::path::Path, role: &str) -> Result<Vec<String>, ContractError> {
    let text = crate::crypto::read_private_text(path, role)?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect())
}
