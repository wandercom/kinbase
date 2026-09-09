//! Launcher-only user configuration and the derived shared-process
//! configuration (cli.md "Configuration", architecture §1 and §6).
//!
//! Only the launcher reads the whole user config. `SharedConfig` is the
//! immutable configuration handed to shared projector/writer work: it holds
//! no Personal path, descriptor, environment value, or serialized parent
//! config, and the type system is the first enforcement of that
//! non-possession (there is no accessor from `SharedConfig` to Personal).

use crate::crypto::{PrivateKey, PublicKey};
use crate::error::ContractError;
use crate::paths;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub const USER_CONFIG_SCHEMA: &str = "1";
pub const SERVICE_CONFIG_SCHEMA: &str = "1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonalConfig {
    pub data_root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanyConfig {
    pub url: String,
    pub facts_token_file: PathBuf,
    pub root_public_key_file: PathBuf,
    pub cache_root: PathBuf,
    pub admin_token_file: Option<PathBuf>,
    pub directory_token_file: Option<PathBuf>,
    pub authority_token_file: Option<PathBuf>,
    pub client_key_file: PathBuf,
    pub maintainer_key_file: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifierConfig {
    pub model: String,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub args: Vec<String>,
    pub timeout_seconds: u64,
    pub processor_scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostsConfig {
    pub codex_version: String,
    pub claude_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerConfig {
    pub canary_file: Option<PathBuf>,
    pub forbidden_identifier_file: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserConfig {
    pub path: PathBuf,
    pub personal: PersonalConfig,
    pub company: Option<CompanyConfig>,
    pub classifier: Option<ClassifierConfig>,
    pub hosts: HostsConfig,
    pub scanner: ScannerConfig,
    pub principal_id: String,
    pub host_instance_id: String,
}

/// Which product mode the launcher resolved (cli.md: missing config selects
/// Codebase-only mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Full,
    CodebaseOnly,
}

/// A bearer token as stored in a mode-0600 token file: the bare token bytes
/// with an optional trailing newline (Validator ruling R-3). Capability
/// scopes and the client-key binding are service-side records.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenRecord {
    pub token: String,
}

impl TokenRecord {
    pub fn load(path: &Path, role: &str) -> Result<Self, ContractError> {
        let text = crate::crypto::read_private_text(path, role)?;
        let token = text.trim().to_owned();
        if token.is_empty() || token.len() > 512 || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(ContractError::refused(
                "CONFIG_INVARIANT",
                format!("{role} file does not hold a bare bearer token"),
                "Reissue the token file through `guildhall company init`; contents are never printed.",
            ));
        }
        Ok(Self { token })
    }
}

/// Everything a shared (non-Personal) process may hold. Constructed only by
/// the launcher from a `UserConfig`; carries no Personal field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedConfig {
    pub mode: Mode,
    pub principal_id: String,
    pub host_instance_id: String,
    pub company: Option<SharedCompanyAccess>,
    pub classifier: Option<SharedClassifier>,
    pub hosts: SharedHosts,
    pub canary_digests: Vec<String>,
    pub forbidden_identifiers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedCompanyAccess {
    pub url: String,
    pub facts_token: TokenRecord,
    pub admin_token: Option<TokenRecord>,
    pub directory_token: Option<TokenRecord>,
    pub authority_token: Option<TokenRecord>,
    pub root_public_key: String,
    pub cache_root: PathBuf,
    pub client_private_seed: String,
    pub maintainer_private_seed: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedClassifier {
    pub model: String,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub args: Vec<String>,
    pub timeout_seconds: u64,
    pub processor_scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedHosts {
    pub codex_version: String,
    pub claude_version: String,
}

impl SharedCompanyAccess {
    pub fn root_key(&self) -> Result<PublicKey, ContractError> {
        PublicKey::from_hex(&self.root_public_key)
    }
    pub fn client_key(&self) -> Result<PrivateKey, ContractError> {
        PrivateKey::from_seed_text(&self.client_private_seed)
    }
    pub fn maintainer_key(&self) -> Result<PrivateKey, ContractError> {
        PrivateKey::from_seed_text(&self.maintainer_private_seed)
    }
}

pub fn user_config_path() -> PathBuf {
    paths::config_dir().join("config.toml")
}

fn config_error(message: impl Into<String>) -> ContractError {
    ContractError::refused(
        "CONFIG_INVARIANT",
        message,
        "Correct the named configuration value; no state was changed.",
    )
}

fn closed_keys(table: &toml::Table, allowed: &[&str], section: &str) -> Result<(), ContractError> {
    for key in table.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(config_error(format!(
                "unknown key `{key}` in {section}; unknown keys fail closed"
            )));
        }
    }
    Ok(())
}

fn required_str<'a>(
    table: &'a toml::Table,
    key: &str,
    section: &str,
) -> Result<&'a str, ContractError> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| config_error(format!("{section}.{key} is required")))
}

fn optional_path(
    table: &toml::Table,
    key: &str,
    section: &str,
) -> Result<Option<PathBuf>, ContractError> {
    match table.get(key) {
        None => Ok(None),
        Some(value) => {
            let text = value
                .as_str()
                .ok_or_else(|| config_error(format!("{section}.{key} must be a string path")))?;
            absolute(text, &format!("{section}.{key}")).map(Some)
        }
    }
}

fn absolute(text: &str, field: &str) -> Result<PathBuf, ContractError> {
    let path = PathBuf::from(text);
    if !path.is_absolute() {
        return Err(config_error(format!("{field} must be an absolute path")));
    }
    Ok(path)
}

/// Enforce cli.md's file rules for a config/token/key path: regular file,
/// no symlink, mode not broader than 0600.
pub fn enforce_private_file(path: &Path, role: &str) -> Result<(), ContractError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| ContractError::unreadable(role, &error))?;
    if metadata.file_type().is_symlink() {
        return Err(config_error(format!("{role} file is a symlink")));
    }
    if !metadata.is_file() {
        return Err(config_error(format!("{role} path is not a regular file")));
    }
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(ContractError::broad_mode(role, path, mode));
    }
    Ok(())
}

/// Load the launcher-only user config. `Ok(None)` is Codebase-only mode.
pub fn load_user_config() -> Result<Option<UserConfig>, ContractError> {
    let path = user_config_path();
    if !path.exists() && std::fs::symlink_metadata(&path).is_err() {
        return Ok(None);
    }
    enforce_private_file(&path, "user config")?;
    let text = std::fs::read_to_string(&path)
        .map_err(|error| ContractError::unreadable("user config", &error))?;
    parse_user_config(&path, &text).map(Some)
}

pub fn parse_user_config(path: &Path, text: &str) -> Result<UserConfig, ContractError> {
    let table: toml::Table = text.parse().map_err(|error: toml::de::Error| {
        config_error(format!("user config is not valid TOML: {error}"))
    })?;
    closed_keys(
        &table,
        &[
            "schema_version",
            "personal",
            "company",
            "classifier",
            "hosts",
            "scanner",
            "identity",
        ],
        "user config",
    )?;
    if table.get("schema_version").and_then(toml::Value::as_str) != Some(USER_CONFIG_SCHEMA) {
        return Err(config_error("user config schema_version must be \"1\""));
    }
    let personal_table = table
        .get("personal")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| config_error("[personal] is required"))?;
    closed_keys(personal_table, &["data_root"], "[personal]")?;
    let data_root = absolute(
        required_str(personal_table, "data_root", "personal")?,
        "personal.data_root",
    )?;
    let config_dir = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(paths::config_dir);

    let company = match table.get("company") {
        None => None,
        Some(value) => {
            let section = value
                .as_table()
                .ok_or_else(|| config_error("[company] must be a table"))?;
            closed_keys(
                section,
                &[
                    "url",
                    "facts_token_file",
                    "root_public_key_file",
                    "cache_root",
                    "admin_token_file",
                    "directory_token_file",
                    "authority_token_file",
                    "client_key_file",
                    "maintainer_key_file",
                ],
                "[company]",
            )?;
            let url = required_str(section, "url", "company")?.to_owned();
            validate_loopback_url(&url)?;
            Some(CompanyConfig {
                url,
                facts_token_file: absolute(
                    required_str(section, "facts_token_file", "company")?,
                    "company.facts_token_file",
                )?,
                root_public_key_file: absolute(
                    required_str(section, "root_public_key_file", "company")?,
                    "company.root_public_key_file",
                )?,
                cache_root: absolute(
                    required_str(section, "cache_root", "company")?,
                    "company.cache_root",
                )?,
                admin_token_file: optional_path(section, "admin_token_file", "company")?,
                directory_token_file: optional_path(section, "directory_token_file", "company")?,
                authority_token_file: optional_path(section, "authority_token_file", "company")?,
                client_key_file: optional_path(section, "client_key_file", "company")?
                    .unwrap_or_else(|| config_dir.join("client.key")),
                maintainer_key_file: optional_path(section, "maintainer_key_file", "company")?
                    .unwrap_or_else(|| config_dir.join("maintainer.key")),
            })
        }
    };

    let classifier = match table.get("classifier") {
        None => None,
        Some(value) => {
            let section = value
                .as_table()
                .ok_or_else(|| config_error("[classifier] must be a table"))?;
            closed_keys(
                section,
                &[
                    "model",
                    "executable",
                    "executable_sha256",
                    "args",
                    "timeout_seconds",
                    "processor_scope",
                ],
                "[classifier]",
            )?;
            let model = section
                .get("model")
                .and_then(toml::Value::as_str)
                .unwrap_or("deterministic")
                .to_owned();
            if !model.starts_with("deterministic") && !model.starts_with("ollama:") {
                return Err(config_error(
                    "classifier.model must be \"deterministic\" or \"ollama:<name>\"",
                ));
            }
            let executable = absolute(
                required_str(section, "executable", "classifier")?,
                "classifier.executable",
            )?;
            let digest = required_str(section, "executable_sha256", "classifier")?.to_owned();
            if !crate::hash::is_sha256(&digest) {
                return Err(config_error(
                    "classifier.executable_sha256 must be a lowercase 64-hex digest",
                ));
            }
            let args = section
                .get("args")
                .map(|value| {
                    value
                        .as_array()
                        .ok_or_else(|| config_error("classifier.args must be an array of strings"))?
                        .iter()
                        .map(|item| {
                            item.as_str()
                                .map(str::to_owned)
                                .ok_or_else(|| config_error("classifier.args must be strings"))
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?
                .unwrap_or_default();
            let timeout_seconds = section
                .get("timeout_seconds")
                .and_then(toml::Value::as_integer)
                .ok_or_else(|| config_error("classifier.timeout_seconds is required"))?;
            if !(1..=600).contains(&timeout_seconds) {
                return Err(config_error(
                    "classifier.timeout_seconds must be within 1..=600",
                ));
            }
            let processor_scope = section
                .get("processor_scope")
                .and_then(toml::Value::as_str)
                .unwrap_or("local")
                .to_owned();
            Some(ClassifierConfig {
                model,
                executable,
                executable_sha256: digest,
                args,
                timeout_seconds: timeout_seconds as u64,
                processor_scope,
            })
        }
    };

    let hosts = match table.get("hosts") {
        None => HostsConfig {
            codex_version: ">=0.0.0".to_owned(),
            claude_version: ">=0.0.0".to_owned(),
        },
        Some(value) => {
            let section = value
                .as_table()
                .ok_or_else(|| config_error("[hosts] must be a table"))?;
            closed_keys(section, &["codex_version", "claude_version"], "[hosts]")?;
            HostsConfig {
                codex_version: section
                    .get("codex_version")
                    .and_then(toml::Value::as_str)
                    .unwrap_or(">=0.0.0")
                    .to_owned(),
                claude_version: section
                    .get("claude_version")
                    .and_then(toml::Value::as_str)
                    .unwrap_or(">=0.0.0")
                    .to_owned(),
            }
        }
    };

    let scanner = match table.get("scanner") {
        None => ScannerConfig {
            canary_file: None,
            forbidden_identifier_file: None,
        },
        Some(value) => {
            let section = value
                .as_table()
                .ok_or_else(|| config_error("[scanner] must be a table"))?;
            closed_keys(
                section,
                &["canary_file", "forbidden_identifier_file"],
                "[scanner]",
            )?;
            ScannerConfig {
                canary_file: optional_path(section, "canary_file", "scanner")?,
                forbidden_identifier_file: optional_path(
                    section,
                    "forbidden_identifier_file",
                    "scanner",
                )?,
            }
        }
    };

    let (principal_id, host_instance_id, identity_maintainer_key) = match table.get("identity") {
        None => (default_principal(), default_host_instance(), None),
        Some(value) => {
            let section = value
                .as_table()
                .ok_or_else(|| config_error("[identity] must be a table"))?;
            closed_keys(
                section,
                &["principal_id", "host_instance_id", "maintainer_key_file"],
                "[identity]",
            )?;
            (
                section
                    .get("principal_id")
                    .and_then(toml::Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(default_principal),
                section
                    .get("host_instance_id")
                    .and_then(toml::Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(default_host_instance),
                // Ruling R-18: the repository maintainer's signing key reaches the
                // product through `[identity] maintainer_key_file`; it takes
                // precedence over the legacy `[company]` location.
                optional_path(section, "maintainer_key_file", "identity")?,
            )
        }
    };
    let company = match (company, identity_maintainer_key) {
        (Some(mut company), Some(path)) => {
            company.maintainer_key_file = path;
            Some(company)
        }
        (company, _) => company,
    };

    Ok(UserConfig {
        path: path.to_path_buf(),
        personal: PersonalConfig { data_root },
        company,
        classifier,
        hosts,
        scanner,
        principal_id,
        host_instance_id,
    })
}

fn default_principal() -> String {
    std::env::var("GUILDHALL_PRINCIPAL")
        .unwrap_or_else(|_| std::env::var("USER").unwrap_or_else(|_| "local-principal".to_owned()))
}

fn default_host_instance() -> String {
    std::env::var("GUILDHALL_HOST_INSTANCE").unwrap_or_else(|_| {
        let host = std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty())
            .unwrap_or_else(|| "local-host".to_owned());
        format!("host_{}", &crate::hash::sha256_text(&host)[..16])
    })
}

pub fn validate_loopback_url(url: &str) -> Result<(), ContractError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| config_error("company.url must be an http:// loopback URL in this proof"))?;
    let authority = rest.split('/').next().unwrap_or_default();
    let host = authority
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(authority);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let loopback = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if !loopback {
        return Err(config_error("company.url must name a loopback endpoint"));
    }
    Ok(())
}

impl UserConfig {
    /// Derive the immutable shared-process configuration. Reads every token
    /// and key file under the cli.md file rules; contents are held in memory
    /// only. The Personal data root is deliberately not representable here.
    pub fn shared(&self) -> Result<SharedConfig, ContractError> {
        let company = match &self.company {
            None => None,
            Some(company) => {
                let facts_token = TokenRecord::load(&company.facts_token_file, "facts token")?;
                let admin_token = company
                    .admin_token_file
                    .as_ref()
                    .map(|path| TokenRecord::load(path, "administrative token"))
                    .transpose()?;
                let directory_token = company
                    .directory_token_file
                    .as_ref()
                    .map(|path| TokenRecord::load(path, "directory token"))
                    .transpose()?;
                let authority_token = company
                    .authority_token_file
                    .as_ref()
                    .map(|path| TokenRecord::load(path, "authority token"))
                    .transpose()?;
                let root_public_key =
                    PublicKey::load(&company.root_public_key_file, "Company root public key")?;
                paths::ensure_private_dir(&company.cache_root, "Company cache root")?;
                let client_key = match std::env::var("GUILDHALL_CLIENT_KEY_FD") {
                    Ok(fd) => {
                        let fd: i32 = fd.parse().map_err(|_| {
                            config_error("GUILDHALL_CLIENT_KEY_FD must be an integer")
                        })?;
                        PrivateKey::load_fd(fd, "client key")?
                    }
                    Err(_) => PrivateKey::load_or_generate(&company.client_key_file, "client key")?,
                };
                let maintainer_key =
                    PrivateKey::load_or_generate(&company.maintainer_key_file, "maintainer key")?;
                Some(SharedCompanyAccess {
                    url: company.url.clone(),
                    facts_token,
                    admin_token,
                    directory_token,
                    authority_token,
                    root_public_key: root_public_key.to_hex(),
                    cache_root: company.cache_root.clone(),
                    client_private_seed: client_key.to_seed_text(),
                    maintainer_private_seed: maintainer_key.to_seed_text(),
                })
            }
        };
        let canary_digests = match &self.scanner.canary_file {
            None => Vec::new(),
            Some(path) => load_registry_lines(path, "canary registry")?
                .into_iter()
                .map(|value| crate::scanner::canary_digest(&value))
                .collect(),
        };
        let forbidden_identifiers = match &self.scanner.forbidden_identifier_file {
            None => Vec::new(),
            Some(path) => load_registry_lines(path, "forbidden identifier registry")?,
        };
        Ok(SharedConfig {
            mode: Mode::Full,
            principal_id: self.principal_id.clone(),
            host_instance_id: self.host_instance_id.clone(),
            company,
            classifier: self.classifier.as_ref().map(|classifier| SharedClassifier {
                model: classifier.model.clone(),
                executable: classifier.executable.clone(),
                executable_sha256: classifier.executable_sha256.clone(),
                args: classifier.args.clone(),
                timeout_seconds: classifier.timeout_seconds,
                processor_scope: classifier.processor_scope.clone(),
            }),
            hosts: SharedHosts {
                codex_version: self.hosts.codex_version.clone(),
                claude_version: self.hosts.claude_version.clone(),
            },
            canary_digests,
            forbidden_identifiers,
        })
    }
}

fn load_registry_lines(path: &Path, role: &str) -> Result<Vec<String>, ContractError> {
    let text = crate::crypto::read_private_text(path, role)?;
    let mut set = BTreeSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        set.insert(line.to_owned());
    }
    Ok(set.into_iter().collect())
}

/// Codebase-only shared configuration (no user config present).
pub fn codebase_only_shared() -> SharedConfig {
    SharedConfig {
        mode: Mode::CodebaseOnly,
        principal_id: default_principal(),
        host_instance_id: default_host_instance(),
        company: None,
        classifier: None,
        hosts: SharedHosts {
            codex_version: ">=0.0.0".to_owned(),
            claude_version: ">=0.0.0".to_owned(),
        },
        canary_digests: Vec::new(),
        forbidden_identifiers: Vec::new(),
    }
}

/// Service configuration (`guildhalld.toml`).
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub path: PathBuf,
    pub company_id: String,
    pub sqlite_path: PathBuf,
    pub bind: std::net::SocketAddr,
    pub root_key_file: PathBuf,
    pub facts_token_file: PathBuf,
    pub directory_token_file: Option<PathBuf>,
    pub admin_token_file: Option<PathBuf>,
    pub authority_token_file: Option<PathBuf>,
    pub auth_failures_per_minute: i64,
    pub default_fact_freshness_seconds: i64,
    pub candidate_lifetime_seconds: i64,
    pub clock_skew_seconds: i64,
    pub nonce_retention_seconds: i64,
    pub read_volume_per_hour: i64,
    pub read_bytes_per_hour: i64,
    pub requests_per_minute: i64,
    pub revocation_freshness_seconds: i64,
    pub directory_retention_seconds: i64,
    /// Exact canonical authority scopes granted to the facts token issued
    /// from `facts_token_file`; empty grants nothing.
    pub facts_token_scopes: Vec<String>,
}

pub fn load_service_config(path: &Path) -> Result<ServiceConfig, ContractError> {
    enforce_private_file(path, "service config")?;
    let text = std::fs::read_to_string(path)
        .map_err(|error| ContractError::unreadable("service config", &error))?;
    let table: toml::Table = text.parse().map_err(|error: toml::de::Error| {
        config_error(format!("service config is not valid TOML: {error}"))
    })?;
    closed_keys(
        &table,
        &[
            "schema_version",
            "company_id",
            "sqlite_path",
            "bind",
            "root_key_file",
            "facts_token_file",
            "directory_token_file",
            "admin_token_file",
            "authority_token_file",
            "auth_failures_per_minute",
            "default_fact_freshness_seconds",
            "candidate_lifetime_seconds",
            "clock_skew_seconds",
            "nonce_retention_seconds",
            "read_volume_per_hour",
            "read_bytes_per_hour",
            "requests_per_minute",
            "revocation_freshness_seconds",
            "directory_retention_seconds",
            "facts_token_scopes",
        ],
        "service config",
    )?;
    if table.get("schema_version").and_then(toml::Value::as_str) != Some(SERVICE_CONFIG_SCHEMA) {
        return Err(config_error("service config schema_version must be \"1\""));
    }
    let integer = |key: &str, default: Option<i64>, minimum: i64| -> Result<i64, ContractError> {
        let value = match table.get(key) {
            Some(value) => value
                .as_integer()
                .ok_or_else(|| config_error(format!("{key} must be an integer")))?,
            None => default.ok_or_else(|| config_error(format!("{key} is required")))?,
        };
        if value < minimum {
            return Err(config_error(format!("{key} must be at least {minimum}")));
        }
        Ok(value)
    };
    let bind_text = required_str(&table, "bind", "service")?;
    let bind: std::net::SocketAddr = bind_text
        .parse()
        .map_err(|_| config_error("bind must be an IP:port address"))?;
    if !bind.ip().is_loopback() {
        return Err(config_error(
            "bind must be a loopback address in this proof",
        ));
    }
    let lifetime = integer("candidate_lifetime_seconds", None, 1)?;
    let skew = integer("clock_skew_seconds", None, 0)?;
    let retention = integer("nonce_retention_seconds", None, 1)?;
    if retention <= lifetime + skew {
        return Err(config_error(
            "nonce_retention_seconds must be strictly greater than candidate_lifetime_seconds + clock_skew_seconds",
        ));
    }
    Ok(ServiceConfig {
        path: path.to_path_buf(),
        company_id: required_str(&table, "company_id", "service")?.to_owned(),
        sqlite_path: absolute(required_str(&table, "sqlite_path", "service")?, "sqlite_path")?,
        bind,
        root_key_file: absolute(required_str(&table, "root_key_file", "service")?, "root_key_file")?,
        facts_token_file: absolute(required_str(&table, "facts_token_file", "service")?, "facts_token_file")?,
        directory_token_file: optional_path(&table, "directory_token_file", "service")?,
        admin_token_file: optional_path(&table, "admin_token_file", "service")?,
        authority_token_file: optional_path(&table, "authority_token_file", "service")?,
        auth_failures_per_minute: integer("auth_failures_per_minute", None, 1)?,
        default_fact_freshness_seconds: integer("default_fact_freshness_seconds", None, 1)?,
        candidate_lifetime_seconds: lifetime,
        clock_skew_seconds: skew,
        nonce_retention_seconds: retention,
        read_volume_per_hour: integer("read_volume_per_hour", Some(2_000), 1)?,
        read_bytes_per_hour: integer("read_bytes_per_hour", Some(64 * 1024 * 1024), 1)?,
        requests_per_minute: integer("requests_per_minute", Some(600), 1)?,
        revocation_freshness_seconds: integer("revocation_freshness_seconds", Some(900), 1)?,
        directory_retention_seconds: integer("directory_retention_seconds", Some(365 * 24 * 3600), 1)?,
        facts_token_scopes: table
            .get("facts_token_scopes")
            .map(|value| {
                value
                    .as_array()
                    .ok_or_else(|| config_error("facts_token_scopes must be an array of strings"))?
                    .iter()
                    .map(|item| {
                        item.as_str()
                            .map(str::to_owned)
                            .filter(|scope| {
                                !scope.is_empty()
                                    && !scope.contains('*')
                                    && !scope.contains('%')
                                    && !scope.contains('?')
                                    && !scope.contains('[')
                                    && !scope.ends_with(':')
                                    && !scope.contains('\0')
                            })
                            .ok_or_else(|| config_error("facts_token_scopes entries must be exact non-empty scope strings; wildcard, prefix, glob, and empty entries are refused"))
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default(),
    })
}
