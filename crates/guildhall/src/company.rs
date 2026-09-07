use crate::error::{ContractError, ExitCode};
use crate::hash::{sha256_bytes, sha256_text};
use crate::json::{canonical_bytes, canonical_text};
use crate::scanner::hard_blocked;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Map, Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone)]
struct ServiceConfig {
    company_id: String,
    sqlite_path: PathBuf,
    bind: SocketAddr,
    root_key_file: PathBuf,
    facts_token_file: PathBuf,
    directory_token_file: Option<PathBuf>,
    auth_failures_per_minute: i64,
    default_fact_freshness_seconds: i64,
    candidate_lifetime_seconds: i64,
    clock_skew_seconds: i64,
    nonce_retention_seconds: i64,
}

pub fn init(config: &Path, json: bool) -> Result<(), ContractError> {
    ensure_config_mode(config)?;
    let parsed = parse_config(config)?;
    if let Some(parent) = parsed.sqlite_path.parent() {
        std::fs::create_dir_all(parent).map_err(io_error)?;
    }
    let connection = Connection::open(&parsed.sqlite_path).map_err(sqlite_error)?;
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS company_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL, cursor INTEGER NOT NULL UNIQUE);
             CREATE TABLE IF NOT EXISTS facts (fact_id TEXT PRIMARY KEY, scope TEXT NOT NULL, statement TEXT NOT NULL, event_id TEXT NOT NULL, authority_id TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS authority_registry (authority_id TEXT NOT NULL, scope TEXT NOT NULL, question_kind TEXT NOT NULL, public_key TEXT NOT NULL, status TEXT NOT NULL, signature TEXT NOT NULL, PRIMARY KEY(authority_id, scope, question_kind));
             CREATE TABLE IF NOT EXISTS questions (question_id TEXT PRIMARY KEY, unknown_id TEXT, authority_id TEXT NOT NULL, scope TEXT NOT NULL, question_kind TEXT NOT NULL, question TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, response_due_at TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS answers (answer_id TEXT PRIMARY KEY, question_id TEXT NOT NULL, authority_id TEXT NOT NULL, scope TEXT NOT NULL, answer TEXT NOT NULL, signature TEXT NOT NULL, answered_at TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS unknowns (unknown_id TEXT PRIMARY KEY, scope TEXT NOT NULL, owner_identity TEXT NOT NULL, status TEXT NOT NULL, question TEXT NOT NULL, response_due_at TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, expires_at TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS auth_failures (minute INTEGER PRIMARY KEY, count INTEGER NOT NULL);
             INSERT OR IGNORE INTO company_meta(key, value) VALUES ('cursor', '0');",
        )
        .map_err(sqlite_error)?;
    connection
        .execute(
            "INSERT OR IGNORE INTO company_meta(key, value) VALUES ('company_id', ?1)",
            params![parsed.company_id],
        )
        .map_err(sqlite_error)?;
    ensure_key_file(&parsed.root_key_file)?;
    ensure_token_file(
        &parsed.facts_token_file,
        &["facts:read"],
        &["architecture:company"],
    )?;
    if let Some(directory_token_file) = &parsed.directory_token_file {
        ensure_token_file(directory_token_file, &["directory:read"], &[])?;
    }
    let result = json!({
        "status": "company-initialized",
        "company_id": parsed.company_id,
        "sqlite_path": parsed.sqlite_path.to_string_lossy(),
        "bind": parsed.bind.to_string(),
        "capabilities": ["facts:read", "questions:write", "answers:write"]
    });
    print_value(&result, json);
    Ok(())
}

fn parse_config(config: &Path) -> Result<ServiceConfig, ContractError> {
    let text = std::fs::read_to_string(config).map_err(io_error)?;
    let parsed: toml::Value = text.parse().map_err(|error: toml::de::Error| {
        ContractError::new(
            "CONFIG_INVARIANT",
            error.to_string(),
            "Fix the Company configuration and retry.",
            false,
            ExitCode::Refused,
        )
    })?;
    if parsed.get("schema_version").and_then(toml::Value::as_str) != Some("1") {
        return Err(config_error("schema_version must be 1"));
    }
    let company_id = parsed
        .get("company_id")
        .and_then(toml::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| config_error("company_id is required"))?;
    let sqlite_path = parsed
        .get("sqlite_path")
        .and_then(toml::Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| config_error("sqlite_path is required"))?;
    let bind_text = parsed
        .get("bind")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| config_error("bind is required"))?;
    let bind: SocketAddr = bind_text
        .parse()
        .map_err(|_| config_error("bind must be an IP:port address"))?;
    if !bind.ip().is_loopback() {
        return Err(config_error("bind must be loopback in this proof"));
    }
    let root_key_file = parsed
        .get("root_key_file")
        .and_then(toml::Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| config_error("root_key_file is required"))?;
    let facts_token_file = parsed
        .get("facts_token_file")
        .and_then(toml::Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| config_error("facts_token_file is required"))?;
    let directory_token_file = parsed
        .get("directory_token_file")
        .and_then(toml::Value::as_str)
        .map(PathBuf::from);
    let lifetime = integer_field(&parsed, "candidate_lifetime_seconds", 1)?;
    let skew = integer_field(&parsed, "clock_skew_seconds", 0)?;
    let retention = integer_field(&parsed, "nonce_retention_seconds", lifetime + skew + 1)?;
    if retention <= lifetime + skew {
        return Err(config_error(
            "nonce_retention_seconds must exceed candidate_lifetime_seconds + clock_skew_seconds",
        ));
    }
    let default_fact_freshness_seconds =
        integer_field(&parsed, "default_fact_freshness_seconds", 1)?;
    let auth_failures_per_minute = integer_field(&parsed, "auth_failures_per_minute", 1)?;
    Ok(ServiceConfig {
        company_id: company_id.to_owned(),
        sqlite_path,
        bind,
        root_key_file,
        facts_token_file,
        directory_token_file,
        auth_failures_per_minute,
        default_fact_freshness_seconds,
        candidate_lifetime_seconds: lifetime,
        clock_skew_seconds: skew,
        nonce_retention_seconds: retention,
    })
}

fn integer_field(parsed: &toml::Value, field: &str, minimum: i64) -> Result<i64, ContractError> {
    let value = parsed
        .get(field)
        .and_then(toml::Value::as_integer)
        .ok_or_else(|| config_error(&format!("{field} is required")))?;
    if value < minimum {
        return Err(config_error(&format!("{field} must be at least {minimum}")));
    }
    Ok(value)
}

fn config_error(message: &str) -> ContractError {
    ContractError::new(
        "CONFIG_INVARIANT",
        message.to_owned(),
        "Correct the named Company configuration value; startup changed no state.",
        false,
        ExitCode::Refused,
    )
}

fn ensure_config_mode(path: &Path) -> Result<(), ContractError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .map_err(io_error)?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(config_error("service config must be mode 0600"));
    }
    Ok(())
}

fn ensure_key_file(path: &Path) -> Result<(), ContractError> {
    let public_path = PathBuf::from(format!("{}.pub", path.to_string_lossy()));
    if path.exists() && !public_path.exists() {
        let encoded = std::fs::read_to_string(path).map_err(io_error)?;
        let decoded = BASE64
            .decode(encoded.trim())
            .map_err(|error| config_error(&error.to_string()))?;
        if decoded.len() != 32 {
            return Err(config_error("root private key must contain 32 bytes"));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&decoded);
        let signing_key = SigningKey::from_bytes(&seed);
        write_mode_0600(
            &public_path,
            BASE64
                .encode(signing_key.verifying_key().to_bytes())
                .as_bytes(),
        )?;
    } else if !path.exists() && public_path.exists() {
        return Err(config_error(
            "root public key exists without its private key; never replace trust locally",
        ));
    } else if !path.exists() {
        let signing_key = SigningKey::generate(&mut OsRng);
        write_mode_0600(path, BASE64.encode(signing_key.to_bytes()).as_bytes())?;
        write_mode_0600(
            &public_path,
            BASE64
                .encode(signing_key.verifying_key().to_bytes())
                .as_bytes(),
        )?;
    }
    check_private_mode(path)?;
    Ok(())
}

fn ensure_token_file(
    path: &Path,
    scopes: &[&str],
    authority_scopes: &[&str],
) -> Result<(), ContractError> {
    if !path.exists() {
        let token = json!({
            "token": format!("guildhall_{}", Uuid::new_v4()),
            "scopes": scopes,
            "authority_scopes": authority_scopes,
            "client_public_key": ""
        });
        write_mode_0600(path, canonical_bytes(&token).as_slice())?;
    }
    check_private_mode(path)?;
    Ok(())
}

fn write_mode_0600(path: &Path, bytes: &[u8]) -> Result<(), ContractError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io_error)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)
}

fn check_private_mode(path: &Path) -> Result<(), ContractError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .map_err(io_error)?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(config_error(&format!(
            "{} must be mode 0600",
            path.to_string_lossy()
        )));
    }
    Ok(())
}

pub fn serve(config: &Path, json: bool) -> Result<(), ContractError> {
    ensure_config_mode(config)?;
    let parsed = parse_config(config)?;
    let listener = TcpListener::bind(parsed.bind).map_err(|error| {
        ContractError::new(
            "COMPANY_UNREACHABLE",
            error.to_string(),
            "Free the declared loopback port and retry.",
            true,
            ExitCode::DependencyUnavailable,
        )
    })?;
    let result = json!({"status":"company-serving","bind":parsed.bind.to_string(),"company_id":parsed.company_id});
    print_value(&result, json);
    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            let config = parsed.clone();
            let result = handle_connection(stream, &config);
            if let Err(error) = result {
                let _ = std::fs::write("/tmp/guildhall-last-service-error", error.to_string());
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct TokenRecord {
    token: String,
    scopes: Vec<String>,
    authority_scopes: Vec<String>,
    client_public_key: Option<String>,
}

fn handle_connection(mut stream: TcpStream, config: &ServiceConfig) -> Result<(), ContractError> {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(250)));
    let mut reader = BufReader::new(stream.try_clone().map_err(io_error)?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).map_err(io_error)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let mut host = String::new();
    let mut origin: Option<String> = None;
    let mut content_type: Option<String> = None;
    let mut content_length = 0usize;
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).map_err(io_error)?;
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
        let lower = line.to_lowercase();
        if let Some(value) = lower.strip_prefix("host:") {
            host = value.trim().to_owned();
        } else if lower.starts_with("origin:") {
            origin = Some(line.split(':').nth(1).unwrap_or_default().trim().to_owned());
        } else if let Some(value) = lower.strip_prefix("content-type:") {
            content_type = Some(value.trim().to_owned());
        } else if let Some(value) = lower.strip_prefix("content-length:") {
            content_length = value
                .trim()
                .parse()
                .map_err(|_| config_error("invalid content length"))?;
        }
        headers.push(line);
    }
    if !host_is_loopback(&host) {
        return respond(&mut stream, 403, &json!({"error":"forbidden-host"}));
    }
    if origin.is_some() {
        return respond(&mut stream, 403, &json!({"error":"origin-forbidden"}));
    }
    if method != "GET" && method != "HEAD" {
        if content_type.as_deref() != Some("application/json") {
            return respond(&mut stream, 415, &json!({"error":"json-required"}));
        }
    }
    if content_length > 64 * 1024 {
        return respond(&mut stream, 413, &json!({"error":"request-too-large"}));
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).map_err(io_error)?;
    }
    let route = path.split('?').next().unwrap_or_default().to_owned();
    let parsed_body = if body.is_empty() {
        serde_json::Map::new()
    } else {
        crate::json::parse_strict_object(&body).map_err(|error| {
            ContractError::new(
                "CONFIG_INVARIANT",
                error,
                "Send canonical strict JSON with sorted keys and no floats.",
                false,
                ExitCode::Refused,
            )
        })?
    };
    let mut connection = Connection::open(&config.sqlite_path).map_err(sqlite_error)?;
    if auth_failures_exceeded(&connection, config)? {
        return respond(
            &mut stream,
            429,
            &json!({"error":"authentication-ceiling-exceeded"}),
        );
    }
    let token = bearer_token(&headers).ok_or_else(|| config_error("bearer token required"))?;
    let token_record = read_token_record(&config.facts_token_file)?;
    if !constant_time_equal(token.as_bytes(), token_record.token.as_bytes()) {
        record_auth_failure(&mut connection, config)?;
        return respond(&mut stream, 401, &json!({"error":"unauthorized"}));
    }
    if !verify_request_signature(&headers, &method, &path, &body, &token_record)? {
        record_auth_failure(&mut connection, config)?;
        return respond(
            &mut stream,
            401,
            &json!({"error":"request-signature-invalid"}),
        );
    }
    if !consume_request_nonce(&connection, config, &headers)? {
        record_auth_failure(&mut connection, config)?;
        return respond(&mut stream, 401, &json!({"error":"request-replayed"}));
    }
    let mut status = 200;
    let response = match (method.as_str(), route.as_str()) {
        ("GET", "/status") => {
            require_scope(&token_record, "facts:read")?;
            let cursor: String = connection
                .query_row(
                    "SELECT value FROM company_meta WHERE key='cursor'",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or_else(|_| "0".to_owned());
            json!({
                "status":"ok",
                "company_id":config.company_id,
                "cursor":cursor.parse::<i64>().unwrap_or(0),
                "token_scopes":token_record.scopes,
                "authority_scopes":token_record.authority_scopes
            })
        }
        ("GET", "/facts") => {
            require_scope(&token_record, "facts:read")?;
            let scope = path_scope(&path);
            if !token_record
                .authority_scopes
                .iter()
                .any(|authorized| authorized == &scope)
            {
                return respond(&mut stream, 403, &json!({"error":"authority-scope-denied"}));
            }
            let mut statement = connection
                .prepare(
                    "SELECT fact_id, scope, statement FROM facts WHERE scope = ?1 ORDER BY fact_id",
                )
                .map_err(sqlite_error)?;
            let facts = statement
                .query_map(params![scope], |row| {
                    Ok(json!({"fact_id":row.get::<_,String>(0)?, "scope":row.get::<_,String>(1)?, "statement":row.get::<_,String>(2)?}))
                })
                .map_err(sqlite_error)?
                .collect::<Result<Vec<Value>, _>>()
                .map_err(sqlite_error)?;
            json!({"facts":facts})
        }
        ("POST", "/questions") => {
            require_scope(&token_record, "questions:write")?;
            let scope = required_text(&parsed_body, "scope")?;
            let question_kind = required_text(&parsed_body, "question_kind")?;
            let authority = resolve_registered_authority(&connection, &scope, &question_kind)?;
            let authority_id = authority
                .get("authority_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let supplied_authority = parsed_body
                .get("authority_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !supplied_authority.is_empty() && supplied_authority != authority_id {
                status = 403;
                json!({"error":"authority-wrong-scope"})
            } else {
                let question_id = parsed_body
                    .get("question_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("question_{}", Uuid::new_v4()));
                let unknown_id = parsed_body
                    .get("unknown_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let question = required_text(&parsed_body, "question")?;
                let now = crate::time::now_rfc3339_millis();
                let due = crate::time::format_rfc3339_millis(
                    chrono::Utc::now() + chrono::Duration::hours(24),
                );
                let inserted = connection
                    .execute(
                        "INSERT OR IGNORE INTO questions(question_id, unknown_id, authority_id, scope, question_kind, question, status, created_at, response_due_at) VALUES (?1,?2,?3,?4,?5,?6,'queued',?7,?8)",
                        params![question_id, unknown_id, authority_id, scope, question_kind, question, now, due],
                    )
                    .map_err(sqlite_error)?;
                if inserted == 0 {
                    status = 409;
                    json!({"error":"question-already-exists"})
                } else {
                    json!({"status":"queued", "question_id":question_id, "authority_id":authority_id})
                }
            }
        }
        ("GET", path) if path.starts_with("/questions/") => {
            require_scope(&token_record, "facts:read")?;
            let id = path.trim_start_matches("/questions/");
            let row = connection
                .query_row("SELECT question_id, authority_id, scope, question, status FROM questions WHERE question_id=?1", params![id], |row| {
                    Ok(json!({"question_id":row.get::<_,String>(0)?, "authority_id":row.get::<_,String>(1)?, "scope":row.get::<_,String>(2)?, "question":row.get::<_,String>(3)?, "status":row.get::<_,String>(4)?}))
                })
                .optional()
                .map_err(sqlite_error)?;
            if row.is_none() {
                status = 404;
            }
            row.unwrap_or_else(|| json!({"error":"not-found"}))
        }
        ("POST", "/answers") => {
            require_scope(&token_record, "answers:write")?;
            admit_answer(&mut connection, config, &parsed_body).map(|(answer_status, value)| {
                status = answer_status;
                value
            })?
        }
        _ => json!({"error":"not-found"}),
    };
    if response.get("error").is_some() && status == 200 {
        status = 404;
    }
    respond(&mut stream, status, &response)
}

fn host_is_loopback(host: &str) -> bool {
    let host = host
        .rsplit_once(':')
        .map(|(hostname, _)| hostname)
        .unwrap_or(host);
    host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn bearer_token(headers: &[String]) -> Option<String> {
    headers.iter().find_map(|header| {
        let lower = header.to_lowercase();
        lower
            .strip_prefix("authorization: bearer ")
            .map(|token| token.trim().to_owned())
    })
}

fn read_token_record(path: &Path) -> Result<TokenRecord, ContractError> {
    let bytes = std::fs::read(path).map_err(io_error)?;
    if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
        Ok(TokenRecord {
            token: value
                .get("token")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            scopes: value
                .get("scopes")
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            authority_scopes: value
                .get("authority_scopes")
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            client_public_key: value
                .get("client_public_key")
                .and_then(Value::as_str)
                .map(str::to_owned),
        })
    } else {
        Ok(TokenRecord {
            token: String::from_utf8_lossy(&bytes).trim().to_owned(),
            scopes: vec!["facts:read".to_owned()],
            authority_scopes: Vec::new(),
            client_public_key: None,
        })
    }
}

fn require_scope(token: &TokenRecord, scope: &str) -> Result<(), ContractError> {
    if token.scopes.iter().any(|granted| granted == scope) {
        Ok(())
    } else {
        Err(config_error("token lacks the exact required capability"))
    }
}

fn path_scope(path: &str) -> String {
    path.split_once("?scope=")
        .map(|(_, scope)| scope)
        .unwrap_or_default()
        .to_owned()
}

fn auth_failures_exceeded(
    connection: &Connection,
    config: &ServiceConfig,
) -> Result<bool, ContractError> {
    let minute = chrono::Utc::now().timestamp() / 60;
    let count = connection
        .query_row(
            "SELECT count FROM auth_failures WHERE minute=?1",
            params![minute],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(sqlite_error)?
        .unwrap_or(0);
    Ok(count >= config.auth_failures_per_minute)
}

fn consume_request_nonce(
    connection: &Connection,
    config: &ServiceConfig,
    headers: &[String],
) -> Result<bool, ContractError> {
    let nonce = header_value(headers, "x-guildhall-nonce");
    if nonce.is_empty() {
        return Ok(false);
    }
    let now = chrono::Utc::now();
    connection
        .execute(
            "DELETE FROM nonces WHERE expires_at <= ?1",
            params![now.to_rfc3339()],
        )
        .map_err(sqlite_error)?;
    let expires_at = crate::time::format_rfc3339_millis(
        now + chrono::Duration::seconds(config.nonce_retention_seconds),
    );
    let inserted = connection
        .execute(
            "INSERT OR IGNORE INTO nonces(nonce, expires_at) VALUES (?1, ?2)",
            params![nonce, expires_at],
        )
        .map_err(sqlite_error)?;
    Ok(inserted == 1)
}

fn required_text(body: &Map<String, Value>, field: &str) -> Result<String, ContractError> {
    let value = body
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| config_error(&format!("{field} is required")))?;
    if value.is_empty() {
        return Err(config_error(&format!("{field} must not be empty")));
    }
    Ok(value.to_owned())
}

fn resolve_registered_authority(
    connection: &Connection,
    scope: &str,
    question_kind: &str,
) -> Result<Value, ContractError> {
    let authorities = connection
        .prepare(
            "SELECT authority_id, public_key, status FROM authority_registry
             WHERE scope=?1 AND question_kind=?2 ORDER BY authority_id",
        )
        .map_err(sqlite_error)?
        .query_map(params![scope, question_kind], |row| {
            Ok(json!({
                "authority_id": row.get::<_, String>(0)?,
                "public_key": row.get::<_, String>(1)?,
                "status": row.get::<_, String>(2)?
            }))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<Value>, _>>()
        .map_err(sqlite_error)?;
    let active: Vec<&Value> = authorities
        .iter()
        .filter(|authority| authority.get("status").and_then(Value::as_str) == Some("active"))
        .collect();
    match active.as_slice() {
        [authority] => Ok((*authority).clone()),
        [] => Err(ContractError::new(
            "UNKNOWN_OWNER_UNRESOLVED",
            "no active authority resolves the exact scope and question kind",
            "Ask the Company steward to publish exactly one active authority.",
            false,
            ExitCode::DegradedSafe,
        )),
        _ => Err(ContractError::new(
            "UNKNOWN_OWNER_UNRESOLVED",
            "multiple active authorities resolve the exact scope",
            "Ask the Company steward to resolve the registry conflict.",
            false,
            ExitCode::DegradedSafe,
        )),
    }
}

fn admit_answer(
    connection: &mut Connection,
    config: &ServiceConfig,
    body: &Map<String, Value>,
) -> Result<(u16, Value), ContractError> {
    let question_id = required_text(body, "question_id")?;
    let answer_text = required_text(body, "answer")?;
    let signature = required_text(body, "signature")?;
    if hard_blocked(&answer_text) {
        return Ok((403, json!({"error": "hard-blocked-answer"})));
    }
    let question = connection
        .prepare(
            "SELECT question_id, unknown_id, authority_id, scope, question_kind, question, status
             FROM questions WHERE question_id=?1",
        )
        .map_err(sqlite_error)?
        .query_row(params![question_id], |row| {
            Ok(json!({
                "question_id": row.get::<_, String>(0)?,
                "unknown_id": row.get::<_, Option<String>>(1)?,
                "authority_id": row.get::<_, String>(2)?,
                "scope": row.get::<_, String>(3)?,
                "question_kind": row.get::<_, String>(4)?,
                "question": row.get::<_, String>(5)?,
                "status": row.get::<_, String>(6)?
            }))
        })
        .optional()
        .map_err(sqlite_error)?;
    let Some(question) = question else {
        return Ok((404, json!({"error": "question-not-found"})));
    };
    if question.get("status").and_then(Value::as_str) == Some("answered") {
        return Ok((409, json!({"error": "question-already-answered"})));
    }
    let scope = question
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let question_kind = question
        .get("question_kind")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let authority = resolve_registered_authority(connection, &scope, &question_kind)?;
    let authority_id = authority
        .get("authority_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if question.get("authority_id").and_then(Value::as_str) != Some(&authority_id)
        || body.get("authority_id").and_then(Value::as_str) != Some(&authority_id)
    {
        return Ok((403, json!({"error": "authority-wrong-scope"})));
    }
    let public_key = authority
        .get("public_key")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let decoded_key = BASE64
        .decode(public_key)
        .map_err(|error| config_error(&error.to_string()))?;
    if decoded_key.len() != 32 {
        return Err(config_error("authority public key must contain 32 bytes"));
    }
    let public_path =
        std::env::temp_dir().join(format!("guildhall-authority-{}.pub", Uuid::new_v4()));
    write_mode_0600(&public_path, &decoded_key)?;
    let answer_value = json!({
        "answer": answer_text,
        "authority_id": authority_id,
        "question_id": question_id
    });
    let signed = crate::crypto::verify_message(
        "answer",
        canonical_bytes(&answer_value).as_slice(),
        &signature,
        &public_path,
    );
    let _ = std::fs::remove_file(&public_path);
    if !signed? {
        return Ok((401, json!({"error": "authority-signature-invalid"})));
    }
    let answer_id = format!(
        "answer_{}",
        &sha256_text(&format!("{question_id}\0{answer_text}"))[..24]
    );
    let fact_id = format!(
        "fact_{}",
        &sha256_text(&format!("{scope}\0{answer_text}"))[..24]
    );
    let event_id = format!(
        "event_{}",
        &sha256_text(&format!("{scope}\0{answer_text}\0{answer_id}"))[..24]
    );
    let answered_at = crate::time::now_rfc3339_millis();
    let cursor = advance_cursor(connection)?;
    let transaction = connection.transaction().map_err(sqlite_error)?;
    transaction
        .execute(
            "INSERT INTO answers(answer_id, question_id, authority_id, scope, answer, signature, answered_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                answer_id,
                question_id,
                authority_id,
                scope,
                answer_text,
                signature,
                answered_at
            ],
        )
        .map_err(sqlite_error)?;
    transaction
        .execute(
            "UPDATE questions SET status='answered' WHERE question_id=?1",
            params![question_id],
        )
        .map_err(sqlite_error)?;
    if let Some(unknown_id) = question.get("unknown_id").and_then(Value::as_str) {
        transaction
            .execute(
                "UPDATE unknowns SET status='closed', question=?2 WHERE unknown_id=?1",
                params![unknown_id, question_id],
            )
            .map_err(sqlite_error)?;
    }
    transaction
        .execute(
            "INSERT INTO facts(fact_id, scope, statement, event_id, authority_id)
             VALUES (?1,?2,?3,?4,?5)",
            params![fact_id, scope, answer_text, event_id, authority_id],
        )
        .map_err(sqlite_error)?;
    transaction
        .execute(
            "INSERT INTO events(id, kind, payload, cursor) VALUES (?1,'authority-answer',?2,?3)",
            params![event_id, canonical_text(&answer_value), cursor],
        )
        .map_err(sqlite_error)?;
    transaction.commit().map_err(sqlite_error)?;
    let _ = config;
    Ok((
        201,
        json!({
            "status": "answered",
            "answer_id": answer_id,
            "question_id": question_id,
            "unknown_id": question.get("unknown_id").cloned().unwrap_or(Value::Null),
            "fact_id": fact_id,
            "event_id": event_id,
            "cursor": cursor
        }),
    ))
}

fn advance_cursor(connection: &Connection) -> Result<i64, ContractError> {
    connection
        .query_row(
            "UPDATE company_meta SET value=CAST(value AS INTEGER)+1
             WHERE key='cursor' RETURNING value",
            [],
            |row| {
                row.get::<_, String>(0)
                    .map(|value| value.parse::<i64>().unwrap_or_default())
            },
        )
        .map_err(sqlite_error)
}

fn verify_request_signature(
    headers: &[String],
    method: &str,
    path: &str,
    body: &[u8],
    token: &TokenRecord,
) -> Result<bool, ContractError> {
    let signature = header_value(headers, "x-guildhall-request-signature");
    let nonce = header_value(headers, "x-guildhall-nonce");
    let expires = header_value(headers, "x-guildhall-expires-at");
    let public_key_text = token.client_public_key.as_deref().unwrap_or_default();
    if signature.is_empty() || nonce.is_empty() || expires.is_empty() || public_key_text.is_empty()
    {
        return Ok(false);
    }
    let expires =
        crate::time::parse_rfc3339_millis(&expires).map_err(|error| config_error(&error))?;
    if expires <= chrono::Utc::now() {
        return Ok(false);
    }
    let request = json!({
        "method":method,
        "path":path,
        "body_digest":sha256_bytes(body),
        "nonce":nonce,
        "expires_at":expires
    });
    let decoded = BASE64
        .decode(public_key_text)
        .map_err(|error| config_error(&error.to_string()))?;
    let public_path = std::env::temp_dir().join(format!("guildhall-client-{}.pub", Uuid::new_v4()));
    std::fs::write(&public_path, decoded).map_err(io_error)?;
    let valid = crate::crypto::verify_message(
        "receipt",
        canonical_bytes(&request).as_slice(),
        &signature,
        &public_path,
    )?;
    let _ = std::fs::remove_file(&public_path);
    Ok(valid)
}

fn header_value(headers: &[String], name: &str) -> String {
    headers
        .iter()
        .find_map(|header| {
            let lower = header.to_lowercase();
            lower
                .strip_prefix(&format!("{name}:"))
                .map(|value| value.trim().to_owned())
        })
        .unwrap_or_default()
}

fn record_auth_failure(
    connection: &mut Connection,
    config: &ServiceConfig,
) -> Result<(), ContractError> {
    let _ = config;
    let minute = chrono::Utc::now().timestamp() / 60;
    connection
        .execute(
            "INSERT INTO auth_failures(minute, count) VALUES (?1, 1) ON CONFLICT(minute) DO UPDATE SET count=count+1",
            params![minute],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn respond(stream: &mut TcpStream, status: u16, body: &Value) -> Result<(), ContractError> {
    let body = canonical_bytes(body);
    let reason = if status == 200 { "OK" } else { "Error" };
    write!(stream, "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).map_err(io_error)?;
    stream.write_all(&body).map_err(io_error)?;
    Ok(())
}

fn print_value(value: &Value, json: bool) {
    if json {
        let output = canonical_bytes(value);
        println!("{}", String::from_utf8_lossy(&output));
    } else {
        println!(
            "status: {}",
            value.get("status").and_then(Value::as_str).unwrap_or("ok")
        );
        if let Some(bind) = value.get("bind").and_then(Value::as_str) {
            println!("bind: {bind}");
        }
    }
}

fn sqlite_error(error: rusqlite::Error) -> ContractError {
    ContractError::new(
        "RUN_INTEGRITY_FAILED",
        error.to_string(),
        "Inspect the Company SQLite database and retry.",
        false,
        ExitCode::InternalFailure,
    )
}

fn io_error(error: std::io::Error) -> ContractError {
    ContractError::new(
        "RUN_INTEGRITY_FAILED",
        error.to_string(),
        "Check filesystem permissions and retry.",
        false,
        ExitCode::InternalFailure,
    )
}
