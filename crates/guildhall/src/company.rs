use crate::error::ContractError;
use std::path::Path;

pub fn init(config: &Path, json: bool) -> Result<(), ContractError> {
    let text = std::fs::read_to_string(config).map_err(|error| {
        ContractError::new(
            "CONFIG_INVARIANT",
            error.to_string(),
            "Fix the Company configuration and retry.",
            false,
            crate::error::ExitCode::Refused,
        )
    })?;
    let parsed: toml::Value = text
        .parse::<toml::Value>()
        .map_err(|error: toml::de::Error| {
            ContractError::new(
                "CONFIG_INVARIANT",
                error.to_string(),
                "Fix the Company configuration and retry.",
                false,
                crate::error::ExitCode::Refused,
            )
        })?;
    let sqlite_path = parsed
        .get("sqlite_path")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            ContractError::new(
                "CONFIG_INVARIANT",
                "sqlite_path is required",
                "Add a writable SQLite path.",
                false,
                crate::error::ExitCode::Refused,
            )
        })?;
    if let Some(parent) = std::path::Path::new(sqlite_path).parent() {
        std::fs::create_dir_all(parent).map_err(|error: std::io::Error| {
            io_error(std::io::Error::new(
                std::io::ErrorKind::Other,
                error.to_string(),
            ))
        })?;
    }
    let connection =
        rusqlite::Connection::open(sqlite_path).map_err(|error: rusqlite::Error| {
            io_error(std::io::Error::new(
                std::io::ErrorKind::Other,
                error.to_string(),
            ))
        })?;
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS facts (id TEXT PRIMARY KEY, scope TEXT NOT NULL, statement TEXT NOT NULL, signature TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS questions (id TEXT PRIMARY KEY, question TEXT NOT NULL, owner TEXT NOT NULL, status TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS answers (id TEXT PRIMARY KEY, question_id TEXT NOT NULL, answer TEXT NOT NULL, signature TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS unknowns (id TEXT PRIMARY KEY, question_id TEXT NOT NULL, status TEXT NOT NULL);",
    ).map_err(|error: rusqlite::Error| io_error(std::io::Error::new(std::io::ErrorKind::Other, error.to_string())))?;
    println!(
        "{}",
        serde_json::to_string(
            &serde_json::json!({"status":"company-initialized","sqlite_path":sqlite_path})
        )
        .unwrap_or_default()
    );
    if !json {
        println!("Company initialized");
    }
    Ok(())
}

pub fn serve(config: &Path, json: bool) -> Result<(), ContractError> {
    let text = std::fs::read_to_string(config).map_err(|error| {
        ContractError::new(
            "CONFIG_INVARIANT",
            error.to_string(),
            "Fix the Company configuration and retry.",
            false,
            crate::error::ExitCode::Refused,
        )
    })?;
    let parsed: toml::Value = text
        .parse::<toml::Value>()
        .map_err(|error: toml::de::Error| {
            ContractError::new(
                "CONFIG_INVARIANT",
                error.to_string(),
                "Fix the Company configuration and retry.",
                false,
                crate::error::ExitCode::Refused,
            )
        })?;
    let bind = parsed
        .get("bind")
        .and_then(|value| value.as_str())
        .unwrap_or("127.0.0.1:8421")
        .to_owned();
    let listener = std::net::TcpListener::bind(&bind).map_err(|error: std::io::Error| {
        ContractError::new(
            "COMPANY_UNREACHABLE",
            error.to_string(),
            "Free the declared loopback port and retry.",
            true,
            crate::error::ExitCode::DependencyUnavailable,
        )
    })?;
    if json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({"status":"company-serving","bind":bind}))
                .unwrap_or_default()
        );
    } else {
        println!("Company listening on {bind}");
    }
    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let mut request = [0u8; 4096];
            let read = std::io::Read::read(&mut stream, &mut request).unwrap_or(0);
            let request_text = String::from_utf8_lossy(&request[..read]).to_string();
            let path = request_text.split(' ').nth(1).unwrap_or("/");
            let response = if path == "/status" {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{{\"status\":\"ok\"}}",
                    15
                )
            } else {
                format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{{\"error\":\"not found\"}}",
                    23
                )
            };
            let _ = std::io::Write::write_all(&mut stream, response.as_bytes());
        }
    }
    Ok(())
}

fn io_error(error: std::io::Error) -> ContractError {
    ContractError::new(
        "RUN_INTEGRITY_FAILED",
        error.to_string(),
        "Check filesystem permissions and retry.",
        false,
        crate::error::ExitCode::InternalFailure,
    )
}
