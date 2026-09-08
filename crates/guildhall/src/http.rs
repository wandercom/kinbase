//! Minimal bounded HTTP/1.1 over loopback TCP: request parsing with hard
//! limits, typed JSON responses, and a client with an explicit connection
//! budget (architecture §9: 250 ms connect budget; §12: loopback only).

use crate::error::ContractError;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

pub const MAX_HEADER_BYTES: usize = 16 * 1024;
pub const MAX_BODY_BYTES: usize = 256 * 1024;
pub const MAX_ERROR_BODY_BYTES: usize = 4096;
pub const CONNECT_BUDGET: Duration = Duration::from_millis(250);

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub route: String,
    pub query: BTreeMap<String, String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub peer: Option<SocketAddr>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(key, _)| *key == lower)
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Debug)]
pub enum ReadError {
    /// The connection produced no request line at all (client closed).
    Empty,
    /// A malformed or oversized request; answer with the status and error.
    Bad(u16, ContractError),
}

/// Parse one request from a stream with bounded headers and body.
pub fn read_request(stream: &TcpStream, body_limit: usize) -> Result<Request, ReadError> {
    let peer = stream.peer_addr().ok();
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    let mut total = 0usize;
    match reader.read_line(&mut request_line) {
        Ok(0) => return Err(ReadError::Empty),
        Ok(n) => total += n,
        Err(_) => return Err(ReadError::Empty),
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let version = parts.next().unwrap_or_default();
    if method.is_empty() || path.is_empty() || !version.starts_with("HTTP/1.") {
        return Err(ReadError::Bad(
            400,
            ContractError::invariant("malformed HTTP request line"),
        ));
    }
    if !path.starts_with('/') || path.len() > 2048 {
        return Err(ReadError::Bad(400, ContractError::invariant("malformed request path")));
    }
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => {
                return Err(ReadError::Bad(400, ContractError::invariant("unreadable request headers")));
            }
        }
        if total > MAX_HEADER_BYTES {
            return Err(ReadError::Bad(
                431,
                ContractError::limit("request headers exceed the 16 KiB bound", serde_json::json!({"refused_count": 1})),
            ));
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            return Err(ReadError::Bad(400, ContractError::invariant("malformed header line")));
        };
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    let content_length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .map(|(_, value)| value.parse::<usize>())
        .transpose()
        .map_err(|_| ReadError::Bad(400, ContractError::invariant("malformed content-length")))?
        .unwrap_or(0);
    if headers.iter().any(|(name, value)| name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked")) {
        return Err(ReadError::Bad(411, ContractError::invariant("chunked bodies are not accepted; send content-length")));
    }
    if content_length > body_limit {
        return Err(ReadError::Bad(
            413,
            ContractError::limit(
                format!("request body exceeds the {body_limit}-byte bound"),
                serde_json::json!({"refused_count": 1, "bytes": content_length, "ceiling_bytes": body_limit}),
            ),
        ));
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader
            .read_exact(&mut body)
            .map_err(|_| ReadError::Bad(400, ContractError::invariant("request body shorter than content-length")))?;
    }
    let (route, query_text) = path.split_once('?').map(|(r, q)| (r.to_owned(), q.to_owned())).unwrap_or((path.clone(), String::new()));
    let mut query = BTreeMap::new();
    for pair in query_text.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        query.insert(percent_decode(key), percent_decode(value));
    }
    Ok(Request {
        method,
        path,
        route,
        query,
        headers,
        body,
        peer,
    })
}

pub fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if let Some(slice) = bytes.get(index + 1..index + 3) {
                if let Some(value) = std::str::from_utf8(slice)
                    .ok()
                    .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                {
                    out.push(value);
                    index += 3;
                    continue;
                }
            }
        }
        if bytes[index] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[index]);
        }
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Response",
    }
}

/// Write one bounded JSON response and close. Error bodies are capped at
/// 4096 bytes by construction (message/remediation truncated).
pub fn respond(stream: &mut TcpStream, status: u16, body: &Value) -> std::io::Result<()> {
    let mut bytes = crate::json::try_canonical_bytes(body)
        .unwrap_or_else(|_| b"{\"error\":{\"code\":\"RUN_INTEGRITY_FAILED\",\"message\":\"response serialization failed\",\"remediation\":\"Preserve evidence.\",\"retryable\":false,\"evidence_id\":\"err_serialize\"}}".to_vec());
    if status >= 400 && bytes.len() > MAX_ERROR_BODY_BYTES {
        let truncated = crate::error::ContractError::internal("error body exceeded the 4096-byte bound and was replaced");
        bytes = crate::json::canonical_bytes(&serde_json::json!({"error": truncated}));
    }
    let head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        reason(status),
        bytes.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()
}

pub fn error_body(error: &ContractError) -> Value {
    let mut compact = error.clone();
    if compact.message.len() > 1024 {
        compact.message.truncate(1024);
    }
    if compact.remediation.len() > 1024 {
        compact.remediation.truncate(1024);
    }
    compact.detail = None;
    serde_json::json!({"error": compact})
}

/// Parse `http://host:port/base` into a socket address and base path.
pub fn parse_url(url: &str) -> Result<(String, u16, String), ContractError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| ContractError::invariant("Company URL must use http:// over loopback"))?;
    let (authority, path) = rest.split_once('/').map(|(a, p)| (a, format!("/{p}"))).unwrap_or((rest, String::new()));
    let (host, port) = authority.rsplit_once(':').unwrap_or((authority, "80"));
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port.parse().map_err(|_| ContractError::invariant("Company URL port is not a number"))?;
    let loopback = host == "localhost" || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback());
    if !loopback {
        return Err(ContractError::invariant("Company URL must name a loopback host"));
    }
    let host = if host == "localhost" { "127.0.0.1".to_owned() } else { host.to_owned() };
    Ok((host, port, path.trim_end_matches('/').to_owned()))
}

pub struct Response {
    pub status: u16,
    pub body: Value,
    pub raw: Vec<u8>,
}

/// One client request with the 250 ms connection budget and bounded
/// read/write timeouts. Any failure to connect or answer within budget is
/// `COMPANY_UNREACHABLE`.
pub fn request(
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
    read_timeout: Duration,
) -> Result<Response, ContractError> {
    let address = (host, port)
        .to_socket_addrs()
        .map_err(|error| ContractError::unreachable(format!("Company endpoint does not resolve ({error})")))?
        .next()
        .ok_or_else(|| ContractError::unreachable("Company endpoint does not resolve"))?;
    let mut stream = TcpStream::connect_timeout(&address, CONNECT_BUDGET)
        .map_err(|error| ContractError::unreachable(format!("Company endpoint did not accept a connection within 250 ms ({})", error.kind())))?;
    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(|error| ContractError::io("read timeout", error))?;
    stream
        .set_write_timeout(Some(read_timeout))
        .map_err(|error| ContractError::io("write timeout", error))?;
    let _ = stream.set_nodelay(true);
    let mut text = format!("{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
    if !body.is_empty() {
        text.push_str("Content-Type: application/json\r\n");
    }
    for (name, value) in headers {
        text.push_str(name);
        text.push_str(": ");
        text.push_str(value);
        text.push_str("\r\n");
    }
    text.push_str("\r\n");
    stream
        .write_all(text.as_bytes())
        .and_then(|_| stream.write_all(body))
        .map_err(|error| ContractError::unreachable(format!("Company endpoint refused the request bytes ({})", error.kind())))?;
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .map_err(|error| ContractError::unreachable(format!("Company endpoint did not answer within the read budget ({})", error.kind())))?;
    if status_line.is_empty() {
        return Err(ContractError::unreachable("Company endpoint closed the connection without a response"));
    }
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| ContractError::unreachable("Company endpoint answered with a malformed status line"))?;
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .map_err(|error| ContractError::unreachable(format!("Company endpoint headers unreadable ({})", error.kind())))?;
        if read == 0 || line.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }
    if content_length > MAX_BODY_BYTES * 4 {
        return Err(ContractError::limit(
            "Company response exceeds the bounded body size",
            serde_json::json!({"refused_count": 1, "bytes": content_length}),
        ));
    }
    let mut raw = vec![0u8; content_length];
    if content_length > 0 {
        reader
            .read_exact(&mut raw)
            .map_err(|error| ContractError::unreachable(format!("Company response truncated ({})", error.kind())))?;
    }
    let body = if raw.is_empty() {
        Value::Null
    } else {
        crate::json::parse_strict_value(&raw).unwrap_or_else(|_| serde_json::from_slice(&raw).unwrap_or(Value::Null))
    };
    Ok(Response { status, body, raw })
}
