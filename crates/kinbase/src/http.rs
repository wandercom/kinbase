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
/// The longest request line accepted: a 2048-byte path plus method and
/// version.
pub const MAX_REQUEST_LINE_BYTES: usize = 2048 + 64;
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

/// One line of at most `limit` bytes. The bound applies while reading: an
/// unbounded `read_line` buffered whatever a client sent before any limit
/// was checked. `Ok(None)` is end of stream; a line over the bound, or one
/// that is not UTF-8, is `Err(true)` and `Err(false)` respectively.
fn read_bounded_line(
    reader: &mut BufReader<&TcpStream>,
    limit: usize,
) -> Result<Option<String>, bool> {
    let mut bytes = Vec::new();
    let read = reader
        .by_ref()
        .take(limit as u64 + 1)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| false)?;
    if read == 0 {
        return Ok(None);
    }
    if bytes.len() > limit {
        return Err(true);
    }
    String::from_utf8(bytes).map(Some).map_err(|_| false)
}

fn headers_too_large() -> ReadError {
    ReadError::Bad(
        431,
        ContractError::limit(
            "request headers exceed the 16 KiB bound",
            serde_json::json!({"refused_count": 1, "omitted_count": 1}),
        ),
    )
}

/// Parse one request from a stream with bounded headers and body.
pub fn read_request(stream: &TcpStream, body_limit: usize) -> Result<Request, ReadError> {
    let peer = stream.peer_addr().ok();
    let mut reader = BufReader::new(stream);
    let mut total = 0usize;
    let request_line = match read_bounded_line(&mut reader, MAX_REQUEST_LINE_BYTES) {
        Ok(Some(line)) => line,
        Ok(None) => return Err(ReadError::Empty),
        Err(true) => {
            return Err(ReadError::Bad(
                414,
                ContractError::invariant("request line exceeds the 2 KiB bound"),
            ));
        }
        Err(false) => return Err(ReadError::Empty),
    };
    total += request_line.len();
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
        return Err(ReadError::Bad(
            400,
            ContractError::invariant("malformed request path"),
        ));
    }
    let mut headers = Vec::new();
    loop {
        let line = match read_bounded_line(&mut reader, MAX_HEADER_BYTES.saturating_sub(total)) {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(true) => return Err(headers_too_large()),
            Err(false) => {
                return Err(ReadError::Bad(
                    400,
                    ContractError::invariant("unreadable request headers"),
                ));
            }
        };
        total += line.len();
        if total > MAX_HEADER_BYTES {
            return Err(headers_too_large());
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            return Err(ReadError::Bad(
                400,
                ContractError::invariant("malformed header line"),
            ));
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
    if headers.iter().any(|(name, value)| {
        name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked")
    }) {
        return Err(ReadError::Bad(
            411,
            ContractError::invariant("chunked bodies are not accepted; send content-length"),
        ));
    }
    if content_length > body_limit {
        return Err(ReadError::Bad(
            413,
            ContractError::limit(
                format!("request body exceeds the {body_limit}-byte bound"),
                serde_json::json!({"refused_count": 1, "omitted_count": 1, "bytes": content_length, "ceiling_bytes": body_limit}),
            ),
        ));
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).map_err(|_| {
            ReadError::Bad(
                400,
                ContractError::invariant("request body shorter than content-length"),
            )
        })?;
    }
    let (route, query_text) = path
        .split_once('?')
        .map(|(r, q)| (r.to_owned(), q.to_owned()))
        .unwrap_or((path.clone(), String::new()));
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
        let truncated = crate::error::ContractError::internal(
            "error body exceeded the 4096-byte bound and was replaced",
        );
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

/// Cut `text` to at most `limit` bytes without splitting a character;
/// `String::truncate` panics inside one, and messages carry client text.
fn truncate_on_char_boundary(text: &mut String, limit: usize) {
    if text.len() > limit {
        let cut = (0..=limit)
            .rev()
            .find(|index| text.is_char_boundary(*index))
            .unwrap_or(0);
        text.truncate(cut);
    }
}

pub fn error_body(error: &ContractError) -> Value {
    let mut compact = error.clone();
    truncate_on_char_boundary(&mut compact.message, 1024);
    truncate_on_char_boundary(&mut compact.remediation, 1024);
    // Structured detail is privacy-minimized by construction (counts, ids,
    // dispositions, digests); it stays in the body only while it is small,
    // so refusals such as a ceiling stop or a CLOCK_SKEW quarantine remain
    // typed for the caller inside the 4096-byte bound.
    let small_detail = compact
        .detail
        .as_ref()
        .filter(|detail| detail.is_object() && crate::json::canonical_bytes(detail).len() <= 1024)
        .cloned();
    compact.detail = small_detail;
    serde_json::json!({"error": compact})
}

/// Parse `http://host:port/base` into a socket address and base path.
pub fn parse_url(url: &str) -> Result<(String, u16, String), ContractError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| ContractError::invariant("Company URL must use http:// over loopback"))?;
    let (authority, path) = rest
        .split_once('/')
        .map(|(a, p)| (a, format!("/{p}")))
        .unwrap_or((rest, String::new()));
    let (host, port) = authority.rsplit_once(':').unwrap_or((authority, "80"));
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port
        .parse()
        .map_err(|_| ContractError::invariant("Company URL port is not a number"))?;
    let loopback = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if !loopback {
        return Err(ContractError::invariant(
            "Company URL must name a loopback host",
        ));
    }
    let host = if host == "localhost" {
        "127.0.0.1".to_owned()
    } else {
        host.to_owned()
    };
    Ok((host, port, path.trim_end_matches('/').to_owned()))
}

pub struct Response {
    pub status: u16,
    pub body: Value,
    pub raw: Vec<u8>,
}

/// The host-start probe gives up 50 ms before the connection budget so that
/// the measured attempt, and the response carrying it, land inside 250 ms.
pub const PROBE_BUDGET: Duration = Duration::from_millis(200);

/// Probe only the connection budget: does the endpoint accept a TCP
/// connection within the probe budget? Nothing is sent; the socket closes
/// at once.
pub fn probe_connect(host: &str, port: u16) -> Result<(), ContractError> {
    let address = (host, port)
        .to_socket_addrs()
        .map_err(|error| {
            ContractError::unreachable(format!("Company endpoint does not resolve ({error})"))
        })?
        .next()
        .ok_or_else(|| ContractError::unreachable("Company endpoint does not resolve"))?;
    TcpStream::connect_timeout(&address, PROBE_BUDGET)
        .map(|_stream| ())
        .map_err(|error| {
            ContractError::unreachable(format!(
                "Company endpoint did not accept a connection within the 250 ms budget ({})",
                error.kind()
            ))
        })
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
        .map_err(|error| {
            ContractError::unreachable(format!("Company endpoint does not resolve ({error})"))
        })?
        .next()
        .ok_or_else(|| ContractError::unreachable("Company endpoint does not resolve"))?;
    let mut stream = TcpStream::connect_timeout(&address, CONNECT_BUDGET).map_err(|error| {
        ContractError::unreachable(format!(
            "Company endpoint did not accept a connection within 250 ms ({})",
            error.kind()
        ))
    })?;
    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(|error| ContractError::io("read timeout", error))?;
    stream
        .set_write_timeout(Some(read_timeout))
        .map_err(|error| ContractError::io("write timeout", error))?;
    let _ = stream.set_nodelay(true);
    let mut text = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
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
        .map_err(|error| {
            ContractError::unreachable(format!(
                "Company endpoint refused the request bytes ({})",
                error.kind()
            ))
        })?;
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).map_err(|error| {
        ContractError::unreachable(format!(
            "Company endpoint did not answer within the read budget ({})",
            error.kind()
        ))
        .with_detail(serde_json::json!({
            "timeout_observed": true,
            "omitted_count": 1
        }))
    })?;
    if status_line.is_empty() {
        return Err(ContractError::unreachable(
            "Company endpoint closed the connection without a response",
        ));
    }
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| {
            ContractError::unreachable("Company endpoint answered with a malformed status line")
        })?;
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).map_err(|error| {
            ContractError::unreachable(format!(
                "Company endpoint headers unreadable ({})",
                error.kind()
            ))
        })?;
        if read == 0 || line.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }
    // A repository's snapshot carries every fact that governs it plus the
    // versions and traces behind them; a 390-fact repository is 1.1 MB, and a
    // ceiling that refuses it silently withholds the repository's own
    // direction. Responses are signed and verified after this bound, so the
    // bound only protects memory.
    if content_length > MAX_BODY_BYTES * 32 {
        return Err(ContractError::limit(
            "Company response exceeds the bounded body size",
            serde_json::json!({"refused_count": 1, "omitted_count": 1, "bytes": content_length}),
        ));
    }
    let mut raw = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut raw).map_err(|error| {
            ContractError::unreachable(format!("Company response truncated ({})", error.kind()))
        })?;
    }
    let body = if raw.is_empty() {
        Value::Null
    } else {
        crate::json::parse_strict_value(&raw)
            .unwrap_or_else(|_| serde_json::from_slice(&raw).unwrap_or(Value::Null))
    };
    Ok(Response { status, body, raw })
}

#[cfg(test)]
mod error_body_tests {
    use super::*;

    #[test]
    fn a_long_multibyte_message_is_cut_on_a_character_boundary() {
        let message = format!("digest algorithm {}", "\u{e9}".repeat(550));
        assert!(!message.is_char_boundary(1024));
        let error = ContractError::refused("CONFIG_INVARIANT", message, "\u{e9}".repeat(600));
        let body = error_body(&error);
        let text = body["error"]["message"].as_str().expect("message");
        assert!(text.len() <= 1024);
        assert!(text.starts_with("digest algorithm "));
        assert!(
            body["error"]["remediation"]
                .as_str()
                .expect("remediation")
                .len()
                <= 1024
        );
    }
}

#[cfg(test)]
mod request_bound_tests {
    use super::*;
    use std::net::TcpListener;

    fn read_sent(bytes: Vec<u8>) -> Result<Request, ReadError> {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let writer = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(address).expect("connect");
            // The server stops reading at the bound; a refused write is fine.
            let _ = stream.write_all(&bytes);
        });
        let (stream, _) = listener.accept().expect("accept");
        let result = read_request(&stream, MAX_BODY_BYTES);
        drop(stream);
        let _ = writer.join();
        result
    }

    #[test]
    fn an_overlong_request_line_is_refused_at_the_bound() {
        let mut bytes = b"GET /".to_vec();
        bytes.extend(std::iter::repeat_n(b'a', 4 * 1024 * 1024));
        match read_sent(bytes) {
            Err(ReadError::Bad(status, _)) => assert_eq!(status, 414),
            other => panic!("expected 414, got {other:?}"),
        }
    }

    #[test]
    fn an_overlong_header_line_is_refused_at_the_bound() {
        let mut bytes = b"GET / HTTP/1.1\r\nX-Long: ".to_vec();
        bytes.extend(std::iter::repeat_n(b'b', 4 * 1024 * 1024));
        match read_sent(bytes) {
            Err(ReadError::Bad(status, _)) => assert_eq!(status, 431),
            other => panic!("expected 431, got {other:?}"),
        }
    }

    #[test]
    fn an_ordinary_request_still_parses() {
        let request = read_sent(
            b"POST /facts?x=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        )
        .expect("request");
        assert_eq!(request.method, "POST");
        assert_eq!(request.body, b"{}");
        assert_eq!(request.header("host"), Some("127.0.0.1"));
    }
}
