//! RFC 3339 UTC millisecond times (architecture §3) and the proof clock.

use chrono::{DateTime, Duration, SecondsFormat, Utc};

pub fn now_utc() -> DateTime<Utc> {
    proof_clock_instant()
}

pub fn now_rfc3339_millis() -> String {
    format_rfc3339_millis(now_utc())
}

pub fn format_rfc3339_millis(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Strict parse: exactly millisecond precision, `Z` suffix, UTC.
pub fn parse_rfc3339_millis(value: &str) -> Result<DateTime<Utc>, String> {
    let parsed = DateTime::parse_from_rfc3339(value).map_err(|error| error.to_string())?;
    if parsed.timestamp_subsec_nanos() % 1_000_000 != 0 {
        return Err("timestamps must use millisecond precision".to_owned());
    }
    let utc = parsed.with_timezone(&Utc);
    if format_rfc3339_millis(utc) != value {
        return Err(format!(
            "timestamps must be RFC 3339 UTC with exactly millisecond precision and a Z suffix: {value}"
        ));
    }
    Ok(utc)
}

/// Lenient parse for foreign source metadata (host transcripts, GitHub
/// exports): any RFC 3339 offset, any sub-second precision, normalized to
/// the canonical millisecond form.
pub fn normalize_foreign_time(value: &str) -> Option<String> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|parsed| format_rfc3339_millis(parsed.with_timezone(&Utc)))
}

pub fn plus_seconds(value: &str, seconds: i64) -> Result<String, String> {
    let parsed = parse_rfc3339_millis(value)?;
    Ok(format_rfc3339_millis(parsed + Duration::seconds(seconds)))
}

/// Source of an `as_of` value, recorded in every reducer trace so a rebuild
/// can be reproduced from the exact instant that was used.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AsOf {
    pub as_of: String,
    pub as_of_source: String,
}

impl AsOf {
    pub fn explicit(value: &str) -> Result<Self, String> {
        resolve_as_of(Some(value))
    }
}

/// `GUILDHALL_PROOF_CLOCK_OFFSET_SECONDS` advances the proof clock by a
/// signed integer number of seconds for one invocation (interface contract
/// §0); it is recorded in every `as_of_source`.
fn clock_offset_seconds() -> i64 {
    std::env::var("GUILDHALL_PROOF_CLOCK_OFFSET_SECONDS")
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok())
        .unwrap_or(0)
}

fn proof_clock_instant() -> DateTime<Utc> {
    let base = if let Some(pinned) = std::env::var_os("GUILDHALL_PROOF_CLOCK") {
        parse_rfc3339_millis(pinned.to_string_lossy().trim()).unwrap_or_else(|_| Utc::now())
    } else {
        Utc::now()
    };
    let shifted = base + Duration::seconds(clock_offset_seconds());
    DateTime::from_timestamp_millis(shifted.timestamp_millis()).unwrap_or(shifted)
}

/// The proof clock: the explicit `GUILDHALL_PROOF_CLOCK` instant when an
/// acceptance run pins one, otherwise the host wall clock at millisecond
/// precision. Callers must record which one they used.
pub fn proof_clock() -> AsOf {
    let offset = clock_offset_seconds();
    let pinned = std::env::var_os("GUILDHALL_PROOF_CLOCK")
        .map(|value| parse_rfc3339_millis(value.to_string_lossy().trim()).is_ok())
        .unwrap_or(false);
    let source = match (pinned, offset) {
        (true, 0) => "proof-clock:GUILDHALL_PROOF_CLOCK".to_owned(),
        (true, offset) => format!("proof-clock:GUILDHALL_PROOF_CLOCK+{offset}s"),
        (false, 0) => "proof-clock:wall".to_owned(),
        (false, offset) => format!("proof-clock:wall+{offset}s"),
    };
    AsOf {
        as_of: format_rfc3339_millis(proof_clock_instant()),
        as_of_source: source,
    }
}

/// Resolve the reducer instant per Validator ruling R-1: an explicit
/// `--as-of` wins and is validated; otherwise the proof clock is read once
/// and its exact value is recorded.
pub fn resolve_as_of(explicit: Option<&str>) -> Result<AsOf, String> {
    match explicit {
        Some(text) => {
            let parsed = parse_rfc3339_millis(text)?;
            Ok(AsOf {
                as_of: format_rfc3339_millis(parsed),
                as_of_source: "explicit:--as-of".to_owned(),
            })
        }
        None => Ok(proof_clock()),
    }
}

/// Seconds between two canonical instants (`later - earlier`).
pub fn seconds_between(earlier: &str, later: &str) -> Result<i64, String> {
    let earlier = parse_rfc3339_millis(earlier)?;
    let later = parse_rfc3339_millis(later)?;
    Ok(later.signed_duration_since(earlier).num_seconds())
}

/// Receipt-time skew (R-14). Returns the direction and signed second offset
/// only when a receipt claim is more than five minutes from the proof clock.
/// Historical claims are never passed to this function.
pub fn receipt_clock_skew(claim: &str, proof_clock: &str) -> Option<(&'static str, i64)> {
    let Ok(claim) = parse_rfc3339_millis(claim) else {
        return None;
    };
    let Ok(proof) = parse_rfc3339_millis(proof_clock) else {
        return None;
    };
    let seconds = claim.signed_duration_since(proof).num_seconds();
    if seconds.abs() <= 300 {
        return None;
    }
    Some((if seconds > 0 { "ahead" } else { "behind" }, seconds))
}
