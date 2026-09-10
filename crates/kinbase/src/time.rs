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
        let parsed = parse_rfc3339_millis(value)?;
        Ok(Self {
            as_of: format_rfc3339_millis(parsed),
            as_of_source: "explicit:--as-of".to_owned(),
        })
    }

    /// Replay a proof-clock value that was persisted at repository creation,
    /// advanced by this invocation's `KINBASE_PROOF_CLOCK_OFFSET_SECONDS`
    /// (interface contract §0, ruling R-14: the offset applies to the proof
    /// clock every command compares against).
    pub fn recorded(value: &str) -> Result<Self, String> {
        let parsed = parse_rfc3339_millis(value)?;
        let offset = clock_offset_seconds();
        Ok(Self {
            as_of: format_rfc3339_millis(parsed + Duration::seconds(offset)),
            as_of_source: if offset == 0 {
                "recorded-proof-clock".to_owned()
            } else {
                format!("recorded-proof-clock+{offset}s")
            },
        })
    }
}

/// Advance a recorded proof-clock instant by this invocation's offset.
pub fn recorded_with_offset(value: &str) -> Result<String, String> {
    let parsed = parse_rfc3339_millis(value)?;
    Ok(format_rfc3339_millis(
        parsed + Duration::seconds(clock_offset_seconds()),
    ))
}

/// `KINBASE_PROOF_CLOCK_OFFSET_SECONDS` advances the proof clock by a
/// signed integer number of seconds for one invocation (interface contract
/// §0); it is recorded in every `as_of_source`.
fn clock_offset_seconds() -> i64 {
    std::env::var("KINBASE_PROOF_CLOCK_OFFSET_SECONDS")
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok())
        .unwrap_or(0)
}

fn proof_clock_instant() -> DateTime<Utc> {
    let base = if let Some(pinned) = std::env::var_os("KINBASE_PROOF_CLOCK") {
        parse_rfc3339_millis(pinned.to_string_lossy().trim()).unwrap_or_else(|_| Utc::now())
    } else {
        Utc::now()
    };
    let shifted = base + Duration::seconds(clock_offset_seconds());
    DateTime::from_timestamp_millis(shifted.timestamp_millis()).unwrap_or(shifted)
}

/// The proof clock: the explicit `KINBASE_PROOF_CLOCK` instant when an
/// acceptance run pins one, otherwise the host wall clock at millisecond
/// precision. Callers must record which one they used.
pub fn proof_clock() -> AsOf {
    let offset = clock_offset_seconds();
    let pinned = std::env::var_os("KINBASE_PROOF_CLOCK")
        .map(|value| parse_rfc3339_millis(value.to_string_lossy().trim()).is_ok())
        .unwrap_or(false);
    let source = match (pinned, offset) {
        (true, 0) => "proof-clock:KINBASE_PROOF_CLOCK".to_owned(),
        (true, offset) => format!("proof-clock:KINBASE_PROOF_CLOCK+{offset}s"),
        (false, 0) => "proof-clock:wall".to_owned(),
        (false, offset) => format!("proof-clock:wall+{offset}s"),
    };
    AsOf {
        as_of: format_rfc3339_millis(proof_clock_instant()),
        as_of_source: source,
    }
}

/// Resolve an explicit reducer instant. Ambient wall-clock reads are never
/// permitted here.
pub fn resolve_as_of(explicit: Option<&str>) -> Result<AsOf, String> {
    let Some(text) = explicit else {
        return Err("no recorded proof clock is available; pass --as-of".to_owned());
    };
    AsOf::explicit(text)
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
    let (ahead_bound, behind_bound) = receipt_skew_bounds();
    if seconds > ahead_bound {
        return Some(("ahead", seconds));
    }
    if seconds < -behind_bound {
        return Some(("behind", seconds));
    }
    None
}

/// How far a receipt claim may lead or trail the proof clock before it is
/// quarantined (architecture §6, ruling R-14: five minutes either way).
///
/// The bound is widened by this invocation's own declared proof-clock advance.
/// `KINBASE_PROOF_CLOCK_OFFSET_SECONDS` is a perturbation the *receiver*
/// applies to simulate elapsed time; evidence collected before that advance is
/// older, not skewed, and the receiver never charges its own simulated time
/// travel to the source's clock. With no offset the bound is exactly the
/// ratified five minutes in both directions, so a genuinely skewed receipt
/// still quarantines.
fn receipt_skew_bounds() -> (i64, i64) {
    let simulated = clock_offset_seconds();
    (
        RECEIPT_SKEW_SECONDS + simulated.min(0).saturating_neg(),
        RECEIPT_SKEW_SECONDS + simulated.max(0),
    )
}

/// The ratified five-minute receipt-time bound.
pub const RECEIPT_SKEW_SECONDS: i64 = 300;
