use chrono::{DateTime, SecondsFormat, Utc};

pub fn now_rfc3339_millis() -> String {
    format_rfc3339_millis(Utc::now())
}

pub fn format_rfc3339_millis(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub fn parse_rfc3339_millis(value: &str) -> Result<DateTime<Utc>, String> {
    let parsed = DateTime::parse_from_rfc3339(value).map_err(|error| error.to_string())?;
    if parsed.timestamp_subsec_nanos() % 1_000_000 != 0 {
        return Err("timestamps must use millisecond precision".to_owned());
    }
    Ok(parsed.with_timezone(&Utc))
}

/// Source of an `as_of` value, recorded in every reducer trace so a rebuild
/// can be reproduced from the exact instant that was used.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AsOf {
    pub as_of: String,
    pub as_of_source: String,
}

/// The proof clock: the explicit `GUILDHALL_PROOF_CLOCK` instant when an
/// acceptance run pins one, otherwise the host wall clock at millisecond
/// precision. Callers must record which one they used.
pub fn proof_clock() -> AsOf {
    if let Some(pinned) = std::env::var_os("GUILDHALL_PROOF_CLOCK") {
        let text = pinned.to_string_lossy().trim().to_owned();
        if let Ok(parsed) = parse_rfc3339_millis(&text) {
            return AsOf {
                as_of: format_rfc3339_millis(parsed),
                as_of_source: "proof-clock:GUILDHALL_PROOF_CLOCK".to_owned(),
            };
        }
    }
    AsOf {
        as_of: now_rfc3339_millis(),
        as_of_source: "proof-clock:wall".to_owned(),
    }
}

/// Resolve the reducer instant per Validator ruling R-1: an explicit
/// `--as-of` wins and is validated; otherwise the proof clock is read once
/// and its exact value is recorded.
pub fn resolve_as_of(explicit: Option<&str>) -> Result<AsOf, String> {
    match explicit {
        Some(text) => {
            let parsed = parse_rfc3339_millis(text)?;
            let normalized = format_rfc3339_millis(parsed);
            if normalized != text {
                return Err(format!(
                    "as_of must be RFC 3339 UTC with exactly millisecond precision and a Z suffix: {text}"
                ));
            }
            Ok(AsOf {
                as_of: normalized,
                as_of_source: "explicit:--as-of".to_owned(),
            })
        }
        None => Ok(proof_clock()),
    }
}
