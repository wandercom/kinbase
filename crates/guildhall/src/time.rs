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
