use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use time::OffsetDateTime;

/// Get the current unix timestamp in microseconds
pub fn time_now_us() -> Result<u128> {
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH)?;
    Ok(since_the_epoch.as_micros())
}

/// Get the current date and time in UTC
pub fn time_now_utc() -> String {
    let time_now = OffsetDateTime::now_utc();
    time_now.to_string()
}
