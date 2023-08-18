use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use time::OffsetDateTime;

/// Get the current unix timestamp in microseconds
pub fn time_now_us() -> Result<u128> {
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH)?;
    Ok(since_the_epoch.as_micros())
}

/// Get the current UTC date and time as a string
pub fn time_now_utc() -> String {
    let time_now = OffsetDateTime::now_utc();
    time_now.to_string()
}

/// Calculate the amount of time for a connection
/// pre_timestamp and post_timestamp are unix timestamps in (u) microseconds
/// a float value is returned represented as milliseconds
pub fn calc_connect_ms(pre_timestamp: u128, post_timestamp: u128) -> f64 {
    match (post_timestamp < pre_timestamp) || (pre_timestamp < 1000) || (post_timestamp < 1000) {
        // clocks are not sufficiently synced to calculate difference
        true => -1.0,
        false => {
            let us = post_timestamp - pre_timestamp;
            us as f64 / 1000.0
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::util::time::calc_connect_ms;

    #[test]
    fn calc_connect_ms_returns_1ms() {
        let pre_timestamp = 1000;
        let post_timestamp = 2000;
        let result = calc_connect_ms(pre_timestamp, post_timestamp);
        assert_eq!(result, 1.0);
    }
    #[test]
    fn calc_connect_ms_returns_neg_1ms() {
        let pre_timestamp = 2000;
        let post_timestamp = 1000;
        let result = calc_connect_ms(pre_timestamp, post_timestamp);
        assert_eq!(result, -1.0);
    }
    #[test]
    fn calc_connect_ms_returns_0ms() {
        let pre_timestamp = 1000;
        let post_timestamp = 1000;
        let result = calc_connect_ms(pre_timestamp, post_timestamp);
        assert_eq!(result, 0.0);
    }
    #[test]
    fn calc_connect_ms_returns_9_877ms() {
        let pre_timestamp = 10123;
        let post_timestamp = 20000;
        let result = calc_connect_ms(pre_timestamp, post_timestamp);
        assert_eq!(result, 9.877);
    }
    #[test]
    fn calc_connect_ms_with_pre_timestamp_neg_1000_returns_1ms() {
        let pre_timestamp = 900;
        let post_timestamp = 1000;
        let result = calc_connect_ms(pre_timestamp, post_timestamp);
        assert_eq!(result, -1.0);
    }
    #[test]
    fn calc_connect_ms_with_post_timestamp_neg_1000_returns_1ms() {
        let pre_timestamp = 1000;
        let post_timestamp = 900;
        let result = calc_connect_ms(pre_timestamp, post_timestamp);
        assert_eq!(result, -1.0);
    }
}
