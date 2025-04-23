use tokio::time::{Duration, sleep};
use tracing::Level;
use tracing::event;

use crate::core::common::LogLevel;
use crate::core::common::LoggingOptions;
use crate::core::common::{ConnectError, ConnectRecord};
use crate::core::konst::APP_NAME;

/// Handler to manage loop iterations. On `true` the loop
/// will break, on `false` it will continue.
/// # Arguments
/// * `loop_counter` - The loop iteration count
/// * `num_repeats` - How many times the loop should num_repeats
/// * `sleep_interval` - How long the loop should sleep for between iterations
///
/// ## Break conditions
///  * loop count == 65535 (u16 max value)
///  * loop count >= number of repeats
pub async fn loop_handler(loop_count: u16, num_repeats: u16, sleep_interval: u16) -> bool {
    if loop_count == u16::MAX {
        println!("max ping count reached");
        true
    } else if num_repeats != 0 && loop_count >= num_repeats {
        true
    } else {
        if loop_count > 0 {
            sleep(Duration::from_millis(sleep_interval.into())).await;
        }
        false
    }
}

pub async fn log_handler(log_level: LogLevel, message: &String, logging_options: &LoggingOptions) {
    if !logging_options.quiet {
        println!("{message}");
    }
    if logging_options.syslog {
        match log_level {
            LogLevel::DEBUG => event!(target: APP_NAME, Level::DEBUG, "{message}"),
            LogLevel::ERROR => event!(target: APP_NAME, Level::ERROR, "{message}"),
            LogLevel::INFO => event!(target: APP_NAME, Level::INFO, "{message}"),
            LogLevel::WARN => event!(target: APP_NAME, Level::WARN, "{message}"),
            LogLevel::TRACE => event!(target: APP_NAME, Level::TRACE, "{message}"),
        };
    }
    if logging_options.json {
        // json handler
    }
}

pub fn io_error_switch_handler(error: std::io::Error) -> ConnectError {
    match error.kind() {
        std::io::ErrorKind::ConnectionRefused => ConnectError::Refused,
        std::io::ErrorKind::ConnectionReset => ConnectError::Reset,
        std::io::ErrorKind::TimedOut => ConnectError::Timeout,
        _ => ConnectError::Unknown,
    }
}

pub async fn log_handler2(record: &ConnectRecord, message: &String, logging_options: &LoggingOptions) {
    if !logging_options.quiet {
        println!("{message}");
    }
    if logging_options.syslog {
        match record.success {
            true => event!(target: APP_NAME, Level::INFO, "{message}"),
            false => event!(target: APP_NAME, Level::ERROR, "{message}"),
        };
    }
    if logging_options.json {
        // json handler
    }
}

#[cfg(test)]
mod tests {
    use crate::util::handler::*;

    #[tokio::test]
    async fn loop_handler_with_max_count_is_true() {
        let result = loop_handler(65535, 0, 1).await;
        assert_eq!(result, true);
    }

    #[tokio::test]
    async fn loop_handler_with_loop_count_gt_num_repeats_is_true() {
        let result = loop_handler(2, 1, 1).await;
        assert_eq!(result, true);
    }

    #[tokio::test]
    async fn loop_handler_with_loop_count_eq_num_repeats_is_true() {
        let result = loop_handler(1, 1, 1).await;
        assert_eq!(result, true);
    }

    #[tokio::test]
    async fn loop_handler_with_repeat_count_gt_0_is_false() {
        let result = loop_handler(0, 1, 1).await;
        assert_eq!(result, false);
    }
}
