use tokio::time::{sleep, Duration};
use tracing::event;
use tracing::Level;

use crate::core::common::LogLevel;
use crate::core::konst::APP_NAME;

pub async fn loop_handler(count: u16, repeat: u16, sleep_interval: u16) -> bool {
    if count == u16::MAX {
        println!("max ping count reached");
        return true;
    } else if repeat != 0 && count >= repeat {
        return true;
    } else {
        if count > 0 {
            sleep(Duration::from_millis(sleep_interval.into())).await;
        }
        return false;
    }
}

pub async fn output_handler(
    log_level: LogLevel,
    message: &String,
    quiet_output: bool,
    syslog_output: bool,
    json_output: bool,
) {
    if !quiet_output {
        println!("{message}");
    }
    if syslog_output {
        match log_level {
            LogLevel::DEBUG => event!(target: APP_NAME, Level::DEBUG, "{message}"),
            LogLevel::ERROR => event!(target: APP_NAME, Level::ERROR, "{message}"),
            LogLevel::INFO => event!(target: APP_NAME, Level::INFO, "{message}"),
            LogLevel::WARN => event!(target: APP_NAME, Level::WARN, "{message}"),
            LogLevel::TRACE => event!(target: APP_NAME, Level::TRACE, "{message}"),
        };
    }
    if json_output {
        // json handler
    }
}
