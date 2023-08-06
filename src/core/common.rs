use std::fmt::Display;

use anyhow::Result;
use clap::ValueEnum;
use serde_derive::{Deserialize, Serialize};
use uuid::Uuid;

use crate::util::time::{time_now_us, time_now_utc};

#[derive(ValueEnum, Clone, Debug, Default)]
pub enum ConnectMethod {
    #[default]
    TCP,
    UDP,
    ICMP,
    HTTP,
}

impl Display for ConnectMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectMethod::TCP => write!(f, "tcp"),
            ConnectMethod::UDP => write!(f, "udp"),
            ConnectMethod::ICMP => write!(f, "icmp"),
            ConnectMethod::HTTP => write!(f, "http"),
        }
    }
}

#[derive(Debug)]
pub struct OutputOptions {
    pub quiet: bool,
    pub json: bool,
}

impl Default for OutputOptions {
    fn default() -> Self {
        Self {
            quiet: false,
            json: false,
        }
    }
}

#[derive(Debug)]
pub struct PingOptions {
    pub repeat: u8,
    pub interval: u16,
}

impl Default for PingOptions {
    fn default() -> Self {
        Self {
            repeat: 4,
            interval: 1000,
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct ConnectMessage {
    pub uuid: String,
    pub send_time_utc: String,
    pub send_timestamp: u128,
    pub receive_time_utc: String,
    pub receive_timestamp: u128,
    pub rtt_time_utc: String,
    pub rtt_timestamp: u128,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub malformed: bool,
}

impl ConnectMessage {
    pub fn new(
        source: &String,
        destination: &String,
        protocol: ConnectMethod,
    ) -> Result<ConnectMessage> {
        let uuid = Uuid::new_v4();

        let message = ConnectMessage {
            uuid: uuid.to_string(),
            protocol: protocol.to_string(),
            send_time_utc: time_now_utc(),
            send_timestamp: time_now_us()?,
            source: source.to_owned(),
            destination: destination.to_owned(),
            ..Default::default()
        };

        Ok(message)
    }
}
