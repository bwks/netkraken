use std::fmt::Display;

use clap::ValueEnum;
use serde_derive::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(ValueEnum, Clone, Debug, Default)]
pub enum ConnectMethod {
    #[default]
    Tcp,
    Udp,
    Icmp,
    Http,
}

impl Display for ConnectMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectMethod::Tcp => write!(f, "tcp"),
            ConnectMethod::Udp => write!(f, "udp"),
            ConnectMethod::Icmp => write!(f, "icmp"),
            ConnectMethod::Http => write!(f, "http"),
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

#[derive(Clone, Deserialize, Serialize)]
pub struct ConnectMessage {
    pub uuid: String,
    pub send_time_utc: String,
    pub send_timestamp: i64,
    pub source: String,
    pub destination: String,
    pub protocol: String,
}

impl ConnectMessage {
    pub fn new(source: &String, destination: &String, protocol: ConnectMethod) -> ConnectMessage {
        let time_now = OffsetDateTime::now_utc();
        let unix_timestamp = time_now.unix_timestamp();
        let uuid = Uuid::new_v4();
        ConnectMessage {
            uuid: uuid.to_string(),
            protocol: protocol.to_string(),
            send_time_utc: time_now.to_string(),
            send_timestamp: unix_timestamp,
            source: source.to_owned(),
            destination: destination.to_owned(),
        }
    }
}
