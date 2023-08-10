use std::fmt::Display;

use anyhow::Result;
use clap::ValueEnum;
use serde_derive::{Deserialize, Serialize};
use uuid::Uuid;

use crate::util::time::{time_now_us, time_now_utc};

pub enum ConnectResult {
    // Success
    Established,
    Received,
    Reply,

    // Errors
    Refused,
    Timeout,
    Unknown,
}
impl Display for ConnectResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectResult::Established => write!(f, "established"),
            ConnectResult::Received => write!(f, "received"),
            ConnectResult::Reply => write!(f, "reply"),
            ConnectResult::Refused => write!(f, "refused"),
            ConnectResult::Timeout => write!(f, "timeout"),
            ConnectResult::Unknown => write!(f, "unknown"),
        }
    }
}

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
    pub echo: bool,
    pub quiet: bool,
    pub json: bool,
}

impl Default for OutputOptions {
    fn default() -> Self {
        Self {
            echo: false,
            quiet: false,
            json: false,
        }
    }
}

#[derive(Debug)]
pub struct PingOptions {
    pub repeat: u16,
    pub interval: u16,
    pub discover: bool,
}

impl Default for PingOptions {
    fn default() -> Self {
        Self {
            repeat: 4,
            interval: 1000,
            discover: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HelloMessage {
    pub uuid: String,
    pub ping: bool,
    pub pong: bool,
}

impl Default for HelloMessage {
    fn default() -> Self {
        let uuid = Uuid::new_v4();
        Self {
            uuid: uuid.to_string(),
            ping: false,
            pong: false,
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct NetKrakenMessage {
    pub uuid: String,
    pub send_time_utc: String,
    pub send_timestamp: u128,
    pub receive_time_utc: String,
    pub receive_timestamp: u128,
    pub client_server_time: f64,
    pub rount_trip_time_utc: String,
    pub rount_trip_timestamp: u128,
    pub rount_trip_time_ms: f64,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub malformed: bool,
}

impl NetKrakenMessage {
    #[allow(dead_code)]
    pub fn new(
        uuid: &String,
        source: &String,
        destination: &String,
        protocol: ConnectMethod,
    ) -> Result<NetKrakenMessage> {
        let message = NetKrakenMessage {
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
