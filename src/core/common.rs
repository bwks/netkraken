use std::fmt::Display;
use std::net::{IpAddr, SocketAddr};

use anyhow::Result;
use clap::ValueEnum;
use reqwest::StatusCode;
use serde_derive::{Deserialize, Serialize};
use tabled::Tabled;

use crate::core::konst::{
    CURRENT_DIR, LOGFILE_NAME, LOGGING_JSON, LOGGING_QUIET, LOGGING_SYSLOG, PING_INTERVAL, PING_NK_PEER, PING_REPEAT,
    PING_TIMEOUT,
};
use crate::util::serializer::serialize_status_code;
use crate::util::time::{time_now_us, time_now_utc};

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub enum ConnectResult {
    Http(StatusCode),
    Success(ConnectSuccess),
    Error(ConnectError),
}

impl serde::Serialize for ConnectResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            ConnectResult::Http(status) => serialize_status_code(status, serializer),
            ConnectResult::Success(success) => success.serialize(serializer),
            ConnectResult::Error(error) => error.serialize(serializer),
        }
    }
}
impl Display for ConnectResult {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ConnectResult::Http(http) => http.fmt(f),
            ConnectResult::Success(success) => success.fmt(f),
            ConnectResult::Error(error) => error.fmt(f),
        }
    }
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug, Serialize)]
pub enum ConnectSuccess {
    // Success
    Ok,
    Ping,
    Pong,
    Reply,
}
impl Display for ConnectSuccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectSuccess::Ok => write!(f, "OK"),
            ConnectSuccess::Ping => write!(f, "Ping"),
            ConnectSuccess::Pong => write!(f, "Pong"),
            ConnectSuccess::Reply => write!(f, "Reply"),
        }
    }
}
#[allow(dead_code)]
#[derive(Copy, Clone, Debug, Serialize)]
pub enum ConnectError {
    ConnectionError,
    Error,
    Refused,
    Reset,
    Timeout,
    Unknown,
    BindError,
}
impl Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::ConnectionError => write!(f, "ConnectError"),
            ConnectError::Error => write!(f, "Error"),
            ConnectError::Refused => write!(f, "Refused"),
            ConnectError::Reset => write!(f, "Reset"),
            ConnectError::Timeout => write!(f, "Timeout"),
            ConnectError::Unknown => write!(f, "Unknown"),
            ConnectError::BindError => write!(f, "BindError"),
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(ValueEnum, Copy, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub enum ConnectMethod {
    #[default]
    Tcp,
    Udp,

    Dns,
    Http,
    Https,
    Icmp,
}

impl Display for ConnectMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectMethod::Tcp => write!(f, "tcp"),
            ConnectMethod::Udp => write!(f, "udp"),
            ConnectMethod::Dns => write!(f, "dns"),
            ConnectMethod::Http => write!(f, "http"),
            ConnectMethod::Https => write!(f, "https"),
            ConnectMethod::Icmp => write!(f, "icmp"),
        }
    }
}

#[derive(Debug, Default, Clone, ValueEnum, PartialEq)]
pub enum HttpScheme {
    Http,
    #[default]
    Https,
}
impl std::fmt::Display for HttpScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpScheme::Http => write!(f, "http"),
            HttpScheme::Https => write!(f, "https"),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, ValueEnum, PartialEq, Deserialize)]
pub enum HttpVersion {
    #[default]
    #[value(name = "1")]
    V1,
    #[value(name = "2")]
    V2,
    #[value(name = "3")]
    V3,
}
impl std::fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpVersion::V1 => write!(f, "1"),
            HttpVersion::V2 => write!(f, "2"),
            HttpVersion::V3 => write!(f, "3"),
        }
    }
}

#[derive(Debug, Default, Clone, ValueEnum, PartialEq)]
pub enum Transport {
    Tcp,
    #[default]
    Udp,
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Transport::Tcp => write!(f, "tcp"),
            Transport::Udp => write!(f, "udp"),
        }
    }
}

#[derive(ValueEnum, Copy, Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IpProtocol {
    All,
    #[default]
    V4,
    V6,
}

impl Display for IpProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpProtocol::All => write!(f, "all"),
            IpProtocol::V4 => write!(f, "v4"),
            IpProtocol::V6 => write!(f, "v6"),
        }
    }
}

#[allow(dead_code, clippy::upper_case_acronyms)]
pub enum LogLevel {
    DEBUG,
    ERROR,
    INFO,
    WARN,
    TRACE,
}

#[derive(Copy, Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct IpOptions {
    pub ip_protocol: IpProtocol,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingOptions {
    pub file: String,
    pub dir: String,
    pub quiet: bool,
    pub json: bool,
    pub syslog: bool,
}

impl Default for LoggingOptions {
    fn default() -> Self {
        Self {
            file: LOGFILE_NAME.to_owned(),
            dir: CURRENT_DIR.to_owned(),
            quiet: LOGGING_QUIET,
            json: LOGGING_JSON,
            syslog: LOGGING_SYSLOG,
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct PingOptions {
    pub repeat: u16,
    pub interval: u16,
    pub timeout: u16,
    pub nk_peer: bool,
}

impl Default for PingOptions {
    fn default() -> Self {
        Self {
            repeat: PING_REPEAT,
            interval: PING_INTERVAL,
            timeout: PING_TIMEOUT,
            nk_peer: PING_NK_PEER,
        }
    }
}

#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
pub struct ListenOptions {
    pub nk_peer: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConnectRecord {
    pub result: ConnectResult,
    pub context: Option<String>,
    pub protocol: ConnectMethod,
    pub source: String,
    pub destination: String,
    pub time: f64,
    pub success: bool,
    pub error_msg: Option<String>, // Original error message
}

impl Display for ConnectRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let error_msg = match &self.error_msg {
            Some(m) => m.to_owned(),
            None => "".to_owned(),
        };
        let msg = format!(
            "result: {}
context: {:?}
protocol: {}
source: {}
destination: {}
time: {:.3}
success: {}
error: {}
",
            self.result,
            self.context,
            self.protocol.to_string().to_uppercase(),
            self.source,
            self.destination,
            self.time,
            self.success,
            error_msg,
        );
        write!(f, "{msg}")
    }
}

pub struct ClientSummary {
    pub send_count: u16,
    pub latencies: Vec<f64>,
}

pub struct ClientResult {
    pub destination: String,
    pub protocol: ConnectMethod,
    pub sent: u16,
    pub received: u16,
    pub lost: u16,
    pub loss_percent: f64,
    pub min: f64,
    pub max: f64,
    pub avg: f64,
}
impl Tabled for ClientResult {
    const LENGTH: usize = 42;

    fn fields(&self) -> Vec<std::borrow::Cow<'_, str>> {
        vec![
            self.destination.clone().into(),
            self.protocol.to_string().to_uppercase().into(),
            self.sent.to_string().into(),
            self.received.to_string().into(),
            self.lost.to_string().into(),
            format!("{:.2}", self.loss_percent).into(),
            format!("{:.3}", self.min).into(),
            format!("{:.3}", self.max).into(),
            format!("{:.3}", self.avg).into(),
        ]
    }

    fn headers() -> Vec<std::borrow::Cow<'static, str>> {
        vec![
            std::borrow::Cow::Borrowed("Destination"),
            std::borrow::Cow::Borrowed("Protocol"),
            std::borrow::Cow::Borrowed("Sent"),
            std::borrow::Cow::Borrowed("Received"),
            std::borrow::Cow::Borrowed("Lost"),
            std::borrow::Cow::Borrowed("Loss (%)"),
            std::borrow::Cow::Borrowed("Min (ms)"),
            std::borrow::Cow::Borrowed("Max (ms)"),
            std::borrow::Cow::Borrowed("Avg (ms)"),
        ]
    }
}

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct NetKrakenMessage {
    pub uuid: String,
    pub send_time_utc: String,
    pub send_timestamp: u128,
    pub receive_time_utc: String,
    pub receive_timestamp: u128,
    pub one_way_time_ms: f64,
    pub round_trip_time_utc: String,
    pub round_trip_timestamp: u128,
    pub round_trip_time_ms: f64,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub nk_peer: bool,
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
            send_timestamp: time_now_us(),
            source: source.to_owned(),
            destination: destination.to_owned(),
            ..Default::default()
        };

        Ok(message)
    }

    pub fn _to_json(&self) -> Result<String> {
        let json_string = serde_json::to_string(&self)?;
        Ok(json_string)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostRecord {
    pub host: String,
    pub port: u16,
    pub ipv4_sockets: Vec<SocketAddr>,
    pub ipv6_sockets: Vec<SocketAddr>,
}

impl HostRecord {
    pub async fn new(host: &str, port: u16) -> HostRecord {
        let mut ipv4_sockets = vec![];
        let mut ipv6_sockets = vec![];

        let host_port = format!("{}:{}", host, port);
        if let Ok(sockets) = tokio::net::lookup_host(host_port).await {
            for socket in sockets {
                match socket.is_ipv4() {
                    true => ipv4_sockets.push(socket),
                    false => ipv6_sockets.push(socket),
                }
            }
        }
        HostRecord {
            host: host.to_owned(),
            port,
            ipv4_sockets,
            ipv6_sockets,
        }
    }
}

impl Display for HostRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ipv4_sockets = &self.ipv4_sockets;
        let ipv6_sockets = &self.ipv6_sockets;

        let msg = format!(
            "{}
{}
{}
 ",
            self.host,
            ipv4_sockets
                .iter()
                .map(|i| i.ip().to_string())
                .collect::<Vec<String>>()
                .join("\n"),
            ipv6_sockets
                .iter()
                .map(|i| i.ip().to_string())
                .collect::<Vec<String>>()
                .join("\n"),
        );
        write!(f, "{msg}")
    }
}

#[derive(Debug, Clone, Copy)]
pub struct IpPort {
    pub ipv4: IpAddr,
    pub ipv6: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct HostResults {
    pub host: String,
    pub results: Vec<ConnectRecord>,
}

#[cfg(test)]
mod tests {
    use crate::core::common::HostRecord;

    #[tokio::test]
    async fn host_record_empty() {
        let domain = "blahblehblow.doesnotexist";
        let port = 1337;
        let expected = HostRecord {
            host: domain.to_owned(),
            port,
            ipv4_sockets: vec![],
            ipv6_sockets: vec![],
        };
        let host_record = HostRecord::new(domain, port).await;

        assert_eq!(host_record, expected);
    }

    #[tokio::test]
    async fn host_record_not_empty() {
        let domain = "windows.com";
        let port = 1337;

        let host_record = HostRecord::new(domain, port).await;

        assert!(!host_record.ipv4_sockets.is_empty());
        assert!(!host_record.ipv6_sockets.is_empty());
    }
}
