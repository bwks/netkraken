use std::fmt::Display;
use std::net::SocketAddr;

use anyhow::Result;
use clap::ValueEnum;
use serde_derive::{Deserialize, Serialize};

use crate::util::time::{time_now_us, time_now_utc};

#[allow(dead_code)]
#[derive(Copy, Clone, Debug, Serialize)]
pub enum ConnectResult {
    // Success
    Ping,
    Pong,

    // Errors
    Refused,
    Reset,
    Timeout,
    Unknown,
}
impl Display for ConnectResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectResult::Ping => write!(f, "ping"),
            ConnectResult::Pong => write!(f, "pong"),
            ConnectResult::Refused => write!(f, "refused"),
            ConnectResult::Reset => write!(f, "reset"),
            ConnectResult::Timeout => write!(f, "timeout"),
            ConnectResult::Unknown => write!(f, "unknown"),
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(ValueEnum, Copy, Clone, Debug, Default, Serialize)]
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

#[allow(dead_code, clippy::upper_case_acronyms)]
pub enum LogLevel {
    DEBUG,
    ERROR,
    INFO,
    WARN,
    TRACE,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct OutputOptions {
    pub quiet: bool,
    pub json: bool,
    pub syslog: bool,
}

#[derive(Copy, Clone, Debug)]
pub struct PingOptions {
    pub repeat: u16,
    pub interval: u16,
    pub timeout: u16,
    pub nk_peer_messaging: bool,
}

impl Default for PingOptions {
    fn default() -> Self {
        Self {
            repeat: 4,
            interval: 1000,
            timeout: 1000,
            nk_peer_messaging: false,
        }
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct ListenOptions {
    pub nk_peer_messaging: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConnectRecord {
    pub result: ConnectResult,
    pub protocol: ConnectMethod,
    pub source: String,
    pub destination: String,
    pub time: f64,
    pub success: bool,
    pub error_msg: Option<String>, // Original error message
}

impl Display for ConnectRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = format!(
            "result: {}
protocol: {}
source: {}
destination: {}
time: {:.3}
",
            self.result,
            self.protocol.to_string().to_uppercase(),
            self.source,
            self.destination,
            self.time
        );
        write!(f, "{msg}")
    }
}

impl ConnectRecord {
    pub fn client_success_msg(&self) -> String {
        format!(
            "{} => proto={} src={} dst={} time={:.3}ms",
            self.result,
            self.protocol.to_string().to_uppercase(),
            self.source,
            self.destination,
            self.time,
        )
    }
    pub fn client_error_msg(&self, error: std::io::Error) -> String {
        let err = match error.kind() {
            std::io::ErrorKind::ConnectionRefused => ConnectResult::Refused,
            std::io::ErrorKind::ConnectionReset => ConnectResult::Reset,
            std::io::ErrorKind::TimedOut => ConnectResult::Timeout,
            _ => ConnectResult::Unknown,
        };

        format!(
            "{} => proto={} src={} dst={}",
            err,
            self.protocol.to_string().to_uppercase(),
            self.source,
            self.destination,
        )
    }
}

pub struct ClientSummary {
    pub send_count: u16,
    pub received_count: u16,
    pub latencies: Vec<f64>,
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

    pub fn to_json(&self) -> Result<String> {
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
    async fn host_record_notempty() {
        let domain = "windows.com";
        let port = 1337;

        let host_record = HostRecord::new(domain, port).await;

        assert!(!host_record.ipv4_sockets.is_empty());
        assert!(!host_record.ipv6_sockets.is_empty());
    }
}
