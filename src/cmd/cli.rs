use std::fmt::Display;

use clap::{Parser, ValueEnum};

#[derive(Debug, Parser)] // requires `derive` feature
#[command(name = "nk")]
#[command(bin_name = "nk")]
#[command(about = "Net Kraken, network connectivity tester.", long_about = None)]
pub struct Cli {
    /// Destination hostname or IP address
    pub dst_host: String,

    /// Destination port
    pub dst_port: u16,

    #[clap(short, long, default_value_t = ConnectionMethod::Tcp)]
    /// Connection Method
    pub method: ConnectionMethod,

    #[clap(long, default_value = "0.0.0.0")]
    /// Source IP Address
    pub src_addr: String,

    #[clap(long, default_value_t = 0)]
    /// Source port
    pub src_port: u16,
}

#[derive(ValueEnum, Clone, Debug, Default)]
pub enum ConnectionMethod {
    #[default]
    Tcp,
    Udp,
    Icmp,
    Http,
}

impl Display for ConnectionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionMethod::Tcp => write!(f, "tcp"),
            ConnectionMethod::Udp => write!(f, "udp"),
            ConnectionMethod::Icmp => write!(f, "icmp"),
            ConnectionMethod::Http => write!(f, "http"),
        }
    }
}
