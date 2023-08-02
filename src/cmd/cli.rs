use std::fmt::Display;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)] // requires `derive` feature
#[command(name = "nk")]
#[command(bin_name = "nk")]
#[command(about = "Net Kraken, network connectivity tester.", long_about = None)]
pub struct Cli {
    /// Destination hostname or IP address
    destination: String,

    /// Destination port
    port: u16,

    #[clap(short, long, default_value_t = ConnectionMethod::Tcp)]
    /// Connection Method
    method: ConnectionMethod,

    #[clap(short, long)]
    /// Connection Method
    src_addr: Option<String>,
}

#[derive(ValueEnum, Clone, Debug, Default)]
enum ConnectionMethod {
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
