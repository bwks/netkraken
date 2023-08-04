use std::fmt::Display;

use anyhow::Result;
use clap::{Parser, ValueEnum};

use crate::tcp::client::TcpClient;
use crate::tcp::server::TcpServer;
use crate::udp::client::UdpClient;
use crate::udp::server::UdpServer;

#[derive(Debug, Parser)] // requires `derive` feature
#[command(name = "nk")]
#[command(bin_name = "nk")]
#[command(about = "Net Kraken, network connectivity tester.", long_about = None)]
pub struct Cli {
    /// Destination hostname or IP address ||
    /// Listen address in `-l --listen` mode
    pub dst_host: String,

    /// Destination port ||
    /// Listen port in `-l --listen` mode
    pub dst_port: u16,

    /// Connection Method
    #[clap(short, long, default_value_t = ConnectionMethod::Tcp)]
    pub method: ConnectionMethod,

    /// Source IP Address
    #[clap(long, default_value = "0.0.0.0")]
    pub src_addr: String,

    /// Source port (0 detects random unused high port between 1024-65534)
    #[clap(long, default_value_t = 0)]
    pub src_port: u16,

    /// Listen as a server
    #[clap(short, long, default_value_t = false)]
    pub listen: bool,
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

pub async fn init_cli() -> Result<()> {
    let cli = Cli::parse();

    match cli.method {
        ConnectionMethod::Http => println!("http not implemented"),
        ConnectionMethod::Icmp => println!("icmp not implemented"),
        ConnectionMethod::Tcp => {
            if cli.listen {
                let tcp_server = TcpServer {
                    src_addr: cli.dst_host,
                    src_port: cli.dst_port,
                };
                tcp_server.listen().await?;
            } else {
                let tcp_client = TcpClient::new(
                    cli.dst_host,
                    cli.dst_port,
                    Some(cli.src_addr),
                    Some(cli.src_port),
                );
                tcp_client.connect().await?;
            }
        }
        ConnectionMethod::Udp => {
            if cli.listen {
                let udp_server = UdpServer {
                    src_addr: cli.dst_host,
                    src_port: cli.dst_port,
                };
                udp_server.listen().await?;
            } else {
                let udp_client = UdpClient::new(
                    cli.dst_host,
                    cli.dst_port,
                    Some(cli.src_addr),
                    Some(cli.src_port),
                );
                udp_client.connect().await?;
            }
        }
    }
    Ok(())
}
