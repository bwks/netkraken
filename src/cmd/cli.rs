use std::fmt::Display;
use std::io;
use std::net::SocketAddr;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use tokio::net::{TcpSocket, UdpSocket};

use crate::util::parser::parse_ipaddr;

#[derive(Debug, Parser)] // requires `derive` feature
#[command(name = "nk")]
#[command(bin_name = "nk")]
#[command(about = "Net Kraken, network connectivity tester.", long_about = None)]
pub struct Cli {
    /// Destination hostname or IP address
    pub dst_host: String,

    /// Destination port
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

    let src_addr = parse_ipaddr(&cli.src_addr)?;
    let dst_addr = parse_ipaddr(&cli.dst_host)?;

    let bind_addr = SocketAddr::new(src_addr, cli.src_port);
    let connect_addr = SocketAddr::new(dst_addr, cli.dst_port);

    match cli.method {
        ConnectionMethod::Http => println!("http not implemented"),
        ConnectionMethod::Icmp => println!("icmp not implemented"),
        ConnectionMethod::Tcp => {
            let socket = match src_addr.is_ipv4() {
                true => TcpSocket::new_v4()?,
                false => TcpSocket::new_v6()?,
            };

            socket.bind(bind_addr)?;

            match socket.connect(connect_addr).await {
                Ok(s) => {
                    println!("connected to {} using {}", s.peer_addr()?, cli.method);
                }
                Err(e) => match e.kind() {
                    io::ErrorKind::ConnectionRefused => println!("connection refused"),
                    io::ErrorKind::TimedOut => println!("connection timed out"),
                    _ => println!("{:#?}", e),
                },
            };
        }
        ConnectionMethod::Udp => {
            let dst_ip_port_str = format!("{}:{}", dst_addr, cli.dst_port);
            let conn_string = format!("connection from: {}\n", bind_addr);

            let socket = UdpSocket::bind(bind_addr).await?;
            socket.connect(dst_ip_port_str).await?;
            socket.send(conn_string.as_bytes()).await?;
        }
    }
    Ok(())
}
