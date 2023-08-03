mod cmd;
mod tcp;
mod util;

use std::io;
use std::net::SocketAddr;

use clap::Parser;
use tokio::net::{TcpSocket, UdpSocket};

use crate::cmd::cli::{Cli, ConnectionMethod};
use crate::util::parser::parse_ipaddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            socket.connect("172.31.255.20:3001").await?;
            let conn_string = format!("connection from: {}\n", socket.local_addr().unwrap());
            socket.send(conn_string.as_bytes()).await?;
            println!("{:#?}", socket.local_addr())
        }
    }

    Ok(())
}
