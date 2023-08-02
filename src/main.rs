mod cmd;
mod tcp;

use std::io;
use std::net::SocketAddr;

use clap::Parser;
use tokio::io::Interest;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use crate::cmd::cli::Cli;
use crate::tcp::client::TcpConnector;

#[tokio::main]
async fn main() -> io::Result<()> {
    let t_client = TcpConnector::new("172.31.255.21", 3002);
    println!("{:#?}", t_client);

    let bind_addr = SocketAddr::from(([192, 168, 255, 238], 0));
    // let bind_addr = SocketAddr::from(([172, 24, 255, 59], 0));
    let connect_addr = SocketAddr::from(([172, 31, 255, 20], 3000));

    let socket = TcpSocket::new_v4()?;
    socket.bind(bind_addr)?;

    let stream = socket.connect(connect_addr).await?;

    println!("{:#?}", stream);
    println!("{:#?}", stream.local_addr());

    // match socket.connect(connect_addr).await {
    //     Ok(_) => println!("connected"),
    //     Err(e) => match e.kind() {
    //         io::ErrorKind::ConnectionRefused => println!("connection refused"),
    //         io::ErrorKind::TimedOut => println!("connection timed out"),
    //         _ => println!("{:#?}", e),
    //     },
    // }

    // println!("{:#?}", socket.local_addr());

    // println!("{:#?}", socket);

    // match TcpStream::connect(format!("{}:{}", t_client.dst_ip, t_client.dst_port)).await {
    //     Ok(_) => println!("connected"),
    //     Err(e) => match e.kind() {
    //         io::ErrorKind::ConnectionRefused => println!("connection refused"),
    //         io::ErrorKind::TimedOut => println!("connection timed out"),
    //         _ => println!("{:#?}", e),
    //     },
    // };

    // println!("{:#?}", t);
    // println!("{:#?}", t.local_addr());
    // println!("{:#?}", t.linger());
    // println!("{:#?}", t.ttl());

    // let ready = t.ready(Interest::READABLE | Interest::WRITABLE).await?;
    // println!("{:#?}", ready);

    // if ready.is_writable() {
    //     println!("HELLO")
    // }

    // Bind socket
    let socket = UdpSocket::bind("192.168.255.238:0").await?;
    socket.connect("172.31.255.20:3001").await?;

    // Send a message
    socket.send(b"hello world\n").await?;

    let args = Cli::parse();
    println!("{:#?}", args);

    Ok(())
}
