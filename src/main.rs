use std::io;
use tokio::net::{TcpStream, UdpSocket};

#[tokio::main]
async fn main() -> io::Result<()> {
    let t = TcpStream::connect("172.31.255.20:3000").await?;
    println!("{:#?}", t);

    // Bind socket
    let socket = UdpSocket::bind("192.168.255.238:0").await?;
    socket.connect("172.31.255.20:3001").await?;

    // Send a message
    socket.send(b"hello world\n").await?;

    Ok(())
}
