use std::net::SocketAddr;

use anyhow::Result;

use tokio::net::UdpSocket;

use crate::konst::{BIND_ADDR, BIND_PORT};
use crate::util::parser::parse_ipaddr;
use crate::util::text::get_conn_string;

pub struct UdpClient {
    pub dst_addr: String,
    pub dst_port: u16,
    pub src_addr: String,
    pub src_port: u16,
}

impl UdpClient {
    pub fn new(
        dst_addr: String,
        dst_port: u16,
        src_addr: Option<String>,
        src_port: Option<u16>,
    ) -> UdpClient {
        let src_addr = match src_addr {
            Some(x) => x,
            None => BIND_ADDR.to_owned(),
        };
        let src_port = match src_port {
            Some(x) => x,
            None => BIND_PORT,
        };
        UdpClient {
            dst_addr,
            dst_port,
            src_addr,
            src_port,
        }
    }

    pub async fn connect(&self) -> Result<()> {
        let src_addr = parse_ipaddr(&self.src_addr)?;

        let dst_ip_port_str = format!("{}:{}", self.dst_addr, self.dst_port);
        let bind_addr = SocketAddr::new(src_addr, self.src_port);

        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(dst_ip_port_str).await?;
        let conn_string = get_conn_string(
            "UDP".to_owned(),
            socket.local_addr()?.to_string(),
            socket.peer_addr()?.to_string(),
        );
        socket.send(conn_string.as_bytes()).await?;
        println!("{conn_string}");
        Ok(())
    }
}
