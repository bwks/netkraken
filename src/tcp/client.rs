use std::net::SocketAddr;

use anyhow::Result;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpSocket;

use crate::konst::{BIND_ADDR, BIND_PORT};
use crate::util::parser::parse_ipaddr;
use crate::util::text::get_conn_string;

pub struct TcpClient {
    pub dst_addr: String,
    pub dst_port: u16,
    pub src_addr: String,
    pub src_port: u16,
}

impl TcpClient {
    pub fn new(
        dst_addr: String,
        dst_port: u16,
        src_addr: Option<String>,
        src_port: Option<u16>,
    ) -> TcpClient {
        let src_addr = match src_addr {
            Some(x) => x,
            None => BIND_ADDR.to_owned(),
        };
        let src_port = match src_port {
            Some(x) => x,
            None => BIND_PORT,
        };
        TcpClient {
            dst_addr,
            dst_port,
            src_addr,
            src_port,
        }
    }

    pub async fn connect(&self) -> Result<()> {
        let src_addr = parse_ipaddr(&self.src_addr)?;
        let dst_addr = parse_ipaddr(&self.dst_addr)?;

        let bind_addr = SocketAddr::new(src_addr, self.src_port);
        let connect_addr = SocketAddr::new(dst_addr, self.dst_port);

        let socket = match src_addr.is_ipv4() {
            true => TcpSocket::new_v4()?,
            false => TcpSocket::new_v6()?,
        };

        socket.bind(bind_addr)?;

        let mut stream = socket.connect(connect_addr).await?;
        let conn_string = get_conn_string(
            "TCP".to_owned(),
            stream.local_addr()?.to_string(),
            stream.peer_addr()?.to_string(),
        );
        stream.write_all(conn_string.as_bytes()).await?;
        Ok(())
    }
}
