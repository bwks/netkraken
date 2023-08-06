use std::net::SocketAddr;

use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpSocket;
use tokio::time::{sleep, Duration};
use uuid::Uuid;

use crate::core::common::{ConnectMessage, ConnectMethod, OutputOptions, PingOptions};
use crate::core::konst::{BIND_ADDR, BIND_PORT};
use crate::util::parser::parse_ipaddr;

#[derive(Debug)]
pub struct TcpClient {
    pub dst_addr: String,
    pub dst_port: u16,
    pub src_addr: String,
    pub src_port: u16,
    pub output_options: OutputOptions,
    pub ping_options: PingOptions,
}

impl TcpClient {
    pub fn new(
        dst_addr: String,
        dst_port: u16,
        src_addr: Option<String>,
        src_port: Option<u16>,
        output_options: OutputOptions,
        ping_options: PingOptions,
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
            output_options,
            ping_options,
        }
    }

    pub async fn connect(&self) -> Result<()> {
        let src_addr = parse_ipaddr(&self.src_addr)?;
        let dst_addr = parse_ipaddr(&self.dst_addr)?;

        let bind_addr = SocketAddr::new(src_addr, self.src_port);
        let connect_addr = SocketAddr::new(dst_addr, self.dst_port);

        let uuid = Uuid::new_v4();
        let mut count: u8 = 1;
        loop {
            sleep(Duration::from_millis(self.ping_options.interval.into())).await;

            let socket = match src_addr.is_ipv4() {
                true => TcpSocket::new_v4()?,
                false => TcpSocket::new_v6()?,
            };
            socket.bind(bind_addr)?;

            let mut stream = socket.connect(connect_addr).await?;

            let mut connect_message = ConnectMessage::new(
                &stream.local_addr()?.to_string(),
                &stream.peer_addr()?.to_string(),
                ConnectMethod::TCP,
            )?;

            connect_message.uuid = uuid.to_string();
            let json_message = serde_json::to_string(&connect_message)?;

            stream.write_all(json_message.as_bytes()).await?;

            if self.ping_options.repeat == 0 {
                continue;
            } else if self.ping_options.repeat == count {
                break;
            } else {
                count += 1;
            }
        }
        Ok(())
    }
}
