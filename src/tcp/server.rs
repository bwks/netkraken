use anyhow::Result;

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use tracing::event;
use tracing::Level;

use crate::core::common::ConnectMessage;
use crate::core::konst::{APP_NAME, BIND_ADDR, BIND_PORT};
use crate::util::message::get_conn_string;
use crate::util::parser::parse_ipaddr;

pub struct TcpServer {
    pub listen_addr: String,
    pub listen_port: u16,
}

impl TcpServer {
    pub async fn listen(&self) -> Result<()> {
        let listen_addr = parse_ipaddr(&self.listen_addr)?;
        let bind_addr = format!("{}:{}", listen_addr, self.listen_port);

        let listener = TcpListener::bind(&bind_addr).await?;

        println!("TCP server listening on {}", &bind_addr);
        println!("Press CRTL+C to exit");
        println!("--------------------");

        let mut buffer = Vec::with_capacity(64);
        loop {
            // Receive
            let (mut stream, _) = listener.accept().await?;
            let len = stream.read_to_end(&mut buffer).await?;
            let data: ConnectMessage =
                serde_json::from_str(&String::from_utf8_lossy(&buffer[..len]))?;
            let output =
                get_conn_string(data.protocol.to_uppercase(), data.source, data.destination);
            event!(target: APP_NAME, Level::INFO, "{output}");

            // Send

            // Flush buffer
            buffer.clear();
        }
    }
}

impl Default for TcpServer {
    fn default() -> Self {
        Self {
            listen_addr: BIND_ADDR.to_owned(),
            listen_port: BIND_PORT,
        }
    }
}
