use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use tracing::event;
use tracing::Level;

use crate::core::common::{ConnectMethod, ConnectResult, HelloMessage, OutputOptions};
use crate::core::konst::{APP_NAME, BIND_ADDR, BIND_PORT, MAX_PACKET_SIZE};
use crate::util::message::{server_conn_success_msg, server_start_msg};
use crate::util::parser::{hello_msg_reader, parse_ipaddr};

pub struct UdpServer {
    pub listen_addr: String,
    pub listen_port: u16,
    pub output_options: OutputOptions,
}

impl UdpServer {
    pub async fn listen(&self) -> Result<()> {
        let listen_addr = parse_ipaddr(&self.listen_addr)?;
        let echo = self.output_options.echo;

        let bind_addr = format!("{}:{}", listen_addr, self.listen_port);
        let socket = UdpSocket::bind(&bind_addr).await?;
        let reader = Arc::new(socket);
        let writer = reader.clone();
        let (tx_chan, mut rx_chan) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1);

        server_start_msg(ConnectMethod::UDP, &bind_addr);

        tokio::spawn(async move {
            while let Some((bytes, addr)) = rx_chan.recv().await {
                writer.send_to(&bytes, &addr).await?;
            }
            Ok::<(), anyhow::Error>(())
        });

        loop {
            let mut buffer = vec![0u8; MAX_PACKET_SIZE];
            let (len, addr) = reader.recv_from(&mut buffer).await?;
            buffer.truncate(len);

            let local_addr = &reader.local_addr()?.to_string();
            let peer_addr = &addr.to_string();

            server_conn_success_msg(
                ConnectResult::Received,
                ConnectMethod::UDP,
                peer_addr,
                local_addr,
                1.0,
            );

            // Add echo handler
            if echo && len > 0 {
                tx_chan.send((buffer.clone(), addr)).await?;
            } else {
                let data_string = &String::from_utf8_lossy(&buffer);

                // Discover NetKracken peer.
                let mut hello_msg = match hello_msg_reader(data_string) {
                    Some(d) => d,
                    None => continue,
                };
                hello_msg.pong = true;

                let json_message = serde_json::to_string(&hello_msg)?;
                tx_chan
                    .send((json_message.as_bytes().to_vec(), addr))
                    .await?;
            }
        }
    }
}

impl Default for UdpServer {
    fn default() -> Self {
        Self {
            listen_addr: BIND_ADDR.to_owned(),
            listen_port: BIND_PORT,
            output_options: OutputOptions::default(),
        }
    }
}
