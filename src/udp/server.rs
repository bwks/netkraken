use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::core::common::{ConnectMethod, ConnectResult, ListenOptions, LogLevel, OutputOptions};
use crate::core::konst::{BIND_ADDR, BIND_PORT, MAX_PACKET_SIZE};
use crate::util::handler::output_handler;
use crate::util::message::{server_conn_success_msg, server_start_msg};
use crate::util::parser::{nk_msg_reader, parse_ipaddr};
use crate::util::time::{calc_connect_ms, time_now_us, time_now_utc};

pub struct UdpServer {
    pub listen_ip: String,
    pub listen_port: u16,
    pub output_options: OutputOptions,
    pub listen_options: ListenOptions,
}

impl UdpServer {
    pub async fn listen(&self) -> Result<()> {
        let listen_ip = parse_ipaddr(&self.listen_ip)?;

        let bind_addr = format!("{}:{}", listen_ip, self.listen_port);
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
            let (len, addr) = match reader.recv_from(&mut buffer).await {
                Ok((len, addr)) => (len, addr),
                Err(e) => {
                    // Received some kind of connection error
                    // known errors: ConnectionRest by peer
                    println!("{}", e.kind());
                    continue;
                }
            };

            buffer.truncate(len);

            let receive_time_utc = time_now_utc();
            let receive_time_stamp = time_now_us()?;
            let local_addr = &reader.local_addr()?.to_string();
            let peer_addr = &addr.to_string();

            // Add echo handler
            let mut client_server_time = 0.0;

            match self.listen_options.nk_peer_messaging && len > 0 {
                false => {
                    tx_chan.send((buffer.clone(), addr)).await?;
                }
                true => {
                    let data_string = &String::from_utf8_lossy(&buffer);

                    match nk_msg_reader(data_string) {
                        Some(mut m) => {
                            let connection_time =
                                calc_connect_ms(m.send_timestamp, receive_time_stamp);
                            client_server_time = connection_time;

                            m.receive_time_utc = receive_time_utc;
                            m.receive_timestamp = receive_time_stamp;
                            m.one_way_time_ms = connection_time;
                            m.nk_peer = true;

                            let json_message = serde_json::to_string(&m)?;
                            tx_chan
                                .send((json_message.as_bytes().to_vec(), addr))
                                .await?;
                        }
                        None => tx_chan.send((buffer.clone(), addr)).await?,
                    }
                }
            }

            let msg = server_conn_success_msg(
                ConnectResult::Ping,
                ConnectMethod::UDP,
                peer_addr,
                local_addr,
                client_server_time,
            );
            output_handler(LogLevel::INFO, &msg, &self.output_options).await;
        }
    }
}

impl Default for UdpServer {
    fn default() -> Self {
        Self {
            listen_ip: BIND_ADDR.to_owned(),
            listen_port: BIND_PORT,
            output_options: OutputOptions::default(),
            listen_options: ListenOptions::default(),
        }
    }
}
