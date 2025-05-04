use std::net::IpAddr;

use anyhow::Result;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use crate::core::common::IpProtocol;
use crate::core::common::{
    ConnectMethod, ConnectResult, ConnectSuccess, IpOptions, ListenOptions, LogLevel, LoggingOptions,
};
use crate::core::konst::MAX_PACKET_SIZE;
use crate::util::handler::log_handler;
use crate::util::message::{server_conn_success_msg, server_start_msg};
use crate::util::parser::nk_msg_reader;
use crate::util::time::{calc_connect_ms, time_now_us, time_now_utc};

#[derive(Debug, Clone)]
pub struct TcpServerOptions {
    pub local_ipv4: IpAddr,
    pub local_ipv6: IpAddr,
    pub local_port: u16,
}

pub struct TcpServer {
    pub server_options: TcpServerOptions,
    pub logging_options: LoggingOptions,
    pub listen_options: ListenOptions,
    pub ip_options: IpOptions,
}

impl TcpServer {
    pub async fn listen(&self) -> Result<()> {
        let bind_addr_v4 = format!("{}:{}", self.server_options.local_ipv4, self.server_options.local_port);
        let bind_addr_v6 = format!("{}:{}", self.server_options.local_ipv6, self.server_options.local_port);

        let listener_v4 = TcpListener::bind(&bind_addr_v4).await?;
        let listener_v6 = TcpListener::bind(&bind_addr_v6).await?;

        let (v4_listen, v6_listen) = match self.ip_options.ip_protocol {
            IpProtocol::V4 => (Some(&self.server_options.local_ipv4), None),
            IpProtocol::V6 => (None, Some(&self.server_options.local_ipv6)),
            IpProtocol::All => (
                Some(&self.server_options.local_ipv4),
                Some(&self.server_options.local_ipv6),
            ),
        };

        let start_msg = server_start_msg(
            ConnectMethod::Tcp,
            v4_listen,
            v6_listen,
            &self.server_options.local_port,
        );
        println!("{}", start_msg);

        match self.ip_options.ip_protocol {
            IpProtocol::V4 => {
                listener(listener_v4, &self.listen_options, &self.logging_options).await?;
            }
            IpProtocol::V6 => {
                listener(listener_v6, &self.listen_options, &self.logging_options).await?;
            }
            IpProtocol::All => {
                let listen_options_v4 = self.listen_options;
                let logging_options_v4 = self.logging_options.clone();
                let v4_handle = tokio::spawn(async move {
                    //
                    listener(listener_v4, &listen_options_v4, &logging_options_v4).await
                });

                let listen_options_v6 = self.listen_options;
                let logging_options_v6 = self.logging_options.clone();
                let v6_handle = tokio::spawn(async move {
                    //
                    listener(listener_v6, &listen_options_v6, &logging_options_v6).await
                });

                // Wait for both listeners to complete (they should run indefinitely)
                let (v4_result, v6_result) = tokio::join!(v4_handle, v6_handle);
                v4_result??;
                v6_result??;
            }
        }

        Ok(())
    }
}
async fn listener(
    tcp_listener: TcpListener,
    listen_options: &ListenOptions,
    logging_options: &LoggingOptions,
) -> Result<()> {
    loop {
        let (mut stream, _) = tcp_listener.accept().await?;
        let logging_options = logging_options.clone();
        let listen_options = *listen_options;

        tokio::spawn(async move {
            let receive_time_utc = time_now_utc();
            let receive_time_stamp = time_now_us();

            let mut buffer = vec![0u8; MAX_PACKET_SIZE];

            let (mut reader, mut writer) = stream.split();
            let len = reader.read(&mut buffer).await?;
            buffer.truncate(len);
            let mut client_server_time = 0.0;

            match listen_options.nk_peer && len > 0 {
                false => {
                    writer.write_all(&buffer).await?;
                }
                true => {
                    let data_string = &String::from_utf8_lossy(&buffer);
                    match nk_msg_reader(data_string) {
                        Some(mut m) => {
                            let connection_time = calc_connect_ms(m.send_timestamp, receive_time_stamp);
                            client_server_time = connection_time;

                            m.receive_time_utc = receive_time_utc;
                            m.receive_timestamp = receive_time_stamp;
                            m.one_way_time_ms = connection_time;

                            let json_message = serde_json::to_string(&m)?;
                            writer.write_all(json_message.as_bytes()).await?;
                        }
                        None => writer.write_all(data_string.as_bytes()).await?,
                    }
                }
            }

            let msg = server_conn_success_msg(
                ConnectResult::Success(ConnectSuccess::Ping),
                ConnectMethod::Tcp,
                &stream.peer_addr()?.to_string(),
                &stream.local_addr()?.to_string(),
                client_server_time,
            );
            log_handler(LogLevel::INFO, &msg, &logging_options).await;

            // Flush buffer
            buffer.clear();

            Ok::<(), anyhow::Error>(())
        });
    }
}
