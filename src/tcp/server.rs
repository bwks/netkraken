use anyhow::Result;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use crate::core::common::{ConnectMethod, ConnectResult, ListenOptions, LogLevel, LoggingOptions};
use crate::core::konst::{BIND_ADDR_IPV4, BIND_PORT, MAX_PACKET_SIZE};
use crate::util::handler::log_handler;
use crate::util::message::{server_conn_success_msg, server_start_msg};
use crate::util::parser::{nk_msg_reader, parse_ipaddr};
use crate::util::time::{calc_connect_ms, time_now_us, time_now_utc};

pub struct TcpServer {
    pub listen_ip: String,
    pub listen_port: u16,
    pub logging_options: LoggingOptions,
    pub listen_options: ListenOptions,
}

impl TcpServer {
    pub async fn listen(&self) -> Result<()> {
        let listen_ip = parse_ipaddr(&self.listen_ip)?;

        let bind_addr = format!("{}:{}", listen_ip, self.listen_port);

        let listener = TcpListener::bind(&bind_addr).await?;

        let start_msg = server_start_msg(ConnectMethod::TCP, &listen_ip, &self.listen_port);
        println!("{}", start_msg);

        loop {
            let logging_options = self.logging_options.clone();
            let listen_options = self.listen_options;
            // Receive stream
            let (mut stream, _) = listener.accept().await?;

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
                                m.nk_peer = true;

                                println!("{:#?}", m);

                                let json_message = serde_json::to_string(&m)?;
                                writer.write_all(json_message.as_bytes()).await?;
                            }
                            None => writer.write_all(data_string.as_bytes()).await?,
                        }
                    }
                }

                let msg = server_conn_success_msg(
                    ConnectResult::Ping,
                    ConnectMethod::TCP,
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
}

impl Default for TcpServer {
    fn default() -> Self {
        Self {
            listen_ip: BIND_ADDR_IPV4.to_owned(),
            listen_port: BIND_PORT,
            logging_options: LoggingOptions::default(),
            listen_options: ListenOptions::default(),
        }
    }
}
