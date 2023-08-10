use anyhow::Result;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

// use tracing::event;
// use tracing::Level;

use crate::core::common::{ConnectMethod, ConnectResult, OutputOptions};
use crate::core::konst::{BIND_ADDR, BIND_PORT};
use crate::util::message::{server_conn_success_msg, server_start_msg};
use crate::util::parser::{nk_msg_reader, parse_ipaddr};
use crate::util::time::{calc_connect_ms, time_now_us, time_now_utc};

pub struct TcpServer {
    pub listen_addr: String,
    pub listen_port: u16,
    pub output_options: OutputOptions,
}

impl TcpServer {
    pub async fn listen(&self) -> Result<()> {
        let listen_addr = parse_ipaddr(&self.listen_addr)?;
        let bind_addr = format!("{}:{}", listen_addr, self.listen_port);

        let listener = TcpListener::bind(&bind_addr).await?;

        server_start_msg(ConnectMethod::TCP, &bind_addr);

        loop {
            let _json_output_flag = self.output_options.json;
            // Receive stream
            let (mut stream, _) = listener.accept().await?;

            let echo = self.output_options.echo;
            tokio::spawn(async move {
                let receive_time_utc = time_now_utc();
                let receive_time_stamp = time_now_us()?;

                let mut buffer = Vec::with_capacity(64);

                let (mut reader, mut writer) = stream.split();

                let len = reader.read_to_end(&mut buffer).await?;
                let data_string = &String::from_utf8_lossy(&buffer[..len]);

                // Add echo handler
                if echo && len > 0 {
                    writer.write_all(data_string.as_bytes()).await?;
                } else {
                    // Discover NetKracken peer.
                    match nk_msg_reader(&data_string) {
                        Some(mut m) => {
                            let connection_time =
                                calc_connect_ms(m.send_timestamp, receive_time_stamp);

                            m.receive_time_utc = receive_time_utc;
                            m.receive_timestamp = receive_time_stamp;
                            m.client_server_time = connection_time;

                            // println!("{:#?}", m);

                            let json_message = serde_json::to_string(&m)?;
                            writer.write_all(json_message.as_bytes()).await?;
                        }
                        None => writer.write_all(data_string.as_bytes()).await?,
                    }
                }
                server_conn_success_msg(
                    ConnectResult::Received,
                    ConnectMethod::TCP,
                    &stream.peer_addr()?.to_string(),
                    &stream.local_addr()?.to_string(),
                );

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
            listen_addr: BIND_ADDR.to_owned(),
            listen_port: BIND_PORT,
            output_options: OutputOptions::default(),
        }
    }
}
