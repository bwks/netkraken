use anyhow::Result;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

// use tracing::event;
// use tracing::Level;

use crate::core::common::{ConnectMessage, ConnectMethod, OutputOptions};
// use crate::core::konst::{APP_NAME, BIND_ADDR, BIND_PORT};
use crate::core::konst::{BIND_ADDR, BIND_PORT};
use crate::util::message::get_conn_string;
use crate::util::parser::parse_ipaddr;
use crate::util::time::{time_now_us, time_now_utc};

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

        println!("TCP server listening on {}", &bind_addr);
        println!("Press CRTL+C to exit");
        println!("--------------------");

        loop {
            let json_output_flag = self.output_options.json;
            // Receive stream
            let (mut stream, _) = listener.accept().await?;

            tokio::spawn(async move {
                let mut buffer = Vec::with_capacity(64);

                let (mut reader, mut writer) = stream.split();

                let len = reader.read_to_end(&mut buffer).await?;
                let data_string = &String::from_utf8_lossy(&buffer[..len]);

                println!("{}", data_string);

                // Discover netkracken peer.

                // We only expect to receive a `ConnectMessage` payload from a netkraken peer.
                // For non-netkraken peers we consider any payload to be malformed.
                let mut data: ConnectMessage = match serde_json::from_str(data_string) {
                    Ok(d) => d,
                    Err(_) => {
                        let message = ConnectMessage {
                            source: reader.peer_addr()?.to_string(),
                            destination: reader.local_addr()?.to_string(),
                            malformed: true,
                            ..Default::default()
                        };
                        message
                    }
                };

                // set the receiver timestamps
                data.receive_time_utc = time_now_utc();
                data.receive_timestamp = time_now_us()?;

                let json_data = serde_json::to_string(&data)?;

                // non-netkraken clients
                if data.malformed {
                    let output =
                        get_conn_string(ConnectMethod::TCP, &data.source, &data.destination);

                    // Future file logging
                    // event!(target: APP_NAME, Level::INFO, "{output} -1ms");
                    println!("{} time=-1ms", output)

                // netkraken clients
                } else {
                    if json_output_flag {
                        println!("{json_data}")
                    } else {
                        // Calculate the client -> server latency
                        let latency = match data.send_timestamp > data.receive_timestamp {
                            // if `send_timestamp` is greater than `receive_timestamp` clocks
                            // are not in sync so latency cannot be calculated.
                            true => "-1".to_owned(),
                            false => {
                                // Convert microseconds to milliseconds
                                let us = data.receive_timestamp - data.send_timestamp;
                                format!("{}", us as f64 / 1000.0)
                            }
                        };
                        let output =
                            get_conn_string(ConnectMethod::TCP, &data.source, &data.destination);

                        // Future file logging
                        // event!(target: APP_NAME, Level::INFO, "{output} {latency}ms");
                        println!("{} {} cst={}ms", data.uuid, output, latency);
                    }
                }

                // Send
                let json_message = serde_json::to_string(&data)?;
                writer.write_all(json_message.as_bytes()).await?;

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
