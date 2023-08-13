use std::net::SocketAddr;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;
use tokio::time::{timeout, Duration};
use tracing::event;
use tracing::Level;
use uuid::Uuid;

use crate::core::common::{
    ConnectMethod, ConnectResult, NetKrakenMessage, OutputOptions, PingOptions,
};
use crate::core::konst::{APP_NAME, BIND_ADDR, BIND_PORT, MAX_PACKET_SIZE};
use crate::util::handler::loop_handler;
use crate::util::message::{client_conn_success_msg, client_err_msg, ping_header_msg};
use crate::util::parser::{nk_msg_reader, parse_ipaddr};
use crate::util::time::{calc_connect_ms, time_now_us, time_now_utc};

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
        let mut count: u16 = 0;

        ping_header_msg(
            &bind_addr.to_string(),
            &connect_addr.to_string(),
            ConnectMethod::TCP,
        );

        loop {
            match loop_handler(count, self.ping_options.repeat, self.ping_options.interval).await {
                true => break,
                false => count += 1,
            }

            let src_socket = get_tcp_socket(bind_addr).await?;
            let local_addr = src_socket.local_addr()?.to_string();

            // record timestamp before connection
            let pre_conn_timestamp = time_now_us()?;

            let tick = Duration::from_millis(self.ping_options.timeout.into());
            let mut stream = match timeout(tick, src_socket.connect(connect_addr)).await {
                Ok(s) => match s {
                    Ok(s) => s,
                    Err(e) => {
                        let msg = handle_connect_error(e, local_addr, connect_addr.to_string());
                        if !self.output_options.quiet {
                            println!("{msg}");
                        }
                        if self.output_options.syslog {
                            event!(target: APP_NAME, Level::ERROR, "{msg}");
                        }
                        continue;
                    }
                },
                Err(e) => {
                    let msg = client_err_msg(
                        ConnectResult::Timeout,
                        ConnectMethod::TCP,
                        &bind_addr.to_string(),
                        &connect_addr.to_string(),
                        e.into(),
                    );
                    if !self.output_options.quiet {
                        println!("{msg}");
                    }
                    if self.output_options.syslog {
                        event!(target: APP_NAME, Level::ERROR, "{msg}");
                    }
                    continue;
                }
            };

            let local_addr = &stream.local_addr()?.to_string();
            let peer_addr = &stream.peer_addr()?.to_string();

            let mut nk_msg = NetKrakenMessage::new(
                &uuid.to_string(),
                &local_addr,
                &peer_addr,
                ConnectMethod::TCP,
            )?;
            nk_msg.uuid = uuid.to_string();

            let payload = serde_json::to_string(&nk_msg)?;
            let (mut reader, mut writer) = stream.split();

            // Send payload to peer
            writer.write_all(payload.as_bytes()).await?;
            writer.shutdown().await?;

            // Wait for reply
            let mut buffer = vec![0u8; MAX_PACKET_SIZE];

            match reader.read_to_end(&mut buffer).await {
                Ok(len) => {
                    // Record timestamp after connection
                    let post_conn_timestamp = time_now_us()?;

                    // Calculate the round trip time
                    let connection_time = calc_connect_ms(pre_conn_timestamp, post_conn_timestamp);

                    let local_addr = &writer.local_addr()?.to_string();
                    let peer_addr = &reader.peer_addr()?.to_string();

                    if len > 0 {
                        let data_string = &String::from_utf8_lossy(&buffer[..len]);

                        if let Some(mut m) = nk_msg_reader(&data_string) {
                            m.round_trip_time_utc = time_now_utc();
                            m.round_trip_timestamp = time_now_us()?;
                            m.round_trip_time_ms = connection_time;
                        }
                        let msg = client_conn_success_msg(
                            ConnectResult::Pong,
                            ConnectMethod::TCP,
                            &local_addr,
                            &peer_addr,
                            connection_time,
                        );
                        if !self.output_options.quiet {
                            println!("{msg}");
                        }
                        if self.output_options.syslog {
                            event!(target: APP_NAME, Level::INFO, "{msg}");
                        }
                        if self.output_options.json {
                            // handle json output
                        }
                    }
                }
                Err(e) => {
                    let msg = client_err_msg(
                        ConnectResult::Timeout,
                        ConnectMethod::TCP,
                        &local_addr,
                        &peer_addr,
                        e.into(),
                    );
                    if !self.output_options.quiet {
                        println!("{msg}");
                    }
                    if self.output_options.syslog {
                        event!(target: APP_NAME, Level::ERROR, "{msg}");
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn handle_connect_error(error: std::io::Error, source: String, destination: String) -> String {
    let err = match error.kind() {
        std::io::ErrorKind::ConnectionRefused => ConnectResult::Refused,
        std::io::ErrorKind::TimedOut => ConnectResult::Timeout,
        _ => ConnectResult::Unknown,
    };
    client_err_msg(err, ConnectMethod::TCP, &source, &destination, error)
}

async fn get_tcp_socket(bind_addr: SocketAddr) -> Result<TcpSocket> {
    let socket = match bind_addr.is_ipv4() {
        true => TcpSocket::new_v4()?,
        false => TcpSocket::new_v6()?,
    };
    socket.bind(bind_addr)?;
    Ok(socket)
}
