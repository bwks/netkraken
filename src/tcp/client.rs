use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;
use tokio::signal;
use tokio::time::{timeout, Duration};
use uuid::Uuid;

use crate::core::common::{
    ConnectMethod, ConnectRecord, ConnectResult, LogLevel, NetKrakenMessage, OutputOptions,
    PingOptions,
};
use crate::core::konst::{BIND_ADDR, BIND_PORT, MAX_PACKET_SIZE};
use crate::util::handler::{loop_handler, output_handler};
use crate::util::message::{client_summary_msg, ping_header_msg};
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

        let mut send_count: u16 = 0;
        let mut received_count: u16 = 0;
        let mut latencies: Vec<f64> = Vec::new();

        let ping_header = ping_header_msg(
            &bind_addr.to_string(),
            &connect_addr.to_string(),
            ConnectMethod::TCP,
        );
        println!("{ping_header}");

        let cancel = Arc::new(AtomicBool::new(false));
        let c = cancel.clone();
        tokio::spawn(async move {
            signal::ctrl_c().await.unwrap();
            // Your handler here
            c.store(true, Ordering::SeqCst);
        });

        loop {
            if cancel.load(Ordering::SeqCst) {
                break;
            }
            match loop_handler(count, self.ping_options.repeat, self.ping_options.interval).await {
                true => break,
                false => count += 1,
            }

            let src_socket = get_tcp_socket(bind_addr).await?;
            let local_addr = src_socket.local_addr()?.to_string();

            let mut conn_record = ConnectRecord {
                result: ConnectResult::Unknown,
                protocol: ConnectMethod::TCP,
                source: local_addr,
                destination: connect_addr.to_string(),
                time: -1.0,
            };

            // record timestamp before connection
            let pre_conn_timestamp = time_now_us()?;
            send_count += 1;

            let tick = Duration::from_millis(self.ping_options.timeout.into());
            let mut stream = match timeout(tick, src_socket.connect(connect_addr)).await {
                Ok(s) => match s {
                    Ok(s) => {
                        received_count += 1;
                        s
                    }
                    Err(e) => {
                        output_handler(
                            LogLevel::ERROR,
                            &conn_record.client_error_msg(e.into()),
                            &self.output_options,
                        )
                        .await;

                        continue;
                    }
                },
                Err(e) => {
                    output_handler(
                        LogLevel::ERROR,
                        &conn_record.client_error_msg(e.into()),
                        &self.output_options,
                    )
                    .await;

                    continue;
                }
            };

            let local_addr = &stream.local_addr()?.to_string();
            let peer_addr = &stream.peer_addr()?.to_string();

            conn_record.source = local_addr.to_string();

            let mut nk_msg = NetKrakenMessage::new(
                &uuid.to_string(),
                &local_addr,
                &peer_addr,
                ConnectMethod::TCP,
            )?;
            nk_msg.uuid = uuid.to_string();

            let payload = nk_msg.to_json()?;
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
                    conn_record.result = ConnectResult::Pong;
                    conn_record.time = connection_time;
                    latencies.push(connection_time);

                    if len > 0 {
                        let data_string = &String::from_utf8_lossy(&buffer[..len]);

                        if let Some(mut m) = nk_msg_reader(&data_string) {
                            m.round_trip_time_utc = time_now_utc();
                            m.round_trip_timestamp = time_now_us()?;
                            m.round_trip_time_ms = connection_time;
                        }
                        // TODO: Do something with nk message
                    }
                    output_handler(
                        LogLevel::INFO,
                        &conn_record.client_success_msg(),
                        &self.output_options,
                    )
                    .await;
                }
                Err(e) => {
                    output_handler(
                        LogLevel::ERROR,
                        &conn_record.client_error_msg(e),
                        &self.output_options,
                    )
                    .await;
                }
            }
        }

        let summary_msg = client_summary_msg(
            &connect_addr.to_string(),
            ConnectMethod::TCP,
            send_count,
            received_count,
            latencies,
        );
        println!("{}", summary_msg);

        Ok(())
    }
}

async fn get_tcp_socket(bind_addr: SocketAddr) -> Result<TcpSocket> {
    let socket = match bind_addr.is_ipv4() {
        true => TcpSocket::new_v4()?,
        false => TcpSocket::new_v6()?,
    };
    socket.bind(bind_addr)?;
    Ok(socket)
}
