use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::signal;
use tokio::time::{timeout, Duration};
use uuid::Uuid;

use crate::core::common::{
    ClientSummary, ConnectMethod, ConnectRecord, ConnectResult, LogLevel, NetKrakenMessage,
};
use crate::core::common::{OutputOptions, PingOptions};
use crate::core::konst::{BIND_ADDR, BIND_PORT, MAX_PACKET_SIZE, PING_MSG};
use crate::util::handler::{loop_handler, output_handler};
use crate::util::message::{client_summary_msg, ping_header_msg};
use crate::util::parser::{nk_msg_reader, parse_ipaddr};
use crate::util::time::{calc_connect_ms, time_now_us, time_now_utc};

pub struct UdpClient {
    pub dst_ip: String,
    pub dst_port: u16,
    pub src_addr: String,
    pub src_port: u16,
    pub output_options: OutputOptions,
    pub ping_options: PingOptions,
}

impl UdpClient {
    pub fn new(
        dst_ip: String,
        dst_port: u16,
        src_addr: Option<String>,
        src_port: Option<u16>,
        output_options: OutputOptions,
        ping_options: PingOptions,
    ) -> UdpClient {
        let src_addr = match src_addr {
            Some(x) => x,
            None => BIND_ADDR.to_owned(),
        };
        let src_port = match src_port {
            Some(x) => x,
            None => BIND_PORT,
        };
        UdpClient {
            dst_ip,
            dst_port,
            src_addr,
            src_port,
            output_options,
            ping_options,
        }
    }

    pub async fn connect(&self) -> Result<()> {
        let src_addr = parse_ipaddr(&self.src_addr)?;
        let dst_ip = parse_ipaddr(&self.dst_ip)?;

        let bind_addr = SocketAddr::new(src_addr, self.src_port);
        let peer_addr = SocketAddr::new(dst_ip, self.dst_port);

        let uuid = Uuid::new_v4();
        let mut count = 0;

        let mut send_count: u16 = 0;
        let mut received_count: u16 = 0;
        let mut latencies: Vec<f64> = Vec::new();

        let ping_header = ping_header_msg(&peer_addr.to_string(), ConnectMethod::UDP);
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

            let socket = UdpSocket::bind(bind_addr).await?;

            let reader = Arc::new(socket);
            let writer = reader.clone();

            let mut conn_record = ConnectRecord {
                result: ConnectResult::Unknown,
                protocol: ConnectMethod::UDP,
                source: writer.local_addr()?.to_string().to_owned(),
                destination: peer_addr.to_string().to_owned(),
                time: -1.0,
                success: false,
                error_msg: None,
            };

            // record timestamp before connection
            let pre_conn_timestamp = time_now_us();
            send_count += 1;
            writer.connect(peer_addr).await?;

            match self.ping_options.nk_peer_messaging {
                false => {
                    writer.send(PING_MSG.as_bytes()).await?;
                }
                true => {
                    let mut nk_msg = NetKrakenMessage::new(
                        &uuid.to_string(),
                        &writer.local_addr()?.to_string(),
                        &peer_addr.to_string(),
                        ConnectMethod::UDP,
                    )?;
                    nk_msg.uuid = uuid.to_string();

                    let payload = serde_json::to_string(&nk_msg)?;

                    writer.send(payload.as_bytes()).await?;
                }
            }

            // Wait for a reply
            let tick = Duration::from_millis(self.ping_options.timeout.into());
            let mut buffer = vec![0u8; MAX_PACKET_SIZE];

            match timeout(tick, reader.recv_from(&mut buffer)).await {
                Ok(result) => {
                    if let Ok((len, _addr)) = result {
                        received_count += 1;

                        // Record timestamp after connection
                        let post_conn_timestamp = time_now_us();

                        // Calculate the round trip time
                        let connection_time =
                            calc_connect_ms(pre_conn_timestamp, post_conn_timestamp);

                        conn_record.result = ConnectResult::Pong;
                        conn_record.time = connection_time;
                        latencies.push(connection_time);

                        if self.ping_options.nk_peer_messaging && len > 0 {
                            let data_string = &String::from_utf8_lossy(&buffer[..len]);

                            // Handle connection to a NetKraken peer
                            if let Some(mut m) = nk_msg_reader(data_string) {
                                m.round_trip_time_utc = time_now_utc();
                                m.round_trip_timestamp = time_now_us();
                                m.round_trip_time_ms = connection_time;

                                // TODO: Do something with nk message
                                // println!("{:#?}", m);
                            }
                        }

                        output_handler(
                            LogLevel::INFO,
                            &conn_record.client_success_msg(),
                            &self.output_options,
                        )
                        .await;
                    }
                }
                Err(e) => {
                    conn_record.result = ConnectResult::Timeout;
                    output_handler(
                        LogLevel::ERROR,
                        &conn_record.client_error_msg(e.into()),
                        &self.output_options,
                    )
                    .await;
                }
            }
        }

        let client_summary = ClientSummary {
            send_count,
            received_count,
            latencies,
        };
        let summary_msg =
            client_summary_msg(&peer_addr.to_string(), ConnectMethod::UDP, client_summary);
        println!("{}", summary_msg);

        Ok(())
    }
}
