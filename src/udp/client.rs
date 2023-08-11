use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;

use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout, Duration};
use uuid::Uuid;

use crate::core::common::{ConnectMethod, ConnectResult, NetKrakenMessage};
use crate::core::common::{OutputOptions, PingOptions};
use crate::core::konst::{BIND_ADDR, BIND_PORT, MAX_PACKET_SIZE};
use crate::util::message::{client_conn_success_msg, client_err_msg, ping_header_msg};
use crate::util::parser::{nk_msg_reader, parse_ipaddr};
use crate::util::time::{calc_connect_ms, time_now_us, time_now_utc};

pub struct UdpClient {
    pub dst_addr: String,
    pub dst_port: u16,
    pub src_addr: String,
    pub src_port: u16,
    pub output_options: OutputOptions,
    pub ping_options: PingOptions,
}

impl UdpClient {
    pub fn new(
        dst_addr: String,
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
        let peer_addr = SocketAddr::new(dst_addr, self.dst_port);

        let ping_interval = self.ping_options.interval;
        let ping_timeout = self.ping_options.timeout;

        let uuid = Uuid::new_v4();
        let mut first_loop = true;
        let mut count = 0;

        ping_header_msg(
            &bind_addr.to_string(),
            &peer_addr.to_string(),
            ConnectMethod::UDP,
        );

        loop {
            match loop_handler(count, self.ping_options.repeat, self.ping_options.interval).await {
                true => break,

                false => count += 1,
            }

            let socket = UdpSocket::bind(bind_addr).await?;

            let reader = Arc::new(socket);
            let writer = reader.clone();

            let mut nk_msg = NetKrakenMessage::new(
                &uuid.to_string(),
                &reader.local_addr()?.to_string(),
                &peer_addr.to_string(),
                ConnectMethod::UDP,
            )?;
            nk_msg.uuid = uuid.to_string();

            let payload = serde_json::to_string(&nk_msg)?;

            // record timestamp before connection
            let pre_conn_timestamp = time_now_us()?;

            writer.connect(peer_addr).await?;
            writer.send(payload.as_bytes()).await?;

            // Wait for a reply
            let tick = Duration::from_millis(ping_timeout.into());
            let mut buffer = vec![0u8; MAX_PACKET_SIZE];

            match timeout(tick, reader.recv_from(&mut buffer)).await {
                Ok(result) => {
                    if let Ok((len, addr)) = result {
                        // Record timestamp after connection
                        let post_conn_timestamp = time_now_us()?;

                        // Calculate the round trip time
                        let connection_time =
                            calc_connect_ms(pre_conn_timestamp, post_conn_timestamp);

                        let local_addr = &writer.local_addr()?.to_string();
                        let peer_addr = &addr.to_string();

                        client_conn_success_msg(
                            ConnectResult::Pong,
                            ConnectMethod::UDP,
                            &local_addr,
                            &peer_addr,
                            connection_time,
                        );

                        let data_string = &String::from_utf8_lossy(&buffer[..len]);

                        // Handle connection to a NetKraken peer
                        if let Some(mut m) = nk_msg_reader(&data_string) {
                            m.round_trip_time_utc = time_now_utc();
                            m.round_trip_timestamp = time_now_us()?;
                            m.round_trip_time_ms = connection_time;

                            // TODO: write nk message to file
                            println!("{:#?}", m)
                        }
                    }
                }
                Err(e) => client_err_msg(ConnectResult::Timeout, e.into()),
            }
        }
        Ok(())
    }
}

async fn loop_handler(count: u16, repeat: u16, sleep_interval: u16) -> bool {
    if count == u16::MAX {
        println!("max ping count reached");
        return true;
    } else if repeat != 0 && count >= repeat {
        return true;
    } else {
        if count > 0 {
            sleep(Duration::from_millis(sleep_interval.into())).await;
        }
        return false;
    }
}
