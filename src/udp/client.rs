use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;

use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout, Duration};
use uuid::Uuid;

use crate::core::common::{ConnectMethod, ConnectResult, NetKrakenMessage};
use crate::core::common::{OutputOptions, PingOptions};
use crate::core::konst::{BIND_ADDR, BIND_PORT, MAX_PACKET_SIZE};
use crate::util::message::{client_conn_success_msg, client_err_msg, ping_header_msg};
use crate::util::parser::{hello_msg_reader, parse_ipaddr};
use crate::util::time::{calc_connect_ms, time_now_us};

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
        let dst_ip_port_str = format!("{}:{}", self.dst_addr, self.dst_port);

        let bind_addr = SocketAddr::new(src_addr, self.src_port);

        let ping_interval = self.ping_options.interval;

        let uuid = Uuid::new_v4();
        let mut first_loop = true;
        let mut count = 0;

        ping_header_msg(&bind_addr.to_string(), &dst_ip_port_str, ConnectMethod::UDP);

        loop {
            if count == u16::MAX {
                println!("max ping count reached");
                break;
            } else if self.ping_options.repeat != 0 && count >= self.ping_options.repeat {
                break;
            } else {
                match first_loop {
                    true => first_loop = false,
                    false => sleep(Duration::from_millis(ping_interval.into())).await,
                }
                count += 1;
            }

            let socket = UdpSocket::bind(bind_addr).await?;

            let reader = Arc::new(socket);
            let writer = reader.clone();

            let mut nk_msg = NetKrakenMessage::new(
                &uuid.to_string(),
                &reader.local_addr()?.to_string(),
                &dst_ip_port_str,
                ConnectMethod::TCP,
            )?;
            nk_msg.uuid = uuid.to_string();

            let payload = serde_json::to_string(&nk_msg)?;

            // record timestamp before connection
            let pre_conn_timestamp = time_now_us()?;

            writer.connect(dst_ip_port_str.to_owned()).await?;
            writer.send(payload.as_bytes()).await?;

            // Wait for a reply
            let my_duration = tokio::time::Duration::from_millis(ping_interval.into());
            let mut buffer = vec![0u8; MAX_PACKET_SIZE];

            match timeout(my_duration, reader.recv_from(&mut buffer)).await {
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
                    }
                }
                Err(e) => client_err_msg(ConnectResult::Timeout, e.into()),
            }
        }
        Ok(())
    }
}
