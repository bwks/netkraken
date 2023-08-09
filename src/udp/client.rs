use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;

use tokio::net::UdpSocket;
use tokio::time::{sleep, Duration};

use crate::core::common::{ConnectMethod, ConnectResult, HelloMessage};
use crate::core::common::{OutputOptions, PingOptions};
use crate::core::konst::{BIND_ADDR, BIND_PORT, MAX_PACKET_SIZE};
use crate::util::message::{client_conn_success_msg, ping_header_msg};
use crate::util::parser::parse_ipaddr;
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

        let mut is_nk_peer = false;
        let mut first_loop = true;
        let mut count = 0;

        ping_header_msg(ConnectMethod::UDP, &dst_ip_port_str);

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

            let mut hello_msg = HelloMessage::default();
            hello_msg.ping = true;

            let json_hello = serde_json::to_string(&hello_msg)?;

            // record timestamp before connection
            let pre_conn_timestamp = time_now_us()?;

            writer.connect(dst_ip_port_str.to_owned()).await?;
            writer.send(json_hello.as_bytes()).await?;

            let mut buffer = vec![0u8; MAX_PACKET_SIZE];

            let (len, addr) = reader.recv_from(&mut buffer).await?;

            // Record timestamp after connection
            let post_conn_timestamp = time_now_us()?;

            // Calculate the round trip time
            let connection_time = calc_connect_ms(pre_conn_timestamp, post_conn_timestamp);

            let local_addr = &writer.local_addr()?.to_string();
            let peer_addr = &addr.to_string();

            client_conn_success_msg(
                ConnectResult::Reply,
                ConnectMethod::UDP,
                &local_addr,
                &peer_addr,
                connection_time,
            );

            let data_string = &String::from_utf8_lossy(&buffer[..len]);

            let data: HelloMessage = match serde_json::from_str(data_string) {
                Ok(d) => d,
                Err(_) => {
                    // Not a NetKraken peer
                    continue;
                }
            };
            if data.pong {
                is_nk_peer = true;
                // println!("{:#?}", data)
            }

            // TODO: NK <-> NK connection
            if is_nk_peer {
                // println!("nk peer: {is_nk_peer}");
            }
        }
        Ok(())
    }
}
