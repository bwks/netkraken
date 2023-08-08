use std::net::SocketAddr;

use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::{sleep, Duration};
use uuid::Uuid;

use crate::core::common::{
    ConnectMessage, ConnectMethod, HelloMessage, OutputOptions, PingOptions,
};
use crate::core::konst::{BIND_ADDR, BIND_PORT};
use crate::util::message::{
    client_conn_success_msg, client_err_msg, get_conn_string, ping_header_msg,
};
use crate::util::parser::parse_ipaddr;
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
        let ping_interval = self.ping_options.interval.into();
        let nk_peer_discovery = self.ping_options.discover;

        let mut is_nk_peer = false;
        let uuid = Uuid::new_v4();
        let mut count: u16 = 0;

        ping_header_msg(ConnectMethod::TCP, connect_addr.to_string());

        loop {
            if count == u16::MAX {
                println!("max ping count reached");
                break;
            } else if self.ping_options.repeat != 0 && count >= self.ping_options.repeat {
                break;
            } else {
                sleep(Duration::from_millis(ping_interval)).await;
                count += 1;
            }

            let socket = match src_addr.is_ipv4() {
                true => TcpSocket::new_v4()?,
                false => TcpSocket::new_v6()?,
            };
            socket.bind(bind_addr)?;

            // record timestamp before connection
            let pre_conn_timestamp = time_now_us()?;

            let mut stream = match socket.connect(connect_addr).await {
                Ok(s) => s,
                Err(e) => match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => {
                        client_err_msg(count, "connection refused");
                        continue;
                    }
                    std::io::ErrorKind::TimedOut => {
                        client_err_msg(count, "connection timeout");
                        continue;
                    }
                    _ => bail!(e),
                },
            };

            // Record timestamp after connection
            let post_conn_timestamp = time_now_us()?;

            // Calculate the round trip time
            let connection_time = calc_connect_ms(pre_conn_timestamp, post_conn_timestamp);

            let local_addr = &stream.local_addr()?.to_string();
            let peer_addr = &stream.peer_addr()?.to_string();

            client_conn_success_msg(
                count,
                ConnectMethod::TCP,
                &local_addr,
                &peer_addr,
                connection_time,
            );

            // Future file logging
            // event!(target: APP_NAME, Level::INFO, "{output} {latency}ms");
            // println!("{} rtt={}ms", output, connection_time);

            // Discover NetKraken peer.
            if nk_peer_discovery {
                // println!("connected from: {} to: {}", local_addr, peer_addr);
                println!("warming up");

                let mut hello_msg = HelloMessage::default();
                hello_msg.ping = true;
                // send and handle hello message

                let json_hello = serde_json::to_string(&hello_msg)?;
                let (mut reader, mut writer) = stream.split();

                writer.write_all(json_hello.as_bytes()).await?;
                writer.shutdown().await?;

                let mut buffer: Vec<u8> = Vec::with_capacity(64);
                let len = reader.read_to_end(&mut buffer).await?;
                let data_string = &String::from_utf8_lossy(&buffer[..len]);

                // println!("{}", data_string);

                let data: HelloMessage = serde_json::from_str(data_string)?;
                println!("{:#?}", data);
            }

            /* TODO: NK <-> NK connection



            let mut connect_message = ConnectMessage::new(
                &stream.local_addr()?.to_string(),
                &stream.peer_addr()?.to_string(),
                ConnectMethod::TCP,
            )?;

            connect_message.uuid = uuid.to_string();
            let json_message = serde_json::to_string(&connect_message)?;

            let (mut reader, mut writer) = stream.split();

            writer.write_all(json_message.as_bytes()).await?;
            writer.shutdown().await?;

            // read
            let mut buffer: Vec<u8> = Vec::with_capacity(64);
            let len = reader.read_to_end(&mut buffer).await?;
            let data_string = &String::from_utf8_lossy(&buffer[..len]);

            // println!("{}", data_string);

            let mut data: ConnectMessage = serde_json::from_str(data_string)?;

            data.rtt_time_utc = time_now_utc();
            data.rtt_timestamp = time_now_us()?;

            // Calculate the client -> server latency
            let latency = match data.send_timestamp > data.rtt_timestamp {
                // if `send_timestamp` is greater than `receive_timestamp` clocks
                // are not in sync so latency cannot be calculated.
                true => "-1".to_owned(),
                false => {
                    // Convert microseconds to milliseconds
                    let us = data.rtt_timestamp - data.send_timestamp;
                    format!("{}", us as f64 / 1000.0)
                }
            };

            let output = get_conn_string(ConnectMethod::TCP, &data.source, &data.destination);

            // Future file logging
            // event!(target: APP_NAME, Level::INFO, "{output} {latency}ms");
            println!("{} {} {}ms", data.uuid, output, latency);

             */
        }
        Ok(())
    }
}
