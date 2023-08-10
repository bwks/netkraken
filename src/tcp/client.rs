use std::net::SocketAddr;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::{sleep, Duration};
use uuid::Uuid;

use crate::core::common::{
    ConnectMethod, ConnectResult, HelloMessage, NetKrakenMessage, OutputOptions, PingOptions,
};
use crate::core::konst::{BIND_ADDR, BIND_PORT};
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

        let ping_interval = self.ping_options.interval;

        let uuid = Uuid::new_v4();
        let mut first_loop = true;
        let mut count: u16 = 0;

        ping_header_msg(
            &bind_addr.to_string(),
            &connect_addr.to_string(),
            ConnectMethod::TCP,
        );

        loop {
            // Setting a hard limit on ping repeats to 65535
            if count == u16::MAX {
                println!("max ping count reached");
                break;
            // All messages sent
            } else if self.ping_options.repeat != 0 && count >= self.ping_options.repeat {
                break;
            } else {
                // we don't want to sleep on the first loop, as this slows down
                // the initial execution
                match first_loop {
                    true => first_loop = false,
                    false => sleep(Duration::from_millis(ping_interval.into())).await,
                }
                count += 1;
            }
            let src_socket = get_tcp_socket(bind_addr).await?;

            // record timestamp before connection
            let pre_conn_timestamp = time_now_us()?;

            let mut stream = match tcp_connect(src_socket, connect_addr).await {
                Some(s) => s,
                None => continue,
            };

            // Record timestamp after connection
            let post_conn_timestamp = time_now_us()?;

            // Calculate the round trip time
            let connection_time = calc_connect_ms(pre_conn_timestamp, post_conn_timestamp);

            let local_addr = &stream.local_addr()?.to_string();
            let peer_addr = &stream.peer_addr()?.to_string();

            // Future file logging
            // event!(target: APP_NAME, Level::INFO, "{output} {latency}ms");
            // println!("{} rtt={}ms", output, connection_time);

            // Build a NetKrakenMessage to use as the payload
            // that is sent to the peer.
            let nk_msg = NetKrakenMessage::new(
                &uuid.to_string(),
                &local_addr,
                &peer_addr,
                ConnectMethod::TCP,
            )?;

            let nk_msg_string = serde_json::to_string(&nk_msg)?;
            let (mut reader, mut writer) = stream.split();

            writer.write_all(nk_msg_string.as_bytes()).await?;
            writer.shutdown().await?;

            let mut buffer: Vec<u8> = Vec::with_capacity(64);
            let len = reader.read_to_end(&mut buffer).await?;
            let data_string = &String::from_utf8_lossy(&buffer[..len]);
            // println!("{}", data_string)
            if let Some(mut m) = nk_msg_reader(&data_string) {
                m.rount_trip_time_utc = time_now_utc();
                m.rount_trip_timestamp = time_now_us()?;
                m.rount_trip_time_ms = connection_time;

                // TODO: write nk message to file
                // println!("{:#?}", m)
            }
            client_conn_success_msg(
                ConnectResult::Reply,
                ConnectMethod::TCP,
                &local_addr,
                &peer_addr,
                connection_time,
            );
        }
        Ok(())
    }
}

fn handle_connect_error(error: std::io::Error) {
    match error.kind() {
        std::io::ErrorKind::ConnectionRefused => client_err_msg(ConnectResult::Refused, error),
        std::io::ErrorKind::TimedOut => client_err_msg(ConnectResult::Timeout, error),
        _ => client_err_msg(ConnectResult::Unknown, error),
    }
}

async fn tcp_connect(src_socket: TcpSocket, connect_addr: SocketAddr) -> Option<TcpStream> {
    let stream = match src_socket.connect(connect_addr).await {
        Ok(s) => s,
        Err(e) => {
            handle_connect_error(e);
            return None;
        }
    };
    Some(stream)
}

async fn get_tcp_socket(bind_addr: SocketAddr) -> Result<TcpSocket> {
    let socket = match bind_addr.is_ipv4() {
        true => TcpSocket::new_v4()?,
        false => TcpSocket::new_v6()?,
    };
    socket.bind(bind_addr)?;
    Ok(socket)
}
