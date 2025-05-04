use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::core::common::{
    ConnectMethod, ConnectResult, ConnectSuccess, IpOptions, IpProtocol, ListenOptions, LogLevel, LoggingOptions,
};
use crate::core::konst::MAX_PACKET_SIZE;
use crate::util::handler::log_handler;
use crate::util::message::{server_conn_success_msg, server_start_msg};
use crate::util::parser::nk_msg_reader;
use crate::util::time::{calc_connect_ms, time_now_us, time_now_utc};

#[derive(Debug, Clone)]
pub struct UdpServerOptions {
    pub local_ipv4: IpAddr,
    pub local_ipv6: IpAddr,
    pub local_port: u16,
}

pub struct UdpServer {
    pub server_options: UdpServerOptions,
    pub logging_options: LoggingOptions,
    pub listen_options: ListenOptions,
    pub ip_options: IpOptions,
}

impl UdpServer {
    pub async fn listen(&self) -> Result<()> {
        let bind_addr_v4 = format!("{}:{}", self.server_options.local_ipv4, self.server_options.local_port);
        let bind_addr_v6 = format!("{}:{}", self.server_options.local_ipv6, self.server_options.local_port);

        let listener_v4 = UdpSocket::bind(&bind_addr_v4).await?;
        let listener_v6 = UdpSocket::bind(&bind_addr_v6).await?;

        let (v4_listen, v6_listen) = match self.ip_options.ip_protocol {
            IpProtocol::V4 => (Some(&self.server_options.local_ipv4), None),
            IpProtocol::V6 => (None, Some(&self.server_options.local_ipv6)),
            IpProtocol::All => (
                Some(&self.server_options.local_ipv4),
                Some(&self.server_options.local_ipv6),
            ),
        };

        let start_msg = server_start_msg(
            ConnectMethod::Udp,
            v4_listen,
            v6_listen,
            &self.server_options.local_port,
        );
        println!("{}", start_msg);

        match self.ip_options.ip_protocol {
            IpProtocol::V4 => {
                listener(listener_v4, &self.listen_options, &self.logging_options).await?;
            }
            IpProtocol::V6 => {
                listener(listener_v6, &self.listen_options, &self.logging_options).await?;
            }
            IpProtocol::All => {
                listener(listener_v4, &self.listen_options, &self.logging_options).await?;
                listener(listener_v6, &self.listen_options, &self.logging_options).await?;
            }
        }
        Ok(())
    }
}

async fn listener(
    udp_socket: UdpSocket,
    listen_options: &ListenOptions,
    logging_options: &LoggingOptions,
) -> Result<()> {
    let reader = Arc::new(udp_socket);
    let writer = reader.clone();
    let (tx_chan, mut rx_chan) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1);

    tokio::spawn(async move {
        while let Some((bytes, addr)) = rx_chan.recv().await {
            writer.send_to(&bytes, &addr).await?;
        }
        Ok::<(), anyhow::Error>(())
    });

    loop {
        let mut buffer = vec![0u8; MAX_PACKET_SIZE];
        let (len, addr) = match reader.recv_from(&mut buffer).await {
            Ok((len, addr)) => (len, addr),
            Err(e) => {
                // Received some kind of connection error
                // known errors: ConnectionRest by peer
                println!("{}", e.kind());
                continue;
            }
        };

        buffer.truncate(len);

        let receive_time_utc = time_now_utc();
        let receive_time_stamp = time_now_us();
        let local_addr = &reader.local_addr()?.to_string();
        let peer_addr = &addr.to_string();

        // Add echo handler
        let mut client_server_time = 0.0;

        match listen_options.nk_peer && len > 0 {
            false => {
                tx_chan.send((buffer.clone(), addr)).await?;
            }
            true => {
                let data_string = &String::from_utf8_lossy(&buffer);

                match nk_msg_reader(data_string) {
                    Some(mut m) => {
                        let connection_time = calc_connect_ms(m.send_timestamp, receive_time_stamp);
                        client_server_time = connection_time;

                        m.receive_time_utc = receive_time_utc;
                        m.receive_timestamp = receive_time_stamp;
                        m.one_way_time_ms = connection_time;
                        m.nk_peer = true;

                        let json_message = serde_json::to_string(&m)?;
                        tx_chan.send((json_message.as_bytes().to_vec(), addr)).await?;
                    }
                    None => tx_chan.send((buffer.clone(), addr)).await?,
                }
            }
        }

        let msg = server_conn_success_msg(
            ConnectResult::Success(ConnectSuccess::Ping),
            ConnectMethod::Udp,
            peer_addr,
            local_addr,
            client_server_time,
        );
        log_handler(LogLevel::INFO, &msg, logging_options).await;
    }
}
