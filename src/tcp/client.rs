use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use futures::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::signal;
use tokio::time::{timeout, Duration};
use uuid::Uuid;

use crate::core::common::{
    ClientSummary, ConnectMethod, ConnectRecord, ConnectResult, HostRecord, LogLevel,
    NetKrakenMessage, OutputOptions, PingOptions,
};
use crate::core::konst::{BIND_ADDR, BIND_PORT, MAX_PACKET_SIZE};
use crate::util::handler::{loop_handler, output_handler, output_handler2};
use crate::util::message::{client_summary_msg, ping_header_msg};
use crate::util::parser::{nk_msg_reader, parse_ipaddr};
use crate::util::time::{calc_connect_ms, time_now_us, time_now_utc};

const BUFFER_SIZE: usize = 100;

#[derive(Debug, Clone)]
struct IpPort {
    ip: IpAddr,
    port: u16,
}

#[derive(Debug, Clone)]
pub struct HostConnection {
    pub socket: String,
    pub is_open: bool,
}

#[derive(Debug, Clone)]
pub struct HostResults {
    pub host: String,
    results: Vec<ConnectRecord>,
}

#[derive(Debug)]
pub struct TcpClient {
    pub dst_ip: String,
    pub dst_port: u16,
    pub src_ip: String,
    pub src_port: u16,
    pub output_options: OutputOptions,
    pub ping_options: PingOptions,
}

impl TcpClient {
    pub fn new(
        dst_ip: String,
        dst_port: u16,
        src_ip: Option<String>,
        src_port: Option<u16>,
        output_options: OutputOptions,
        ping_options: PingOptions,
    ) -> TcpClient {
        let src_ip = match src_ip {
            Some(x) => x,
            None => BIND_ADDR.to_owned(),
        };
        let src_port = match src_port {
            Some(x) => x,
            None => BIND_PORT,
        };
        TcpClient {
            dst_ip,
            dst_port,
            src_ip,
            src_port,
            output_options,
            ping_options,
        }
    }

    pub async fn connect(&self) -> Result<()> {
        let src_ip_port = IpPort {
            ip: parse_ipaddr(&self.src_ip)?,
            port: self.src_port,
        };

        let host_records = HostRecord::new(&self.dst_ip, self.dst_port).await;
        println!("{}", host_records);

        let hosts = vec![host_records.clone()];

        let lookup_data: Vec<HostRecord> = futures::stream::iter(hosts)
            .map(|host| {
                async move {
                    //
                    HostRecord::new(&host.host, host.port).await
                }
            })
            .buffer_unordered(BUFFER_SIZE)
            .collect()
            .await;

        println!("{:#?}", lookup_data);

        let connect_addr = host_records.ipv4_sockets[0];

        let uuid = Uuid::new_v4();
        let mut count: u16 = 0;

        let mut send_count: u16 = 0;
        let mut received_count: u16 = 0;
        let mut latencies: Vec<f64> = Vec::new();

        let ping_header = ping_header_msg(&connect_addr.to_string(), ConnectMethod::TCP);
        println!("{ping_header}");

        let cancel = Arc::new(AtomicBool::new(false));
        let c = cancel.clone();
        tokio::spawn(async move {
            signal::ctrl_c().await.unwrap();
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

            let mut host_results: Vec<HostResults> = futures::stream::iter(lookup_data.clone())
                .map(|host_record| {
                    let src_ip_port = src_ip_port.clone();
                    async move {
                        //
                        process_host(src_ip_port, host_record, self.ping_options).await
                    }
                })
                .buffer_unordered(BUFFER_SIZE)
                .collect()
                .await;

            host_results.sort_by_key(|h| h.host.to_owned());
            for host in host_results {
                println!("{} ->", host.host);
                for result in host.results {
                    let success_msg = client_result_msg(&result);
                    output_handler2(&result, &success_msg, &self.output_options).await;
                }
            }

            send_count += 1;
        }

        let client_summary = ClientSummary {
            send_count,
            received_count,
            latencies,
        };
        let summary_msg = client_summary_msg(
            &connect_addr.to_string(),
            ConnectMethod::TCP,
            client_summary,
        );
        println!("{}", summary_msg);

        Ok(())
    }
}

async fn process_host(
    src_ip_port: IpPort,
    host_record: HostRecord,
    ping_options: PingOptions,
) -> HostResults {
    let results: Vec<ConnectRecord> = futures::stream::iter(host_record.ipv4_sockets)
        .map(|dst_socket| {
            let src_ip_port = src_ip_port.clone();
            async move {
                //
                connect_host(src_ip_port, dst_socket, ping_options).await
            }
        })
        .buffer_unordered(BUFFER_SIZE)
        .collect()
        .await;

    HostResults {
        host: host_record.host,
        results,
    }
}

async fn connect_host(
    src: IpPort,
    dst_socket: SocketAddr,
    ping_options: PingOptions,
) -> ConnectRecord {
    let bind_addr = SocketAddr::new(src.ip, src.port);
    let src_socket = get_tcp_socket(bind_addr)
        .await
        // This should never fail unless:
        // Every high port number socket is in use.
        // Or, when trying to bind multiple source IPs
        // to the same socket.
        .unwrap_or_else(|_| panic!("ERROR BINDING TCP SOCKET ADDRESS {} {}", src.ip, src.port));

    let local_addr = src_socket
        .local_addr()
        // This should never fail because we always
        // pass a bound socket.
        .unwrap_or_else(|_| panic!("ERROR GETTING TCP SOCKET LOCAL ADDRESS"))
        .to_string();

    // record timestamp before connection
    let pre_conn_timestamp = time_now_us();

    let mut conn_record = ConnectRecord {
        result: ConnectResult::Unknown,
        protocol: ConnectMethod::TCP,
        source: local_addr,
        destination: dst_socket.to_string(),
        time: -1.0,
        error_msg: None,
    };

    let tick = Duration::from_millis(ping_options.timeout.into());
    match timeout(tick, src_socket.connect(dst_socket)).await {
        Ok(s) => match s {
            Ok(stream) => {
                // Update conn record
                // Calculate the round trip time
                let post_conn_timestamp = time_now_us();
                let connection_time = calc_connect_ms(pre_conn_timestamp, post_conn_timestamp);

                conn_record.source = stream
                    .local_addr()
                    // This should never fail. If we have a TCP stream,
                    // we should have always have a local address.
                    .unwrap_or_else(|_| panic!("ERROR GETTING TCP STREAM LOCAL ADDRESS"))
                    .to_string();
                conn_record.result = ConnectResult::Pong;
                conn_record.time = connection_time;
            }
            // Connection timeout
            Err(e) => {
                let error_msg = e.to_string();
                conn_record.result = io_error_switch(e);
                conn_record.error_msg = Some(error_msg);
            }
        },
        // Timeout error
        Err(e) => {
            let error_msg = e.to_string();
            conn_record.result = io_error_switch(e.into());
            conn_record.error_msg = Some(error_msg);
        }
    };
    conn_record
}

async fn get_tcp_socket(bind_addr: SocketAddr) -> Result<TcpSocket> {
    let socket = match bind_addr.is_ipv4() {
        true => TcpSocket::new_v4()?,
        false => TcpSocket::new_v6()?,
    };
    socket.bind(bind_addr)?;
    Ok(socket)
}

pub fn io_error_switch(error: std::io::Error) -> ConnectResult {
    match error.kind() {
        std::io::ErrorKind::ConnectionRefused => ConnectResult::Refused,
        std::io::ErrorKind::ConnectionReset => ConnectResult::Reset,
        std::io::ErrorKind::TimedOut => ConnectResult::Timeout,
        _ => ConnectResult::Unknown,
    }
}

pub fn client_result_msg(record: &ConnectRecord) -> String {
    match record.result {
        ConnectResult::Ping | ConnectResult::Pong => {
            format!(
                "{} => proto={} src={} dst={} time={:.3}ms",
                record.result,
                record.protocol.to_string().to_uppercase(),
                record.source,
                record.destination,
                record.time,
            )
        }
        ConnectResult::Refused
        | ConnectResult::Reset
        | ConnectResult::Timeout
        | ConnectResult::Unknown => {
            format!(
                "{} => proto={} src={} dst={}",
                record.result.to_string(),
                record.protocol.to_string().to_uppercase(),
                record.source,
                record.destination,
            )
        }
    }
}
