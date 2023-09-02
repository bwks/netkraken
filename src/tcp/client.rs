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

use crate::core::common::{
    ClientSummary, ConnectMethod, ConnectRecord, ConnectResult, HostRecord, LogLevel,
    NetKrakenMessage, OutputOptions, PingOptions,
};
use crate::core::konst::{BIND_ADDR, BIND_PORT, MAX_PACKET_SIZE};
use crate::util::handler::{loop_handler, output_handler};
use crate::util::message::{client_summary_msg, ping_header_msg};
use crate::util::parser::{nk_msg_reader, parse_ipaddr};
use crate::util::time::{calc_connect_ms, time_now_us, time_now_utc};

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

        let src_ip = parse_ipaddr(&self.src_ip)?;
        // let dst_ip = parse_ipaddr(&self.dst_ip)?;

        let host_records = HostRecord::new(&self.dst_ip, self.dst_port).await;
        println!("{}", host_records);

        let hosts = vec![host_records.clone()];

        let lookup_data: Vec<HostRecord> = futures::stream::iter(hosts)
            // 'StreamExt::map()' performs an action on each iteration of the 'stream'
            // and converts it to a new type.
            .map(|host| {
                // Create a new 'client' object from the original '&client' reference
                // that is enclosed in this scope.
                // let client = &client;
                // Start an async block moving ownership of any captured varibales
                // into the block.
                async move {
                    // Send a 'get' request to the 'url' and 'await' the response.
                    let result = HostRecord::new(&host.host, host.port).await;
                    // Return the 'response text' as the 'String' portion of the
                    // 'Result<String, Error>' type.
                    result
                }
            })
            // Kick of the requests asynchronously in batches equal to 'BUFFER_SIZE'.
            .buffer_unordered(BUFFER_SIZE)
            // Collect all the responses and add them to the 'data' vector.
            .collect()
            // Wait for all requests to finish.
            .await;

        println!("{:#?}", lookup_data);

        let bind_addr = SocketAddr::new(src_ip, self.src_port);
        // let connect_addr = SocketAddr::new(dst_ip, self.dst_port);

        let connect_addr = host_records.ipv4_sockets[0];

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

            // let src_socket = get_tcp_socket(bind_addr).await?;
            // let local_addr = src_socket.local_addr()?.to_string();

            let mut host_results: Vec<HostResults> = futures::stream::iter(lookup_data.clone())
                // 'StreamExt::map()' performs an action on each iteration of the 'stream'
                // and converts it to a new type.
                .map(|host_record| {
                    // Create a new 'client' object from the original '&client' reference
                    // that is enclosed in this scope.
                    // let client = &client;
                    // Start an async block moving ownership of any captured varibales
                    // into the block.
                    let src_ip_port = src_ip_port.clone();
                    async move {
                        // Send a 'get' request to the 'url' and 'await' the response.
                        let result =
                            process_host(src_ip_port, host_record, self.ping_options).await;
                        // Return the 'response text' as the 'String' portion of the
                        // 'Result<String, Error>' type.
                        result
                    }
                })
                // Kick of the requests asynchronously in batches equal to 'BUFFER_SIZE'.
                .buffer_unordered(BUFFER_SIZE)
                // Collect all the responses and add them to the 'data' vector.
                .collect()
                // Wait for all requests to finish.
                .await;

            host_results.sort_by_key(|h| h.host.to_owned());
            for host in host_results {
                println!("{} ->", host.host);
                for result in host.results {
                    println!(
                        " {} - {} -> {} - {}",
                        result.result, result.source, result.destination, result.time
                    )
                }
            }

            // let mut conn_record = ConnectRecord {
            //     result: ConnectResult::Unknown,
            //     protocol: ConnectMethod::TCP,
            //     source: local_addr,
            //     destination: connect_addr.to_string(),
            //     time: -1.0,
            //     error_msg: None,
            // };

            // record timestamp before connection
            // let pre_conn_timestamp = time_now_us();
            send_count += 1;

            // let tick = Duration::from_millis(self.ping_options.timeout.into());
            // let mut stream = match timeout(tick, src_socket.connect(connect_addr)).await {
            //     Ok(s) => match s {
            //         Ok(s) => {
            //             received_count += 1;
            //             s
            //         }
            //         // Connection timeout
            //         Err(e) => {
            //             output_handler(
            //                 LogLevel::ERROR,
            //                 &conn_record.client_error_msg(e),
            //                 &self.output_options,
            //             )
            //             .await;
            //             continue;
            //         }
            //     },
            //     Err(e) => {
            //         output_handler(
            //             LogLevel::ERROR,
            //             &conn_record.client_error_msg(e.into()),
            //             &self.output_options,
            //         )
            //         .await;

            //         continue;
            //     }
            // };

            // // Record timestamp after connection
            // let post_conn_timestamp = time_now_us();

            // let local_addr = &stream.local_addr()?.to_string();
            // let peer_addr = &stream.peer_addr()?.to_string();

            // conn_record.source = local_addr.to_string();

            // // Calculate the round trip time
            // let connection_time = calc_connect_ms(pre_conn_timestamp, post_conn_timestamp);
            // conn_record.result = ConnectResult::Pong;
            // conn_record.time = connection_time;

            // latencies.push(connection_time);

            // Only send payload with NetKraken peers
            // if self.ping_options.nk_peer_messaging {
            //     let (mut reader, mut writer) = stream.split();
            //     let mut nk_msg = NetKrakenMessage::new(
            //         &uuid.to_string(),
            //         local_addr,
            //         peer_addr,
            //         ConnectMethod::TCP,
            //     )?;
            //     nk_msg.uuid = uuid.to_string();

            //     let payload = nk_msg.to_json()?;

            //     // Send payload to peer
            //     writer.write_all(payload.as_bytes()).await?;

            //     writer.shutdown().await?;

            //     // Wait for reply
            //     let mut buffer = vec![0u8; MAX_PACKET_SIZE];

            //     match reader.read_to_end(&mut buffer).await {
            //         Ok(len) => {
            //             if self.ping_options.nk_peer_messaging && len > 0 {
            //                 let data_string = &String::from_utf8_lossy(&buffer[..len]);

            //                 if let Some(mut m) = nk_msg_reader(data_string) {
            //                     m.round_trip_time_utc = time_now_utc();
            //                     m.round_trip_timestamp = time_now_us();
            //                     m.round_trip_time_ms = connection_time;
            //                 }
            //                 // TODO: Do something with nk message
            //             }
            //         }
            //         Err(e) => {
            //             output_handler(
            //                 LogLevel::ERROR,
            //                 &conn_record.client_error_msg(e),
            //                 &self.output_options,
            //             )
            //             .await;
            //         }
            //     }
            // }

            // output_handler(
            //     LogLevel::INFO,
            //     &conn_record.client_success_msg(),
            //     &self.output_options,
            // )
            // .await;
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
        // 'StreamExt::map()' performs an action on each iteration of the 'stream'
        // and converts it to a new type.
        .map(|dst_socket| {
            // Create a new 'client' object from the original '&client' reference
            // that is enclosed in this scope.
            // let client = &client;
            // Start an async block moving ownership of any captured varibales
            // into the block.
            // let src_socket = src_socket.clone();
            let src_ip_port = src_ip_port.clone();
            async move {
                // Send a 'get' request to the 'url' and 'await' the response.
                let host_connection = connect_host(src_ip_port, dst_socket, ping_options).await;
                // Return the 'response text' as the 'String' portion of the
                // 'Result<String, Error>' type.

                host_connection
            }
        })
        // Kick of the requests asynchronously in batches equal to 'BUFFER_SIZE'.
        .buffer_unordered(BUFFER_SIZE)
        // Collect all the responses and add them to the 'data' vector.
        .collect()
        // Wait for all requests to finish.
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
        // I expect that this should never fail unless
        // every high port number socket is in use.
        // Or, when trying to bind multiple source IPs
        // to the same socket.
        .expect(&format!(
            "ERROR BINDING TCP SOCKET ADDRESS {} {}",
            src.ip, src.port
        ));

    let local_addr = src_socket
        .local_addr()
        // This should never fail because we always
        // pass a bound socket.
        .expect("ERROR GETTING TCP SOCKET LOCAL ADDRESS")
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
                    .expect("ERROR GETTING TCP STREAM LOCAL ADDRESS")
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
