use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{bail, Result};
use futures::StreamExt;
use tokio::net::UdpSocket;
use tokio::signal;
use tokio::time::{timeout, Duration};

use crate::core::common::{
    ClientResult, ClientSummary, ConnectMethod, ConnectRecord, ConnectResult, HostRecord,
    HostResults, IpPort, OutputOptions, PingOptions,
};
use crate::core::konst::{BIND_ADDR, BIND_PORT, BUFFER_SIZE, MAX_PACKET_SIZE, PING_MSG};
use crate::util::dns::resolve_host;
use crate::util::handler::{io_error_switch_handler, loop_handler, output_handler2};
use crate::util::message::{
    client_result_msg, client_summary_table_msg, ping_header_msg, resolved_ips_msg,
};
use crate::util::parser::parse_ipaddr;
use crate::util::result::{client_summary_result, get_results_map};
use crate::util::time::{calc_connect_ms, time_now_us};

pub struct UdpClient {
    pub dst_ip: String,
    pub dst_port: u16,
    pub src_ip: String,
    pub src_port: u16,
    pub output_options: OutputOptions,
    pub ping_options: PingOptions,
}

impl UdpClient {
    pub fn new(
        dst_ip: String,
        dst_port: u16,
        src_ip: Option<String>,
        src_port: Option<u16>,
        output_options: OutputOptions,
        ping_options: PingOptions,
    ) -> UdpClient {
        UdpClient {
            dst_ip,
            dst_port,
            src_ip: src_ip.unwrap_or_else(|| BIND_ADDR.to_owned()),
            src_port: src_port.unwrap_or_else(|| BIND_PORT.to_owned()),
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

        let hosts = vec![host_records.clone()];

        let resolved_hosts = resolve_host(hosts).await;

        for record in &resolved_hosts {
            match record.ipv4_sockets.is_empty() && record.ipv6_sockets.is_empty() {
                true => bail!("{} did not resolve to an IP address", record.host),
                false => {
                    let resolved_host_msg = resolved_ips_msg(record);
                    println!("{resolved_host_msg}");
                }
            }
        }

        let mut results_map = get_results_map(&resolved_hosts);

        let mut count: u16 = 0;
        let mut send_count: u16 = 0;

        let ping_header = ping_header_msg(&self.dst_ip, self.dst_port, ConnectMethod::UDP);
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

            let host_results: Vec<HostResults> = futures::stream::iter(resolved_hosts.clone())
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

            for host in host_results {
                for result in host.results {
                    results_map
                        .get_mut(&host.host)
                        .unwrap()
                        .get_mut(&result.destination)
                        .unwrap()
                        .push(result.time);

                    let success_msg = client_result_msg(&result);
                    output_handler2(&result, &success_msg, &self.output_options).await;
                }
            }
            send_count += 1;
        }

        let mut client_results: Vec<ClientResult> = Vec::new();
        for (_, addrs) in results_map {
            for (addr, latencies) in addrs {
                let client_summary = ClientSummary {
                    send_count,
                    latencies,
                };
                let client_summary =
                    client_summary_result(&addr, ConnectMethod::UDP, client_summary);
                client_results.push(client_summary)
            }
        }
        client_results.sort_by_key(|x| x.destination.to_owned());

        let summary_table = client_summary_table_msg(
            &self.dst_ip,
            self.dst_port,
            ConnectMethod::UDP,
            &client_results,
        );
        println!("{}", summary_table);

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
    // let src_socket = SocketAddr::new(dst_socket.ip(), dst_socket.port());

    let socket = UdpSocket::bind(bind_addr)
        .await
        // This should never fail because we always
        // pass a bound socket. (Not sure with UDP sockets)
        .unwrap_or_else(|_| panic!("ERROR GETTING UDP SOCKET LOCAL ADDRESS"));

    let reader = Arc::new(socket);
    let writer = reader.clone();

    // TODO: this should never fail
    let local_addr = &writer.local_addr().unwrap().to_string();

    let mut conn_record = ConnectRecord {
        result: ConnectResult::Unknown,
        protocol: ConnectMethod::UDP,
        source: local_addr.to_owned(),
        destination: dst_socket.to_string(),
        time: -1.0,
        success: false,
        error_msg: None,
    };

    // record timestamp before connection
    let pre_conn_timestamp = time_now_us();

    // TODO: need to investigate if this can error
    let _ = writer.connect(dst_socket).await;

    match ping_options.nk_peer_messaging {
        false => {
            // TODO: need to investigate if this can error
            // This should not error if connect was successful.
            let _ = writer.send(PING_MSG.as_bytes()).await;
        }
        true => {
            // let mut nk_msg = NetKrakenMessage::new(
            //     &uuid.to_string(),
            //     &writer.local_addr()?.to_string(),
            //     &peer_addr.to_string(),
            //     ConnectMethod::UDP,
            // )?;
            // nk_msg.uuid = uuid.to_string();

            // let payload = serde_json::to_string(&nk_msg)?;

            // writer.send(payload.as_bytes()).await?;
        }
    }

    // Wait for a reply
    let tick = Duration::from_millis(ping_options.timeout.into());
    let mut buffer = vec![0u8; MAX_PACKET_SIZE];

    match timeout(tick, reader.recv_from(&mut buffer)).await {
        Ok(result) => {
            if let Ok((len, _addr)) = result {
                // received_count += 1;

                // Record timestamp after connection
                let post_conn_timestamp = time_now_us();

                // Calculate the round trip time
                let connection_time = calc_connect_ms(pre_conn_timestamp, post_conn_timestamp);

                conn_record.success = true;
                conn_record.result = ConnectResult::Pong;
                conn_record.time = connection_time;
                // latencies.push(connection_time);

                if ping_options.nk_peer_messaging && len > 0 {
                    // let data_string = &String::from_utf8_lossy(&buffer[..len]);

                    // // Handle connection to a NetKraken peer
                    // if let Some(mut m) = nk_msg_reader(data_string) {
                    //     m.round_trip_time_utc = time_now_utc();
                    //     m.round_trip_timestamp = time_now_us();
                    //     m.round_trip_time_ms = connection_time;

                    //     // TODO: Do something with nk message
                    //     // println!("{:#?}", m);
                    // }
                }
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            conn_record.result = io_error_switch_handler(e.into());
            conn_record.error_msg = Some(error_msg);
        }
    }

    conn_record
}
