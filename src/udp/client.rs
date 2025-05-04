use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, bail};
use futures::StreamExt;
use tokio::net::UdpSocket;
use tokio::signal;
use tokio::time::{Duration, timeout};

use crate::core::common::{
    ClientResult, ClientSummary, ConnectError, ConnectMethod, ConnectRecord, ConnectResult, ConnectSuccess, HostRecord,
    HostResults, IpOptions, IpPort, IpProtocol, LoggingOptions, PingOptions,
};
use crate::core::konst::{BUFFER_SIZE, MAX_PACKET_SIZE, PING_MSG};
use crate::util::dns::resolve_host;
use crate::util::handler::{io_error_switch_handler, log_handler2, loop_handler};
use crate::util::message::{client_result_msg, client_summary_table_msg, ping_header_msg, resolved_ips_msg};
use crate::util::result::{client_summary_result, get_results_map};
use crate::util::time::{calc_connect_ms, time_now_us};

#[derive(Debug, Clone)]
pub struct UdpClientOptions {
    pub remote_host: String,
    pub remote_port: u16,
    pub local_ipv4: IpAddr,
    pub local_ipv6: IpAddr,
    pub local_port: u16,
}

pub struct UdpClient {
    pub client_options: UdpClientOptions,
    pub logging_options: LoggingOptions,
    pub ping_options: PingOptions,
    pub ip_options: IpOptions,
}

impl UdpClient {
    pub async fn connect(&self) -> Result<()> {
        let src_ip_port = IpPort {
            // These should never be None at this point as they are set in the UdpClient::new() constructor.
            ipv4: self.client_options.local_ipv4,
            ipv6: self.client_options.local_ipv6,
            port: self.client_options.local_port,
        };

        // Resolve the destination host to IPv4 and IPv6 addresses.
        let host_records = HostRecord::new(&self.client_options.remote_host, self.client_options.remote_port).await;
        let hosts = vec![host_records.clone()];
        let resolved_hosts = resolve_host(hosts).await;

        // Check if the host resolved to an IPv4 or IPv6 addresses.
        // If not, return an error.
        for record in &resolved_hosts {
            match record.ipv4_sockets.is_empty() && record.ipv6_sockets.is_empty() {
                true => bail!("{} did not resolve to an IP address", record.host),
                false => {
                    let resolved_host_msg = resolved_ips_msg(record);
                    println!("{resolved_host_msg}");
                }
            }
        }

        // Filter the resolved hosts based on the IP protocol.
        let mut filtered_hosts = Vec::new();
        for record in &resolved_hosts {
            let mut record = record.clone();
            match &self.ip_options.ip_protocol {
                IpProtocol::All => {
                    filtered_hosts.push(record);
                }
                IpProtocol::V4 => {
                    record.ipv6_sockets.clear();
                    filtered_hosts.push(record);
                }
                IpProtocol::V6 => {
                    record.ipv4_sockets.clear();
                    filtered_hosts.push(record);
                }
            }
        }

        let mut results_map = get_results_map(&filtered_hosts);

        let mut count: u16 = 0;
        let mut send_count: u16 = 0;

        let ping_header = ping_header_msg(
            &self.client_options.remote_host,
            self.client_options.remote_port,
            ConnectMethod::Udp,
        );
        println!("{ping_header}");

        // This is a signal handler that listens for a Ctrl-C signal.
        // When the signal is received, it sets the cancel flag to true.
        // If the cancel flag is True we break the loop and exit the program.
        let cancel = Arc::new(AtomicBool::new(false));
        let c = cancel.clone();
        tokio::spawn(async move {
            // this will eventually move to a channel signalling mechanism.
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
                    async move {
                        //
                        process_host(src_ip_port, host_record, self.ping_options, self.ip_options).await
                    }
                })
                .buffer_unordered(BUFFER_SIZE)
                .collect()
                .await;

            for host in host_results {
                for result in host.results {
                    results_map
                        // This should never fail
                        .get_mut(&host.host)
                        .unwrap()
                        // This should never fail
                        .get_mut(&result.destination)
                        .unwrap()
                        .push(result.time);

                    let success_msg = client_result_msg(&result);
                    log_handler2(&result, &success_msg, &self.logging_options).await;
                }
            }
            send_count += 1;
        }

        let mut client_results: Vec<ClientResult> = Vec::new();
        for (_, addrs) in results_map {
            for (addr, latencies) in addrs {
                let client_summary = ClientSummary { send_count, latencies };
                let client_summary = client_summary_result(&addr, ConnectMethod::Udp, client_summary);
                client_results.push(client_summary)
            }
        }
        client_results.sort_by_key(|x| x.destination.to_owned());

        let summary_table = client_summary_table_msg(
            &self.client_options.remote_host,
            self.client_options.remote_port,
            ConnectMethod::Udp,
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
    ip_options: IpOptions,
) -> HostResults {
    // Create a vector of sockets based on the IP protocol.
    let sockets = match ip_options.ip_protocol {
        IpProtocol::All => [host_record.ipv4_sockets, host_record.ipv6_sockets].concat(),
        IpProtocol::V4 => host_record.ipv4_sockets,
        IpProtocol::V6 => host_record.ipv6_sockets,
    };

    let results: Vec<ConnectRecord> = futures::stream::iter(sockets)
        .map(|dst_socket| {
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

async fn connect_host(src: IpPort, dst_socket: SocketAddr, ping_options: PingOptions) -> ConnectRecord {
    let bind_addr = match &dst_socket.is_ipv4() {
        // Bind the source socket to the same IP Version as the destination socket.
        true => SocketAddr::new(src.ipv4, src.port),
        false => SocketAddr::new(src.ipv6, src.port),
    };

    let src_socket = UdpSocket::bind(bind_addr).await.ok();

    // If the source socket is None, we could not bind to the socket.
    if src_socket.is_none() {
        return ConnectRecord {
            result: ConnectResult::Error(ConnectError::BindError),
            context: None,
            protocol: ConnectMethod::Udp,
            source: bind_addr.to_string(),
            destination: dst_socket.to_string(),
            time: -1.0,
            success: false,
            error_msg: None,
        };
    }
    // Unwrap the socket because we have already checked that it is not None.
    let src_socket = src_socket.unwrap();

    let reader = Arc::new(src_socket);
    let writer = reader.clone();

    // TODO: this should never fail, validate this assumption.
    let local_addr = &writer.local_addr().unwrap().to_string();

    let mut conn_record = ConnectRecord {
        result: ConnectResult::Error(ConnectError::Unknown),
        context: None,
        protocol: ConnectMethod::Udp,
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

    match ping_options.nk_peer {
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

                if let Ok(local_addr) = reader.local_addr() {
                    conn_record.source = local_addr.to_string();
                }

                conn_record.success = true;
                conn_record.result = ConnectResult::Success(ConnectSuccess::Ok);
                conn_record.time = connection_time;
                // latencies.push(connection_time);

                if ping_options.nk_peer && len > 0 {
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
            conn_record.result = ConnectResult::Error(io_error_switch_handler(e.into()));
            conn_record.error_msg = Some(error_msg);
        }
    }

    conn_record
}
