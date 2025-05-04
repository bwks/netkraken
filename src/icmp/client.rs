use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, bail};
use futures::StreamExt;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::signal;
use tokio::time::Duration;
use tracing::debug;

use crate::core::common::{
    ClientResult, ClientSummary, ConnectError, ConnectMethod, ConnectRecord, ConnectResult, ConnectSuccess, HostRecord,
    HostResults, IpOptions, IpPort, IpProtocol, LoggingOptions, PingOptions,
};
use crate::core::konst::{
    BUFFER_SIZE, ICMP_PORT, ICMPV4_ECHO_REPLY, ICMPV4_ECHO_REQUEST, ICMPV6_ECHO_REPLY, ICMPV6_ECHO_REQUEST,
};
use crate::util::dns::resolve_host;
use crate::util::handler::{log_handler2, loop_handler};
use crate::util::message::{client_result_msg, client_summary_table_msg, ping_header_msg, resolved_ips_msg};
use crate::util::result::{client_summary_result, get_results_map};
use crate::util::time::{calc_connect_ms, time_now_us};

#[derive(Debug, Clone)]
pub struct IcmpClientOptions {
    pub remote_host: String,
    pub local_ipv4: IpAddr,
    pub local_ipv6: IpAddr,
}

#[derive(Debug)]
pub struct IcmpClient {
    pub client_options: IcmpClientOptions,
    pub logging_options: LoggingOptions,
    pub ping_options: PingOptions,
    pub ip_options: IpOptions,
}

impl IcmpClient {
    pub async fn connect(&self) -> Result<()> {
        let src_ip_port = IpPort {
            ipv4: self.client_options.local_ipv4,
            ipv6: self.client_options.local_ipv6,
            port: ICMP_PORT,
        };

        // Resolve the destination host to IPv4 and IPv6 addresses.
        let host_records = HostRecord::new(&self.client_options.remote_host, ICMP_PORT).await;
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

        let ping_header = ping_header_msg(&self.client_options.remote_host, ICMP_PORT, ConnectMethod::Icmp);
        println!("{ping_header}");

        // This is a signal handler that listens for a Ctrl-C signal.
        // When the signal is received, it sets the cancel flag to true.
        // If the cancel flag is True we break the loop and exit the program.
        let cancel = Arc::new(AtomicBool::new(false));
        let c = cancel.clone();
        tokio::spawn(async move {
            // TODO: this will eventually move to a channel signalling mechanism.
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

            let host_results: Vec<HostResults> = futures::stream::iter(resolved_hosts.clone())
                .map(|host_record| {
                    async move {
                        //
                        process_host(send_count, src_ip_port, host_record, self.ping_options, self.ip_options).await
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
                let summary_msg = client_summary_result(&addr, ConnectMethod::Icmp, client_summary);
                client_results.push(summary_msg)
            }
        }
        client_results.sort_by_key(|x| x.destination.to_owned());

        let summary_table = client_summary_table_msg(
            &self.client_options.remote_host,
            ICMP_PORT,
            ConnectMethod::Icmp,
            &client_results,
        );
        println!("{}", summary_table);

        Ok(())
    }
}

async fn process_host(
    send_count: u16,
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
                connect_host(send_count, src_ip_port, dst_socket, ping_options).await
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
    send_count: u16,
    src: IpPort,
    dst_socket: SocketAddr,
    ping_options: PingOptions,
) -> ConnectRecord {
    // For loopback address, use a special handling
    let is_loopback = dst_socket.ip().is_loopback();

    let (bind_addr, src_socket) = match &dst_socket.is_ipv4() {
        // Bind the source socket to the same IP Version as the destination socket.
        true => {
            let bind_ipv4_addr = SocketAddr::new(src.ipv4, src.port);
            let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).ok();
            (bind_ipv4_addr, socket)
        }
        false => {
            let bind_ipv6_addr = SocketAddr::new(src.ipv6, src.port);
            let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).ok();
            (bind_ipv6_addr, socket)
        }
    };

    let local_addr = bind_addr.to_string();

    // If the source socket is None, we could not bind to the socket.
    if src_socket.is_none() {
        return ConnectRecord {
            result: ConnectResult::Error(ConnectError::BindError),
            context: None,
            protocol: ConnectMethod::Icmp,
            source: local_addr,
            destination: dst_socket.to_string(),
            time: -1.0,
            success: false,
            error_msg: Some("Error binding to socket".to_owned()),
        };
    }
    // Unwrap the socket because we have already checked that it is not None.
    let src_socket = src_socket.unwrap();

    let mut conn_record = ConnectRecord {
        result: ConnectResult::Error(ConnectError::Unknown),
        context: None,
        protocol: ConnectMethod::Icmp,
        source: local_addr.clone(),
        destination: dst_socket.to_string(),
        time: -1.0,
        success: false,
        error_msg: None,
    };

    // record timestamp before connection
    let pre_conn_timestamp = time_now_us();

    if src_socket
        .set_read_timeout(Some(Duration::from_millis(ping_options.timeout as u64)))
        .is_err()
    {
        conn_record.error_msg = Some("Error setting read timeout.".to_owned());
        return conn_record;
    }

    let identifier = (std::process::id() % u16::MAX as u32) as u16;

    let packet = build_icmp_echo(identifier, send_count, dst_socket.is_ipv6());

    match src_socket.send_to(&packet, &dst_socket.into()) {
        Ok(_) => {}
        Err(e) => {
            conn_record.result = ConnectResult::Error(ConnectError::ConnectionError);
            conn_record.error_msg = Some(format!("Failed to send packet: {}", e));
            return conn_record;
        }
    };

    let mut buf = [MaybeUninit::<u8>::uninit(); 1024];

    match src_socket.recv_from(&mut buf) {
        Ok((n, _remote_socket)) => {
            let post_conn_timestamp = time_now_us();
            let connection_time = calc_connect_ms(pre_conn_timestamp, post_conn_timestamp);

            // This is safe to because:
            //  - recv_from guarantees initialization of first n bytes
            //  - We only access buf[..n] on successful recieve.
            let received_data = buf[..n].iter().map(|b| unsafe { b.assume_init() }).collect::<Vec<u8>>();

            if parse_icmp_reply(&received_data, identifier, send_count, is_loopback) {
                conn_record.success = true;
                conn_record.result = ConnectResult::Success(ConnectSuccess::Ok);
                conn_record.time = connection_time;
            } else {
                conn_record.result = ConnectResult::Error(ConnectError::Error);
                conn_record.error_msg = Some("Error parsing icmp reply".to_owned());
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            conn_record.result = ConnectResult::Error(ConnectError::Timeout);
            conn_record.error_msg = Some(error_msg);
        }
    }
    conn_record
}

fn build_icmp_echo(identifier: u16, seq: u16, is_ipv6: bool) -> Vec<u8> {
    let mut packet = vec![
        // 8, // Type=8 (Echo Request)
        if is_ipv6 { ICMPV6_ECHO_REQUEST } else { ICMPV4_ECHO_REQUEST }, // Type=8 (ICMPv4 Echo Request) or 128 (ICMPv6 Echo Request)
        0,                                                               // Code=0
        0,
        0, // Checksum (placeholder)
        (identifier >> 8) as u8,
        (identifier & 0xFF) as u8, // Identifier
        (seq >> 8) as u8,
        (seq & 0xFF) as u8, // Sequence
    ];
    packet.extend(vec![0; 32]); // 32-byte payload

    let checksum = icmp_checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn parse_icmp_reply(packet: &[u8], identifier: u16, seq: u16, is_loopback: bool) -> bool {
    // Make sure we have at least one byte for the IP header
    if packet.is_empty() {
        return false;
    }

    // Check if we're dealing with a packet that includes IP header or just ICMP data
    let icmp_data: &[u8];

    // Get the version from the first byte's high nibble
    let apparent_version = (packet[0] >> 4) & 0x0F;

    if apparent_version == 4 {
        // This is likely an IPv4 packet with header
        let ip_header_length = (packet[0] & 0x0F) * 4;
        if packet.len() < ip_header_length as usize {
            return false;
        }
        icmp_data = &packet[ip_header_length as usize..];

        debug!("Processing as IPv4 packet with IP header. ICMP type: {}", icmp_data[0]);
    } else if apparent_version == 6 {
        // This is likely an IPv6 packet with header (though rare with raw sockets)
        if packet.len() < 40 {
            // IPv6 header is fixed 40 bytes
            return false;
        }
        icmp_data = &packet[40..];

        debug!("Processing as IPv6 packet with IP header. ICMP type: {}", icmp_data[0]);
    } else if apparent_version == 8 || packet[0] == ICMPV6_ECHO_REPLY {
        // This might be an ICMPv6 packet delivered without IP header
        // Version "8" is actually the high nibble of ICMPv6 type 128 (Echo Request)
        // or we're seeing 129 (Echo Reply)
        icmp_data = packet; // The packet starts with ICMPv6 header

        debug!(
            "Processing as raw ICMPv6 packet (no IP header). ICMP type: {}",
            icmp_data[0]
        );
    } else {
        // Unrecognized format
        // println!("Unrecognized packet format. First byte: {}", packet[0]);
        return false;
    }

    // Now check the ICMP header
    let icmp_types = if is_loopback {
        // We are looking for the ICMP types:
        //  - 0/129 - Echo Reply (ipv4/ipv6)
        //  - 8/128 - Echo Request (ipv4/ipv6)
        // When pinging a loopback, sometimes we get the Echo Request type reflected back,
        // so we need to check for both Type 0/128 and 8/129 when pinging a loopback.
        icmp_data[0] == ICMPV4_ECHO_REPLY
            || icmp_data[0] == ICMPV4_ECHO_REQUEST
            || icmp_data[0] == ICMPV6_ECHO_REPLY
            || icmp_data[0] == ICMPV6_ECHO_REQUEST
    } else {
        // Otherwise if it's a remote host, only look for Echo reply
        icmp_data[0] == ICMPV4_ECHO_REPLY || icmp_data[0] == ICMPV6_ECHO_REPLY
    };

    icmp_data.len() >= 8
        && icmp_types // Echo Reply type
        && icmp_data[1] == 0  // Code
        && u16::from_be_bytes([icmp_data[4], icmp_data[5]]) == identifier
        && u16::from_be_bytes([icmp_data[6], icmp_data[7]]) == seq
}

fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        let word =
            if chunk.len() == 2 { u16::from_be_bytes([chunk[0], chunk[1]]) } else { u16::from_be_bytes([chunk[0], 0]) };
        sum += word as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
