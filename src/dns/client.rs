use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::xfer::Protocol;
use hickory_resolver::Resolver;

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{bail, Result};
use futures::StreamExt;
use tokio::signal;

use crate::core::common::{
    ClientResult, ClientSummary, ConnectRecord, ConnectResult, HostRecord, HostResults, IpOptions, IpPort, IpProtocol,
    LoggingOptions, PingOptions, Transport,
};
use crate::core::konst::BUFFER_SIZE;
use crate::util::dns::resolve_host;
use crate::util::handler::{log_handler2, loop_handler};
use crate::util::message::{client_result_msg, client_summary_table_msg, ping_header_msg, resolved_ips_msg};
use crate::util::result::{client_summary_result, get_results_map};
use crate::util::socket::get_tcp_socket;
use crate::util::time::{calc_connect_ms, time_now_us};

#[derive(Debug, Clone)]
pub struct DnsClientOptions {
    pub remote_host: Vec<String>,
    pub remote_port: u16,
    pub local_ipv4: IpAddr,
    pub local_ipv6: IpAddr,
    pub local_port: u16,
    pub transport: Transport,
    pub domain: String,
}

pub struct DnsClient {
    pub dns_client_options: DnsClientOptions,
    pub logging_options: LoggingOptions,
    pub ping_options: PingOptions,
    pub ip_options: IpOptions,
}

impl DnsClient {
    pub async fn connect(&self) -> Result<()> {
        let local_ip_port = IpPort {
            ipv4: self.dns_client_options.local_ipv4,
            ipv6: self.dns_client_options.local_ipv6,
            port: self.dns_client_options.local_port,
        };

        // Resolve the destination host to IPv4 and IPv6 addresses.

        let mut host_records = vec![];
        for host in self.dns_client_options.remote_host.iter() {
            host_records.push(HostRecord::new(&host, self.dns_client_options.remote_port).await);
        }

        let resolved_hosts = resolve_host(host_records).await;

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

        //
        let mut results_map = get_results_map(&filtered_hosts);

        let mut count: u16 = 0;
        let mut send_count: u16 = 0;

        let ping_header = ping_header_msg(
            &self.dns_client_options.remote_host[0],
            self.dns_client_options.remote_port,
            self.ping_options.method,
        );
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
                    let dns_client_options = self.dns_client_options.clone();
                    async move {
                        //
                        process_host(
                            local_ip_port,
                            dns_client_options,
                            host_record,
                            self.ping_options,
                            self.ip_options,
                        )
                        .await
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
                let summary_msg = client_summary_result(&addr, self.ping_options.method, client_summary);
                client_results.push(summary_msg)
            }
        }
        client_results.sort_by_key(|x| x.destination.to_owned());

        let summary_table = client_summary_table_msg(
            &self.dns_client_options.remote_host[0],
            self.dns_client_options.remote_port,
            self.ping_options.method,
            &client_results,
        );
        println!("{}", summary_table);

        Ok(())
    }
}

async fn process_host(
    src_ip_port: IpPort,
    dns_client_options: DnsClientOptions,
    host_record: HostRecord,
    ping_options: PingOptions,
    ip_options: IpOptions,
) -> HostResults {
    // Create a vector of sockets based on the IP protocol.
    let host_record_clone = host_record.clone();
    let sockets = match ip_options.ip_protocol {
        IpProtocol::All => [host_record_clone.ipv4_sockets, host_record_clone.ipv6_sockets].concat(),
        IpProtocol::V4 => host_record_clone.ipv4_sockets,
        IpProtocol::V6 => host_record_clone.ipv6_sockets,
    };

    let results: Vec<ConnectRecord> = futures::stream::iter(sockets)
        .map(|dst_socket| {
            {
                let dns_client_options = dns_client_options.clone();
                async move {
                    //
                    match connect_host(dns_client_options, src_ip_port, dst_socket, ping_options).await {
                        Ok(record) => record,
                        Err(e) => ConnectRecord {
                            result: ConnectResult::Unknown,
                            protocol: ping_options.method,
                            source: src_ip_port.ipv4.to_string(),
                            destination: dst_socket.to_string(),
                            time: -1.0,
                            success: false,
                            error_msg: Some(e.to_string()),
                        },
                    }
                }
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
    // host_record: HostRecord,
    dns_client_options: DnsClientOptions,
    local: IpPort,
    dst_socket: SocketAddr,
    ping_options: PingOptions,
) -> Result<ConnectRecord> {
    let (bind_addr, local_socket) = match &dst_socket.is_ipv4() {
        // Bind the source socket to the same IP Version as the destination socket.
        true => {
            let bind_ipv4_addr = SocketAddr::new(local.ipv4, local.port);
            let socket = get_tcp_socket(bind_ipv4_addr).ok();
            (bind_ipv4_addr, socket)
        }
        false => {
            let bind_ipv6_addr = SocketAddr::new(local.ipv6, local.port);
            let socket = get_tcp_socket(bind_ipv6_addr).ok();
            (bind_ipv6_addr, socket)
        }
    };

    // If the source socket is None, we could not bind to the socket.
    if local_socket.is_none() {
        return Ok(ConnectRecord {
            result: ConnectResult::BindError,
            protocol: ping_options.method,
            source: bind_addr.to_string(),
            destination: dst_socket.to_string(),
            time: -1.0,
            success: false,
            error_msg: Some("Error binding to socket".to_owned()),
        });
    }

    let transport_protocol = match dns_client_options.transport {
        Transport::Tcp => Protocol::Tcp,
        Transport::Udp => Protocol::Udp,
    };

    // Configure resolver for this server
    let ns_config = NameServerConfig {
        socket_addr: dst_socket,
        protocol: transport_protocol,
        http_endpoint: None,
        tls_dns_name: None,
        trust_negative_responses: false,
        bind_addr: Some(bind_addr),
    };

    let mut config = ResolverConfig::new();
    config.add_name_server(ns_config);

    // Build resolver with our config and options
    let resolver = Resolver::builder_with_config(config, TokioConnectionProvider::default()).build();

    let mut conn_record = ConnectRecord {
        result: ConnectResult::Unknown,
        protocol: ping_options.method,
        source: bind_addr.to_string(),
        destination: dst_socket.to_string(),
        time: -1.0,
        success: false,
        error_msg: None,
    };

    // record timestamp before connection
    let pre_conn_timestamp = time_now_us();

    match resolver.lookup_ip(dns_client_options.domain).await {
        Ok(_) => {
            let post_conn_timestamp = time_now_us();
            let connection_time = calc_connect_ms(pre_conn_timestamp, post_conn_timestamp);
            conn_record.success = true;
            conn_record.time = connection_time;
            conn_record.result = ConnectResult::Pong;
            // reponse.as_lookup().record_iter().
        }
        Err(e) => {
            println!("{}", e);
            conn_record.result = ConnectResult::Error;
        }
    }

    Ok(conn_record)
}
