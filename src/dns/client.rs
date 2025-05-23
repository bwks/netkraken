use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::proto::xfer::Protocol;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, bail};
use futures::StreamExt;
use futures::future::join_all;
use tokio::signal;

use crate::core::common::{
    ClientResult, ClientSummary, ConnectError, ConnectMethod, ConnectRecord, ConnectResult, ConnectSuccess, HostRecord,
    HostResults, IpOptions, IpPort, IpProtocol, LoggingOptions, PingOptions, Transport,
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
    pub remote_host: String,
    pub remote_port: u16,
    pub local_ipv4: IpAddr,
    pub local_ipv6: IpAddr,
    pub local_port: u16,
    pub transport: Transport,
    pub domain: String,
}

pub struct DnsClient {
    pub client_options: DnsClientOptions,
    pub logging_options: LoggingOptions,
    pub ping_options: PingOptions,
    pub ip_options: IpOptions,
}

impl DnsClient {
    pub async fn connect(&self) -> Result<()> {
        let local_ip_port = IpPort {
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

        //
        let mut results_map = get_results_map(&filtered_hosts);

        let mut count: u16 = 0;
        let mut send_count: u16 = 0;

        let ping_header = ping_header_msg(
            &self.client_options.remote_host,
            self.client_options.remote_port,
            ConnectMethod::Dns,
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
                    let client_options = self.client_options.clone();
                    async move {
                        //
                        process_host(
                            local_ip_port,
                            client_options,
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
                let summary_msg = client_summary_result(&addr, ConnectMethod::Dns, client_summary);
                client_results.push(summary_msg)
            }
        }
        client_results.sort_by_key(|x| x.destination.to_owned());

        let summary_table = client_summary_table_msg(
            &self.client_options.remote_host,
            self.client_options.remote_port,
            ConnectMethod::Dns,
            &client_results,
        );
        println!("{}", summary_table);

        Ok(())
    }
}

async fn process_host(
    src_ip_port: IpPort,
    client_options: DnsClientOptions,
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
                let client_options = client_options.clone();
                async move {
                    //
                    match connect_host(client_options, src_ip_port, dst_socket, ping_options).await {
                        Ok(record) => record,
                        Err(e) => ConnectRecord {
                            result: ConnectResult::Error(ConnectError::Unknown),
                            context: None,
                            protocol: ConnectMethod::Dns,
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
    client_options: DnsClientOptions,
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
            result: ConnectResult::Error(ConnectError::BindError),
            context: None,
            protocol: ConnectMethod::Dns,
            source: bind_addr.to_string(),
            destination: dst_socket.to_string(),
            time: -1.0,
            success: false,
            error_msg: Some("Error binding to socket".to_owned()),
        });
    }

    // Map to symbol used by Hickory resolver.
    let transport_protocol = match client_options.transport {
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

    // DNS record types to query
    let query_types = [RecordType::A, RecordType::AAAA];

    let mut conn_record = ConnectRecord {
        result: ConnectResult::Error(ConnectError::Unknown),
        context: None,
        protocol: ConnectMethod::Dns,
        source: bind_addr.to_string(),
        destination: dst_socket.to_string(),
        time: -1.0,
        success: false,
        error_msg: None,
    };

    // record timestamp before connection
    let pre_conn_timestamp = time_now_us();

    // Normalize the domain to enhance query performance.
    // A trailing '.' ensure only a single query is performed.
    let domain = if client_options.domain.ends_with(".") {
        client_options.domain
    } else {
        format!("{}.", client_options.domain)
    };

    // Create individual futures for each lookup
    let lookup_futures = query_types
        .iter()
        .map(|&record_type| resolver.lookup(domain.clone(), record_type))
        .collect::<Vec<_>>();

    // DOGWATER: I could not find a method to set the timeout in the Hickory resolver config.
    // Wrap the request in a tokio timeout to control this until a method can be
    // found in the Hickory Resolver.
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(ping_options.timeout as u64),
        join_all(lookup_futures),
    )
    .await;

    // `lookup_ip` returns an error if the dns record is not found.
    // `server_connected` is used to reduce repeating successful
    // params in `conn_record` in the error case.
    let mut server_connected = false;
    let mut records_found = vec![];
    match result {
        // We connected to the server and got responses for all queries
        Ok(lookup_results) => {
            server_connected = true;

            for lookup_result in lookup_results {
                match lookup_result {
                    Ok(r) => {
                        // We got a positive response for this record type
                        for record in r.records() {
                            let data = record.clone().into_data();
                            records_found.push(data.record_type().to_string());
                        }
                    }
                    Err(e) => {
                        // Handle errors for this specific lookup
                        if e.proto().is_some() {
                            if e.is_nx_domain() {
                                records_found.push("NX".to_owned());
                            }
                            if e.is_no_records_found() {
                                records_found.push("NR".to_owned());
                            }
                        }
                    }
                }
            }
        }
        Err(_) => {
            // Timeout connecting to the server
            conn_record.result = ConnectResult::Error(ConnectError::Timeout);
            conn_record.error_msg = Some("DNS lookup timed out".to_owned());
        }
    };

    records_found.sort();
    records_found.dedup();

    if server_connected {
        let post_conn_timestamp = time_now_us();
        let connection_time = calc_connect_ms(pre_conn_timestamp, post_conn_timestamp);
        conn_record.success = true;
        conn_record.context = Some(records_found.join(", "));
        conn_record.time = connection_time;
        conn_record.result = ConnectResult::Success(ConnectSuccess::Reply);
    }

    Ok(conn_record)
}
