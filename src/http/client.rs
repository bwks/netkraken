use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, bail};
use futures::StreamExt;
use hyper_util::client::legacy::connect::HttpInfo;
use reqwest::header::HeaderMap;
use reqwest::{Client, header};
use tokio::signal;
use tokio::time::Duration;
use tracing::debug;

use crate::core::common::{
    ClientResult, ClientSummary, ConnectError, ConnectMethod, ConnectRecord, ConnectResult, ConnectSuccess, HostRecord,
    HostResults, HttpScheme, HttpVersion, IpOptions, IpPort, IpProtocol, LoggingOptions, PingOptions,
};
use crate::core::konst::{BUFFER_SIZE, NK_VERSION};
use crate::util::dns::resolve_host;
use crate::util::handler::{log_handler2, loop_handler};
use crate::util::message::{client_result_msg, client_summary_table_msg, ping_header_msg, resolved_ips_msg};
use crate::util::result::{client_summary_result, get_results_map};
use crate::util::socket::get_tcp_socket;
use crate::util::time::{calc_connect_ms, time_now_us};

#[derive(Debug, Clone)]
pub struct HttpClientOptions {
    pub remote_host: String,
    pub remote_port: u16,
    pub local_ipv4: IpAddr,
    pub local_ipv6: IpAddr,
    pub local_port: u16,
    pub scheme: HttpScheme,
    pub version: HttpVersion,
    pub allow_insecure: bool,
}

#[derive(Debug)]
pub struct HttpClient {
    pub client_options: HttpClientOptions,
    pub logging_options: LoggingOptions,
    pub ping_options: PingOptions,
    pub ip_options: IpOptions,
}
impl HttpClient {
    pub async fn connect(&self) -> Result<()> {
        let src_ip_port = IpPort {
            ipv4: self.client_options.local_ipv4,
            ipv6: self.client_options.local_ipv6,
            port: self.client_options.local_port,
        };
        let protocol = get_connect_method(&self.client_options.scheme);

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
            protocol,
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
                    async move {
                        //
                        process_host(
                            src_ip_port,
                            host_record,
                            self.client_options.clone(),
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
                let summary_msg = client_summary_result(&addr, protocol, client_summary);
                client_results.push(summary_msg)
            }
        }
        client_results.sort_by_key(|x| x.destination.to_owned());

        let summary_table = client_summary_table_msg(
            &self.client_options.remote_host,
            self.client_options.remote_port,
            protocol,
            &client_results,
        );
        println!("{}", summary_table);

        Ok(())
    }
}

async fn process_host(
    src_ip_port: IpPort,
    host_record: HostRecord,
    client_options: HttpClientOptions,
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
                let host_record = host_record.clone();
                let client_options = client_options.clone();
                async move {
                    //
                    match connect_host(
                        host_record,
                        src_ip_port,
                        dst_socket,
                        client_options.clone(),
                        ping_options,
                    )
                    .await
                    {
                        Ok(record) => record,
                        Err(e) => ConnectRecord {
                            result: ConnectResult::Error(ConnectError::Unknown),
                            protocol: get_connect_method(&client_options.scheme),
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
    host_record: HostRecord,
    src: IpPort,
    dst_socket: SocketAddr,
    client_options: HttpClientOptions,
    ping_options: PingOptions,
) -> Result<ConnectRecord> {
    let (bind_addr, src_socket) = match &dst_socket.is_ipv4() {
        // Bind the source socket to the same IP Version as the destination socket.
        true => {
            let bind_ipv4_addr = SocketAddr::new(src.ipv4, src.port);
            let socket = get_tcp_socket(bind_ipv4_addr).ok();
            (bind_ipv4_addr, socket)
        }
        false => {
            let bind_ipv6_addr = SocketAddr::new(src.ipv6, src.port);
            let socket = get_tcp_socket(bind_ipv6_addr).ok();
            (bind_ipv6_addr, socket)
        }
    };

    let protocol = get_connect_method(&client_options.scheme);

    // If the source socket is None, we could not bind to the socket.
    if src_socket.is_none() {
        return Ok(ConnectRecord {
            result: ConnectResult::Error(ConnectError::BindError),
            protocol,
            source: bind_addr.to_string(),
            destination: dst_socket.to_string(),
            time: -1.0,
            success: false,
            error_msg: Some("Error binding to socket".to_owned()),
        });
    }

    let mut headers = HeaderMap::new();
    // These should never fail.
    headers.insert(header::ACCEPT, "*/*".parse().unwrap());
    headers.insert(header::USER_AGENT, format!("netkraken/{NK_VERSION}").parse().unwrap());
    headers.insert(header::CONNECTION, "keep-alive".parse().unwrap());
    headers.insert(
        header::HOST,
        format!("{}:{}", host_record.host, host_record.port).parse().unwrap(),
    );

    let http_client = match client_options.scheme {
        HttpScheme::Http => {
            Client::builder()
                .default_headers(headers)
                .redirect(reqwest::redirect::Policy::limited(10))
                .resolve(&host_record.host, dst_socket) // Bypass DNS resolution as we have already resolved the IP
                .timeout(Duration::from_millis(ping_options.timeout as u64))
                .local_address(bind_addr.ip())
                .build()?
        }
        HttpScheme::Https => {
            let client = Client::builder()
                .default_headers(headers)
                .tls_built_in_root_certs(true) // Use system root certificates
                .use_rustls_tls() // Use rustls instead of native-tls
                .tls_sni(true)
                .redirect(reqwest::redirect::Policy::limited(10))
                .resolve(&host_record.host, dst_socket) // Bypass DNS resolution as we have already resolved the IP
                .timeout(Duration::from_millis(ping_options.timeout as u64))
                .local_address(bind_addr.ip());

            let client = match client_options.version {
                HttpVersion::V1 => client.http1_only(),
                HttpVersion::V2 => client
                    .http2_prior_knowledge()
                    .http2_initial_stream_window_size(1024 * 1024)
                    .http2_initial_connection_window_size(1024 * 1024)
                    .http2_keep_alive_interval(Some(Duration::from_millis(100)))
                    .http2_keep_alive_timeout(Duration::from_millis(ping_options.timeout as u64)),
                _ => client,
            };

            // Handle insecure certificates if allowed
            let client = if client_options.allow_insecure {
                client
                    .danger_accept_invalid_certs(true)
                    .danger_accept_invalid_hostnames(true)
            } else {
                client
            };

            client.build()?
        }
    };

    let mut conn_record = ConnectRecord {
        result: ConnectResult::Error(ConnectError::Unknown),
        protocol,
        source: bind_addr.to_string(),
        destination: dst_socket.to_string(),
        time: -1.0,
        success: false,
        error_msg: None,
    };

    // record timestamp before connection
    let pre_conn_timestamp = time_now_us();

    let url = format!("{}://{}:{}", client_options.scheme, host_record.host, host_record.port);
    debug!("Connecting to URL: {}", url);

    match http_client.get(url.clone()).send().await {
        Ok(response) => {
            let post_conn_timestamp = time_now_us();
            let connection_time = calc_connect_ms(pre_conn_timestamp, post_conn_timestamp);
            conn_record.success = true;
            conn_record.time = connection_time;
            conn_record.result = ConnectResult::Success(ConnectSuccess::Ok);

            // Extract the local IP address from the response if available
            if let Some(info) = response.extensions().get::<HttpInfo>() {
                conn_record.source = info.local_addr().to_string();
            }

            debug!(
                "Connection successful: status={}, protocol={:?}",
                response.status(),
                response.version()
            );

            // Log details about TLS if available
            if let Some(info) = response.extensions().get::<HttpInfo>() {
                debug!(
                    "Connection details: local={}, remote={}",
                    info.local_addr(),
                    info.remote_addr()
                );
            }
            // Explicitly drop the response after recording the success
            // to avoid the need to consume the body
            drop(response);
        }
        Err(e) => {
            // We got a redirection from http to https we could end up in the error case as
            // the client does not support this flow. If we are connected, still consider
            // it a success as we could reach the server.
            if e.is_connect() {
                let post_conn_timestamp = time_now_us();
                let connection_time = calc_connect_ms(pre_conn_timestamp, post_conn_timestamp);
                conn_record.success = true;
                conn_record.time = connection_time;
                conn_record.result = ConnectResult::Success(ConnectSuccess::Ok);
            } else {
                conn_record.error_msg = Some(e.to_string());
                if e.is_timeout() {
                    conn_record.result = ConnectResult::Error(ConnectError::Timeout);
                    debug!("Timeout Error: {}: {}", url, e)
                } else if e.is_connect() {
                    conn_record.result = ConnectResult::Error(ConnectError::ConnectionError);
                    debug!("Connection Error {}: {}", url, e)
                } else {
                    conn_record.result = ConnectResult::Error(ConnectError::Error);
                    debug!("Unknown Error {}: {}", url, e)
                }
            }
        }
    };

    Ok(conn_record)
}

// Map the `ConnectMethod` from the `HttpScheme`
fn get_connect_method(scheme: &HttpScheme) -> ConnectMethod {
    match scheme {
        HttpScheme::Http => ConnectMethod::Http,
        HttpScheme::Https => ConnectMethod::Https,
    }
}
