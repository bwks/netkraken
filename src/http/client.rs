use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{bail, Result};
use futures::StreamExt;
use reqwest::Client;
use tokio::net::TcpSocket;
use tokio::signal;
use tokio::time::{timeout, Duration};

use crate::core::common::{
    ClientResult, ClientSummary, ConnectMethod, ConnectRecord, ConnectResult, HostRecord, HostResults, IpOptions,
    IpPort, IpProtocol, LoggingOptions, PingOptions,
};
use crate::core::konst::{BIND_ADDR_IPV4, BIND_ADDR_IPV6, BIND_PORT, BUFFER_SIZE};
use crate::util::dns::resolve_host;
use crate::util::handler::{io_error_switch_handler, log_handler2, loop_handler};
use crate::util::message::{client_result_msg, client_summary_table_msg, ping_header_msg, resolved_ips_msg};
use crate::util::parser::parse_ipaddr;
use crate::util::result::{client_summary_result, get_results_map};
use crate::util::time::{calc_connect_ms, time_now_us};

#[derive(Debug)]
pub struct HttpClient {
    pub dst_ip: String,
    pub dst_port: u16,
    pub src_ipv4: Option<IpAddr>,
    pub src_ipv6: Option<IpAddr>,
    pub src_port: u16,
    pub logging_options: LoggingOptions,
    pub ping_options: PingOptions,
    pub ip_options: IpOptions,
}
impl HttpClient {
    pub async fn connect(&self) -> Result<()> {
        // Create a reqwest client with appropriate configuration
        let client = Client::new();

        // Format the URL with proper HTTP prefix
        let url = format!("http://{}:{}", self.dst_ip, self.dst_port);
        println!("{url}");
        let response = client.get(url).send().await?;
        let status = response.status();
        println!("Status code: {}", status);

        if !status.is_success() {
            bail!("Request failed with status: {}", status);
        }
        Ok(())
    }
}
