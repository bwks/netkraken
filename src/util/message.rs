use std::net::SocketAddr;

use crate::core::common::{
    ClientSummary, ClientSummary2, ConnectMethod, ConnectRecord, ConnectResult, HostRecord,
};

/// Return the CLI header message
pub fn cli_header_msg() -> String {
    "NetKraken - Cross platform network connectivity tester\n".to_string()
}

/// Return server start message
pub fn server_start_msg(protocol: ConnectMethod, bind_addr: &String) -> String {
    format!(
        "{} server listening on {}
Press CRTL+C to exit
",
        protocol.to_string().to_uppercase(),
        &bind_addr
    )
}

/// Return a list of resolved IPs from a hostname
pub fn resolved_ips_msg(host_record: &HostRecord) -> String {
    let ip_records: Vec<&SocketAddr> = host_record
        .ipv4_sockets
        .iter()
        .chain(host_record.ipv6_sockets.iter())
        .collect();

    let ip_str = ip_records
        .iter()
        .map(|x| format!(" {}", x.ip()))
        .collect::<Vec<String>>()
        .join("\n");

    format!(
        "{} resolves to {} IPs
{}
",
        host_record.host,
        host_record.ipv4_sockets.len() + host_record.ipv6_sockets.len(),
        ip_str,
    )
}

/// Return a ping header message
pub fn ping_header_msg(destination: &String, port: u16, protocol: ConnectMethod) -> String {
    format!(
        "Connecting to {}:{} via {}",
        destination,
        port,
        protocol.to_string().to_uppercase(),
    )
}

/// Returns a client result message
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
                record.result,
                record.protocol.to_string().to_uppercase(),
                record.source,
                record.destination,
            )
        }
    }
}

/// Returns a client connection summary message
pub fn client_summary_msg(
    destination: &String,
    protocol: ConnectMethod,
    client_summary: ClientSummary,
) -> String {
    let mut min: f64 = 0.0;
    let mut max: f64 = 0.0;
    let mut avg: f64 = 0.0;
    let mut latencies = client_summary.latencies;

    // Filetr our any f64::NAN
    latencies.retain(|f| !f.is_nan());
    latencies.retain(|f| f > &0.0);

    // Sort lowest to highest
    // TODO: Fix this unwrap
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

    if !latencies.is_empty() {
        min = *latencies.first().unwrap_or(&0.0);
        max = *latencies.last().unwrap_or(&0.0);
        let sum: f64 = latencies.iter().sum();
        avg = sum / latencies.len() as f64;
    }

    let received_count = latencies.len() as u16;

    let msg = format!(
        "\nStatistics for {} connection to {} 
 sent={} received={} lost={} ({:.2}% loss)
 min={:.3}ms max={:.3}ms avg={:.3}ms",
        protocol.to_string().to_uppercase(),
        destination,
        client_summary.send_count,
        received_count,
        client_summary.send_count - received_count,
        calc_loss_percent(client_summary.send_count, received_count),
        min,
        max,
        avg,
    );
    msg
}

/// Returns a client connection summary message
pub fn client_summary_msg2(
    destination: &String,
    protocol: ConnectMethod,
    client_summary: ClientSummary,
) -> ClientSummary2 {
    let mut min: f64 = 0.0;
    let mut max: f64 = 0.0;
    let mut avg: f64 = 0.0;
    let mut latencies = client_summary.latencies;

    // Filetr our any f64::NAN
    latencies.retain(|f| !f.is_nan());
    latencies.retain(|f| f > &0.0);

    // Sort lowest to highest
    // TODO: Fix this unwrap
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

    if !latencies.is_empty() {
        min = *latencies.first().unwrap_or(&0.0);
        max = *latencies.last().unwrap_or(&0.0);
        let sum: f64 = latencies.iter().sum();
        avg = sum / latencies.len() as f64;
    }

    let received_count = latencies.len() as u16;

    let msg = ClientSummary2 {
        destination: destination.to_owned(),
        protocol,
        sent: client_summary.send_count,
        received: received_count,
        lost: client_summary.send_count - received_count,
        loss_percent: calc_loss_percent(client_summary.send_count, received_count),
        min,
        max,
        avg,
    };
    msg
}

/// Returns a server connection summary message
pub fn server_conn_success_msg(
    result: ConnectResult,
    protocol: ConnectMethod,
    source: &String,
    destination: &String,
    time: f64,
) -> String {
    match time == 0.0 {
        true => {
            format!(
                "{} => proto={} src={} dst={}",
                result,
                protocol.to_string().to_uppercase(),
                source,
                destination,
            )
        }
        false => {
            format!(
                "{} => proto={} src={} dst={} time={:.3}ms",
                result,
                protocol.to_string().to_uppercase(),
                source,
                destination,
                time,
            )
        }
    }
}

/// Calculate the percentage of loss between the
/// amount of pings sent and the amount received
pub fn calc_loss_percent(sent: u16, received: u16) -> f64 {
    let percent = (sent as f64 - received as f64) / sent as f64;
    percent * 100.0
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use crate::core::common::HostRecord;
    use crate::util::message::*;

    #[test]
    fn resolved_ips_msg_with_no_ips_is_expected() {
        let host_record = HostRecord {
            host: "blah.bleh".to_owned(),
            port: 443,
            ipv4_sockets: vec![],
            ipv6_sockets: vec![],
        };
        let msg = resolved_ips_msg(&host_record);

        assert_eq!(msg, "blah.bleh resolves to 0 IPs\n\n");
    }

    #[test]
    fn resolved_ips_msg_with_only_ip4s_is_expected() {
        let host_record = HostRecord {
            host: "blah.bleh".to_owned(),
            port: 443,
            ipv4_sockets: vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                443,
            )],
            ipv6_sockets: vec![],
        };
        let msg = resolved_ips_msg(&host_record);

        assert_eq!(msg, "blah.bleh resolves to 1 IPs\n 127.0.0.1\n");
    }

    #[test]
    fn resolved_ips_msg_with_only_ip6s_is_expected() {
        let host_record = HostRecord {
            host: "blah.bleh".to_owned(),
            port: 443,
            ipv4_sockets: vec![],
            ipv6_sockets: vec![SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                443,
            )],
        };
        let msg = resolved_ips_msg(&host_record);

        assert_eq!(msg, "blah.bleh resolves to 1 IPs\n ::1\n");
    }

    #[test]
    fn resolved_ips_msg_with_ipv4_and_ip6s_is_expected() {
        let host_record = HostRecord {
            host: "blah.bleh".to_owned(),
            port: 443,
            ipv4_sockets: vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                443,
            )],
            ipv6_sockets: vec![SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                443,
            )],
        };
        let msg = resolved_ips_msg(&host_record);

        assert_eq!(msg, "blah.bleh resolves to 2 IPs\n 127.0.0.1\n ::1\n");
    }

    #[test]
    fn ping_header_msg_is_expected() {
        let msg = ping_header_msg(&"198.51.100.1".to_owned(), 443, ConnectMethod::TCP);

        assert_eq!(msg, "Connecting to 198.51.100.1:443 via TCP");
    }

    #[test]
    fn calc_loss_percent_is_expected() {
        let loss = calc_loss_percent(100, 99);

        assert_eq!(loss, 1.0);
    }

    #[test]
    fn cli_header_msg_is_expected() {
        let msg = cli_header_msg();

        assert_eq!(
            msg,
            "NetKraken - Cross platform network connectivity tester\n"
        );
    }

    #[test]
    fn server_start_msg_is_expected() {
        let msg = server_start_msg(ConnectMethod::TCP, &"198.51.100.1:443".to_owned());

        assert_eq!(
            msg,
            "TCP server listening on 198.51.100.1:443\nPress CRTL+C to exit\n".to_string()
        );
    }

    #[test]
    fn client_summary_msg_is_expected() {
        let client_summary = ClientSummary {
            send_count: 4,
            latencies: vec![104.921, 108.447, 105.009],
        };
        let msg = client_summary_msg(
            &"198.51.100.1:443".to_string(),
            ConnectMethod::TCP,
            client_summary,
        );

        assert_eq!(
            msg,
            "\nStatistics for TCP connection to 198.51.100.1:443 \n sent=4 received=3 lost=1 (25.00% loss)\n min=104.921ms max=108.447ms avg=106.126ms",
        );
    }

    #[test]
    fn server_conn_success_msg_with_time_is_expected() {
        let msg = server_conn_success_msg(
            ConnectResult::Ping,
            ConnectMethod::TCP,
            &"127.0.0.1:13337".to_string(),
            &"127.0.0.1:8080".to_string(),
            123.0,
        );

        assert_eq!(
            msg,
            "ping => proto=TCP src=127.0.0.1:13337 dst=127.0.0.1:8080 time=123.000ms",
        );
    }

    #[test]
    fn server_conn_success_msg_without_time_is_expected() {
        let msg = server_conn_success_msg(
            ConnectResult::Ping,
            ConnectMethod::TCP,
            &"127.0.0.1:13337".to_string(),
            &"127.0.0.1:8080".to_string(),
            0.0,
        );

        assert_eq!(
            msg,
            "ping => proto=TCP src=127.0.0.1:13337 dst=127.0.0.1:8080",
        );
    }
}
