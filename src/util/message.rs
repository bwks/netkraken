use std::net::{IpAddr, SocketAddr};

use tabled::settings::Panel;
use tabled::settings::{object::Rows, Alignment, Margin, Modify, Span, Style};
use tabled::Table;

use crate::core::common::{ClientResult, ConnectMethod, ConnectRecord, ConnectResult, ConnectResult2, HostRecord};

/// Return server start message
pub fn server_start_msg(protocol: ConnectMethod, bind_addr: &IpAddr, bind_port: &u16) -> String {
    let addr = match bind_addr.is_ipv6() {
        true => format!("[{}]", bind_addr),
        false => bind_addr.to_string(),
    };

    format!(
        "{} server listening on {}:{}\n\
        Press CRTL+C to exit\n",
        protocol.to_string().to_uppercase(),
        addr,
        bind_port,
    )
}

/// Return a list of resolved IPs from a hostname
pub fn resolved_ips_msg(host_record: &HostRecord) -> String {
    let num_ips = host_record.ipv4_sockets.len() + host_record.ipv6_sockets.len();
    let ip_desc = match num_ips {
        1 => "IP",
        _ => "IPs",
    };
    let ip_records: Vec<&SocketAddr> = host_record
        .ipv4_sockets
        .iter()
        .chain(host_record.ipv6_sockets.iter())
        .collect();

    let ip_record_str = ip_records
        .iter()
        .map(|x| format!(" {}", x.ip()))
        .collect::<Vec<String>>()
        .join("\n");

    format!(
        "{} resolves to {} {}\n\
        {}\n",
        host_record.host, num_ips, ip_desc, ip_record_str,
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
        ConnectResult2::Old(ConnectResult::Ping) | ConnectResult2::Old(ConnectResult::Pong) => {
            format!(
                "{} => proto={} src={} dst={} time={:.3}ms",
                record.result,
                record.protocol.to_string().to_uppercase(),
                record.source,
                record.destination,
                record.time,
            )
        }
        ConnectResult2::Old(ConnectResult::ConnectError)
        | ConnectResult2::Old(ConnectResult::Error)
        | ConnectResult2::Old(ConnectResult::Refused)
        | ConnectResult2::Old(ConnectResult::Reset)
        | ConnectResult2::Old(ConnectResult::Timeout)
        | ConnectResult2::Old(ConnectResult::Unknown)
        | ConnectResult2::Old(ConnectResult::BindError)
        | ConnectResult2::Http(_) => {
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

pub fn client_summary_table_msg(
    dst_host: &String,
    dst_port: u16,
    connect_method: ConnectMethod,
    client_results: &Vec<ClientResult>,
) -> String {
    let header = format!(
        "--- Statistics for {} connection to {}:{} ---",
        connect_method.to_string().to_uppercase(),
        dst_host,
        dst_port,
    );
    Table::new(client_results)
        // table
        .with(Style::ascii())
        .with(Margin::new(0, 0, 1, 1))
        .with(Panel::header(header))
        .with(
            Modify::new(Rows::first())
                .with(Span::column(9))
                .with(Alignment::center()),
        )
        .to_string()
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use crate::core::common::HostRecord;
    use crate::core::konst::CLI_HEADER_MSG;
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
            ipv4_sockets: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443)],
            ipv6_sockets: vec![],
        };
        let msg = resolved_ips_msg(&host_record);

        assert_eq!(msg, "blah.bleh resolves to 1 IP\n 127.0.0.1\n");
    }

    #[test]
    fn resolved_ips_msg_with_only_ip6s_is_expected() {
        let host_record = HostRecord {
            host: "blah.bleh".to_owned(),
            port: 443,
            ipv4_sockets: vec![],
            ipv6_sockets: vec![SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 443)],
        };
        let msg = resolved_ips_msg(&host_record);

        assert_eq!(msg, "blah.bleh resolves to 1 IP\n ::1\n");
    }

    #[test]
    fn resolved_ips_msg_with_ipv4_and_ip6s_is_expected() {
        let host_record = HostRecord {
            host: "blah.bleh".to_owned(),
            port: 443,
            ipv4_sockets: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443)],
            ipv6_sockets: vec![SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 443)],
        };
        let msg = resolved_ips_msg(&host_record);

        assert_eq!(msg, "blah.bleh resolves to 2 IPs\n 127.0.0.1\n ::1\n");
    }

    #[test]
    fn ping_header_msg_is_expected() {
        let msg = ping_header_msg(&"198.51.100.1".to_owned(), 443, ConnectMethod::Tcp);

        assert_eq!(msg, "Connecting to 198.51.100.1:443 via TCP");
    }

    #[test]
    fn cli_header_msg_is_expected() {
        assert_eq!(
            CLI_HEADER_MSG,
            "NetKraken - Cross platform network connectivity tester\n"
        );
    }

    #[test]
    fn server_start_msg_is_expected() {
        let listen_ip: IpAddr = "127.0.0.1".parse::<IpAddr>().unwrap();

        let msg = server_start_msg(ConnectMethod::Tcp, &listen_ip, &42069);

        assert_eq!(
            msg,
            "TCP server listening on 127.0.0.1:42069\nPress CRTL+C to exit\n".to_string()
        );
    }

    #[test]
    fn client_summary_table_msg_is_expected() {
        let client_results = ClientResult {
            destination: "198.51.100.1".to_owned(),
            protocol: ConnectMethod::Tcp,
            sent: 4,
            received: 4,
            lost: 0,
            loss_percent: 0.0,
            min: 234.0,
            max: 254.0,
            avg: 243.0,
        };

        let summary_table = client_summary_table_msg(
            &"stuff.things".to_string(),
            443,
            ConnectMethod::Tcp,
            &vec![client_results],
        );

        let expected = "                                                                                                \n\
        +--------------+----------+------+----------+------+----------+----------+----------+----------+\n\
        |                  --- Statistics for TCP connection to stuff.things:443 ---                   |\n\
        +--------------+----------+------+----------+------+----------+----------+----------+----------+\n\
        | Destination  | Protocol | Sent | Received | Lost | Loss (%) | Min (ms) | Max (ms) | Avg (ms) |\n\
        +--------------+----------+------+----------+------+----------+----------+----------+----------+\n\
        | 198.51.100.1 | TCP      | 4    | 4        | 0    | 0.00     | 234.000  | 254.000  | 243.000  |\n\
        +--------------+----------+------+----------+------+----------+----------+----------+----------+\n                                                                                                ";

        assert_eq!(summary_table, expected);
    }

    #[test]
    fn server_conn_success_msg_with_time_is_expected() {
        let msg = server_conn_success_msg(
            ConnectResult::Ping,
            ConnectMethod::Tcp,
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
            ConnectMethod::Tcp,
            &"127.0.0.1:13337".to_string(),
            &"127.0.0.1:8080".to_string(),
            0.0,
        );

        assert_eq!(msg, "ping => proto=TCP src=127.0.0.1:13337 dst=127.0.0.1:8080",);
    }
}
