use std::collections::HashMap;

use crate::core::common::{ClientResult, ClientSummary, ConnectMethod, HostRecord};

/// Return a results_map hash from a Vec of HostRecords
pub fn get_results_map(host_records: &[HostRecord]) -> HashMap<String, HashMap<String, Vec<f64>>> {
    let mut results_map: HashMap<String, HashMap<String, Vec<f64>>> = HashMap::new();

    for record in host_records.iter().cloned() {
        results_map.insert(record.host.to_owned(), HashMap::new());

        for addr in record.ipv4_sockets {
            results_map
                .get_mut(&record.host)
                // this should never fail because we just inserted record.host
                .unwrap()
                .insert(addr.to_string(), vec![]);
        }
        for addr in record.ipv6_sockets {
            results_map
                .get_mut(&record.host)
                // this should never fail because we just inserted record.host
                .unwrap()
                .insert(addr.to_string(), vec![]);
        }
    }

    results_map
}

/// Returns a client summary result
pub fn client_summary_result(
    destination: &String,
    protocol: ConnectMethod,
    client_summary: ClientSummary,
) -> ClientResult {
    let mut min: f64 = 0.0;
    let mut max: f64 = 0.0;
    let mut avg: f64 = 0.0;
    let mut latencies = client_summary.latencies;

    // Filetr our any f64::NAN
    latencies.retain(|f| !f.is_nan());
    latencies.retain(|f| f > &0.0);

    // Sort lowest to highest
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    if !latencies.is_empty() {
        min = *latencies.first().unwrap_or(&0.0);
        max = *latencies.last().unwrap_or(&0.0);
        let sum: f64 = latencies.iter().sum();
        avg = sum / latencies.len() as f64;
    }

    let received_count = latencies.len() as u16;

    ClientResult {
        destination: destination.to_owned(),
        protocol,
        sent: client_summary.send_count,
        received: received_count,
        lost: client_summary.send_count - received_count,
        loss_percent: calc_loss_percent(client_summary.send_count, received_count),
        min,
        max,
        avg,
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
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use crate::core::common::HostRecord;
    use crate::util::result::*;

    #[test]
    fn result_map_with_no_ips_is_expected() {
        let host_record = HostRecord {
            host: "blah.bleh".to_owned(),
            port: 443,
            ipv4_sockets: vec![],
            ipv6_sockets: vec![],
        };
        let host = host_record.host.to_owned();

        let results_map = get_results_map(&[host_record]);
        let mut expected: HashMap<String, HashMap<String, Vec<f64>>> = HashMap::new();
        let ip_map: HashMap<String, Vec<f64>> = HashMap::new();

        expected.insert(host.to_owned(), ip_map);

        assert_eq!(results_map, expected);
    }

    #[test]
    fn result_map_with_ipv4_and_ip6s_is_expected() {
        let host_record = HostRecord {
            host: "blah.bleh".to_owned(),
            port: 443,
            ipv4_sockets: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443)],
            ipv6_sockets: vec![SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 443)],
        };
        let host = host_record.host.to_owned();
        let ipv4_sockets = host_record.ipv4_sockets.clone();
        let ipv6_sockets = host_record.ipv6_sockets.clone();
        let results_map = get_results_map(&[host_record]);
        let mut expected: HashMap<String, HashMap<String, Vec<f64>>> = HashMap::new();
        let mut ipv4_map: HashMap<String, Vec<f64>> = HashMap::new();

        ipv4_map.insert(ipv4_sockets[0].to_string(), vec![]);
        expected.insert(host.to_owned(), ipv4_map);
        expected
            .get_mut(&host)
            .unwrap()
            .insert(ipv6_sockets[0].to_string(), vec![]);

        assert_eq!(results_map, expected);
    }

    #[test]
    fn calc_loss_percent_is_expected() {
        let loss = calc_loss_percent(100, 99);

        assert_eq!(loss, 1.0);
    }
}
