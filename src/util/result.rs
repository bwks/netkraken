use std::collections::HashMap;

use crate::core::common::HostRecord;

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
            ipv4_sockets: vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                443,
            )],
            ipv6_sockets: vec![SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                443,
            )],
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
}
