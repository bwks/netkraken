use std::net::IpAddr;

use anyhow::{Result, bail};

use local_ip_address::list_afinet_netifas;

/// Validate that the source IP address is an IP address on a local interface.
pub fn validate_local_ip(src_ip: &IpAddr) -> Result<()> {
    let network_interfaces = list_afinet_netifas()?;

    let mut ipv4_addrs = Vec::new();

    let mut ipv6_addrs = Vec::new();

    for (_name, ip) in network_interfaces.iter() {
        match ip.is_ipv4() {
            true => {
                ipv4_addrs.push(ip);
            }
            false => {
                ipv6_addrs.push(ip);
            }
        }
    }

    match src_ip.is_ipv4() {
        true => {
            if ipv4_addrs.contains(&src_ip) {
                return Ok(());
            }
        }
        false => {
            if ipv6_addrs.contains(&src_ip) {
                return Ok(());
            }
        }
    }

    bail!("Source address: `{}` is not a local address", src_ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    const IPV4_ADDR: &str = "198.51.100.1";
    const IPV6_ADDR: &str = "2001:0DB8::1";

    #[test]
    fn test_validate_local_ipv4_fails() {
        let ipv4 = IPV4_ADDR.parse().unwrap();
        assert!(validate_local_ip(&ipv4).is_err());
    }

    #[test]
    fn test_validate_local_ipv6_fails() {
        let ipv6 = IPV6_ADDR.parse().unwrap();
        assert!(validate_local_ip(&ipv6).is_err());
    }
}
