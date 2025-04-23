use std::net::IpAddr;

use anyhow::{Result, bail};

use crate::core::common::NetKrakenMessage;

/// Parse into a std::net::IPv4 or std::net::IPv6 address from a string
pub fn parse_ipaddr(s: &str) -> Result<IpAddr> {
    if !s.contains('.') && !s.contains(':') {
        bail!("source address: `{s}` is invalid")
    }

    match s.parse::<IpAddr>() {
        Ok(a) => Ok(a),
        Err(_) => bail!("source address: `{s}` is invalid"),
    }
}

/// Attempt to read in a NetKrakenMessage from a string
/// If the string cannot be read into a NetKrakenMessage then
/// it will be assumed that the peer is not a NetKraken host
pub fn nk_msg_reader(s: &str) -> Option<NetKrakenMessage> {
    let data: NetKrakenMessage = match serde_json::from_str(s) {
        // If we can read this message we have a NetKraken Peer
        Ok(d) => d,
        // Not a NetKraken peer
        Err(_) => return None,
    };
    Some(data)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::core::common::NetKrakenMessage;
    use crate::util::parser::{nk_msg_reader, parse_ipaddr};

    const IPV4_ADDR: &str = "198.51.100.1";
    const IPV6_ADDR: &str = "2001:0DB8::1";

    #[test]
    fn parse_ipaddr_with_ipv4_addr() {
        let result = parse_ipaddr(&IPV4_ADDR.to_owned()).unwrap();
        assert_eq!(result, Ipv4Addr::new(198, 51, 100, 1));
    }

    #[test]
    fn parse_ipaddr_with_ipv6_addr() {
        let result = parse_ipaddr(&IPV6_ADDR.to_owned()).unwrap();
        assert_eq!(result, Ipv6Addr::new(0x2001, 0x0DB8, 0, 0, 0, 0, 0, 1));
    }

    #[test]
    #[should_panic]
    fn parse_ipaddr_with_invalid_param() {
        parse_ipaddr(&"blah".to_string()).unwrap();
    }

    #[test]
    fn parse_nk_message_some() {
        let msg = serde_json::to_string(&NetKrakenMessage::default()).unwrap();
        assert!(nk_msg_reader(&msg).is_some());
    }

    #[test]
    fn parse_nk_message_none() {
        assert!(nk_msg_reader("msg").is_none());
    }
}
