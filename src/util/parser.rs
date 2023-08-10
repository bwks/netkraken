use std::net::IpAddr;

use anyhow::{bail, Result};

use crate::core::common::{HelloMessage, NetKrakenMessage};

pub fn parse_ipaddr(s: &String) -> Result<IpAddr> {
    if !s.contains(".") && !s.contains(":") {
        bail!("source address: `{s}` is invalid")
    }

    match s.parse::<IpAddr>() {
        Ok(a) => Ok(a),
        Err(_) => bail!("source address: `{s}` is invalid"),
    }
}

/// Attempt to read in a HelloMessage from a string
pub fn hello_msg_reader(s: &str) -> Option<HelloMessage> {
    let data: HelloMessage = match serde_json::from_str(s) {
        // If we can read this hello message we have a
        // NetKraken Peer
        Ok(d) => d,
        // Not a NetKraken peer
        Err(_) => return None,
    };
    Some(data)
}

/// Attempt to read in a NetKrakenMessage from a string
pub fn nk_msg_reader(s: &str) -> Option<NetKrakenMessage> {
    let data: NetKrakenMessage = match serde_json::from_str(s) {
        // If we can read this hello message we have a
        // NetKraken Peer
        Ok(d) => d,
        // Not a NetKraken peer
        Err(_) => return None,
    };
    Some(data)
}
