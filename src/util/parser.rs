use std::net::IpAddr;

use anyhow::{bail, Result};

pub fn parse_ipaddr(s: &String) -> Result<IpAddr> {
    if !s.contains(".") && !s.contains(":") {
        bail!("source address: `{s}` is invalid")
    }

    match s.parse::<IpAddr>() {
        Ok(a) => Ok(a),
        Err(_) => bail!("source address: `{s}` is invalid"),
    }
}
