use socket2::{Domain, Protocol, Socket, Type};
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::Result;

pub fn ping(dest: &str, count: usize) -> Result<()> {
    let addr: SocketAddr = format!("{dest}:0").parse()?;
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;

    let identifier = (std::process::id() % u16::MAX as u32) as u16;
    let mut seq = 0;

    for _ in 0..count {
        let packet = build_icmp_echo(identifier, seq);
        let start = Instant::now();
        socket.send_to(&packet, &addr.into())?;

        let mut buf = [MaybeUninit::<u8>::uninit(); 1024];

        match socket.recv_from(&mut buf) {
            Ok((n, _src_addr)) => {
                let rtt = start.elapsed().as_millis();

                // This is safe to because:
                // recv_from guarantees initialization of first n bytes
                // We only access buf[..n] after successful reception
                let received_data = buf[..n].iter().map(|b| unsafe { b.assume_init() }).collect::<Vec<u8>>();

                if n > 0 && parse_icmp_reply(&received_data, identifier, seq) {
                    println!("Reply from {} seq={} time={}ms", dest, seq, rtt);
                }
            }
            Err(e) => eprintln!("Request timeout: {}", e),
        }
        seq += 1;
    }
    Ok(())
}

fn build_icmp_echo(identifier: u16, seq: u16) -> Vec<u8> {
    let mut packet = vec![
        8,
        0, // Type=8 (Echo Request), Code=0
        0,
        0, // Checksum (placeholder)
        (identifier >> 8) as u8,
        (identifier & 0xFF) as u8, // Identifier
        (seq >> 8) as u8,
        (seq & 0xFF) as u8, // Sequence
    ];
    packet.extend(vec![0; 32]); // 32-byte payload

    let checksum = icmp_checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn parse_icmp_reply(packet: &[u8], identifier: u16, seq: u16) -> bool {
    // Make sure we have at least one byte for the IP header
    if packet.is_empty() {
        return false;
    }

    // Skip the IP header (the first byte is the version and IHL)
    let ip_header_length = (packet[0] & 0x0F) * 4; // IHL gives length in 4-byte words

    // Check if we have enough data for the IP header
    if packet.len() < ip_header_length as usize {
        return false;
    }

    // ICMP data starts after the IP header
    let icmp_data = &packet[ip_header_length as usize..];

    // println!("IP header length: {}", ip_header_length);
    // println!("ICMP type: {}", icmp_data[0]);
    // println!("ICMP data: {:#?}", icmp_data);

    // Now check the ICMP header
    icmp_data.len() >= 8
        && icmp_data[0] == 0  // Echo Reply type
        && icmp_data[1] == 0  // Code
        && u16::from_be_bytes([icmp_data[4], icmp_data[5]]) == identifier
        && u16::from_be_bytes([icmp_data[6], icmp_data[7]]) == seq
}

fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        let word =
            if chunk.len() == 2 { u16::from_be_bytes([chunk[0], chunk[1]]) } else { u16::from_be_bytes([chunk[0], 0]) };
        sum += word as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
