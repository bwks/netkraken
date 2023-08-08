use crate::core::common::ConnectMethod;

/// Prints the CLI header message
pub fn cli_header_msg() {
    println!("Net Kraken - Network connectivity tester");
    println!("----------------------------------------")
}

/// Prints out a ping header message
pub fn ping_header_msg(protocol: ConnectMethod, destination: String) {
    println!(
        "Connecting via {} to {}",
        protocol.to_string().to_uppercase(),
        destination
    );
}

pub fn get_conn_string(protocol: ConnectMethod, source: &String, destination: &String) -> String {
    format!(
        "proto={} src={} dst={}",
        protocol.to_string().to_uppercase(),
        source,
        destination
    )
}

/// Prints out an error message
pub fn client_err_msg(sequence: u16, message: &str) {
    println!("seq={} err={}", sequence, message)
}

/// Prints out a client connection success message
pub fn client_conn_success_msg(
    sequence: u16,
    protocol: ConnectMethod,
    source: &String,
    destination: &String,
    time: f64,
) {
    println!(
        "seq={} proto={} src={} dst={} time={}ms",
        sequence,
        protocol.to_string().to_uppercase(),
        source,
        destination,
        time,
    )
}

/// Prints out a server connection success message
pub fn server_conn_success_msg(protocol: ConnectMethod, source: &String, destination: &String) {
    println!(
        "proto={} src={} dst={}",
        protocol.to_string().to_uppercase(),
        source,
        destination,
    )
}
