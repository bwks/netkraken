use crate::core::common::{ConnectMethod, ConnectResult};

/// Prints the CLI header message
pub fn cli_header_msg() {
    println!("NetKraken - Cross platform network connectivity tester");
    println!("")
}

/// Prints out server start message
pub fn server_start_msg(protocol: ConnectMethod, bind_addr: &String) {
    println!(
        "{} server listening on {}",
        protocol.to_string().to_uppercase(),
        &bind_addr
    );
    println!("Press CRTL+C to exit");
    println!("");
}

/// Prints out a ping header message
pub fn ping_header_msg(source: &String, destination: &String, protocol: ConnectMethod) {
    println!(
        "Connecting from {} to {} via {}",
        source,
        destination,
        protocol.to_string().to_uppercase(),
    );
}

/// Prints out an error message
pub fn client_err_msg(result: ConnectResult, error: std::io::Error) {
    match result {
        ConnectResult::Unknown => {
            println!("error => {}", error)
        }
        _ => {
            println!("error => {}", result.to_string())
        }
    }
}

/// Prints out a client connection success message
pub fn client_conn_success_msg(
    result: ConnectResult,
    protocol: ConnectMethod,
    source: &String,
    destination: &String,
    time: f64,
) {
    println!(
        // "{} => proto={} src={} dst={} time={:.3}ms",
        "{} => proto={} src={} dst={} time={:.3}ms",
        result.to_string(),
        protocol.to_string().to_uppercase(),
        source,
        destination,
        time,
    )
}

/// Prints out a server connection success message
pub fn server_conn_success_msg(
    result: ConnectResult,
    protocol: ConnectMethod,
    source: &String,
    destination: &String,
    time: f64,
) {
    let msg = match time == 0.0 {
        true => {
            format!(
                "{} => proto={} src={} dst={}",
                result.to_string(),
                protocol.to_string().to_uppercase(),
                source,
                destination,
            )
        }
        false => {
            format!(
                "{} => proto={} src={} dst={} time={:.3}",
                result.to_string(),
                protocol.to_string().to_uppercase(),
                source,
                destination,
                time,
            )
        }
    };
    println!("{msg}")
}
