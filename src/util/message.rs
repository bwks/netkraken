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
pub fn client_err_msg(
    result: ConnectResult,
    protocol: ConnectMethod,
    source: &String,
    destination: &String,
    error: std::io::Error,
) -> String {
    let err = match result {
        ConnectResult::Unknown => error.to_string(),
        _ => result.to_string(),
    };
    format!(
        "{} => proto={} src={} dst={}",
        err,
        protocol.to_string().to_uppercase(),
        source,
        destination,
    )
}

/// Prints out a client connection success message
pub fn client_conn_success_msg(
    result: ConnectResult,
    protocol: ConnectMethod,
    source: &String,
    destination: &String,
    time: f64,
) -> String {
    let msg = format!(
        "{} => proto={} src={} dst={} time={:.3}ms",
        result.to_string(),
        protocol.to_string().to_uppercase(),
        source,
        destination,
        time,
    );
    msg
}

pub fn client_summary_msg(
    destination: &String,
    protocol: ConnectMethod,
    send_count: u16,
    received_count: u16,
    mut latencies: Vec<f64>,
) -> String {
    let mut min: f64 = 0.0;
    let mut max: f64 = 0.0;
    let mut avg: f64 = 0.0;

    if !latencies.is_empty() {
        // Filetr our any f64::NAN
        latencies.retain(|f| !f.is_nan());
        // Sort lowest to highest
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

        min = *latencies.first().unwrap_or(&0.0);
        max = *latencies.last().unwrap_or(&0.0);
        let count: f64 = latencies.iter().sum();
        avg = count / latencies.len() as f64;
    }

    format!(
        "\nStatistics for {} {}
  sent={} received={} lost={} ({} loss)
  min={:.2}ms max={:.2}ms avg={:.2}ms",
        destination,
        protocol.to_string().to_uppercase(),
        send_count,
        received_count,
        send_count - received_count,
        calc_loss_percent(send_count, received_count),
        min,
        max,
        avg,
    )
}

/// Prints out a server connection success message
pub fn server_conn_success_msg(
    result: ConnectResult,
    protocol: ConnectMethod,
    source: &String,
    destination: &String,
    time: f64,
) -> String {
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
                "{} => proto={} src={} dst={} time={:.3}ms",
                result.to_string(),
                protocol.to_string().to_uppercase(),
                source,
                destination,
                time,
            )
        }
    };
    msg
}

pub fn calc_loss_percent(sent: u16, received: u16) -> String {
    let percent = (sent as f64 - received as f64) / sent as f64;
    format!("{:.2}%", percent * 100.0)
}
