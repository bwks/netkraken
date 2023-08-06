use crate::core::common::ConnectMethod;

pub fn get_conn_string(protocol: ConnectMethod, source: &String, destination: &String) -> String {
    format!(
        "{} {} => {}",
        protocol.to_string().to_uppercase(),
        source,
        destination
    )
}
