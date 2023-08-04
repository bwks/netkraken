pub fn get_conn_string(protocol: String, source: String, destination: String) -> String {
    format!("{} {} => {}", protocol, source, destination)
}
