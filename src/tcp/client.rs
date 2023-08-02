use tokio::net::TcpSocket;

#[derive(Debug)]
pub struct TcpConnector {
    // pub src_ip: String,
    // pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
}

impl TcpConnector {
    pub fn new(
        // src_ip: &str,
        // src_port: u16,
        dst_ip: &str,
        dst_port: u16,
    ) -> Self {
        Self {
            // src_ip: src_ip.to_owned(),
            // src_port,
            dst_ip: dst_ip.to_owned(),
            dst_port,
        }
    }
}
