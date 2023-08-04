pub struct TcpServer {
    pub src_addr: String,
    pub src_port: u16,
}

impl Default for TcpServer {
    fn default() -> Self {
        Self {
            src_addr: "0.0.0.0".to_owned(),
            src_port: 13337,
        }
    }
}
