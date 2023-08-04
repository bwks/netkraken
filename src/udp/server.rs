use anyhow::Result;
use tokio::net::UdpSocket;

pub struct UdpServer {
    pub src_addr: String,
    pub src_port: u16,
}

impl UdpServer {
    pub async fn listen(&self) -> Result<()> {
        let bind_addr = format!("{}:{}", self.src_addr, self.src_port);

        let sock = UdpSocket::bind(&bind_addr).await?;
        println!("UDP server listening on {}", &bind_addr);
        println!("Press CRTL+C to exit");
        println!("--------------------");

        let mut buf = Vec::with_capacity(64);
        loop {
            let len = sock.recv_buf(&mut buf).await?;
            let data = String::from_utf8_lossy(&buf[..len]);
            println!("RECV: {data}");
            buf.clear();
        }
    }
}

impl Default for UdpServer {
    fn default() -> Self {
        Self {
            src_addr: "0.0.0.0".to_owned(),
            src_port: 13337,
        }
    }
}
