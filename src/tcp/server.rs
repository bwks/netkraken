use anyhow::Result;

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use crate::konst::{BIND_ADDR, BIND_PORT};
use crate::util::parser::parse_ipaddr;

pub struct TcpServer {
    pub src_addr: String,
    pub src_port: u16,
}

impl TcpServer {
    pub async fn listen(&self) -> Result<()> {
        let src_addr = parse_ipaddr(&self.src_addr)?;
        let bind_addr = format!("{}:{}", src_addr, self.src_port);

        let listener = TcpListener::bind(&bind_addr).await?;

        println!("TCP server listening on {}", &bind_addr);
        println!("Press CRTL+C to exit");
        println!("--------------------");

        let mut buffer = Vec::with_capacity(64);
        loop {
            let (mut stream, _) = listener.accept().await?;
            let len = stream.read_to_end(&mut buffer).await?;
            let data = String::from_utf8_lossy(&buffer[..len]);
            println!("RECV: {data}");
            buffer.clear();
        }
    }
}

impl Default for TcpServer {
    fn default() -> Self {
        Self {
            src_addr: BIND_ADDR.to_owned(),
            src_port: BIND_PORT,
        }
    }
}
