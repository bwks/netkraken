use anyhow::Result;
use clap::Parser;

use crate::core::common::{ConnectMethod, ListenOptions, OutputOptions, PingOptions};
use crate::core::konst::{BIND_ADDR_IPV4, BIND_ADDR_IPV6, LOGFILE_DIR, LOGFILE_NAME};
use crate::tcp::client::TcpClient;
use crate::tcp::server::TcpServer;
use crate::udp::client::UdpClient;
use crate::udp::server::UdpServer;
use crate::util::message::cli_header_msg;

#[derive(Debug, Parser)]
#[command(name = "nk")]
#[command(bin_name = "nk")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "NetKraken - Cross platform network connectivity tester", long_about = None)]
pub struct Cli {
    /// Destination hostname or IP address ||
    /// Listen address in `-l --listen` mode
    pub dst_host: String,

    /// Destination port ||
    /// Listen port in `-l --listen` mode
    pub dst_port: u16,

    /// Logging directory
    #[clap(short, long, default_value = LOGFILE_DIR)]
    pub dir: String,

    /// Logging filename
    #[clap(short, long, default_value = LOGFILE_NAME)]
    pub file: String,

    /// Interval between pings (in milliseconds)
    #[clap(short, long, default_value_t = 1000)]
    pub interval: u16,

    /// Connection Method
    #[clap(short, long, default_value_t = ConnectMethod::TCP)]
    pub method: ConnectMethod,

    /// Repeat count (0 == max == 65535)
    #[clap(short, long, default_value_t = 4)]
    pub repeat: u16,

    /// Source IPv4 Address
    #[clap(short = '4', long, default_value = BIND_ADDR_IPV4)]
    pub src_ipv4: String,

    /// Source IPv6 Address
    #[clap(short = '6', long, default_value = BIND_ADDR_IPV6)]
    pub src_ipv6: String,

    /// Source port (0 detects random unused high port between 1024-65534)
    #[clap(short = 'P', long, default_value_t = 0)]
    pub src_port: u16,

    /// Connection timeout (in milliseconds)
    #[clap(short, long, default_value_t = 3000)]
    pub timeout: u16,

    // Server specific options
    // -----------------------
    /// Listen as a server
    #[clap(short, long, default_value_t = false)]
    pub listen: bool,

    // Output options
    // --------------
    /// Log to file in JSON format
    #[clap(short, long, default_value_t = false)]
    pub json: bool,

    /// NetKraken peer messaging
    #[clap(short, long, default_value_t = false)]
    pub nk_peer: bool,

    /// Silence terminal output
    #[clap(short, long, default_value_t = false)]
    pub quiet: bool,

    /// Log to file in SYSLOG format
    #[clap(short, long, default_value_t = false)]
    pub syslog: bool,
}

impl Cli {
    pub fn init() -> Cli {
        Cli::parse()
    }

    pub async fn run(&self) -> Result<()> {
        let header_msg = cli_header_msg();
        println!("{header_msg}");
        let cli = Cli::parse();

        let ping_options = PingOptions {
            repeat: cli.repeat,
            interval: cli.interval,
            timeout: cli.timeout,
            nk_peer_messaging: cli.nk_peer,
        };

        let listen_options = ListenOptions {
            nk_peer_messaging: cli.nk_peer,
        };
        let output_options = OutputOptions {
            json: cli.json,
            quiet: cli.quiet,
            syslog: cli.syslog,
        };

        match cli.method {
            ConnectMethod::HTTP => println!("http not implemented"),
            ConnectMethod::ICMP => println!("icmp not implemented"),
            ConnectMethod::TCP => {
                if cli.listen {
                    let tcp_server = TcpServer {
                        listen_ip: cli.dst_host,
                        listen_port: cli.dst_port,
                        output_options,
                        listen_options,
                    };
                    tcp_server.listen().await?;
                } else {
                    let tcp_client = TcpClient::new(
                        cli.dst_host,
                        cli.dst_port,
                        Some(cli.src_ipv4),
                        Some(cli.src_ipv6),
                        Some(cli.src_port),
                        output_options,
                        ping_options,
                    );
                    tcp_client.connect().await?;
                }
            }
            ConnectMethod::UDP => {
                if cli.listen {
                    let udp_server = UdpServer {
                        listen_ip: cli.dst_host,
                        listen_port: cli.dst_port,
                        output_options,
                        listen_options,
                    };
                    udp_server.listen().await?;
                } else {
                    let udp_client = UdpClient::new(
                        cli.dst_host,
                        cli.dst_port,
                        Some(cli.src_ipv4),
                        Some(cli.src_port),
                        output_options,
                        ping_options,
                    );
                    udp_client.connect().await?;
                }
            }
        }
        Ok(())
    }
}
