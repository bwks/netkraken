use anyhow::Result;
use clap::Parser;

use crate::core::common::{ConnectMethod, OutputOptions, PingOptions};
use crate::core::konst::{LOGFILE_DIR, LOGFILE_NAME};
use crate::tcp::client::TcpClient;
use crate::tcp::server::TcpServer;
use crate::udp::client::UdpClient;
use crate::udp::server::UdpServer;
use crate::util::message::cli_header_msg;

#[derive(Debug, Parser)]
#[command(name = "nk")]
#[command(bin_name = "nk")]
#[command(version = "0.1.0")]
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

    /// Repeat count (0 for infinite)
    #[clap(short, long, default_value_t = 4)]
    pub repeat: u16,

    /// Source IP Address
    #[clap(long, default_value = "0.0.0.0")]
    pub src_addr: String,

    /// Source port (0 detects random unused high port between 1024-65534)
    #[clap(long, default_value_t = 0)]
    pub src_port: u16,

    /// Connection timeout (in milliseconds)
    #[clap(short, long, default_value_t = 5000)]
    pub timeout: u16,

    // Output options
    /// Log to file in JSON format
    #[clap(short, long, default_value_t = false)]
    pub json: bool,

    /// Log to file in SYSLOG format
    #[clap(short, long, default_value_t = false)]
    pub syslog: bool,

    /// Silence terminal output
    #[clap(short, long, default_value_t = false)]
    pub quiet: bool,

    // Server specific options
    /// Listen as a server
    #[clap(short, long, default_value_t = false)]
    pub listen: bool,
}

impl Cli {
    pub fn init() -> Cli {
        Cli::parse()
    }

    pub async fn run(&self) -> Result<()> {
        cli_header_msg();
        let cli = Cli::parse();

        let mut ping_options = PingOptions::default();
        ping_options.repeat = cli.repeat;
        ping_options.interval = cli.interval;
        ping_options.timeout = cli.timeout;

        let mut output_options = OutputOptions::default();
        output_options.json = cli.json;
        output_options.quiet = cli.quiet;
        output_options.syslog = cli.syslog;

        match cli.method {
            ConnectMethod::HTTP => println!("http not implemented"),
            ConnectMethod::ICMP => println!("icmp not implemented"),
            ConnectMethod::TCP => {
                if cli.listen {
                    let tcp_server = TcpServer {
                        listen_addr: cli.dst_host,
                        listen_port: cli.dst_port,
                        output_options,
                    };
                    tcp_server.listen().await?;
                } else {
                    let tcp_client = TcpClient::new(
                        cli.dst_host,
                        cli.dst_port,
                        Some(cli.src_addr),
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
                        listen_addr: cli.dst_host,
                        listen_port: cli.dst_port,
                        output_options,
                    };
                    udp_server.listen().await?;
                } else {
                    let udp_client = UdpClient::new(
                        cli.dst_host,
                        cli.dst_port,
                        Some(cli.src_addr),
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
