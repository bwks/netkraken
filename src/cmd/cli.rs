use anyhow::{bail, Result};
use clap::Parser;

use crate::core::common::{ConnectMethod, IpOptions, IpProtocol, ListenOptions, LoggingOptions, PingOptions};
use crate::core::config::Config;
use crate::core::konst::{
    BIND_ADDR_IPV4, BIND_ADDR_IPV6, BIND_PORT, CLI_HEADER_MSG, CONFIG_FILE, CURRENT_DIR, LOGFILE_NAME, PING_INTERVAL,
    PING_NK_PEER, PING_REPEAT, PING_TIMEOUT,
};
use crate::tcp::client::TcpClient;
use crate::tcp::server::TcpServer;
use crate::udp::client::UdpClient;
use crate::udp::server::UdpServer;
use crate::util::validate::validate_local_ip;

#[derive(Debug, Parser)]
#[command(name = "nk")]
#[command(bin_name = "nk")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "NetKraken - Cross platform network connectivity tester", long_about = None)]
pub struct Cli {
    /// Destination hostname or IP address
    pub host: Option<String>,

    /// Destination port or
    /// Listen port in `-l --listen` mode
    pub port: Option<u16>,

    /// Repeat count (0 == max == 65535)
    #[clap(short, long, default_value_t = PING_REPEAT)]
    pub repeat: u16,

    /// Interval between pings (in milliseconds)
    #[clap(short, long, default_value_t = PING_INTERVAL)]
    pub interval: u16,

    /// Connection timeout (in milliseconds)
    #[clap(short, long, default_value_t = PING_TIMEOUT)]
    pub timeout: u16,

    /// Connection Method
    #[clap(short, long, default_value_t = ConnectMethod::TCP)]
    pub method: ConnectMethod,

    /// IP Protocol to use
    #[clap(short = 'I', long, default_value_t = IpProtocol::V4)]
    pub ip_proto: IpProtocol,

    /// Source IPv4 Address
    #[clap(long, default_value = BIND_ADDR_IPV4)]
    pub src_v4: String,

    /// Source IPv6 Address
    #[clap(long, default_value = BIND_ADDR_IPV6)]
    pub src_v6: String,

    /// Source port (0 detects random unused high port between 1024-65534)
    #[clap(short = 'P', long, default_value_t = BIND_PORT)]
    pub src_port: u16,

    /// NetKraken peer messaging
    #[clap(short, long, default_value_t = false)]
    pub nk_peer: bool,

    /// Config filename.
    /// Search Path: $HOME/.config/nk.toml >> $CWD/nk.toml
    #[clap(short, long, default_value = CONFIG_FILE)]
    pub config: String,

    /// Generate a default config file: $CWD/nk.toml.
    #[clap(long, default_value_t = false)]
    pub config_generate: bool,

    // Server specific options
    // -----------------------
    /// Listen as a server
    #[clap(short, long, default_value_t = false)]
    pub listen: bool,

    // Logging options
    // --------------
    /// Logging directory
    #[clap(short, long="dir", default_value = CURRENT_DIR)]
    pub dir: String,

    /// Logging filename
    #[clap(short, long="file", default_value = LOGFILE_NAME)]
    pub file: String,

    /// Log to file in JSON format
    #[clap(short, long, default_value_t = false)]
    pub json: bool,

    /// Log to file in SYSLOG format
    #[clap(short, long, default_value_t = false)]
    pub syslog: bool,

    /// Silence terminal output
    #[clap(short, long, default_value_t = false)]
    pub quiet: bool,
}

impl Cli {
    pub fn init() -> Cli {
        Cli::parse()
    }

    pub async fn run(&self) -> Result<()> {
        println!("{CLI_HEADER_MSG}");
        let cli = Cli::parse();

        if cli.config_generate {
            Config::generate()?;
            return Ok(());
        }

        let host = cli.host.unwrap_or_default();
        let port = cli.port.unwrap_or_default();
        if host.is_empty() || port == 0 {
            bail!("Destination host and port are required.");
        }

        let config = match Config::load(&cli.config) {
            Ok(c) => {
                println!("Using configuration file `{}`.\n", cli.config);
                c
            }
            Err(_) => {
                println!(
                    "Configuration file `{}` not found. Using default configuration.\n",
                    cli.config
                );
                Config::default()
            }
        };

        println!("{:#?}", config);

        let ip_options = IpOptions {
            ip_protocol: if cli.ip_proto != IpProtocol::V4 { cli.ip_proto } else { config.ip_options.ip_protocol },
        };

        // CLI options should override config file options.
        // If a CLI option is NOT the same as the default,
        // the option was set from the CLI. Therefore we should
        // use the CLI option. Otherwise use the config file option.
        let ping_options = PingOptions {
            repeat: if cli.repeat != PING_REPEAT { cli.repeat } else { config.ping_options.repeat },
            interval: if cli.interval != PING_INTERVAL { cli.interval } else { config.ping_options.interval },
            timeout: if cli.timeout != PING_TIMEOUT { cli.timeout } else { config.ping_options.timeout },
            nk_peer: if cli.nk_peer != PING_NK_PEER { cli.nk_peer } else { config.ping_options.nk_peer },
        };

        let listen_options = ListenOptions {
            nk_peer: if cli.nk_peer != PING_NK_PEER { cli.nk_peer } else { config.listen_options.nk_peer },
        };

        let logging_options = LoggingOptions {
            file: cli.file,
            dir: cli.dir,
            json: cli.json,
            quiet: cli.quiet,
            syslog: cli.syslog,
        };

        // region:    ===== validators ===== //

        // validate source IP addresses
        if cli.src_v4 != BIND_ADDR_IPV4 {
            validate_local_ip(&cli.src_v4.parse()?)?;
        }
        if cli.src_v6 != BIND_ADDR_IPV6 {
            validate_local_ip(&cli.src_v6.parse()?)?;
        }

        // endregion: ===== validators ===== //

        match cli.method {
            // ConnectMethod::HTTP => println!("http not implemented"),
            // ConnectMethod::ICMP => println!("icmp not implemented"),
            ConnectMethod::TCP => {
                if cli.listen {
                    let tcp_server = TcpServer {
                        listen_ip: host,
                        listen_port: port,
                        logging_options,
                        listen_options,
                    };
                    tcp_server.listen().await?;
                } else {
                    let tcp_client = TcpClient::new(
                        host,
                        port,
                        Some(cli.src_v4),
                        Some(cli.src_v6),
                        Some(cli.src_port),
                        logging_options,
                        ping_options,
                        ip_options,
                    );
                    tcp_client.connect().await?;
                }
            }
            ConnectMethod::UDP => {
                if cli.listen {
                    let udp_server = UdpServer {
                        listen_ip: host,
                        listen_port: port,
                        logging_options,
                        listen_options,
                    };
                    udp_server.listen().await?;
                } else {
                    let udp_client = UdpClient::new(
                        host,
                        port,
                        Some(cli.src_v4),
                        Some(cli.src_v6),
                        Some(cli.src_port),
                        logging_options,
                        ping_options,
                        ip_options,
                    );
                    udp_client.connect().await?;
                }
            }
        }
        Ok(())
    }
}
