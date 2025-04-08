use anyhow::Result;
use clap::{Args, Parser, Subcommand};

use crate::core::common::{
    ConnectMethod, IpOptions, IpProtocol, ListenOptions, LoggingOptions, PingOptions, Transport,
};
use crate::core::config::Config;
use crate::core::konst::{
    BIND_ADDR_IPV4, BIND_ADDR_IPV6, BIND_PORT, CLI_HEADER_MSG, CONFIG_FILE, CURRENT_DIR, DNS_LOOKUP_DOMAIN, DNS_PORT,
    LOGFILE_NAME, LOGGING_JSON, LOGGING_QUIET, LOGGING_SYSLOG, PING_INTERVAL, PING_NK_PEER, PING_REPEAT, PING_TIMEOUT,
};
use crate::dns::client::DnsClient;
use crate::http::client::HttpClient;
use crate::tcp::client::TcpClient;
use crate::tcp::server::TcpServer;
use crate::udp::client::UdpClient;
use crate::udp::server::UdpServer;
use crate::util::validate::validate_local_ip;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// DNS connection
    Dns {
        /// Target DNS servers
        #[clap(short, long)]
        servers: String,

        /// DNS port
        #[clap(short, long, default_value_t = DNS_PORT)]
        port: u16,

        /// Test DNS domain
        #[clap(short, long, default_value = DNS_LOOKUP_DOMAIN)]
        domain: String,

        /// Transport protocol
        #[clap(short, long, default_value_t = Transport::default())]
        transport: Transport,
    },
    /// HTTP connection
    Http,

    /// TCP connection
    Tcp,
    /// UDP connection
    Udp,
}

#[derive(Debug, Args)]
pub struct SharedOptions {
    /// Destination hostname or IP address
    host: Option<String>,

    /// Destination port or
    /// Listen port in `-l --listen` mode
    port: Option<u16>,

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
    #[clap(short, long, default_value_t = ConnectMethod::default())]
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
    /// Search Path: $CWD/nk.toml
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

#[derive(Debug, Parser)]
#[command(name = "nk")]
#[command(bin_name = "nk")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "NetKraken - Cross platform network connectivity tester", long_about = None)]
pub struct Cli {
    #[clap(subcommand)]
    command: Command,

    #[clap(flatten)]
    pub shared_options: SharedOptions,
}

impl Cli {
    pub fn init() -> Cli {
        Cli::parse()
    }

    pub async fn run(&self) -> Result<()> {
        println!("{CLI_HEADER_MSG}");
        let cli_top = Cli::parse();
        let cli = cli_top.shared_options;

        // region:    ===== pre-required args ===== //

        if cli.config_generate {
            Config::generate()?;
            return Ok(());
        }

        // endregion: ===== pre-required args ===== //

        // Host and port are required. If we don't receive them
        // from the CLI, we should error out.
        let host = cli.host.unwrap_or_default();
        let port = cli.port.unwrap_or_default();
        // if host.is_empty() || port == 0 {
        //     bail!("Destination host and port are required.");
        // }

        let config = match Config::load(&cli.config) {
            Ok(config) => {
                println!("Using configuration file `{}`.\n", cli.config);
                config
            }
            Err(_) => {
                println!(
                    "Configuration file `{}` not found. Using default configuration.\n",
                    cli.config
                );
                Config::default()
            }
        };

        let ip_options = IpOptions {
            ip_protocol: if cli.ip_proto != IpProtocol::V4 { cli.ip_proto } else { config.ip_options.ip_protocol },
        };

        // CLI options should override config file options.
        // If a CLI option is NOT the same as the default,
        // the option was set from the CLI. Therefore we should
        // use the CLI option. Otherwise use the config file option.
        let mut ping_options = PingOptions {
            repeat: if cli.repeat != PING_REPEAT { cli.repeat } else { config.ping_options.repeat },
            interval: if cli.interval != PING_INTERVAL { cli.interval } else { config.ping_options.interval },
            timeout: if cli.timeout != PING_TIMEOUT { cli.timeout } else { config.ping_options.timeout },
            nk_peer: if cli.nk_peer != PING_NK_PEER { cli.nk_peer } else { config.ping_options.nk_peer },
            method: if cli.method != ConnectMethod::default() { cli.method } else { config.ping_options.method },
        };

        let listen_options = ListenOptions {
            nk_peer: if cli.nk_peer != PING_NK_PEER { cli.nk_peer } else { config.listen_options.nk_peer },
        };

        let logging_options = LoggingOptions {
            file: if cli.file != LOGFILE_NAME { cli.file } else { config.logging_options.file },
            dir: if cli.dir != CURRENT_DIR { cli.dir } else { config.logging_options.dir },
            json: if cli.json != LOGGING_JSON { cli.json } else { config.logging_options.json },
            quiet: if cli.quiet != LOGGING_QUIET { cli.quiet } else { config.logging_options.quiet },
            syslog: if cli.syslog != LOGGING_SYSLOG { cli.syslog } else { config.logging_options.syslog },
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

        match cli_top.command {
            Command::Dns {
                servers,
                port,
                domain,
                transport,
            } => {
                ping_options.method = match transport {
                    Transport::Tcp => ConnectMethod::TCP,
                    Transport::Udp => ConnectMethod::UDP,
                };
                let dns_client = DnsClient::new(
                    servers,
                    port,
                    Some(cli.src_v4.clone()),
                    Some(cli.src_v6.clone()),
                    Some(cli.src_port),
                    domain,
                    transport,
                    logging_options.clone(),
                    ping_options.clone(),
                    ip_options,
                );
                dns_client.connect().await?;
            }
            _ => {}
        }
        match cli.method {
            ConnectMethod::DNS => {
                let dns_client = DnsClient::new(
                    host,
                    port,
                    Some(cli.src_v4),
                    Some(cli.src_v6),
                    Some(cli.src_port),
                    DNS_LOOKUP_DOMAIN.to_owned(),
                    Transport::Tcp,
                    logging_options,
                    ping_options,
                    ip_options,
                );
                dns_client.connect().await?;
            }
            ConnectMethod::HTTP | ConnectMethod::HTTPS => {
                let http_client = HttpClient::new(
                    host,
                    port,
                    Some(cli.src_v4),
                    Some(cli.src_v6),
                    Some(cli.src_port),
                    logging_options,
                    ping_options,
                    ip_options,
                );
                http_client.connect().await?;
            }
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
