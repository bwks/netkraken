use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::core::common::{
    ConnectMethod, IpOptions, IpProtocol, ListenOptions, LoggingOptions, PingOptions, Transport,
};
use crate::core::config::Config;
use crate::core::konst::{
    BIND_ADDR_IPV4, BIND_ADDR_IPV6, BIND_PORT, CLI_HEADER_MSG, CONFIG_FILE, CURRENT_DIR, DNS_LOOKUP_DOMAIN, DNS_PORT,
    LOGFILE_NAME, LOGGING_JSON, LOGGING_QUIET, LOGGING_SYSLOG, PING_INTERVAL, PING_NK_PEER, PING_REPEAT, PING_TIMEOUT,
};
use crate::dns::client::{DnsClient, DnsClientOptions};
use crate::http::client::HttpClient;
use crate::tcp::client::TcpClient;
use crate::tcp::server::TcpServer;
use crate::udp::client::UdpClient;
use crate::udp::server::UdpServer;
use crate::util::parser::parse_ipaddr;
use crate::util::validate::validate_local_ip;

#[derive(Debug, Subcommand, PartialEq, Clone)]
pub enum ConfigCommand {
    Create {
        /// Config filename.
        /// Search Path: $CWD/nk.toml
        #[clap(short, long, default_value = CONFIG_FILE)]
        file: String,

        #[clap(long, default_value_t = false)]
        force: bool,
    },
}

#[derive(Debug, Subcommand, PartialEq)]
pub enum Command {
    /// DNS connection
    Dns {
        /// Remote host(s). Seperate hosts with a space ' '. EG: 1.1.1.1 9.9.9.9
        #[clap(short = 'H', long, display_order = 1, value_delimiter = ' ', num_args = 1..)]
        remote_host: Vec<String>,

        /// Remote port
        #[clap(short = 'p', long, default_value_t = DNS_PORT, display_order = 2)]
        remote_port: u16,

        /// Test DNS domain
        #[clap(short, long, default_value = DNS_LOOKUP_DOMAIN, display_order = 50)]
        domain: String,

        /// Transport protocol
        #[clap(short = 'T', long, default_value_t = Transport::default(), display_order = 51)]
        transport: Transport,

        #[clap(flatten)]
        shared_options: SharedOptions,
    },
    /// HTTP connection
    Http,

    /// TCP connection
    Tcp,

    /// UDP connection
    Udp,

    /// Generate a NetKraken config
    Config {
        #[clap(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Clone, Debug, Args, PartialEq)]
pub struct SharedOptions {
    /// Repeat count (0 == max == 65535)
    #[clap(short, long, default_value_t = PING_REPEAT, display_order = 120)]
    pub repeat: u16,

    /// Interval between pings (in milliseconds)
    #[clap(short, long, default_value_t = PING_INTERVAL, display_order = 121)]
    pub interval: u16,

    /// Connection timeout (in milliseconds)
    #[clap(short, long, default_value_t = PING_TIMEOUT, display_order = 122)]
    pub timeout: u16,

    /// Connection Method
    #[clap(long, default_value_t = ConnectMethod::default(), display_order = 123)]
    pub method: ConnectMethod,

    /// IP Protocol to use
    #[clap(short = 'I', long, default_value_t = IpProtocol::V4, display_order = 124)]
    pub ip_proto: IpProtocol,

    /// Source IPv4 Address
    #[clap(long, default_value = BIND_ADDR_IPV4, display_order = 125)]
    pub src_v4: String,

    /// Source IPv6 Address
    #[clap(long, default_value = BIND_ADDR_IPV6, display_order = 126)]
    pub src_v6: String,

    /// Source IPv4 Address
    #[clap(long, default_value = BIND_ADDR_IPV4, display_order = 125)]
    pub local_v4: String,

    /// Source IPv6 Address
    #[clap(long, default_value = BIND_ADDR_IPV6, display_order = 126)]
    pub local_v6: String,

    /// Source port (0 detects random unused high port between 1024-65534)
    #[clap(short = 'P', long, default_value_t = BIND_PORT, display_order = 127)]
    pub src_port: u16,

    /// Source port (0 detects random unused high port between 1024-65534)
    #[clap(long, default_value_t = BIND_PORT, display_order = 127)]
    pub local_port: u16,

    /// NetKraken peer messaging
    #[clap(long, default_value_t = false, display_order = 128)]
    pub nk_peer: bool,

    /// Config filename.
    /// Search Path: $CWD/nk.toml
    #[clap(short, long, default_value = CONFIG_FILE, display_order = 129)]
    pub config: String,

    // Server specific options
    // -----------------------
    /// Listen as a server
    #[clap(short, long, default_value_t = false, display_order = 220)]
    pub listen: bool,

    // Logging options
    // --------------
    /// Logging directory
    #[clap(long, default_value = CURRENT_DIR, display_order = 320)]
    pub dir: String,

    /// Logging filename
    #[clap(long, default_value = LOGFILE_NAME, display_order = 321)]
    pub file: String,

    /// Log to file in JSON format
    #[clap(long, default_value_t = false, display_order = 322)]
    pub json: bool,

    /// Log to file in SYSLOG format
    #[clap(long, default_value_t = false, display_order = 323)]
    pub syslog: bool,

    /// Silence terminal output
    #[clap(long, default_value_t = false, display_order = 324)]
    pub quiet: bool,
}
impl Default for SharedOptions {
    fn default() -> Self {
        Self {
            repeat: PING_REPEAT,
            interval: PING_INTERVAL,
            timeout: PING_TIMEOUT,
            method: ConnectMethod::default(),
            ip_proto: IpProtocol::V4,
            src_v4: BIND_ADDR_IPV4.to_owned(),
            src_v6: BIND_ADDR_IPV6.to_owned(),
            local_v4: BIND_ADDR_IPV4.to_owned(),
            local_v6: BIND_ADDR_IPV6.to_owned(),
            src_port: BIND_PORT,
            local_port: BIND_PORT,
            nk_peer: false,
            config: CONFIG_FILE.to_owned(),
            listen: false,
            dir: CURRENT_DIR.to_owned(),
            file: LOGFILE_NAME.to_owned(),
            json: false,
            syslog: false,
            quiet: false,
        }
    }
}

#[derive(Debug, Parser)]
#[command(name = "nk")]
#[command(bin_name = "nk")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "NetKraken - Cross platform network connectivity tester", long_about = None)]
pub struct Cli {
    #[clap(subcommand)]
    command: Command,
}

impl Cli {
    pub fn init() -> Cli {
        Cli::parse()
    }

    pub async fn run(&self) -> Result<()> {
        println!("{CLI_HEADER_MSG}");
        let cli = Cli::parse();

        let shared_options = match cli.command {
            Command::Dns { ref shared_options, .. } => shared_options.clone(),
            _ => SharedOptions::default(),
        };

        if let Command::Config { command } = &cli.command {
            // Handle config command here
            match command {
                ConfigCommand::Create { file, force } => {
                    Config::generate(&file, *force)?;
                }
            }
            return Ok(());
        }

        let config = match Config::load(&shared_options.config) {
            Ok(config) => {
                println!("Using configuration file `{}`.\n", shared_options.config);
                config
            }
            Err(_) => {
                println!(
                    "Configuration file `{}` not found. Using default configuration.\n",
                    shared_options.config
                );
                Config::default()
            }
        };

        let ip_options = IpOptions {
            ip_protocol: if shared_options.ip_proto != IpProtocol::V4 {
                shared_options.ip_proto
            } else {
                config.ip_options.ip_protocol
            },
        };

        // CLI options should override config file options.
        // If a CLI option is NOT the same as the default,
        // the option was set from the CLI. Therefore we should
        // use the CLI option. Otherwise use the config file option.
        let mut ping_options = PingOptions {
            repeat: if shared_options.repeat != PING_REPEAT {
                shared_options.repeat
            } else {
                config.ping_options.repeat
            },
            interval: if shared_options.interval != PING_INTERVAL {
                shared_options.interval
            } else {
                config.ping_options.interval
            },
            timeout: if shared_options.timeout != PING_TIMEOUT {
                shared_options.timeout
            } else {
                config.ping_options.timeout
            },
            nk_peer: if shared_options.nk_peer != PING_NK_PEER {
                shared_options.nk_peer
            } else {
                config.ping_options.nk_peer
            },
            method: if shared_options.method != ConnectMethod::default() {
                shared_options.method
            } else {
                config.ping_options.method
            },
        };

        let listen_options = ListenOptions {
            nk_peer: if shared_options.nk_peer != PING_NK_PEER {
                shared_options.nk_peer
            } else {
                config.listen_options.nk_peer
            },
        };

        let logging_options = LoggingOptions {
            file: if shared_options.file != LOGFILE_NAME { shared_options.file } else { config.logging_options.file },
            dir: if shared_options.dir != CURRENT_DIR { shared_options.dir } else { config.logging_options.dir },
            json: if shared_options.json != LOGGING_JSON { shared_options.json } else { config.logging_options.json },
            quiet: if shared_options.quiet != LOGGING_QUIET {
                shared_options.quiet
            } else {
                config.logging_options.quiet
            },
            syslog: if shared_options.syslog != LOGGING_SYSLOG {
                shared_options.syslog
            } else {
                config.logging_options.syslog
            },
        };

        // region:    ===== validators ===== //

        // validate source IP addresses
        if shared_options.src_v4 != BIND_ADDR_IPV4 {
            validate_local_ip(&shared_options.src_v4.parse()?)?;
        }
        if shared_options.src_v6 != BIND_ADDR_IPV6 {
            validate_local_ip(&shared_options.src_v6.parse()?)?;
        }

        // endregion: ===== validators ===== //

        match cli.command {
            Command::Dns {
                remote_host,
                remote_port,
                domain,
                transport,
                shared_options,
            } => {
                ping_options.method = ConnectMethod::DNS;

                let local_ipv4 = parse_ipaddr(&shared_options.local_v4)?;
                let local_ipv6 = parse_ipaddr(&shared_options.local_v6)?;
                let local_port = shared_options.local_port;

                let dns_client_options = DnsClientOptions {
                    remote_host: remote_host.clone(),
                    remote_port: remote_port,
                    local_ipv4,
                    local_ipv6,
                    local_port,
                    transport,
                    domain,
                };
                let dns_client = DnsClient {
                    dns_client_options,
                    logging_options: logging_options.clone(),
                    ping_options: ping_options.clone(),
                    ip_options,
                };
                dns_client.connect().await?;
            }
            _ => {}
        }
        // match cli.method {
        //     ConnectMethod::DNS => {}
        //     ConnectMethod::HTTP | ConnectMethod::HTTPS => {
        //         let http_client = HttpClient::new(
        //             host,
        //             port,
        //             Some(cli.src_v4),
        //             Some(cli.src_v6),
        //             Some(cli.src_port),
        //             logging_options,
        //             ping_options,
        //             ip_options,
        //         );
        //         http_client.connect().await?;
        //     }
        //     // ConnectMethod::ICMP => println!("icmp not implemented"),
        //     ConnectMethod::TCP => {
        //         if cli.listen {
        //             let tcp_server = TcpServer {
        //                 listen_ip: host,
        //                 listen_port: port,
        //                 logging_options,
        //                 listen_options,
        //             };
        //             tcp_server.listen().await?;
        //         } else {
        //             let tcp_client = TcpClient::new(
        //                 host,
        //                 port,
        //                 Some(cli.src_v4),
        //                 Some(cli.src_v6),
        //                 Some(cli.src_port),
        //                 logging_options,
        //                 ping_options,
        //                 ip_options,
        //             );
        //             tcp_client.connect().await?;
        //         }
        //     }
        //     ConnectMethod::UDP => {
        //         if cli.listen {
        //             let udp_server = UdpServer {
        //                 listen_ip: host,
        //                 listen_port: port,
        //                 logging_options,
        //                 listen_options,
        //             };
        //             udp_server.listen().await?;
        //         } else {
        //             let udp_client = UdpClient::new(
        //                 host,
        //                 port,
        //                 Some(cli.src_v4),
        //                 Some(cli.src_v6),
        //                 Some(cli.src_port),
        //                 logging_options,
        //                 ping_options,
        //                 ip_options,
        //             );
        //             udp_client.connect().await?;
        //         }
        //     }
        // }

        Ok(())
    }
}
