use std::net::IpAddr;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use tracing_appender::rolling;

use crate::core::common::{
    HttpScheme, HttpVersion, IpOptions, IpProtocol, ListenOptions, LoggingOptions, PingOptions, Transport,
};
use crate::core::config::Config;
use crate::core::konst::{
    APP_NAME, BIND_ADDR_IPV4, BIND_ADDR_IPV6, BIND_PORT, CLI_HEADER_MSG, CONFIG_FILE, CURRENT_DIR, DNS_LOOKUP_DOMAIN,
    DNS_PORT, HTTP_PORT, HTTPS_PORT, LOGFILE_NAME, LOGGING_JSON, LOGGING_QUIET, LOGGING_SYSLOG, PING_INTERVAL,
    PING_NK_PEER, PING_REPEAT, PING_TIMEOUT,
};
use crate::dns::client::{DnsClient, DnsClientOptions};
use crate::http::client::{HttpClient, HttpClientOptions};
use crate::icmp::client::{IcmpClient, IcmpClientOptions};
use crate::tcp::client::{TcpClient, TcpClientOptions};
use crate::tcp::server::{TcpServer, TcpServerOptions};
use crate::udp::client::{UdpClient, UdpClientOptions};
use crate::udp::server::UdpServer;
use crate::util::parser::parse_ipaddr;
use crate::util::validate::validate_local_ip;

#[derive(Debug, Subcommand, PartialEq, Clone)]
pub enum ConfigCommand {
    /// Create configuration
    Create {
        /// Config filename.
        /// Search Path: $CWD/nk.toml
        #[clap(short, long, default_value = CONFIG_FILE)]
        file: String,

        /// Warning: Overwrites existing file if found in path.
        #[clap(long, default_value_t = false)]
        force: bool,
    },
}

#[derive(Debug, Subcommand, PartialEq)]
pub enum Command {
    /// Generate a NetKraken configuration
    Config {
        #[clap(subcommand)]
        command: ConfigCommand,
    },

    /// DNS client
    #[command(after_help = format_examples(&[
        "nk dns -H example.com  # DNS ping",
    ]))]
    Dns {
        /// Remote host
        #[clap(short = 'H', long, display_order = 1)]
        remote_host: String,

        /// Remote port
        #[clap(short = 'P', long, default_value_t = DNS_PORT, display_order = 2)]
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

    /// HTTP client
    #[command(after_help = format_examples(&[
        "nk http -H example.com  # HTTP ping",
    ]))]
    Http {
        /// Remote host
        #[clap(short = 'H', long, display_order = 1)]
        remote_host: String,

        /// Remote port
        #[clap(short = 'P', long, default_value_t = HTTP_PORT, display_order = 2)]
        remote_port: u16,

        /// HTTP Version
        #[clap(short = 'V', long, default_value_t = HttpVersion::default(), display_order = 51)]
        version: HttpVersion,

        #[clap(flatten)]
        shared_options: SharedOptions,
    },

    /// HTTPS client
    #[command(after_help = format_examples(&[
        "nk https -H example.com  # HTTPS ping",
    ]))]
    Https {
        /// Remote host
        #[clap(short = 'H', long, display_order = 1)]
        remote_host: String,

        /// Remote port
        #[clap(short = 'P', long, default_value_t = HTTPS_PORT, display_order = 2)]
        remote_port: u16,

        /// HTTP Version
        #[clap(short = 'V', long, default_value_t = HttpVersion::default(), display_order = 51)]
        version: HttpVersion,

        /// Allow insecure connections ** Danger Will Robinson, be sure you understand the implications **
        #[clap(long, default_value_t = false, display_order = 52)]
        allow_insecure: bool,

        #[clap(flatten)]
        shared_options: SharedOptions,
    },

    /// ICMP client
    #[command(after_help = format_examples(&[
        "nk icmp -H example.com  # ICMP ping",
    ]))]
    Icmp {
        /// Remote host
        #[clap(short = 'H', long, display_order = 1)]
        remote_host: String,

        #[clap(flatten)]
        shared_options: SharedOptions,
    },

    /// TCP client/server
    #[command(after_help = format_examples(&[
        "nk tcp -H example.com -P 80  # Client TCP ping",
        "nk tcp -l -p 8080            # Listen as a TCP server",
        ]))]
    Tcp {
        /// Remote host
        #[clap(
            short = 'H',
            long,
            display_order = 1,
            required = false,
            required_unless_present = "listen"
        )]
        remote_host: Option<String>,

        /// Remote port
        #[clap(
            short = 'P',
            long,
            display_order = 2,
            required = false,
            required_unless_present = "listen"
        )]
        remote_port: Option<u16>,

        #[clap(flatten)]
        shared_options: SharedOptions,
    },

    /// UDP client/server
    #[command(after_help = format_examples(&[
        "nk udp -H example.com -P 80  # Client UDP ping",
        "nk udp -l -p 8080            # Listen as UDP server",
    ]))]
    Udp {
        /// Remote host
        #[clap(
            short = 'H',
            long,
            display_order = 1,
            required = false,
            required_unless_present = "listen"
        )]
        remote_host: Option<String>,

        /// Remote port
        #[clap(
            short = 'P',
            long,
            display_order = 2,
            required = false,
            required_unless_present = "listen"
        )]
        remote_port: Option<u16>,

        #[clap(flatten)]
        shared_options: SharedOptions,
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

    /// IP Protocol to use
    #[clap(short = 'I', long, default_value_t = IpProtocol::V4, display_order = 124)]
    pub ip_proto: IpProtocol,

    /// Source IPv4 Address
    #[clap(short = '4', long, default_value = BIND_ADDR_IPV4, display_order = 125)]
    pub local_v4: String,

    /// Source IPv6 Address
    #[clap(short = '6', long, default_value = BIND_ADDR_IPV6, display_order = 126)]
    pub local_v6: String,

    /// Source port (0 detects random unused high port between 1024-65534).
    /// Required in listen mode.
    #[clap(short = 'p', long, default_value_t = BIND_PORT, display_order = 127, required_if_eq("listen", "true"))]
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
            ip_proto: IpProtocol::V4,
            local_v4: BIND_ADDR_IPV4.to_owned(),
            local_v6: BIND_ADDR_IPV6.to_owned(),
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

        // This pulls out the shared options from the nested CLI commands.
        let shared_options = match cli.command {
            Command::Config { .. } => SharedOptions::default(),
            Command::Dns { ref shared_options, .. } => shared_options.clone(),
            Command::Http { ref shared_options, .. } => shared_options.clone(),
            Command::Https { ref shared_options, .. } => shared_options.clone(),
            Command::Icmp { ref shared_options, .. } => shared_options.clone(),
            Command::Tcp { ref shared_options, .. } => shared_options.clone(),
            Command::Udp { ref shared_options, .. } => shared_options.clone(),
        };

        let file_appender = rolling::never(&shared_options.dir, &shared_options.file);
        let (logfile, _guard) = tracing_appender::non_blocking(file_appender);

        let tracer = tracing_subscriber::fmt()
            .with_env_filter(std::env::var("NK_LOG").unwrap_or_else(|_| format!("{APP_NAME}=info")))
            .with_writer(logfile)
            .with_ansi(false)
            .with_target(true);

        if shared_options.json {
            tracer.json().init()
        } else {
            tracer.init()
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
        #[rustfmt::skip]
        let ping_options = PingOptions {
            repeat: if shared_options.repeat != PING_REPEAT { shared_options.repeat } else { config.ping_options.repeat },
            interval: if shared_options.interval != PING_INTERVAL { shared_options.interval } else { config.ping_options.interval },
            timeout: if shared_options.timeout != PING_TIMEOUT { shared_options.timeout } else { config.ping_options.timeout },
            nk_peer: if shared_options.nk_peer != PING_NK_PEER { shared_options.nk_peer } else { config.ping_options.nk_peer },
        };

        #[rustfmt::skip]
        let listen_options = ListenOptions {
            nk_peer: if shared_options.nk_peer != PING_NK_PEER { shared_options.nk_peer } else { config.listen_options.nk_peer },
        };

        #[rustfmt::skip]
        let logging_options = LoggingOptions {
            file: if shared_options.file != LOGFILE_NAME { shared_options.file } else { config.logging_options.file },
            dir: if shared_options.dir != CURRENT_DIR { shared_options.dir } else { config.logging_options.dir },
            json: if shared_options.json != LOGGING_JSON { shared_options.json } else { config.logging_options.json },
            quiet: if shared_options.quiet != LOGGING_QUIET { shared_options.quiet } else { config.logging_options.quiet },
            syslog: if shared_options.syslog != LOGGING_SYSLOG { shared_options.syslog } else { config.logging_options.syslog },
        };

        // region:    ===== validators ===== //

        // validate source IP addresses
        if shared_options.local_v4 != BIND_ADDR_IPV4 {
            validate_local_ip(&shared_options.local_v4.parse()?)?;
        }
        if shared_options.local_v6 != BIND_ADDR_IPV6 {
            validate_local_ip(&shared_options.local_v6.parse()?)?;
        }

        // endregion: ===== validators ===== //

        match cli.command {
            Command::Config { command } => {
                // Handle config command here
                match command {
                    ConfigCommand::Create { file, force } => {
                        Config::generate(&file, force)?;
                    }
                }
                return Ok(());
            }
            Command::Dns {
                remote_host,
                remote_port,
                domain,
                transport,
                shared_options,
            } => {
                let (local_ipv4, local_ipv6, local_port) = get_local_params(&shared_options)?;

                let dns_client_options = DnsClientOptions {
                    remote_host: remote_host.clone(),
                    remote_port,
                    local_ipv4,
                    local_ipv6,
                    local_port,
                    transport,
                    domain,
                };
                let dns_client = DnsClient {
                    client_options: dns_client_options,
                    logging_options: logging_options.clone(),
                    ping_options,
                    ip_options,
                };
                dns_client.connect().await?;
            }
            Command::Http {
                remote_host,
                remote_port,
                version,
                shared_options,
            } => {
                let (local_ipv4, local_ipv6, local_port) = get_local_params(&shared_options)?;

                let http_client_options = HttpClientOptions {
                    remote_host,
                    remote_port,
                    local_ipv4,
                    local_ipv6,
                    local_port,
                    scheme: HttpScheme::Http,
                    version,
                    allow_insecure: false,
                };
                let http_client = HttpClient {
                    client_options: http_client_options,
                    logging_options,
                    ping_options,
                    ip_options,
                };
                http_client.connect().await?;
            }
            Command::Https {
                remote_host,
                remote_port,
                version,
                allow_insecure,
                shared_options,
            } => {
                let (local_ipv4, local_ipv6, local_port) = get_local_params(&shared_options)?;

                let http_client_options = HttpClientOptions {
                    remote_host,
                    remote_port,
                    local_ipv4,
                    local_ipv6,
                    local_port,
                    scheme: HttpScheme::Https,
                    version,
                    allow_insecure,
                };
                let http_client = HttpClient {
                    client_options: http_client_options,
                    logging_options,
                    ping_options,
                    ip_options,
                };
                http_client.connect().await?;
            }
            Command::Icmp {
                remote_host,
                shared_options,
            } => {
                let (local_ipv4, local_ipv6, _local_port) = get_local_params(&shared_options)?;

                let icmp_client_options = IcmpClientOptions {
                    remote_host,
                    local_ipv4,
                    local_ipv6,
                };
                let icmp_client = IcmpClient {
                    client_options: icmp_client_options,
                    logging_options,
                    ping_options,
                    ip_options,
                };
                icmp_client.connect().await?;
            }
            Command::Tcp {
                remote_host,
                remote_port,
                shared_options,
            } => {
                let (local_ipv4, local_ipv6, local_port) = get_local_params(&shared_options)?;
                let server_options = TcpServerOptions {
                    local_ipv4,
                    local_ipv6,
                    local_port,
                };
                if shared_options.listen {
                    let tcp_server = TcpServer {
                        server_options,
                        logging_options,
                        listen_options,
                        ip_options,
                    };
                    tcp_server.listen().await?;
                } else {
                    // Client mode - remote_host and remote_port must be Some
                    let remote_host = remote_host
                        .ok_or_else(|| anyhow::anyhow!("Remote host is required when not in listen mode"))?;
                    let remote_port = remote_port
                        .ok_or_else(|| anyhow::anyhow!("Remote port is required when not in listen mode"))?;

                    let tcp_client_options = TcpClientOptions {
                        remote_host,
                        remote_port,
                        local_ipv4,
                        local_ipv6,
                        local_port,
                    };
                    let tcp_client = TcpClient {
                        client_options: tcp_client_options,
                        logging_options,
                        ping_options,
                        ip_options,
                    };
                    tcp_client.connect().await?;
                }
            }
            Command::Udp {
                remote_host,
                remote_port,
                shared_options,
            } => {
                let (local_ipv4, local_ipv6, local_port) = get_local_params(&shared_options)?;

                if shared_options.listen {
                    let udp_server = UdpServer {
                        listen_ip: local_ipv4.to_string(),
                        listen_port: local_port,
                        logging_options,
                        listen_options,
                    };
                    udp_server.listen().await?;
                } else {
                    // Client mode - remote_host and remote_port must be Some
                    let remote_host = remote_host
                        .ok_or_else(|| anyhow::anyhow!("Remote host is required when not in listen mode"))?;
                    let remote_port = remote_port
                        .ok_or_else(|| anyhow::anyhow!("Remote port is required when not in listen mode"))?;

                    let udp_client_options = UdpClientOptions {
                        remote_host,
                        remote_port,
                        local_ipv4,
                        local_ipv6,
                        local_port,
                    };

                    let tcp_client = UdpClient {
                        client_options: udp_client_options,
                        logging_options,
                        ping_options,
                        ip_options,
                    };
                    tcp_client.connect().await?;
                }
            }
        }

        Ok(())
    }
}

/// Get the local parameters from the shared options.
fn get_local_params(shared_options: &SharedOptions) -> Result<(IpAddr, IpAddr, u16)> {
    let local_ipv4 = parse_ipaddr(&shared_options.local_v4)?;
    let local_ipv6 = parse_ipaddr(&shared_options.local_v6)?;
    let local_port = shared_options.local_port;
    Ok((local_ipv4, local_ipv6, local_port))
}

/// Format example commands
fn format_examples(examples: &[&str]) -> String {
    let mut result = String::from("\x1B[1;4mExamples:\x1B[0m\n");
    for example in examples {
        result.push_str(&format!("  {}\n", example));
    }
    // Forces visible blank new line.
    // Otherwise, clap strips out raw trailing whitespace.
    result.push_str("\x1B[0m\n");
    result
}
