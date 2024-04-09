mod cmd;
mod core;
mod tcp;
mod udp;
mod util;

use std::fs::File;
use std::path::PathBuf;
use std::process::ExitCode;

use dirs::home_dir;

use tracing::{event, Level};
use tracing_appender::rolling;

use crate::cmd::cli::Cli;
use crate::core::konst::{APP_NAME, CONFIG_FILE};

#[tokio::main]
async fn main() -> ExitCode {
    let mut config_file = match home_dir() {
        Some(c) => c,
        None => {
            event!(target: APP_NAME, Level::WARN, "UNABLE TO OPEN HOME DIR, USING CURRENT DIR");
            PathBuf::from(".")
        }
    };
    config_file.push(CONFIG_FILE);

    // let config = match File::open(&config_file) {
    //     Ok(x) => x,
    //     Err => _,
    // };

    let cli = Cli::init();

    let file_appender = rolling::never(&cli.dir, &cli.file);
    let (logfile, _guard) = tracing_appender::non_blocking(file_appender);

    let tracer = tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| format!("{APP_NAME}=info")))
        .with_writer(logfile)
        .with_ansi(false);

    match cli.json {
        true => tracer.json().init(),
        false => tracer.init(),
    }

    match cli.run().await {
        Ok(()) => ExitCode::from(0),
        Err(e) => {
            match e.source() {
                Some(s) => {
                    eprintln!("{s}");
                    event!(target: APP_NAME, Level::ERROR, "{s}")
                }
                None => {
                    eprintln!("{e}");
                    event!(target: APP_NAME, Level::ERROR, "{e}")
                }
            }
            ExitCode::from(1)
        }
    }
}
