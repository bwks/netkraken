mod cmd;
mod core;
mod dns;
mod http;
mod tcp;
mod udp;
mod util;

use std::process::ExitCode;

use tracing::{event, Level};
use tracing_appender::rolling;

use crate::cmd::cli::{Cli, SharedOptions};
use crate::core::konst::APP_NAME;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::init();
    let shared_options = SharedOptions::default();

    let file_appender = rolling::never(&shared_options.dir, &shared_options.file);
    let (logfile, _guard) = tracing_appender::non_blocking(file_appender);

    let tracer = tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| format!("{APP_NAME}=info")))
        .with_writer(logfile)
        .with_ansi(false);

    match shared_options.json {
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
