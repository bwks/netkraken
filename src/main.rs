mod cmd;
mod core;
mod tcp;
mod udp;
mod util;

use std::process::ExitCode;

use tracing::{event, Level};
use tracing_appender::rolling;

use crate::cmd::cli::Cli;
use crate::core::konst::APP_NAME;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::init();

    let file_appender = rolling::never(&cli.dir, &cli.file);
    let (logfile, _guard) = tracing_appender::non_blocking(file_appender);

    let tracer = tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| format!("{APP_NAME}=info").into()),
        )
        .with_writer(logfile)
        .with_ansi(false);

    if cli.json {
        tracer.json().init();
    } else {
        tracer.init();
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
