mod cmd;
mod core;
mod tcp;
mod udp;
mod util;

use std::process::ExitCode;

use tracing::{event, Level};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::cmd::cli::init_cli;
use crate::core::konst::APP_NAME;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| format!("{APP_NAME}=info").into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    match init_cli().await {
        Ok(()) => ExitCode::from(0),
        Err(e) => {
            match e.source() {
                Some(s) => {
                    event!(target: APP_NAME, Level::ERROR, "{s}")
                }
                None => event!(target: APP_NAME, Level::ERROR, "{e}"),
            }
            ExitCode::from(1)
        }
    }
}
