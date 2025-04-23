mod cmd;
mod core;
mod dns;
mod http;
mod tcp;
mod udp;
mod util;

use std::process::ExitCode;

use tracing::{Level, event};

use crate::cmd::cli::Cli;
use crate::core::konst::APP_NAME;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::init();

    match cli.run().await {
        Ok(_) => ExitCode::from(0),
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
