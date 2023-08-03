mod cmd;
mod tcp;
mod util;

use crate::cmd::cli::init_cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_cli().await?;
    Ok(())
}
