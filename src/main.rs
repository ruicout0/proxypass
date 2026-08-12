mod auth;
mod cli;
mod config;
mod keychain;
mod launchd;
mod pac;
mod proxy;

use anyhow::Result;
use clap::Parser;
use cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    cli::run(cli).await
}
