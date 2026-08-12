mod auth;
mod cli;
mod config;
mod keychain;
mod launchd;
mod pac;
mod proxy;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Start { foreground } => cli::start(foreground).await,
        Commands::Stop => cli::stop(),
        Commands::Restart => cli::restart().await,
        Commands::Status => cli::status(),
        Commands::Test { url } => cli::test(&url).await,
        Commands::Config => cli::edit_config(),
        Commands::Password => cli::set_password(),
        Commands::Install => cli::install(),
        Commands::Uninstall => cli::uninstall(),
    }
}
