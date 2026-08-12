#[cfg(feature = "gssapi")]
#[path = "auth.rs"]
mod auth;
#[cfg(not(feature = "gssapi"))]
#[path = "auth_win.rs"]
mod auth;
mod cli;
mod config;
mod keychain;
mod service;
mod pac;
mod proxy;

use anyhow::Result;
use clap::Parser;
use cli::Cli;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    cli::run(cli).await
}
