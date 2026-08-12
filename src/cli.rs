use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use tracing::info;

use crate::{config, keychain, launchd, proxy};

#[derive(Parser)]
#[command(
    name = "proxypass",
    about = "Lightweight PAC-aware HTTP proxy with OS keychain auth",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the proxy daemon
    Start {
        /// Run in foreground (used by launchd)
        #[arg(long)]
        foreground: bool,
    },
    /// Stop the proxy daemon
    Stop,
    /// Restart the proxy daemon
    Restart,
    /// Show proxy status
    Status,
    /// Test the proxy by fetching a URL through it
    Test {
        /// URL to test (default: https://www.google.com)
        #[arg(default_value = "https://www.google.com")]
        url: String,
    },
    /// Open config file in $EDITOR
    Config,
    /// Store or update proxy password in OS keychain
    Password,
    /// Install proxypass as a launchd agent (auto-start on login)
    Install,
    /// Remove proxypass launchd agent
    Uninstall,
}

pub async fn start(foreground: bool) -> Result<()> {
    if foreground {
        // Running under launchd — start the proxy server directly
        let cfg = config::load()?;
        setup_logging(&cfg);
        info!("Starting proxypass on {}:{}", cfg.proxy.listen, cfg.proxy.port);
        proxy::run(cfg).await
    } else {
        // User ran `proxypass start` — delegate to launchd
        launchd::start_service()
    }
}

pub fn stop() -> Result<()> {
    launchd::stop_service()
}

pub async fn restart() -> Result<()> {
    launchd::stop_service().ok();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    launchd::start_service()
}

pub fn status() -> Result<()> {
    launchd::service_status()
}

pub async fn test(url: &str) -> Result<()> {
    let cfg = config::load()?;
    let proxy_addr = format!("http://{}:{}", cfg.proxy.listen, cfg.proxy.port);

    println!("Testing proxy at {} ...", proxy_addr);
    println!("Fetching: {}", url);

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(&proxy_addr)?)
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() || status.is_redirection() {
                println!("✓ Proxy working — HTTP {}", status);
            } else {
                println!("✗ Unexpected status: HTTP {}", status);
            }
        }
        Err(e) => {
            bail!("✗ Proxy test failed: {}", e);
        }
    }
    Ok(())
}

pub fn edit_config() -> Result<()> {
    let path = config::config_path();

    // Ensure config exists
    if !path.exists() {
        let cfg = config::Config::default();
        config::save(&cfg)?;
        println!("Created default config at {}", path.display());
    }

    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "nano".to_string());
    std::process::Command::new(&editor)
        .arg(&path)
        .status()?;
    Ok(())
}

pub fn set_password() -> Result<()> {
    let cfg = config::load()?;
    let username = match &cfg.auth.username {
        Some(u) => u.clone(),
        None => {
            bail!("No username set in config. Edit your config first: proxypass config");
        }
    };

    println!("Setting password for '{}'", username);
    let password = rpassword::prompt_password("Password: ")?;
    keychain::set_password(&username, &password)?;
    println!("✓ Password stored in macOS Keychain");
    Ok(())
}

pub fn install() -> Result<()> {
    // Find own binary path
    let binary = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "proxypass".to_string());

    // Ensure config exists
    let cfg_path = config::config_path();
    if !cfg_path.exists() {
        let cfg = config::Config::default();
        config::save(&cfg)?;
        println!("Created default config at {}", cfg_path.display());
        println!("→ Edit it before starting: proxypass config");
    }

    launchd::install(&binary)
}

pub fn uninstall() -> Result<()> {
    launchd::uninstall()
}

fn setup_logging(cfg: &config::Config) {
    let filter = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| cfg.log.level.clone());

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter);

    if let Some(log_file) = &cfg.log.file {
        if let Ok(file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)
        {
            subscriber.with_writer(std::sync::Mutex::new(file)).init();
            return;
        }
    }
    subscriber.init();
}
