use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

use crate::{config, keychain, service, proxy};

#[derive(Parser)]
#[command(
    name = "proxypass",
    about = "Lightweight PAC-aware HTTP proxy with OS keychain auth",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run the setup wizard
    Setup,
    /// Stop the proxy daemon
    Stop,
    /// Restart the proxy daemon
    Restart,
    /// Show proxy status
    Status,
    /// Test the proxy by fetching a URL through it
    Test {
        #[arg(default_value = "https://www.google.com")]
        url: String,
    },
    /// Open config file in $EDITOR
    Config,
    /// Store or update proxy password in OS keychain
    Password,
    /// Install proxypass as a background service (auto-start on login)
    Install,
    /// Remove proxypass background service
    Uninstall,
}

/// Entry point — no subcommand = start proxy (or run setup if no config)
pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        None => start_or_setup().await,
        Some(Commands::Setup)     => setup(),
        Some(Commands::Stop)      => stop(),
        Some(Commands::Restart)   => restart().await,
        Some(Commands::Status)    => status(),
        Some(Commands::Test{url}) => test(&url).await,
        Some(Commands::Config)    => edit_config(),
        Some(Commands::Password)  => set_password(),
        Some(Commands::Install)   => install(),
        Some(Commands::Uninstall) => uninstall(),
    }
}

/// If config exists → start proxy. If not → run setup first.
async fn start_or_setup() -> Result<()> {
    let cfg_path = config::config_path();
    if !cfg_path.exists() {
        println!("No config found. Starting setup...\n");
        setup()?;
        println!();
    }
    let cfg = config::load()?;
    setup_logging(&cfg);
    proxy::run(cfg).await
}

// ── Setup wizard ─────────────────────────────────────────────────────────────

pub fn setup() -> Result<()> {
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  proxypass setup");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let mut cfg = config::Config::default();

    // ── Proxy source ──────────────────────────────────────────────────────────
    println!("Proxy source");
    println!("  [1] PAC URL  (e.g. http://wpad.company.com/proxy.pac)");
    println!("  [2] Proxy URL (e.g. proxy.company.com:8080)");
    let choice = prompt("Choice [1]: ", "1");

    match choice.trim() {
        "2" => {
            let url = prompt_required("Proxy URL (host:port): ")?;
            cfg.proxy.proxy = Some(url);
            cfg.proxy.pac = None;
        }
        _ => {
            let url = prompt_required("PAC URL: ")?;
            cfg.proxy.pac = Some(url);
            cfg.proxy.proxy = None;
        }
    }

    // ── Port ──────────────────────────────────────────────────────────────────
    let port_str = prompt("Local port [3128]: ", "3128");
    cfg.proxy.port = port_str.trim().parse().unwrap_or(3128);

    // ── Auth ──────────────────────────────────────────────────────────────────
    println!("\nAuthentication");
    println!("  [1] Negotiate / Kerberos (SSO, no password needed)");
    println!("  [2] Basic (username + password)");
    println!("  [3] None");
    let auth_choice = prompt("Choice [1]: ", "1");

    match auth_choice.trim() {
        "2" => {
            let username = prompt_required("Username (DOMAIN\\user): ")?;
            cfg.auth.username = Some(username.clone());
            cfg.auth.method = config::AuthMethod::Basic;
            let password = rpassword::prompt_password("Password: ")?;
            keychain::set_password(&username, &password)?;
            println!("✓ Password stored in macOS Keychain");
        }
        "3" => {
            cfg.auth.method = config::AuthMethod::None;
        }
        _ => {
            cfg.auth.method = config::AuthMethod::Negotiate;
            // Negotiate/SPNEGO needs your username so it can look up
            // your Kerberos ticket from the system credential cache.
            println!("Negotiate/Kerberos uses your system login ticket (kinit).");
            println!("You may still need a username for the upstream proxy.");
            let user = prompt("Username (leave blank if not needed): ", "");
            if !user.trim().is_empty() {
                cfg.auth.username = Some(user.trim().to_string());
                // Optionally also store a password for fallback to Basic
                let save_pwd = prompt("Also store a password for Basic fallback? [y/N]: ", "n");
                if save_pwd.trim().eq_ignore_ascii_case("y") {
                    let password = rpassword::prompt_password("Password: ")?;
                    keychain::set_password(user.trim(), &password)?;
                    println!("✓ Password stored in macOS Keychain");
                }
            }
        }
    }

    // ── No-proxy ──────────────────────────────────────────────────────────────
    println!("\nNo-proxy list (comma-separated, leave blank for defaults)");
    println!("  Default: localhost,127.0.0.1,*.local");
    let noproxy = prompt("No-proxy: ", "");
    if !noproxy.trim().is_empty() {
        cfg.proxy.no_proxy = noproxy
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
    }

    // ── Save ──────────────────────────────────────────────────────────────────
    config::save(&cfg)?;
    let path = config::config_path();

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("✓ Config saved to {}", path.display());
    println!("\nNext steps:");
    println!("  proxypass          → start proxy");
    println!("  proxypass install  → auto-start on login");
    println!("  proxypass test     → verify it works");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    Ok(())
}

// ── Other commands ────────────────────────────────────────────────────────────

pub fn stop() -> Result<()> {
    service::stop_service()
}

pub async fn restart() -> Result<()> {
    service::stop_service().ok();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    service::start_service()
}

pub fn status() -> Result<()> {
    service::service_status()
}

pub async fn test(url: &str) -> Result<()> {
    let cfg = config::load()?;
    let proxy_addr = format!("http://{}:{}", cfg.proxy.listen, cfg.proxy.port);

    println!("Testing proxy at {} ...", proxy_addr);
    println!("Fetching: {}", url);

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(&proxy_addr)?)
        .http1_only()  // proxy doesn't serve HTTP/2 itself
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
        Err(e) => bail!("✗ Proxy test failed: {}", e),
    }
    Ok(())
}

pub fn edit_config() -> Result<()> {
    let path = config::config_path();
    if !path.exists() {
        config::save(&config::Config::default())?;
        println!("Created default config at {}", path.display());
    }
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "nano".to_string());
    std::process::Command::new(&editor).arg(&path).status()?;
    Ok(())
}

pub fn set_password() -> Result<()> {
    let cfg = config::load()?;
    let username = match &cfg.auth.username {
        Some(u) => u.clone(),
        None => bail!("No username in config. Run: proxypass setup"),
    };
    println!("Setting password for '{}'", username);
    let password = rpassword::prompt_password("Password: ")?;
    keychain::set_password(&username, &password)?;
    println!("✓ Password stored in macOS Keychain");
    Ok(())
}

pub fn install() -> Result<()> {
    if !config::config_path().exists() {
        println!("No config found. Run setup first.\n");
        setup()?;
        println!();
    }
    let binary = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "proxypass".to_string());
    service::install(&binary)
}

pub fn uninstall() -> Result<()> {
    service::uninstall()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn prompt(label: &str, default: &str) -> String {
    use std::io::Write;
    print!("{}", label);
    std::io::stdout().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
    let trimmed = input.trim().to_string();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed
    }
}

fn prompt_required(label: &str) -> Result<String> {
    let val = prompt(label, "");
    if val.is_empty() {
        bail!("This field is required");
    }
    Ok(val)
}

fn setup_logging(cfg: &config::Config) {
    let filter = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| cfg.log.level.clone());
    let subscriber = tracing_subscriber::fmt().with_env_filter(filter);
    if let Some(log_file) = &cfg.log.file {
        if let Ok(file) = std::fs::OpenOptions::new()
            .create(true).append(true).open(log_file)
        {
            subscriber.with_writer(std::sync::Mutex::new(file)).init();
            return;
        }
    }
    subscriber.init();
}
