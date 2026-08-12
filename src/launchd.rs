use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use tracing::info;

const LABEL: &str = "io.github.proxypass";
const PLIST_PATH: &str = "/Library/LaunchAgents/io.github.proxypass.plist";

pub fn plist_path() -> PathBuf {
    PathBuf::from(PLIST_PATH)
}

pub fn install(binary_path: &str) -> Result<()> {
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>

    <key>ProgramArguments</key>
    <array>
        <string>{binary}</string>
        <string>start</string>
        <string>--foreground</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>StandardOutPath</key>
    <string>/tmp/proxypass.out</string>

    <key>StandardErrorPath</key>
    <string>/tmp/proxypass.err</string>
</dict>
</plist>"#,
        label = LABEL,
        binary = binary_path,
    );

    let path = plist_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, plist)
        .with_context(|| format!("Failed to write plist to {}", path.display()))?;

    // Bootstrap the agent
    let uid = unsafe { libc::getuid() };
    let domain = format!("gui/{}", uid);
    let status = std::process::Command::new("launchctl")
        .args(["bootstrap", &domain, PLIST_PATH])
        .status()?;

    if !status.success() {
        bail!("launchctl bootstrap failed");
    }

    let status = std::process::Command::new("launchctl")
        .args(["enable", &format!("{}/{}", domain, LABEL)])
        .status()?;

    if !status.success() {
        bail!("launchctl enable failed");
    }

    let status = std::process::Command::new("launchctl")
        .args(["kickstart", "-kp", &format!("{}/{}", domain, LABEL)])
        .status()?;

    if !status.success() {
        bail!("launchctl kickstart failed");
    }

    info!("proxypass installed and started as launchd agent");
    println!("✓ proxypass installed and running");
    println!("  Plist: {}", PLIST_PATH);
    println!("  Logs:  /tmp/proxypass.out / /tmp/proxypass.err");
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let domain = format!("gui/{}", uid);
    let service = format!("{}/{}", domain, LABEL);

    let _ = std::process::Command::new("launchctl")
        .args(["kill", "SIGTERM", &service])
        .status();

    let _ = std::process::Command::new("launchctl")
        .args(["disable", &service])
        .status();

    let _ = std::process::Command::new("launchctl")
        .args(["bootout", &domain, PLIST_PATH])
        .status();

    let path = plist_path();
    if path.exists() {
        std::fs::remove_file(&path)?;
    }

    println!("✓ proxypass uninstalled");
    Ok(())
}

pub fn start_service() -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let service = format!("gui/{}/{}", uid, LABEL);
    let status = std::process::Command::new("launchctl")
        .args(["kickstart", "-k", &service])
        .status()?;
    if !status.success() {
        bail!("Failed to start service — is it installed? Run: proxypass install");
    }
    println!("✓ proxypass started");
    Ok(())
}

pub fn stop_service() -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let service = format!("gui/{}/{}", uid, LABEL);
    let status = std::process::Command::new("launchctl")
        .args(["kill", "SIGTERM", &service])
        .status()?;
    if !status.success() {
        bail!("Failed to stop service");
    }
    println!("✓ proxypass stopped");
    Ok(())
}

pub fn service_status() -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let service = format!("gui/{}/{}", uid, LABEL);
    let output = std::process::Command::new("launchctl")
        .args(["print", &service])
        .output()?;

    if !output.status.success() {
        println!("✗ proxypass is not running (not installed or stopped)");
        return Ok(());
    }

    let out = String::from_utf8_lossy(&output.stdout);

    // Extract PID and state
    let pid = out.lines()
        .find(|l| l.trim().starts_with("pid ="))
        .map(|l| l.trim().to_string())
        .unwrap_or_else(|| "pid = unknown".to_string());

    let state = out.lines()
        .find(|l| l.trim().starts_with("state ="))
        .map(|l| l.trim().to_string())
        .unwrap_or_else(|| "state = unknown".to_string());

    println!("✓ proxypass is running");
    println!("  {}", pid);
    println!("  {}", state);
    println!("  Label: {}", LABEL);
    println!("  Logs:  tail -f /tmp/proxypass.err");
    Ok(())
}
