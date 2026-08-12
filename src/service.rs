use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use tracing::info;

const LABEL: &str = "io.github.proxypass";

// ── macOS (launchd) ──────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

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
}

// ── Linux (systemd user service) ─────────────────────────────────

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::fs;

    fn unit_path() -> PathBuf {
        let dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("systemd/user");
        dir.join(format!("{}.service", LABEL))
    }

    pub fn install(binary_path: &str) -> Result<()> {
        let unit = format!(
            r#"[Unit]
Description=proxypass corporate proxy helper
After=network-online.target
Wants=network-online.target

[Service]
ExecStart={binary} start --foreground
Restart=on-failure
RestartSec=5
StandardOutput=append:/tmp/proxypass.out
StandardError=append:/tmp/proxypass.err

[Install]
WantedBy=default.target
"#,
            binary = binary_path,
        );

        let path = unit_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, unit)
            .with_context(|| format!("Failed to write unit to {}", path.display()))?;

        // systemctl --user daemon-reload
        let status = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status()?;
        if !status.success() {
            bail!("systemctl --user daemon-reload failed");
        }

        // systemctl --user enable --now proxypass
        let status = std::process::Command::new("systemctl")
            .args(["--user", "enable", "--now", &format!("{}.service", LABEL)])
            .status()?;
        if !status.success() {
            bail!("systemctl --user enable failed");
        }

        info!("proxypass installed and started as systemd user service");
        println!("✓ proxypass installed and running");
        println!("  Unit: {}", path.display());
        println!("  Logs: journalctl --user -u {}.service -f", LABEL);
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "stop", &format!("{}.service", LABEL)])
            .status();
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "disable", &format!("{}.service", LABEL)])
            .status();
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();

        let path = unit_path();
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        println!("✓ proxypass uninstalled");
        Ok(())
    }

    pub fn start_service() -> Result<()> {
        let status = std::process::Command::new("systemctl")
            .args(["--user", "start", &format!("{}.service", LABEL)])
            .status()?;
        if !status.success() {
            bail!("Failed to start service — is it installed? Run: proxypass install");
        }
        println!("✓ proxypass started");
        Ok(())
    }

    pub fn stop_service() -> Result<()> {
        let status = std::process::Command::new("systemctl")
            .args(["--user", "stop", &format!("{}.service", LABEL)])
            .status()?;
        if !status.success() {
            bail!("Failed to stop service");
        }
        println!("✓ proxypass stopped");
        Ok(())
    }

    pub fn service_status() -> Result<()> {
        let output = std::process::Command::new("systemctl")
            .args(["--user", "status", &format!("{}.service", LABEL)])
            .output()?;

        let out = String::from_utf8_lossy(&output.stdout);
        if out.contains("Active: active") {
            println!("✓ proxypass is running");
        } else if out.contains("could not be found") {
            println!("✗ proxypass is not installed");
        } else {
            println!("✗ proxypass is not running");
        }
        Ok(())
    }
}

// ── Windows / unsupported (manual only) ──────────────────────────

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    use super::*;

    pub fn install(_binary_path: &str) -> Result<()> {
        bail!(
            "Automatic service installation is not yet supported on this platform.\n\
             Run proxypass in the foreground:  proxypass start --foreground\n\
             Or use your OS task scheduler / service manager."
        );
    }

    pub fn uninstall() -> Result<()> {
        println!("Service uninstall not needed on this platform (manual setup).");
        Ok(())
    }

    pub fn start_service() -> Result<()> {
        bail!("Service management not supported on this platform. Run: proxypass start --foreground");
    }

    pub fn stop_service() -> Result<()> {
        bail!("Service management not supported on this platform. Run: proxypass start --foreground");
    }

    pub fn service_status() -> Result<()> {
        println!("Service status not available on this platform.");
        Ok(())
    }
}

// ── Re-exports ───────────────────────────────────────────────────

pub use platform::*;
