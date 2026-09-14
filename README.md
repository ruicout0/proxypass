# proxypass

A lightweight PAC-aware HTTP forwarding proxy with OS-native keychain auth and no external runtime dependencies.

- **PAC**: Automatic proxy selection via WPAD/PAC scripts (QuickJS engine)
- **Auth**: Negotiate (Kerberos/SPNEGO) with multi-step 407 handshake, Basic fallback
- **Credentials**: Stored in OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service)
- **Cross-platform**: macOS, Linux, Windows
- **Footprint**: ~3 MB static binary, ~7 MB RAM at idle, ~10 MB under load

## Quick start

```bash
# 1. Run setup wizard
proxypass setup

# 2. Start the proxy
proxypass

# 3. Test
proxypass test
```

## Installation

### Homebrew (macOS)

```bash
brew tap ruicout0/proxypass https://github.com/ruicout0/proxypass.git
brew install ruicout0/proxypass/proxypass
```

> **macOS security notice:** Release binaries are not signed with an Apple Developer
> certificate or notarized. If macOS blocks a downloaded binary, remove its
> quarantine attribute locally, then approve it in **System Settings → Privacy &
> Security** if prompted:
>
> ```bash
> xattr -d com.apple.quarantine /path/to/proxypass
> chmod +x /path/to/proxypass
> /path/to/proxypass --help
> ```
>
> For a local ad-hoc signature instead of removing quarantine, run:
>
> ```bash
> codesign --force --deep --sign - /path/to/proxypass
> ```
>
> Homebrew installations generally handle executable permissions automatically;
> these steps are for manually downloaded or copied binaries.

### From source

```bash
git clone https://github.com/ruicout0/proxypass.git
cd proxypass
cargo build --release
# Binary at target/release/proxypass
```

## Commands

| Command | Description |
|---|---|
| `proxypass` | Start proxy (runs setup if no config found) |
| `proxypass setup` | Interactive setup wizard |
| `proxypass test [url]` | Test proxy by fetching a URL through it |
| `proxypass config` | Open config in `$EDITOR` |
| `proxypass password` | Store/update password in OS keychain |
| `proxypass install` | Install as auto-start service |
| `proxypass uninstall` | Remove auto-start service |
| `proxypass stop` | Stop the daemon |
| `proxypass restart` | Restart the daemon |
| `proxypass status` | Show daemon status |

## Configuration

Config location:

| Platform | Config path | Service unit | Logs (default) |
|---|---|---|---|
| **macOS** | `~/Library/Application Support/proxypass/proxypass.toml` | `~/Library/LaunchAgents/io.github.proxypass.plist` | `/tmp/proxypass.out` / `.err` |
| **Linux** | `~/.config/proxypass/proxypass.toml` | `~/.config/systemd/user/io.github.proxypass.service` | `journalctl --user -u io.github.proxypass` |
| **Windows** | `%APPDATA%\proxypass\proxypass.toml` | Manual (Task Scheduler) | `/tmp/proxypass.out` / `.err` |

> **Password storage**: Auth passwords are **never** written to the TOML file.
> They are stored in the OS-native credential store (see [Basic auth fallback](#basic-auth-fallback)).

```toml
[proxy]
# PAC URL (auto-discovers upstream proxy per request)
pac = "http://wpad.company.com/proxy.pac"

# OR: static upstream proxy (mutually exclusive with pac)
# proxy = "proxy.company.com:8080"

port = 3128
listen = "127.0.0.1"

# Hosts that bypass the proxy (glob patterns supported)
no_proxy = ["localhost", "127.0.0.1", "*.local", "10.*"]

[auth]
# Username for upstream proxy authentication.
# Negotiate uses this to look up Kerberos tickets.
# Basic uses this + keychain password.
# Format: "DOMAIN\\user" or 'DOMAIN\user' (literal string) or just "user"
username = 'DOMAIN\user'

# Auth method: "auto", "negotiate", "basic", "none"
#   auto      — try Negotiate first, fall back to Basic
#   negotiate — Negotiate/Kerberos only (Kerberos ticket required)
#   basic     — username + keychain password
#   none      — no auth
method = "auto"

[pac]
cache_ttl = 300                # seconds before re-fetching PAC
reload_on_network_change = true

[log]
level = "info"                 # trace, debug, info, warn, error
file = "/tmp/proxypass.log"    # omit for stderr
```

> **PAC vs static proxy**: When both `pac` and `proxy` are set, **PAC takes
> precedence**. If the PAC returns `DIRECT`, the request bypasses the static
> proxy as well. Use `no_proxy` to explicitly bypass hosts at the proxypass
> level (before PAC evaluation).

## Authentication deep dive

### How auth works

When the upstream proxy returns `407 Proxy Authentication Required`, proxypass inspects the `Proxy-Authenticate` header and follows this chain:

```
407 received
  ├─ Negotiate requested?
  │   ├─ Try SPNEGO (GSSAPI)
  │   │   ├─ OK → multi-step handshake (up to 5 rounds)
  │   │   │        ├─ 200 → ✓ done
  │   │   │        └─ 407 + challenge → feed token, repeat
  │   │   └─ FAIL (e.g. macOS Heimdal) → fall back to raw Kerberos
  │   ├─ Try raw Kerberos (GSSAPI)
  │   │   └─ FAIL → try Basic fallback
  │   └─ Basic fallback: username + keychain password
  └─ Basic requested?
      └─ username + keychain password
```

### Mechanism selection

proxypass auto-detects the available GSS mechanism at startup:

| Platform | SPNEGO | Raw Kerberos | Notes |
|---|---|---|---|
| **macOS** | ❌ | ✅ | Heimdal ships SPNEGO OID but `gss_init_sec_context` fails |
| **Linux** (MIT Kerberos) | ✅ | ✅ | Both work; SPNEGO preferred |
| **Windows** | ✅ | ✅ | Via SSPI |

### Kerberos prerequisites

Negotiate/Kerberos requires a valid ticket-granting ticket (TGT):

```bash
# Check current tickets
klist

# Obtain a ticket (domain environment)
kinit user@REALM

# Example: valid ticket for proxy service
# HTTP/proxy.company.com@COMPANY.COM
```

The proxy service name is built as `HTTP@<proxy_host>:<port>` — your Kerberos ticket must match this principal.

### Basic auth fallback

Basic auth credentials use the `username` from the config + password from the **OS keychain**:

| OS | Storage |
|---|---|
| macOS | Keychain (service: `proxypass`) |
| Linux | Secret Service / keyutils |
| Windows | Credential Manager |

Set the password:
```bash
proxypass password
```

The password is **never** stored in the TOML config file — only the username.

> **Security notice on Basic authentication:**
> In HTTP Basic auth, credentials (`username:password`) are Base64-encoded in the `Proxy-Authorization` header and sent across the wire. Unless the upstream proxy endpoint itself is protected by TLS (`https://`), these credentials travel unencrypted in transit.
>
> In contrast, **Kerberos/Negotiate** (`method = "negotiate"`) uses ticket-based challenge-response authentication where raw passwords are never transmitted on the wire, and tickets are scoped to the specific proxy service principal.
>
> If your environment requires avoiding plaintext credential transmission over the wire, enforce Negotiate-only auth in `proxypass.toml`:
> ```toml
> [auth]
> method = "negotiate"
> ```

### Troubleshooting auth

```bash
# See auth decision logs (info level)
RUST_LOG=info proxypass

# See every token exchange (debug level)
RUST_LOG=debug proxypass

# Check Kerberos tickets
klist

# Expected log messages
#   "Using GSS mechanism: Kerberos"     — Kerberos selected
#   "Using GSS mechanism: SPNEGO"       — SPNEGO selected
#   "✓ Negotiate authenticated after 1 round(s)"   — success
#   "Negotiate failed, falling back to Basic auth" — fallback
#   "✓ Basic auth (Negotiate fallback) succeeded"  — fallback worked
```

## Performance

proxypass is designed for individual developer workstations, not as a shared
forward proxy for hundreds of users.

| Metric | Value |
|---|---|
| **Idle RSS** | ~7 MB |
| **Under load** (20 concurrent) | ~10 MB |
| **Throughput** (single target, 20 conn) | ~76 req/s |
| **Latency p50** | ~136 ms |
| **Latency p95** | ~680 ms |
| **Worker threads** | 2 (IO-bound — more threads wouldn't help) |

> **Note**: Per-request latency is dominated by the upstream proxy and target
> server, not by proxypass itself. The 2 worker threads handle hundreds of
> concurrent connections via async IO multiplexing.

### Connection pooling

`reqwest` (used for forwarded non-CONNECT requests) maintains an internal
connection pool to the upstream proxy. Connection reuse avoids the cost of
re-establishing TLS and auth handshakes on every request.

### PAC caching

PAC scripts are cached in memory and re-fetched every `cache_ttl` seconds
(default 300). PAC evaluation adds negligible overhead (~1 ms per lookup
once the script is cached).

## Shell environment

### macOS / Linux (`~/.zshrc` or `~/.bashrc`)

```bash
export http_proxy=http://127.0.0.1:3128
export https_proxy=http://127.0.0.1:3128
export all_proxy=http://127.0.0.1:3128
export no_proxy=localhost,127.0.0.1,*.local
```

### Windows PowerShell

**Current session & PowerShell Profile (`$PROFILE`):**
Add to your PowerShell profile (`notepad $PROFILE`) so interactive sessions always have both uppercase and lowercase variables set:

```powershell
$env:HTTP_PROXY  = "http://127.0.0.1:3128"
$env:HTTPS_PROXY = "http://127.0.0.1:3128"
$env:ALL_PROXY   = "http://127.0.0.1:3128"
$env:NO_PROXY    = "localhost,127.0.0.1,::1,*.local"

# Lowercase variants (used by Python, Go, git, and Unix-origin CLI tools)
$env:http_proxy  = $env:HTTP_PROXY
$env:https_proxy = $env:HTTPS_PROXY
$env:all_proxy   = $env:ALL_PROXY
$env:no_proxy    = $env:NO_PROXY
```

**Persistent across all new Windows shells (User Registry):**
```powershell
$proxyUrl = "http://127.0.0.1:3128"
$noProxy  = "localhost,127.0.0.1,::1,*.local"

foreach ($var in @("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")) {
    [Environment]::SetEnvironmentVariable($var, $proxyUrl, "User")
}
foreach ($var in @("NO_PROXY", "no_proxy")) {
    [Environment]::SetEnvironmentVariable($var, $noProxy, "User")
}
```

### Windows Command Prompt (`cmd.exe`)

**Current session:**
```cmd
set HTTP_PROXY=http://127.0.0.1:3128
set HTTPS_PROXY=http://127.0.0.1:3128
set ALL_PROXY=http://127.0.0.1:3128
set NO_PROXY=localhost,127.0.0.1,::1,*.local
set http_proxy=http://127.0.0.1:3128
set https_proxy=http://127.0.0.1:3128
set all_proxy=http://127.0.0.1:3128
set no_proxy=localhost,127.0.0.1,::1,*.local
```

**Persistent (using `setx` or `reg`):**
```cmd
setx HTTP_PROXY "http://127.0.0.1:3128"
setx HTTPS_PROXY "http://127.0.0.1:3128"
setx ALL_PROXY "http://127.0.0.1:3128"
setx NO_PROXY "localhost,127.0.0.1,::1,*.local"
```
*(Or write directly to registry if `NO_PROXY` exceeds `setx` character limits: `reg add "HKCU\Environment" /v NO_PROXY /t REG_SZ /d "localhost,127.0.0.1,::1,..." /f`)*

### WSL2 integration

When running `proxypass` on the Windows host and connecting from WSL2:

- **Mirrored networking (recommended):** Set `networkingMode=mirrored` in `%USERPROFILE%\.wslconfig` under `[wsl2]`. WSL2 can then reach the Windows proxy directly via `http://127.0.0.1:3128`.
- **Default NAT mode:** Configure `listen = "0.0.0.0"` in `proxypass.toml` and configure WSL2 clients with the host gateway IP:
  ```bash
  export HTTP_PROXY="http://$(ip route show | awk '/default/ {print $3}'):3128"
  export HTTPS_PROXY="$HTTP_PROXY"
  ```

### `no_proxy` patterns

The `no_proxy` config field supports glob-style patterns. These are matched
against the request hostname *before* PAC evaluation:

| Pattern | Matches |
|---|---|
| `localhost` | exact match |
| `127.0.0.1` | exact IP |
| `*.local` | any host ending in `.local` |
| `10.*` | any IP starting with `10.` |
| `*.corp.example.com` | any subdomain of `corp.example.com` |

## Running with debug logs

```bash
RUST_LOG=debug proxypass

# Or to a file
RUST_LOG=trace proxypass 2>/tmp/proxypass-debug.log
```

## Architecture

| Layer | Technology |
|---|---|
| Runtime | Tokio async |
| HTTP engine | Hyper 1.x (HTTP/1.1) |
| PAC evaluation | QuickJS via rquickjs |
| Auth | libgssapi (SPNEGO → Kerberos fallback) |
| Credentials | `keyring` crate (multi-platform OS keychain) |
| Config | TOML (serde) |
| Service management | launchd (macOS), systemd (Linux), Windows Service |
| TLS | rustls (via reqwest for PAC fetching) |
| Binary | Static, stripped, LTO-optimized (~3 MB) |

## Platform support

proxypass is tested on macOS, Linux, and Windows. The core proxy (PAC, auth,
HTTP forwarding) works identically across all platforms. Platform differences
are limited to service management and credential storage.

### Service management

| Platform | Manager | Install | Uninstall | Status |
|---|---|---|---|---|
| **macOS** | launchd | `proxypass install` | `proxypass uninstall` | `proxypass status` |
| **Linux** | systemd (user) | `proxypass install` | `proxypass uninstall` | `proxypass status` |
| **Windows** | Manual | Run `proxypass` in foreground | N/A | N/A |

On **Windows**, automatic service installation via `proxypass install` is not yet supported (as background services running under `SYSTEM` or non-interactive service accounts cannot access the user's interactive logon session Kerberos/SSPI tickets).

Use **Windows Task Scheduler** with a lightweight VBScript launcher (`wscript.exe`) so it auto-starts completely hidden in the background on logon:

#### 1. Create the silent background launcher (`run-proxypass.vbs`)

Run once in PowerShell to create the background runner in your config folder:

```powershell
$vbsPath = "$env:APPDATA\proxypass\run-proxypass.vbs"
$targetExe = "$env:USERPROFILE\.cargo\bin\proxypass.exe"

@"
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run """$targetExe""", 0, False
"@ | Set-Content -Path $vbsPath -Encoding Ascii
```
*(The `0` window-style parameter instructs Windows to execute the console application in `SW_HIDE` mode, preventing CMD popups).*

#### 2. Register the Scheduled Task (PowerShell)

```powershell
$action   = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"$env:APPDATA\proxypass\run-proxypass.vbs`""
$trigger  = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName "proxypass" -Action $action -Trigger $trigger -Settings $settings -Description "proxypass corporate proxy daemon (silent background)"
```

#### 3. Task Management Commands

```powershell
# Start immediately (without logging off)
Start-ScheduledTask -TaskName "proxypass"

# Verify it is running and listening on port 3128
Get-NetTCPConnection -LocalPort 3128 -State Listen

# Stop daemon
Stop-ScheduledTask -TaskName "proxypass"

# Uninstall / Remove Scheduled Task
Unregister-ScheduledTask -TaskName "proxypass" -Confirm:$false
```

### Credential storage

| Platform | Backend | Command |
|---|---|---|
| **macOS** | Keychain | `proxypass password` |
| **Linux** | Secret Service (gnome-keyring / kwallet) | `proxypass password` |
| **Windows** | Credential Manager | `proxypass password` |

### Kerberos / Negotiate

| Platform | Kerberos impl | SPNEGO | Raw Kerberos |
|---|---|---|---|
| **macOS** | Heimdal | ❌ (falls back) | ✅ |
| **Linux** | MIT Kerberos | ✅ | ✅ |
| **Windows** | SSPI | ✅ | ✅ |

> On macOS, proxypass auto-detects that Heimdal SPNEGO is broken and falls
> back to raw Kerberos. No configuration needed — the log will show
> `Using GSS mechanism: Kerberos`.

### Build prerequisites

| Platform | Dependencies |
|---|---|
| **macOS** | Xcode CLT (for `libc` headers) |
| **Linux** | `libkrb5-dev` (MIT Kerberos headers for `libgssapi`) |
| **Windows** | MSVC C++ Build Tools, `patch` command (included with Git for Windows, or via Scoop/Chocolatey for QuickJS build) |

## Building

```bash
cargo build --release
# Binary: target/release/proxypass
```

Cross-compilation:
```bash
# macOS → universal binary (x86_64 + arm64)
rustup target add x86_64-apple-darwin aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin
lipo -create -output proxypass target/{x86_64,aarch64}-apple-darwin/release/proxypass

# macOS → Linux (requires cross-compilation toolchain)
rustup target add x86_64-unknown-linux-gnu
# On macOS: brew install x86_64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-gnu

# macOS/Linux → Windows
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
```

## License

MIT
