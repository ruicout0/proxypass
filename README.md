# proxypass

A lightweight PAC-aware HTTP proxy for macOS with OS keychain auth, simple CLI, and launchd integration.

## Install

```bash
brew tap ruicout0/proxypass
brew install proxypass
```

## Setup

```bash
# 1. Edit config (~/.config/proxypass/proxypass.toml)
proxypass config

# 2. Store credentials (saved to macOS Keychain)
proxypass password

# 3. Install as login item
proxypass install

# 4. Test
proxypass test
```

## Commands

| Command | Description |
|---|---|
| `proxypass start` | Start the proxy |
| `proxypass stop` | Stop the proxy |
| `proxypass restart` | Restart the proxy |
| `proxypass status` | Show status + PID |
| `proxypass test [url]` | Test proxy with a URL |
| `proxypass config` | Open config in $EDITOR |
| `proxypass password` | Store password in keychain |
| `proxypass install` | Register launchd agent |
| `proxypass uninstall` | Remove launchd agent |

## Config (`~/.config/proxypass/proxypass.toml`)

```toml
[proxy]
pac = "https://muc.proxy-pac.bmwgroup.net/proxy.pac"
port = 3128
listen = "127.0.0.1"
no_proxy = ["localhost", "127.0.0.1", "*.bmwgroup.net", "10.*", "192.168.*"]

[auth]
username = "DOMAIN\\user"
method = "auto"   # auto | negotiate | basic | none

[pac]
cache_ttl = 300
reload_on_network_change = true

[log]
level = "info"
file = "/tmp/proxypass.log"
```

## Shell environment

Add to `~/.zshrc`:

```bash
export http_proxy=http://127.0.0.1:3128
export https_proxy=http://127.0.0.1:3128
export no_proxy=localhost,127.0.0.1,*.bmwgroup.net
```

## Architecture

- **Runtime**: Tokio async
- **HTTP engine**: Hyper 1.x
- **PAC evaluation**: QuickJS (via rquickjs)
- **Auth**: Kerberos/Negotiate via libgssapi, Basic fallback
- **Credentials**: macOS Keychain via `keyring` crate
- **Config**: TOML
- **Distribution**: Homebrew tap, universal macOS binary (x86_64 + arm64)
