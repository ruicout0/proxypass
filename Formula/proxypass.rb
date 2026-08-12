class Proxypass < Formula
  desc "Lightweight PAC-aware HTTP proxy with SPNEGO/Kerberos auth and OS keychain"
  homepage "https://github.com/ruicout0/proxypass"
  license "MIT"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ruicout0/proxypass/releases/download/v#{version}/proxypass-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_ARM64_SHA256"
    else
      url "https://github.com/ruicout0/proxypass/releases/download/v#{version}/proxypass-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_X86_64_SHA256"
    end
  end

  on_linux do
    url "https://github.com/ruicout0/proxypass/releases/download/v#{version}/proxypass-#{version}-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "PLACEHOLDER_LINUX_SHA256"
  end

  def install
    bin.install "proxypass"
  end

  service do
    run [opt_bin/"proxypass", "start", "--foreground"]
    run_type :immediate
    keep_alive true
    log_path "/tmp/proxypass.out"
    error_log_path "/tmp/proxypass.err"
  end

  def caveats
    <<~EOS
      To start proxypass as a background service:
        brew services start proxypass

      To configure:
        #{etc}/proxypass.toml
        (or ~/.config/proxypass/config.toml)

      To set proxy credentials in the OS keychain:
        proxypass keychain set --username YOUR_USERNAME
    EOS
  end

  test do
    system "#{bin}/proxypass", "--help"
  end
end