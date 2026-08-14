class Proxypass < Formula
  desc "Lightweight PAC-aware HTTP proxy with SPNEGO/Kerberos auth and OS keychain"
  homepage "https://github.com/ruicout0/proxypass"
  license "MIT"
  version "0.2.4"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ruicout0/proxypass/releases/download/v#{version}/proxypass-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "e014fd07c81266fe4888ab4ee16b55b236d173a166a0b01c4ece70b6383e809c"
    else
      url "https://github.com/ruicout0/proxypass/releases/download/v#{version}/proxypass-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "3ee904a9caa23d3f431797174de1a82ae2ea943e80a5d2d0a8b72b119a06dc2d"
    end
  end

  on_linux do
    url "https://github.com/ruicout0/proxypass/releases/download/v#{version}/proxypass-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "d6b6fb83f04750ebb50b8de99fe0b3b2c4b3ffdd4e328564d64039d8e6eb6e9f"
  end

  def install
    bin.install "proxypass"
  end

  service do
    run [opt_bin/"proxypass"]
    run_type :immediate
    keep_alive true
    log_path "/tmp/proxypass.out"
    error_log_path "/tmp/proxypass.err"
  end

  def caveats
    <<~EOS
      Before starting the service, run the setup wizard:
        proxypass setup

      Then start as a background service:
        brew services start proxypass

      To configure manually:
        ~/.config/proxypass/config.toml

      To set proxy credentials in the OS keychain:
        proxypass keychain set --username YOUR_USERNAME
    EOS
  end

  test do
    system "#{bin}/proxypass", "--help"
  end
end
