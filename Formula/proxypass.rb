class Proxypass < Formula
  desc "Lightweight PAC-aware HTTP proxy with SPNEGO/Kerberos auth and OS keychain"
  homepage "https://github.com/ruicout0/proxypass"
  license "MIT"
  version "0.3.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ruicout0/proxypass/releases/download/v#{version}/proxypass-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "75e9f1e72eb648c255598833123bfff5dc20c4808e3c013f023f64c4a3e48235"
    else
      url "https://github.com/ruicout0/proxypass/releases/download/v#{version}/proxypass-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "0438c3093aee09acd59610ae3ad8c4a18ec97a31e6e57c584ae543ea59cd7e34"
    end
  end

  on_linux do
    url "https://github.com/ruicout0/proxypass/releases/download/v#{version}/proxypass-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "14f1b8f35e2de1b73fd93d4d9a2d0b6b5deb176398f0c43cfd9b4ee6818013dc"
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
