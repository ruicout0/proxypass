class Proxypass < Formula
  desc "Lightweight PAC-aware HTTP proxy with SPNEGO/Kerberos auth and OS keychain"
  homepage "https://github.com/ruicout0/proxypass"
  license "MIT"
  version "0.3.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ruicout0/proxypass/releases/download/v#{version}/proxypass-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "41468e0ef553f5d3e077c70aeb25577cbcb01b52f993960f76aca3d4e41854d7"
    else
      url "https://github.com/ruicout0/proxypass/releases/download/v#{version}/proxypass-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "f270e20073dbcc7e5c5893eb6904b3e960d6b663eadd454ab77b43beee056439"
    end
  end

  on_linux do
    url "https://github.com/ruicout0/proxypass/releases/download/v#{version}/proxypass-#{version}-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "b1985eff003b68e210200c2439bdbffff4912053f7af699d78ec4575b18684fa"
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
