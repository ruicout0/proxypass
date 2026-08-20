class Proxypass < Formula
  desc "Lightweight PAC-aware HTTP proxy with SPNEGO/Kerberos auth and OS keychain"
  homepage "https://github.com/ruicout0/proxypass"
  license "MIT"
  version "0.3.1"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ruicout0/proxypass/releases/download/v#{version}/proxypass-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "7740c289bf70aab4005ab05f7180be3acd11154662811469ada6352b3133c043"
    else
      url "https://github.com/ruicout0/proxypass/releases/download/v#{version}/proxypass-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "ed64aa0daef89cda93789a048b18d565e6091ad02af59b615fa267868f8a6412"
    end
  end

  on_linux do
    url "https://github.com/ruicout0/proxypass/releases/download/v#{version}/proxypass-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "07d920dde6b3c1d23ce64b850d19b3eee726000b7208bf6feb7660afe2ee212c"
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
