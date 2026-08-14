class Proxypass < Formula
  desc "Lightweight PAC-aware HTTP proxy with SPNEGO/Kerberos auth and OS keychain"
  homepage "https://github.com/ruicout0/proxypass"
  license "MIT"
  version "0.2.3"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ruicout0/proxypass/releases/download/v#{version}/proxypass-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "0b0756a0f5ffe23fd0afacedd89d7c684392f6090aff69724a292def76e8992a"
    else
      url "https://github.com/ruicout0/proxypass/releases/download/v#{version}/proxypass-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "738453c5e1321c7c60ebd9a3a12f366bfc16dfe5e99f9ca64845b3ce538c9fce"
    end
  end

  on_linux do
    url "https://github.com/ruicout0/proxypass/releases/download/v#{version}/proxypass-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "2f52aefd4050ba5872161941e500285a813138708a3445144e8c4c78045fd084"
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
