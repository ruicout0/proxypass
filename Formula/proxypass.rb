class Proxypass < Formula
  desc "Lightweight PAC-aware HTTP proxy with SPNEGO/Kerberos auth and OS keychain"
  homepage "https://github.com/ruicout0/proxypass"
  license "MIT"
  version "0.2.7"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ruicout0/proxypass/releases/download/v#{version}/proxypass-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "2c50d4ab301eb72bd9f398a9565c276cb8f275c8c16ca96e980c86b94f06894f"
    else
      url "https://github.com/ruicout0/proxypass/releases/download/v#{version}/proxypass-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "6b874167dc04db2f9d0142fdbbfb437ffb8b94fb4b5db577cf3957b94e004b9c"
    end
  end

  on_linux do
    url "https://github.com/ruicout0/proxypass/releases/download/v#{version}/proxypass-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "77dddf6ce57cf4500f578e29b1faa723cd77abe6cdcf3497b759626f2c5609be"
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
