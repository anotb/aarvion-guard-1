# Homebrew formula template. Fill in url + sha256 per release; the guard also
# depends on `opa`, which it spawns as a sidecar.
class AarvionGuard < Formula
  desc "Govern your local OpenClaw with Aarvion"
  homepage "https://aarvion.ai"
  version "0.1.0"
  license "Apache-2.0"

  depends_on "opa"

  on_macos do
    on_arm do
      url "https://github.com/aarvion-ai/aarvion-guard/releases/download/v0.1.0/aarvion-guard_darwin_arm64"
      sha256 "REPLACE_WITH_SHA256"
    end
    on_intel do
      url "https://github.com/aarvion-ai/aarvion-guard/releases/download/v0.1.0/aarvion-guard_darwin_amd64"
      sha256 "REPLACE_WITH_SHA256"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/aarvion-ai/aarvion-guard/releases/download/v0.1.0/aarvion-guard_linux_arm64"
      sha256 "REPLACE_WITH_SHA256"
    end
    on_intel do
      url "https://github.com/aarvion-ai/aarvion-guard/releases/download/v0.1.0/aarvion-guard_linux_amd64"
      sha256 "REPLACE_WITH_SHA256"
    end
  end

  def install
    bin.install Dir["*"].first => "aarvion-guard"
  end

  test do
    assert_match "dev", shell_output("#{bin}/aarvion-guard version")
  end
end
