#!/bin/sh
# Aarvion Guard installer. Usage:  curl -fsSL get.aarvion.ai | sh
# Downloads the guard binary for this OS/arch and installs it to PREFIX/bin.
set -eu

REPO="aarvion-ai/aarvion-guard"
PREFIX="${PREFIX:-/usr/local}"
VERSION="${AARVION_GUARD_VERSION:-latest}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64 | amd64) arch="amd64" ;;
  arm64 | aarch64) arch="arm64" ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac
case "$os" in
  linux | darwin) ;;
  *) echo "unsupported OS: $os" >&2; exit 1 ;;
esac

if [ "$VERSION" = "latest" ]; then
  base="https://github.com/${REPO}/releases/latest/download"
else
  base="https://github.com/${REPO}/releases/download/${VERSION}"
fi
url="${base}/aarvion-guard_${os}_${arch}"

tmp="$(mktemp)"
echo "downloading ${url}"
curl -fsSL "$url" -o "$tmp"
chmod +x "$tmp"

dest="${PREFIX}/bin/aarvion-guard"
if [ -w "${PREFIX}/bin" ]; then
  mv "$tmp" "$dest"
else
  echo "installing to ${dest} (needs sudo)"
  sudo mv "$tmp" "$dest"
fi

echo "installed: $(aarvion-guard version 2>/dev/null || echo aarvion-guard)"
echo "next: aarvion-guard init <pairing-code>   (from your Aarvion dashboard)"
