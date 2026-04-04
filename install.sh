#!/bin/sh
set -e

REPO="gustavhammarin/pypi-scanner"
BINARY="pypi-scanner"
INSTALL_DIR="$HOME/.local/bin"

# Detect OS and arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
  linux)
    case "$ARCH" in
      x86_64)  TARGET="x86_64-unknown-linux-gnu" ;;
      aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
      *) echo "Unsupported arch: $ARCH"; exit 1 ;;
    esac
    ;;
  darwin)
    case "$ARCH" in
      x86_64)  TARGET="x86_64-apple-darwin" ;;
      arm64)   TARGET="aarch64-apple-darwin" ;;
      *) echo "Unsupported arch: $ARCH"; exit 1 ;;
    esac
    ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

# Get latest version
VERSION=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" \
  | grep '"tag_name"' | cut -d'"' -f4)

URL="https://github.com/$REPO/releases/download/$VERSION/$BINARY-$TARGET"

echo "Installing $BINARY $VERSION ($TARGET)..."

mkdir -p "$INSTALL_DIR"
curl -fsSL "$URL" -o "$INSTALL_DIR/$BINARY"
chmod +x "$INSTALL_DIR/$BINARY"

# Add to PATH
add_to_path() {
  local file="$1"
  local line='export PATH="$HOME/.local/bin:$PATH"'
  if [ -f "$file" ] && ! grep -q '.local/bin' "$file"; then
    echo "" >> "$file"
    echo "# Added by pypi-scanner installer" >> "$file"
    echo "$line" >> "$file"
    echo "  → Added to $file"
  fi
}

add_to_path "$HOME/.bashrc"
add_to_path "$HOME/.zshrc"
add_to_path "$HOME/.profile"

echo ""
echo "✓ Installed $BINARY to $INSTALL_DIR"
echo ""
echo "Run one of these commands:"
echo "  source ~/.bashrc"
echo "  source ~/.zshrc"
echo ""
echo "Or restart the terminal, then run: $BINARY"
