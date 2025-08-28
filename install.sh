#!/bin/bash

# Installation script for plsaicheckyay
# A secure yay wrapper with AI-powered PKGBUILD analysis

set -e

echo "🚀 Installing plsaicheckyay..."

# Check if running on Arch Linux
if ! command -v pacman &> /dev/null; then
    echo "❌ This tool requires Arch Linux with pacman"
    exit 1
fi

# Check if yay is installed
if ! command -v yay &> /dev/null; then
    echo "❌ yay is required but not installed"
    echo "Please install yay first: https://github.com/Jguer/yay"
    exit 1
fi

# Check if python3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required"
    exit 1
fi

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip3 install --user -r requirements.txt

# Make the script executable
chmod +x plsaicheckyay.py

# Create symlink in user's local bin (if it exists)
LOCAL_BIN="$HOME/.local/bin"
if [ -d "$LOCAL_BIN" ]; then
    ln -sf "$(pwd)/plsaicheckyay.py" "$LOCAL_BIN/plsyay"
    echo "✅ Created symlink: $LOCAL_BIN/plsyay"
    
    # Check if ~/.local/bin is in PATH
    if [[ ":$PATH:" != *":$LOCAL_BIN:"* ]]; then
        echo "⚠️  Warning: $LOCAL_BIN is not in your PATH"
        echo "Add this to your shell config (~/.bashrc, ~/.zshrc, etc.):"
        echo "export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
else
    echo "⚠️  $LOCAL_BIN doesn't exist, skipping symlink creation"
    echo "You can run the tool directly with: python3 $(pwd)/plsaicheckyay.py"
fi

echo ""
echo "🎉 Installation completed!"
echo ""
echo "Next steps:"
echo "1. Run 'python3 config.py' to configure your AI provider"
echo "2. Test with: plsyay -S <package_name>"
echo ""
echo "Usage examples:"
echo "  plsyay -S discord                    # Install AUR package with security check"
echo "  plsyay -S firefox                    # Official packages installed directly"
echo "  plsyay -S pkg --auto-threshold 0.8   # Auto-install if confidence >= 80%"
echo "  plsyay -S pkg --editmenu --diffmenu  # Enable review mode"
echo "  plsyay -Syu                         # Update all packages (passthrough)"
echo "  plsyay --help                       # Show help"