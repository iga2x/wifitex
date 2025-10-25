#!/bin/bash
# Install or update WifiteX with latest features

echo "Installing/Updating WifiteX..."

# Get the directory where script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    INSTALL_CMD="python3 setup.py install --force"
else
    echo "Note: Not running as root. Will try user install."
    INSTALL_CMD="python3 setup.py install --user --force"
fi

echo "Running: $INSTALL_CMD"
eval $INSTALL_CMD

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Installation complete!"
    echo ""
    echo "New features installed:"
    echo "  ✅ KARMA GUI Client Monitoring"
    echo "  ✅ Real-time client status updates"
    echo "  ✅ Fixed PCAP detection"
    echo "  ✅ GUI freeze prevention"
    echo ""
    echo "To verify installation, run:"
    echo "  python3 -m wifitex.gui"
    echo ""
else
    echo ""
    echo "❌ Installation failed!"
    echo ""
    echo "Try running as root:"
    echo "  sudo bash install_latest.sh"
fi
