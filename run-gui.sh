#!/bin/bash
# Simple launcher script for wifiteX GUI
# This script handles sudo requirements automatically

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 wifiteX GUI Launcher${NC}"
echo "=========================="

# Check if we're in the right directory
if [ ! -f "wifitex/__init__.py" ]; then
    echo -e "${RED}❌ Error: Please run this script from the wifiteX project directory${NC}"
    exit 1
fi

# Function to check if pkexec is available
check_pkexec() {
    command -v pkexec >/dev/null 2>&1
}

# Function to check if gksudo is available
check_gksudo() {
    command -v gksudo >/dev/null 2>&1
}

# Function to check if kdesudo is available
check_kdesudo() {
    command -v kdesudo >/dev/null 2>&1
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}🔐 wifiteX requires root privileges for wireless operations${NC}"
    echo "   Attempting to launch with elevated privileges..."
    
    # Try different sudo methods for GUI
    if check_pkexec; then
        echo -e "${GREEN}   Using pkexec for authentication...${NC}"
        exec pkexec env DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY DBUS_SESSION_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS python3 -m wifitex.gui "$@"
    elif check_gksudo; then
        echo -e "${GREEN}   Using gksudo for authentication...${NC}"
        exec gksudo python3 -m wifitex.gui "$@"
    elif check_kdesudo; then
        echo -e "${GREEN}   Using kdesudo for authentication...${NC}"
        exec kdesudo python3 -m wifitex.gui "$@"
    else
        echo -e "${RED}❌ No GUI sudo method found!${NC}"
        echo ""
        echo "Please run manually:"
        echo -e "${BLUE}  sudo python3 -m wifitex.gui${NC}"
        echo ""
        echo "Or install a GUI sudo method:"
        echo -e "${BLUE}  sudo apt install policykit-1-gnome${NC}"
        echo ""
        exit 1
    fi
else
    # Launch directly as root
    echo -e "${GREEN}✓ Running as root, launching GUI...${NC}"
    exec python3 -m wifitex.gui "$@"
fi
