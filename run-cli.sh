#!/bin/bash
# Simple launcher script for wifiteX CLI
# This script handles sudo requirements automatically

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 wifiteX CLI Launcher${NC}"
echo "========================"

# Check if we're in the right directory
if [ ! -f "wifitex/__init__.py" ]; then
    echo -e "${RED}❌ Error: Please run this script from the wifiteX project directory${NC}"
    exit 1
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}🔐 wifiteX requires root privileges for wireless operations${NC}"
    echo "   Launching with sudo..."
    exec sudo python3 -m wifitex "$@"
else
    # Launch directly as root
    echo -e "${GREEN}✓ Running as root, launching CLI...${NC}"
    exec python3 -m wifitex "$@"
fi
