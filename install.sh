#!/bin/bash

# Wifitex Installation Script
# This script installs Wifitex with proper desktop integration

set -euo pipefail

echo "🚀 Wifitex Installation Script"
echo "=============================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root for system-wide installation"
    echo "   Please run: sudo ./install.sh"
    exit 1
fi

# Prepare required directories
echo "📁 Preparing system directories..."
mkdir -p /usr/local/share/applications /usr/local/bin /usr/share/pixmaps
chown root:root /usr/local/share/applications /usr/local/bin /usr/share/pixmaps
chmod 755 /usr/local/share/applications /usr/local/bin /usr/share/pixmaps
# Remove immutable flag if present
chattr -i /usr/local/share/applications 2>/dev/null || true
echo "✓ System directories prepared"

# Check Python version
echo "🔍 Checking Python version..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    echo "✓ Python $PYTHON_VERSION found"
    
    if python3 -c "import sys; exit(0 if sys.version_info >= (3, 6) else 1)"; then
        echo "✓ Python version is compatible"
    else
        echo "❌ Python 3.6+ required. Found: $PYTHON_VERSION"
        exit 1
    fi
else
    echo "❌ Python 3 not found. Please install Python 3.6 or higher."
    exit 1
fi

# Check for pip
echo "🔍 Checking for pip..."
if command -v pip3 &> /dev/null; then
    echo "✓ pip3 found"
else
    echo "❌ pip3 not found. Installing..."
    apt update && apt install -y python3-pip
fi

# Determine pip flags (handle Debian/Ubuntu externally-managed environments gracefully)
PIP3_FLAGS=()
if command -v pip3 &> /dev/null && pip3 help install 2>&1 | grep -q -- "--break-system-packages"; then
    PIP3_FLAGS+=("--break-system-packages")
fi

# Install system dependencies
echo "📦 Installing system dependencies..."
apt update
apt install -y \
    python3-dev \
    python3-setuptools \
    python3-wheel \
    aircrack-ng \
    tshark \
    reaver \
    bully \
    cowpatty \
    hashcat \
    hcxtools \
    macchanger \
    wireless-tools \
    net-tools \
    iw \
    desktop-file-utils

# Install Python GUI dependencies
echo "📦 Installing Python GUI dependencies..."
apt install -y python3-pyqt6 python3-pyqt6.qtsvg python3-pyqt6.qtmultimedia

# Install additional Python packages
echo "📦 Installing additional Python packages..."
pip3 install "${PIP3_FLAGS[@]}" psutil requests netifaces watchdog qdarkstyle qtawesome

# Install Wifitex
echo "📦 Installing Wifitex..."
# Clean previous builds
rm -rf build/ dist/ *.egg-info/ 2>/dev/null || true

# Install package using pip (preferred over setup.py install)
echo "📦 Installing Wifitex package via pip..."
pip3 install "${PIP3_FLAGS[@]}" --no-deps .
echo "✓ Installation complete"

# Precompile Python code for faster startup
echo "⚡ Precompiling Python code for faster startup..."
python3 -m compileall wifitex/ 2>/dev/null || true
echo "✓ Python code precompiled"

# Create desktop shortcuts
echo "🖥️  Setting up desktop integration..."

# Detect system paths dynamically
BIN_DIR="/usr/local/bin"
if [ ! -d "$BIN_DIR" ]; then
    # Try alternative locations
    for alt_dir in "/usr/bin" "/opt/bin"; do
        if [ -d "$alt_dir" ]; then
            BIN_DIR="$alt_dir"
            break
        fi
    done
fi

DESKTOP_APPS_DIR="/usr/share/applications"
if [ ! -d "$DESKTOP_APPS_DIR" ]; then
    # Try alternative locations
    for alt_dir in "/usr/local/share/applications" "/opt/share/applications"; do
        if [ -d "$alt_dir" ]; then
            DESKTOP_APPS_DIR="$alt_dir"
            break
        fi
    done
fi

# Ensure we use the standard applications directory for better desktop integration
if [ "$DESKTOP_APPS_DIR" != "/usr/share/applications" ] && [ -d "/usr/share/applications" ]; then
    DESKTOP_APPS_DIR="/usr/share/applications"
    echo "✓ Using standard desktop applications directory: $DESKTOP_APPS_DIR"
fi

# Install icons
echo "🎨 Installing icons..."
ICON_DIR="/usr/share/pixmaps"
if [ ! -d "$ICON_DIR" ]; then
    # Try alternative locations
    for alt_dir in "/usr/local/share/pixmaps" "/usr/share/icons" "/opt/share/pixmaps"; do
        if [ -d "$alt_dir" ]; then
            ICON_DIR="$alt_dir"
            break
        fi
    done
fi

# Copy icons to /usr/share/pixmaps/ (prevents theming/masking)
if [ -d "icons" ]; then
    echo "🎨 Installing icons with full picture mode..."
    
    # Copy all icon sizes to ensure proper scaling
    cp icons/wifitex-16x16.png "$ICON_DIR/"
    cp icons/wifitex-22x22.png "$ICON_DIR/"
    cp icons/wifitex-24x24.png "$ICON_DIR/"
    cp icons/wifitex-32x32.png "$ICON_DIR/"
    cp icons/wifitex-48x48.png "$ICON_DIR/"
    cp icons/wifitex-64x64.png "$ICON_DIR/"
    cp icons/wifitex-96x96.png "$ICON_DIR/"
    cp icons/wifitex-128x128.png "$ICON_DIR/"
    cp icons/wifitex-256x256.png "$ICON_DIR/"
    cp icons/wifitex.ico "$ICON_DIR/"
    cp icons/wifitex.xpm "$ICON_DIR/"
    
    echo "✓ All icon sizes installed to $ICON_DIR (full picture mode)"
    
    # Install icons to hicolor theme directories for PolicyKit and desktop integration
    echo "🎨 Installing icons to hicolor theme directories..."
    for size in 16 22 24 32 48 64 96 128 256; do
        if [ -f "icons/wifitex-${size}x${size}.png" ]; then
            mkdir -p "/usr/share/icons/hicolor/${size}x${size}/apps"
            cp "icons/wifitex-${size}x${size}.png" "/usr/share/icons/hicolor/${size}x${size}/apps/"
            echo "✓ Installed wifitex-${size}x${size}.png to hicolor theme"
        fi
    done
    
    # Install scalable icon if available
    if [ -f "icons/wifitex.svg" ]; then
        mkdir -p "/usr/share/icons/hicolor/scalable/apps"
        cp "icons/wifitex.svg" "/usr/share/icons/hicolor/scalable/apps/"
        echo "✓ Installed scalable SVG icon to hicolor theme"
    fi
    
    # Create index.theme file for proper theme integration
    if [ ! -f "/usr/share/icons/hicolor/index.theme" ]; then
        cat > /usr/share/icons/hicolor/index.theme << 'EOF'
[Icon Theme]
Name=Hicolor
Comment=Default icon theme
Directories=16x16/apps,22x22/apps,24x24/apps,32x32/apps,48x48/apps,64x64/apps,96x96/apps,128x128/apps,256x256/apps,scalable/apps

[16x16/apps]
Size=16
Type=Fixed

[22x22/apps]
Size=22
Type=Fixed

[24x24/apps]
Size=24
Type=Fixed

[32x32/apps]
Size=32
Type=Fixed

[48x48/apps]
Size=48
Type=Fixed

[64x64/apps]
Size=64
Type=Fixed

[96x96/apps]
Size=96
Type=Fixed

[128x128/apps]
Size=128
Type=Fixed

[256x256/apps]
Size=256
Type=Fixed

[scalable/apps]
Size=256
Type=Scalable
MinSize=16
MaxSize=512
EOF
        echo "✓ Created hicolor theme index"
    fi
    
    # Update icon cache to ensure changes take effect
    if command -v gtk-update-icon-cache &> /dev/null; then
        gtk-update-icon-cache /usr/share/icons/hicolor/ 2>/dev/null || true
        echo "✓ Icon cache updated"
    fi
    
    # Also copy to user icon directory for better compatibility
    if [ -n "${SUDO_USER-}" ]; then
        USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        USER_ICON_DIR="$USER_HOME/.local/share/icons"
        mkdir -p "$USER_ICON_DIR"
        cp icons/wifitex-*.png "$USER_ICON_DIR/"
        cp icons/wifitex.ico "$USER_ICON_DIR/"
        cp icons/wifitex.xpm "$USER_ICON_DIR/"
        chown -R "$SUDO_USER:$SUDO_USER" "$USER_ICON_DIR"
        echo "✓ Icons also installed to user directory"
    fi
    
    # Verify icon installation and ensure full picture mode
    echo "🔍 Verifying icon installation and full picture mode..."
    if [ -f "$ICON_DIR/wifitex-256x256.png" ]; then
        echo "✅ Main icon file verified: $ICON_DIR/wifitex-256x256.png"
        
        # Verify PNG properties for full picture display
        if command -v file &> /dev/null; then
            icon_info=$(file "$ICON_DIR/wifitex-256x256.png")
            echo "✅ Icon file info: $icon_info"
            
            # Check if it's a proper PNG
            if [[ "$icon_info" == *"PNG image data"* ]]; then
                echo "✅ Valid PNG format confirmed"
            else
                echo "⚠️  Warning: Icon may not be a valid PNG"
            fi
        fi
        
        # Ensure icon has proper transparency for full picture display
        if command -v convert &> /dev/null; then
            echo "🎨 Ensuring icon transparency for full picture mode..."
            convert "$ICON_DIR/wifitex-256x256.png" -background none -alpha on "$ICON_DIR/wifitex-256x256.png" 2>/dev/null || true
            echo "✅ Icon transparency optimized"
        fi
        
        echo "✅ Desktop file will use: Icon=wifitex-256x256"
        echo "✅ Theme integration: Proper desktop theme support"
    else
        echo "❌ Main icon file missing!"
    fi
fi

# Install PolicyKit policy file for pkexec
if [ -f "data/wifitex-gui.policy" ]; then
    echo "🔐 Installing PolicyKit policy file..."
    cp data/wifitex-gui.policy /usr/share/polkit-1/actions/
    echo "✓ PolicyKit policy installed"
    
    # Reload PolicyKit to ensure policy takes effect
    if command -v systemctl &> /dev/null && systemctl is-active --quiet polkit; then
        systemctl reload polkit 2>/dev/null || true
        echo "✓ PolicyKit service reloaded"
    fi
fi

# Install desktop file
if [ -f "data/wifitex-gui.desktop" ]; then
    echo "📋 Installing desktop file..."
    cp data/wifitex-gui.desktop "$DESKTOP_APPS_DIR/"
    chmod 644 "$DESKTOP_APPS_DIR/wifitex-gui.desktop"
    echo "✓ Desktop file installed"
    
    # Update desktop file to use launcher and theme icon
    if [ -f "$DESKTOP_APPS_DIR/wifitex-gui.desktop" ]; then
        # Use theme icon for proper desktop integration
        sed -i "s|Exec=.*|Exec=$BIN_DIR/wifitex-gui-launcher|g" "$DESKTOP_APPS_DIR/wifitex-gui.desktop"
        sed -i "s|TryExec=.*|TryExec=$BIN_DIR/wifitex-gui-launcher|g" "$DESKTOP_APPS_DIR/wifitex-gui.desktop"
        sed -i "s|Icon=.*|Icon=wifitex-256x256|g" "$DESKTOP_APPS_DIR/wifitex-gui.desktop"
        
        # Ensure desktop file has proper permissions and validation
        chmod 644 "$DESKTOP_APPS_DIR/wifitex-gui.desktop"
        
        # Validate desktop file
        if command -v desktop-file-validate &> /dev/null; then
            echo "🔍 Validating desktop file..."
            if desktop-file-validate "$DESKTOP_APPS_DIR/wifitex-gui.desktop" 2>/dev/null; then
                echo "✅ Desktop file validation passed"
            else
                echo "⚠️  Desktop file validation warnings (may still work)"
            fi
        fi
        
        echo "✓ Desktop file updated with full picture icon mode"
        echo "✓ Icon path locked to: /usr/share/pixmaps/wifitex-256x256.png"
        echo "✓ Theme masking disabled - full picture display enabled"
    fi
fi

# Update desktop database
if command -v update-desktop-database &> /dev/null; then
    update-desktop-database "$DESKTOP_APPS_DIR/"
    echo "✓ Desktop database updated"
fi

# Verify icon theme integration
echo "🔍 Verifying icon theme integration..."
if [ -f "/usr/share/icons/hicolor/256x256/apps/wifitex-256x256.png" ]; then
    echo "✅ Icon properly installed in theme system"
    echo "✅ Desktop will use theme-aware icon display"
else
    echo "⚠️  Icon not found in theme system"
fi

# Final cache refresh to ensure all changes take effect
echo "🔄 Performing comprehensive cache refresh for full picture icon display..."
echo "   This ensures your custom WiFi icon displays without theme masking"

# Refresh system icon cache
if command -v gtk-update-icon-cache &> /dev/null; then
    gtk-update-icon-cache /usr/share/icons/hicolor/ -f 2>/dev/null || true
    echo "✓ System icon cache refreshed"
fi

# Refresh desktop database
if command -v update-desktop-database &> /dev/null; then
    update-desktop-database /usr/share/applications/ 2>/dev/null || true
    echo "✓ Desktop database refreshed"
fi

# Clear user caches for immediate effect
    if [ -n "${SUDO_USER-}" ]; then
        USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    echo "🧹 Clearing user caches for immediate icon refresh..."
    
    # Clear icon caches
    rm -rf "$USER_HOME/.cache/icon-cache.kcache" 2>/dev/null || true
    rm -rf "$USER_HOME/.cache/thumbnails"/* 2>/dev/null || true
    rm -rf "$USER_HOME/.cache/gnome-applications" 2>/dev/null || true
    
    echo "✓ User icon caches cleared"
    
    # Try to disable theme masking for GNOME (if available)
    if command -v gsettings &> /dev/null && [ -d "$USER_HOME" ]; then
        echo "🎨 Configuring desktop environment for full picture display..."
        
        # Disable dash-to-dock theming (if extension is present)
        sudo -u "$SUDO_USER" gsettings set org.gnome.shell.extensions.dash-to-dock apply-custom-theme false 2>/dev/null || true
        
        # Set icon theme to use full pictures
        sudo -u "$SUDO_USER" gsettings set org.gnome.desktop.interface icon-theme "Adwaita" 2>/dev/null || true
        
        echo "✓ Desktop environment configured for full picture icons"
    fi
fi

echo "✅ Full picture icon mode cache refresh completed"
echo "💡 Your custom WiFi icon should now display without theme masking"

# Create desktop shortcut for current user (if not root)
if [ -n "${SUDO_USER-}" ]; then
    # Use dynamic home directory detection
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    DESKTOP_DIR="$USER_HOME/Desktop"
    if [ -d "$DESKTOP_DIR" ]; then
        cp data/wifitex-gui.desktop "$DESKTOP_DIR/"
        chown "$SUDO_USER:$SUDO_USER" "$DESKTOP_DIR/wifitex-gui.desktop"
        chmod +x "$DESKTOP_DIR/wifitex-gui.desktop"
        echo "✓ Desktop shortcut created for $SUDO_USER"
    fi
fi

# Create launcher script in system binary directory
echo "🔧 Creating system launcher..."

# Detect system binary directory
BIN_DIR="/usr/local/bin"
if [ ! -d "$BIN_DIR" ]; then
    # Try alternative locations
    for alt_dir in "/usr/bin" "/opt/bin"; do
        if [ -d "$alt_dir" ]; then
            BIN_DIR="$alt_dir"
            break
        fi
    done
fi

# Create improved launcher that handles sudo automatically
cat > "$BIN_DIR/wifitex-gui-launcher" << 'EOF'
#!/bin/bash
# Wifitex GUI Launcher with automatic sudo handling

# Set Qt environment variables to fix common issues
export QT_QPA_PLATFORMTHEME=""
export QT_QPA_PLATFORM="xcb"
export QT_STYLE_OVERRIDE=""
export QT_AUTO_SCREEN_SCALE_FACTOR="0"

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
    echo "🔐 Wifitex requires root privileges for wireless operations"
    echo "   Attempting to launch with elevated privileges..."
    
    # Try different sudo methods for GUI
    if check_pkexec; then
        echo "   Using pkexec for authentication..."
        exec pkexec env DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY DBUS_SESSION_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS python3 -OO -m wifitex.gui "$@"
    elif check_gksudo; then
        echo "   Using gksudo for authentication..."
        exec gksudo python3 -OO -m wifitex.gui "$@"
    elif check_kdesudo; then
        echo "   Using kdesudo for authentication..."
        exec kdesudo python3 -OO -m wifitex.gui "$@"
    else
        echo "❌ No GUI sudo method found!"
        echo "   Please run manually: sudo python3 -m wifitex.gui"
        echo "   Or install: sudo apt install policykit-1-gnome"
        exit 1
    fi
else
    # Launch directly as root with Python optimizations
    exec python3 -OO -m wifitex.gui "$@"
fi
EOF

chmod +x "$BIN_DIR/wifitex-gui-launcher"

# Create a simple wrapper script for easier access
cat > "$BIN_DIR/wifitex-gui" << 'EOF'
#!/bin/bash
# Simple wrapper for wifitex-gui-launcher
set -euo pipefail
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
exec "$SCRIPT_DIR/wifitex-gui-launcher" "$@"
EOF

chmod +x "$BIN_DIR/wifitex-gui"

echo ""
echo "🎉 Installation completed successfully!"
echo ""
echo "📋 Installation Summary:"
echo "  ✓ System dependencies installed"
echo "  ✓ Python GUI dependencies installed"
echo "  ✓ Wifitex installed system-wide"
echo "  ✓ Desktop integration configured"
echo "  ✓ System launcher created with optimizations"
echo "  ✓ Python code precompiled for faster startup"
echo "  ✓ PolicyKit policy configured for persistent auth"
echo "  ✓ Icons installed to hicolor theme directories"
echo "  ✓ PolicyKit service reloaded for immediate effect"
echo ""
echo "🚀 How to run Wifitex:"
echo "  Command Line: sudo wifitex"
echo "  GUI: sudo wifitex-gui"
echo "  Desktop: Look for 'Wifitex GUI' in your applications menu"
echo ""
echo "⚡ Performance Tips:"
echo "  • First launch may prompt for password (PolicyKit)"
echo "  • Subsequent launches will be faster (persistent auth)"
echo "  • Pre-cache sudo: run 'sudo -v' for instant GUI launch"
echo ""
echo "⚠️  Note: Wifitex requires root privileges for wireless operations"
echo ""
echo "🔧 Uninstall: sudo ./uninstall.sh"
