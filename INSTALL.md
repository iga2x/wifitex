# Wifitex Installation Guide

This guide will help you install Wifitex with proper desktop integration and all necessary components.

## 🚀 Quick Installation

### Method 1: Automated Installation (Recommended)

```bash
# Download and extract Wifitex
cd /path/to/wifitex-master

# Run the installation script
sudo ./install.sh
```

### Method 2: Manual Installation

```bash
# Install system dependencies
sudo apt update
sudo apt install -y python3-dev python3-pip aircrack-ng tshark reaver bully cowpatty hashcat hcxtools macchanger wireless-tools net-tools iw

# Install Python GUI dependencies
sudo pip3 install PyQt6

# Install Wifitex
sudo pip3 install -e .
```

## 🔧 Installation Components

The installation script will install:

- ✅ **Wifitex Python Package** - Core functionality
- ✅ **System Dependencies** - Required tools (aircrack-ng, hashcat, etc.)
- ✅ **GUI Dependencies** - PyQt6 for graphical interface
- ✅ **Desktop Integration** - Application menu entry and desktop shortcut
- ✅ **System Launcher** - Proper launcher with Qt fixes
- ✅ **Icons** - Application icons in multiple sizes
- ✅ **Documentation** - User manuals and guides
- ✅ **Man Pages** - Command-line help

## 🖥️ Desktop Integration

After installation, you can launch Wifitex in several ways:

### GUI (Recommended)
- **Applications Menu**: Look for "Wifitex GUI" in your applications
- **Desktop Shortcut**: Double-click the desktop icon
- **Command Line**: `sudo wifitex-gui`

### Command Line
- **Direct Command**: `sudo wifitex`
- **With Options**: `sudo wifitex --wpa --dict /path/to/wordlist.txt`

## 🔍 Verification

Test your installation:

```bash
# Run the installation test
sudo python3 test_install.py
```

This will verify:
- ✅ Python modules can be imported
- ✅ Command-line tools are available
- ✅ Desktop integration is working
- ✅ Dependencies are installed

## 🗑️ Uninstallation

To remove Wifitex completely:

```bash
sudo ./uninstall.sh
```

This will remove:
- ✅ Wifitex Python package
- ✅ Desktop integration files
- ✅ System launcher
- ✅ Icons and documentation
- ✅ Man pages

**Note**: System dependencies (aircrack-ng, hashcat, etc.) are not removed as they may be used by other applications.

## 🚨 Important Notes

### Root Privileges Required
Wifitex requires root privileges for wireless operations:

```bash
# Always run as root
sudo wifitex
sudo wifitex-gui
```

### Wireless Interface Setup
Before scanning, ensure your wireless interface is in monitor mode:

```bash
# Check interfaces
iwconfig

# Enable monitor mode (if needed)
sudo airmon-ng start wlan0
```

### System Requirements
- **OS**: Linux (Ubuntu, Debian, Kali, etc.)
- **Python**: 3.6 or higher
- **Hardware**: Compatible wireless adapter
- **Permissions**: Root access for wireless operations

## 🔧 Troubleshooting

### GUI Won't Start
```bash
# Check Qt dependencies
sudo apt install python3-pyqt6

# Try with Qt fixes
QT_QPA_PLATFORMTHEME="" QT_QPA_PLATFORM="xcb" sudo wifitex-gui
```

### Permission Denied
```bash
# Ensure you're running as root
sudo wifitex-gui

# Check wireless interface permissions
sudo iwconfig
```

### Desktop Icon Missing
```bash
# Update desktop database
sudo update-desktop-database /usr/share/applications/

# Check desktop file
cat /usr/share/applications/wifitex-gui.desktop
```

## 📋 System Dependencies

The following tools are installed automatically:

| Tool | Purpose |
|------|---------|
| **aircrack-ng** | Wireless network scanning and attacks |
| **hashcat** | GPU-accelerated password cracking |
| **hcxtools** | PMKID capture and conversion |
| **reaver** | WPS PIN attacks |
| **bully** | Alternative WPS attacks |
| **tshark** | Wireshark command-line tool |
| **macchanger** | MAC address spoofing |
| **wireless-tools** | Wireless interface management |

## 🎯 Post-Installation

After installation:

1. **Launch GUI**: `sudo wifitex-gui`
2. **Select Interface**: Choose your wireless interface
3. **Enable Monitor Mode**: Use the GUI button or `sudo airmon-ng start wlan0`
4. **Start Scanning**: Click "Start Scan" to find networks
5. **Begin Attacks**: Select networks and choose attack types

## 💡 Tips

- **GPU Acceleration**: Ensure your GPU drivers are installed for faster cracking
- **Wordlists**: Place wordlists in `/usr/share/wordlists/` for easy access
- **Logs**: Check the GUI log viewer for detailed operation logs
- **Updates**: Re-run `sudo ./install.sh` to update Wifitex

## 🆘 Support

If you encounter issues:

1. Run the test script: `sudo python3 test_install.py`
2. Check system requirements
3. Verify wireless adapter compatibility
4. Check logs for error messages
5. Ensure root privileges are available

---

**Happy Hacking!** 🚀
