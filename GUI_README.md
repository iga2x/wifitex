# Wifitex GUI - Installation and Usage Guide

## Overview

Wifitex GUI provides a modern, user-friendly graphical interface for the Wifitex wireless network auditing tool. Built with PyQt6, it offers an intuitive way to perform wireless security assessments without needing to remember complex command-line arguments.

## Features

- **Modern GUI Interface**: Clean, dark-themed interface built with PyQt6
- **Real-time Network Scanning**: Live network discovery with automatic updates
- **Attack Management**: Easy-to-use attack controls with progress tracking
- **Tool Status Monitoring**: Real-time status of required tools and dependencies
- **Logging System**: Comprehensive logging with export capabilities
- **Settings Management**: Persistent configuration with import/export
- **System Integration**: Desktop entry, symlinks, and proper system integration

## Installation

### Quick Installation

```bash
# Clone the repository
git clone https://github.com/iga2x/wifitex.git
cd wifitex

# Run the installer (requires root privileges)
sudo python install.py install
```

### Manual Installation

1. **Install System Dependencies**:
   ```bash
   # For Ubuntu/Debian
   sudo apt update
   sudo apt install aircrack-ng iwconfig tshark reaver bully cowpatty hashcat python3-pip python3-pyqt6 python3-psutil python3-requests
   
   # For CentOS/RHEL/Fedora
   sudo yum install aircrack-ng wireless-tools wireshark reaver python3-pip python3-PyQt6 python3-psutil python3-requests
   
   # For Arch Linux
   sudo pacman -S aircrack-ng wireless_tools wireshark-cli reaver python-pip python-pyqt6 python-psutil python-requests
   ```

2. **Install Python Dependencies**:
   ```bash
   pip install -r requirements-gui.txt
   ```

3. **Install Wifitex**:
   ```bash
   sudo python setup.py install
   ```

### Installation Options

The installer supports several options:

```bash
# Install without GUI
sudo python install.py install --no-gui

# Install without system dependencies
sudo python install.py install --no-deps

# Install without desktop entry
sudo python install.py install --no-desktop

# Install without symlinks
sudo python install.py install --no-symlinks
```

## Usage

### Starting the GUI

After installation, you can start the GUI in several ways:

1. **Command Line**:
   ```bash
   sudo wifitex-gui
   ```

2. **Desktop Entry**: Look for "Wifitex GUI" in your applications menu

3. **From Source**:
   ```bash
   sudo python wifitex-gui
   ```

4. **Using the Main Script**:
   ```bash
   sudo wifitex --gui
   ```

### GUI Interface Overview

#### Main Window Components

1. **Left Panel - Controls**:
   - Network Interface Selection
   - Scan Controls and Options
   - Network List (Results)
   - Attack Configuration
   - Attack Controls

2. **Right Panel - Information**:
   - **Logs Tab**: Real-time application logs
   - **Status Tab**: Progress indicators and system status
   - **Settings Tab**: Configuration options

#### Basic Workflow

1. **Select Interface**: Choose your wireless interface from the dropdown
2. **Configure Scan**: Set channel, frequency band, and other options
3. **Start Scan**: Click "Start Scan" to discover networks
4. **Select Targets**: Click on networks in the list to select them
5. **Configure Attack**: Choose attack type and options
6. **Start Attack**: Click "Start Attack" to begin the attack

#### Attack Types

- **Auto (Recommended)**: Automatically chooses the best attack method
- **WPS Pixie Dust**: Offline brute-force attack on WPS
- **WPS PIN**: Online brute-force PIN attack
- **WPA Handshake**: Capture and crack WPA handshakes
- **PMKID**: Capture and crack PMKID hashes
- **WEP**: Various WEP attacks (replay, chopchop, fragment, etc.)

#### Advanced Options

- **Deauth Packets**: Send deauthentication packets to clients
- **Random MAC**: Use random MAC addresses
- **Auto-crack**: Automatically attempt to crack captured data

## Configuration

### Settings Management

The GUI automatically saves your settings and restores them on startup. Settings include:

- Default network interface
- Scan preferences (channel, frequency band)
- Attack preferences (timeouts, options)
- Display preferences

### Configuration Files

- **GUI Settings**: `~/.config/wifitex/config.json`
- **Qt Settings**: `~/.config/Wifitex/GUI.conf`
- **Log Files**: `/tmp/wifitex_gui.log`

## Troubleshooting

### Common Issues

1. **"Root privileges required"**:
   - Run the GUI with `sudo wifitex-gui`
   - Ensure you have proper sudo permissions

2. **"PyQt6 not found"**:
   - Install GUI dependencies: `pip install -r requirements-gui.txt`
   - For system-wide installation: `sudo pip install -r requirements-gui.txt`

3. **"No wireless interfaces found"**:
   - Check if you have a wireless card: `iwconfig`
   - Ensure wireless drivers are installed
   - Try running: `sudo airmon-ng`

4. **"Missing tools"**:
   - Install required tools using your package manager
   - Run the dependency checker from the Tools menu

5. **GUI doesn't start**:
   - Check system requirements (Linux, Python 3.6+)
   - Ensure X11 or Wayland is running
   - Check for display environment variables

### Dependency Check

The GUI includes a built-in dependency checker:

1. Go to **Tools** → **Check Dependencies**
2. Review the status of all required components
3. Install missing dependencies as needed

### Log Analysis

Check the logs for detailed error information:

1. Go to the **Logs** tab in the GUI
2. Look for error messages in red
3. Export logs for detailed analysis

## Uninstallation

### Complete Uninstallation

```bash
sudo python install.py uninstall
```

### Manual Uninstallation

```bash
# Remove desktop entry
sudo rm -f /usr/share/applications/wifitex-gui.desktop

# Remove icon
sudo rm -f /usr/share/pixmaps/wifitex-*.png

# Remove symlinks
sudo rm -f /usr/local/bin/wifitex-gui

# Remove installation directory
sudo rm -rf /usr/local/wifitex

# Update desktop database
sudo update-desktop-database /usr/share/applications
```

## Development

### Building from Source

1. **Clone Repository**:
   ```bash
   git clone https://github.com/iga2x/wifitex.git
   cd wifitex
   ```

2. **Install Development Dependencies**:
   ```bash
   pip install -r requirements-gui.txt
   pip install -r requirements-dev.txt  # If available
   ```

3. **Run in Development Mode**:
   ```bash
   sudo python wifitex-gui
   ```

### GUI Architecture

The GUI is built using a modular architecture:

- **main_window.py**: Main application window and event handling
- **components.py**: Reusable GUI components
- **styles.py**: Theme and styling definitions
- **utils.py**: Utility functions and system integration

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Security Considerations

- **Root Privileges**: Wifitex requires root privileges for wireless operations
- **Legal Compliance**: Only use on networks you own or have explicit permission to test
- **Responsible Disclosure**: Report vulnerabilities through proper channels
- **Educational Use**: This tool is for educational and authorized testing purposes only

## Support

- **Issues**: Report bugs and request features on GitHub
- **Documentation**: Check the main README.md for additional information
- **Community**: Join discussions on the project's GitHub page

## License

This project is licensed under the GNU GPLv2 License - see the LICENSE file for details.

## Acknowledgments

- Original Wifitex project by iga2x
- PyQt6 framework for the GUI
- Aircrack-ng suite for wireless security tools
- Open source community for various dependencies
