# Wifitex - Advanced Wireless Network Auditor

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![GitHub](https://img.shields.io/github/stars/iga2x/wifitex.svg)](https://github.com/iga2x/wifitex)

**Wifitex** is a comprehensive wireless security testing tool for Linux, featuring both command-line and modern GUI interfaces. It's a complete rewrite of the original project with enhanced capabilities, better architecture, and modern features.

## 🚀 Key Features

### **Modern Dual Interface**
- **CLI Mode**: Traditional command-line interface for power users
- **GUI Mode**: Modern PyQt6-based graphical interface with dark theme
- **Seamless Integration**: Both interfaces share the same powerful backend

### **Advanced Attack Capabilities**
- **WPS Attacks**: Pixie-Dust and PIN brute-force attacks
- **WPA/WPA2 Attacks**: Handshake capture and PMKID hash extraction
- **Multi-Interface Support**: Parallel interface handling during attacks

### **Enhanced User Experience**
- **Real-time Monitoring**: Live network scanning with automatic updates
- **Progress Tracking**: Detailed attack progress with status indicators
- **Tool Management**: Automatic dependency checking and tool status monitoring
- **Comprehensive Logging**: Exportable logs with filtering capabilities
- **Settings Management**: Persistent configuration with import/export

## 🎯 Attack Methods

Wifitex supports the following methods for retrieving wireless access point passwords:

1. **WPS Pixie-Dust Attack**: Offline brute-force attack against WPS vulnerabilities
2. **WPS PIN Attack**: Online brute-force attack against WPS PIN authentication
3. **WPA Handshake Capture**: 4-way handshake capture and offline cracking
4. **PMKID Hash Capture**: Modern PMKID hash extraction and cracking

> **Note**: WEP (Wired Equivalent Privacy) attacks are not implemented in wifitex. WEP was deprecated in 2004 due to severe security vulnerabilities and is considered obsolete. While aircrack-ng supports WEP cracking, wifitex focuses on modern wireless security testing (WPA/WPA2/WPS/PMKID). WEP attack implementation is planned for future development but is currently not available.

> **Test Files**: Some test files contain WEP network data (`wep-crackable.ivs`, `wep-uncrackable.ivs`) for historical reference and potential future WEP attack implementation testing.

## 🖥️ Supported Operating Systems

**Primary Support:**
- [**Kali Linux**](https://www.kali.org/) (latest version)
- [**ParrotSec**](https://www.parrotsec.org/)

**Secondary Support:**
- Ubuntu/Debian (with latest tool versions)
- CentOS/RHEL/Fedora (with latest tool versions)
- Arch Linux (with latest tool versions)

**Requirements:**
- Python 3.6+
- Wireless card with Monitor Mode and packet injection support
- Latest versions of required security tools

## 📁 Project Structure

Wifitex keeps the CLI, GUI, and shared core modules organized for clarity. A trimmed view of the repository looks like this:

```text
wifitex/
├── bin/                 # Development launch helpers
├── data/                # Desktop entry and PolicyKit definitions
├── docs (*.md)          # Supplemental guides (PMKID, brute force, etc.)
├── icons/               # Application icons packaged at install time
├── tests/               # Pytest suite and capture fixtures
├── wifitex/
│   ├── args.py          # CLI argument parsing
│   ├── attack/          # WPA, WPS, PMKID orchestration
│   ├── gui/             # PyQt6 application entry point and widgets
│   ├── model/           # Data models shared by CLI and GUI
│   ├── tools/           # Wrappers around external binaries
│   ├── util/            # Helpers for processes, scanners, timers, colors
│   └── wordlists/       # Bundled default wordlists
├── install.sh           # System installer script
├── uninstall.sh         # Cleanup script
├── pyproject.toml       # Build metadata (PEP 621)
└── setup.py             # Legacy setuptools entry point
```

> Run `tree -L 2` from the repository root for a full directory listing.

## 🛠️ Required Tools

**Hardware Requirements:**
- Wireless card with Monitor Mode and packet injection support
- See [compatible cards guide](http://www.aircrack-ng.org/doku.php?id=compatible_cards)

**Core Tools (Required):**

| Tool | Purpose | Installation |
|------|---------|--------------|
| `python3` | Python runtime (3.6+) | `sudo apt install python3` |
| `iwconfig` | Wireless device identification | `sudo apt install wireless-tools` |
| `ifconfig` | Network interface management | `sudo apt install net-tools` |
| **Aircrack-ng Suite** | Core wireless security tools | `sudo apt install aircrack-ng` |
| ├─ `airmon-ng` | Monitor mode management | Included in aircrack-ng |
| ├─ `aircrack-ng` | WPA/WPA2 cracking | Included in aircrack-ng |
| ├─ `aireplay-ng` | Packet injection & replay | Included in aircrack-ng |
| ├─ `airodump-ng` | Network scanning & capture | Included in aircrack-ng |
| └─ `packetforge-ng` | Packet crafting | Included in aircrack-ng |

**Optional Tools (Recommended):**

| Tool | Purpose | Installation |
|------|---------|--------------|
| `tshark` | WPS detection & handshake analysis | `sudo apt install tshark` |
| `reaver` | WPS Pixie-Dust & PIN attacks | `sudo apt install reaver` |
| `bully` | Alternative WPS attacks | `sudo apt install bully` |
| `coWPAtty` | Handshake validation | `sudo apt install cowpatty` |
| `hashcat` | Advanced password cracking | `sudo apt install hashcat` |
| `hcxdumptool` | PMKID hash capture | `sudo apt install hcxdumptool` |
| `hcxpcapngtool` (`hcxpcaptool`) | PMKID format conversion | `sudo apt install hcxtools` |

**GUI Dependencies (for GUI mode):**
- `PyQt6` - Modern GUI framework
- `psutil` - System monitoring
- `requests` - HTTP requests
- `netifaces` - Network interface detection
- `watchdog` - File system monitoring
- `qdarkstyle` - Dark theme support
- `qtawesome` - Icon fonts


## 🚀 Quick Start

### **Installation**

Choose your preferred installation method:

#### **1. Quick Installer (Recommended)**
```bash
git clone https://github.com/iga2x/wifitex.git
cd wifitex
sudo ./install.sh
```

#### **2. Pip Installation**
```bash
# CLI only
sudo pip3 install .

# With GUI support
sudo pip3 install .[gui]

# Development install
sudo pip3 install -e .
```

#### **3. Manual Installation**
```bash
# Install dependencies
sudo apt install aircrack-ng python3-pyqt6 python3-pip

# Install Python packages
pip3 install -r requirements-gui.txt

# Install wifitex
sudo python3 setup.py install
```

### **Usage**

#### **Command Line Interface**
```bash
# Method 1: Use the simple launcher (handles sudo automatically)
./run-cli.sh

# Method 2: Basic usage with manual sudo
sudo wifitex

# Method 3: With specific options
sudo wifitex --wps-only --pixie
sudo wifitex --pmkid-only
sudo wifitex --karma --multi-interface
```

#### **Graphical User Interface**
```bash
# Method 1: Use the simple launcher (handles sudo automatically)
./run-gui.sh

# Method 2: Launch GUI with manual sudo
sudo wifitex-gui

# Method 3: From applications menu
# Look for "Wifitex GUI" in your applications
```

### **Uninstallation**
```bash
sudo ./uninstall.sh
```

To also remove local build artifacts in this project directory (fresh slate for reinstall), use:
```bash
sudo ./uninstall.sh --purge-local
```

What gets removed:
- System-wide package, launchers, desktop entries, icons, PolicyKit policy, man pages, app data, site-packages, and caches
- With `--purge-local`: local `build/`, `dist/`, `*.egg-info`, and all `__pycache__/` in this repo

## ✨ Advanced Features

### **Attack Capabilities**
- **PMKID Hash Capture**: Modern hash extraction without client interaction
- **WPS Pixie-Dust Attack**: Offline brute-force against WPS vulnerabilities  
- **WPS PIN Attack**: Online brute-force against WPS PIN authentication
- **WPA Handshake Capture**: Traditional 4-way handshake capture and cracking
- **Multi-Interface Support**: Run multiple interfaces simultaneously

### **User Experience Enhancements**
- **Real-time Network Scanning**: Live updates with automatic refresh
- **Hidden AP Decloaking**: Automatic decloaking during scanning/attacks
- **5GHz Support**: Extended support for 5GHz networks
- **Handshake Validation**: Multi-tool validation (tshark, cowpatty, aircrack-ng)
- **Progress Tracking**: Detailed attack progress with status indicators
- **Comprehensive Logging**: Exportable logs with filtering and search
- **Settings Management**: Persistent configuration with import/export

### **Technical Improvements**
- **Clean Process Management**: No background processes left running
- **Modular Architecture**: Clean separation of concerns with unit tests
- **Enhanced Error Handling**: Comprehensive error handling and recovery
- **Tool Status Monitoring**: Real-time dependency checking
- **Verbose Debugging**: Expandable verbosity levels (`-v`, `-vv`, `-vvv`)
- **Python 3 Only**: Modern Python with type hints and better performance

## 🔄 What's New in Wifitex

**Major Improvements over the original Wifitex project:**

### **🎨 Modern GUI Interface**
- **PyQt6-based GUI**: Modern, responsive interface with dark theme
- **Real-time Monitoring**: Live network scanning with automatic updates
- **Attack Management**: Easy-to-use attack controls with progress tracking
- **Tool Status Dashboard**: Real-time status of all required tools
- **Settings Panel**: Comprehensive configuration management
- **Log Viewer**: Advanced logging with filtering and export capabilities

### **🚀 Enhanced Attack Capabilities**
- **PMKID Support**: Modern hash extraction without client interaction
- **Improved WPS Attacks**: Better tool selection and fallback mechanisms
- **Enhanced WPA Attacks**: Improved handshake capture and validation

### **⚡ Performance & Reliability**
- **Faster Scanning**: Target refresh every second instead of every 5 seconds
- **Better Process Management**: Clean process lifecycle management
- **Improved Error Handling**: Comprehensive error recovery and reporting
- **Enhanced Logging**: Detailed logging with multiple output formats
- **Tool Integration**: Better integration with external security tools

### **🛠️ Developer Experience**
- **Modular Architecture**: Clean separation of CLI, GUI, and core functionality
- **Unit Tests**: Comprehensive test suite for reliable development
- **Type Hints**: Modern Python with comprehensive type annotations
- **Documentation**: Extensive documentation and code comments
- **Easy Installation**: Multiple installation methods with dependency management

## 📸 Screenshots

### **GUI Interface**
Modern PyQt6-based interface with dark theme and real-time monitoring:

![Wifitex GUI Interface](https://i.imgur.com/Q5KSDbg.gif)

### **Attack Examples**

**WPS Pixie-Dust Attack:**
![WPS Pixie-Dust Attack](https://i.imgur.com/Q5KSDbg.gif)

**PMKID Hash Capture:**
![PMKID Attack](https://i.imgur.com/CR8oOp0.gif)

**Hidden AP Decloaking:**
![Hidden AP Attack](https://i.imgur.com/F6VPhbm.gif)

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### **Development Setup**
```bash
# Clone the repository
git clone https://github.com/iga2x/wifitex.git
cd wifitex

# Install in development mode
sudo pip3 install -e .[gui]

# Run tests
python3 -m pytest tests/

# Run GUI in development mode
sudo python3 -m wifitex.gui
```

## 📄 License

This project is licensed under the GNU General Public License v2.0 - see the [LICENSE](LICENSE) file for details.

## ⚠️ Legal Notice

**This tool is for educational and authorized testing purposes only.** 

- Only use on networks you own or have explicit permission to test
- Unauthorized access to wireless networks is illegal in most jurisdictions
- Users are responsible for compliance with local laws and regulations
- The authors are not responsible for any misuse of this software

## 🙏 Acknowledgments

- **Original Wifitex project**: [derv82/wifitex](https://github.com/derv82/wifitex) - The foundation that made this possible
- **Aircrack-ng Suite**: Core wireless security tools
- **PyQt6**: Modern GUI framework
- **Open Source Community**: For various dependencies and contributions

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/iga2x/wifitex/issues)
- **Discussions**: [GitHub Discussions](https://github.com/iga2x/wifitex/discussions)
- **Documentation**: [Wiki](https://github.com/iga2x/wifitex/wiki)

---

**Made with ❤️ by the Wifitex Team**
