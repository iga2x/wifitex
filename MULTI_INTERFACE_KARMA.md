# Multi-Interface KARMA Attack Support

## Overview

The KARMA attack has been enhanced to support multiple WiFi devices/interfaces, allowing for more sophisticated and effective Evil Twin attacks. This enhancement addresses scenarios where users have multiple WiFi adapters or want to run multiple Evil Twin access points simultaneously.

## Key Features

### 🔍 **Automatic Interface Detection**
- Automatically detects all available wireless interfaces
- Uses both `iwconfig` and `airmon-ng` for comprehensive detection
- Handles interfaces in different modes (monitor/managed)

### 🎯 **Smart Interface Selection**
- **Probe Interface**: Prefers monitor mode interfaces for optimal probe request capture
- **Rogue Interface**: Prefers managed mode interfaces for optimal AP functionality
- **Automatic Conflict Resolution**: Ensures probe and rogue interfaces are different when possible

### 🚀 **Multiple Evil Twin APs**
- Can run up to 4 Evil Twin access points simultaneously
- Each AP runs on a different interface
- Unique SSID generation for each AP (e.g., `TargetNetwork_AP1`, `TargetNetwork_AP2`)
- Independent process management for each AP

### ⚙️ **Flexible Configuration**
- User-specified interfaces via command line arguments
- Automatic fallback to best available interfaces
- Support for mixed interface modes

## Interface Scenarios

### **Single Interface Scenario**
```
Available: wlan0mon
Configuration:
  - Probe Interface: wlan0mon (monitor mode)
  - Rogue Interface: wlan0mon (will switch to managed mode)
  - Additional APs: None
```
**Note**: May cause conflicts - consider using different interfaces

### **Dual Interface Scenario** (Optimal)
```
Available: wlan0mon, wlan1
Configuration:
  - Probe Interface: wlan0mon (monitor mode)
  - Rogue Interface: wlan1 (managed mode)
  - Additional APs: None
```
**Benefits**: Optimal setup with no conflicts

### **Multi-Interface Scenario** (Advanced)
```
Available: wlan0mon, wlan1, wlan2, wlan3
Configuration:
  - Probe Interface: wlan0mon (monitor mode)
  - Rogue Interface: wlan1 (managed mode)
  - Additional APs: wlan2, wlan3 (up to 3 additional APs)
```
**Benefits**: Maximum coverage with multiple Evil Twin APs

## Usage

### **Automatic Interface Selection**
```bash
# KARMA attack will automatically detect and configure interfaces
sudo python -m wifitex.gui
# Select KARMA attack - interfaces will be auto-configured
```

### **Manual Interface Specification**
```bash
# Specify probe interface for capturing probe requests
sudo python -m wifitex.gui --karma-probe-interface wlan0mon

# Specify rogue interface for hosting Evil Twin AP
sudo python -m wifitex.gui --karma-rogue-interface wlan1

# Specify both interfaces
sudo python -m wifitex.gui --karma-probe-interface wlan0mon --karma-rogue-interface wlan1
```

### **Command Line Arguments**
- `--karma-probe-interface`: Interface for capturing probe requests
- `--karma-rogue-interface`: Interface for hosting Evil Twin AP
- Both arguments are optional - automatic selection if not specified

## Technical Implementation

### **Interface Detection Process**
1. **iwconfig Detection**: Scans for IEEE 802.11 interfaces
2. **airmon-ng Detection**: Additional interface discovery
3. **Mode Detection**: Determines monitor/managed mode for each interface
4. **Conflict Resolution**: Ensures optimal interface assignment

### **Interface Selection Logic**
```python
# Probe Interface Selection (prefer monitor mode)
if monitor_interfaces:
    probe_interface = monitor_interfaces[0]  # Best for capture
elif managed_interfaces:
    probe_interface = managed_interfaces[0]   # Fallback

# Rogue Interface Selection (prefer managed mode)
if managed_interfaces:
    rogue_interface = managed_interfaces[0]   # Best for AP
elif monitor_interfaces:
    rogue_interface = monitor_interfaces[0]   # Will switch to managed
```

### **Multiple AP Management**
- Each additional AP runs in a separate process
- Unique hostapd configuration files for each interface
- Independent SSID generation (e.g., `TargetNetwork_AP1`, `TargetNetwork_AP2`)
- Comprehensive cleanup of all processes

## Configuration Examples

### **Example 1: Single Interface**
```bash
# Available interfaces: wlan0mon
sudo python -m wifitex.gui

# Output:
# [+] Found 1 wireless interfaces: wlan0mon
# [+] Selected probe interface: wlan0mon (monitor mode)
# [+] Selected rogue interface: wlan0mon (monitor mode - will switch to managed)
# [!] Probe and rogue interfaces are the same - selecting different interfaces
```

### **Example 2: Dual Interface**
```bash
# Available interfaces: wlan0mon, wlan1
sudo python -m wifitex.gui

# Output:
# [+] Found 2 wireless interfaces: wlan0mon, wlan1
# [+] Selected probe interface: wlan0mon (monitor mode)
# [+] Selected rogue interface: wlan1 (managed mode)
# [+] No interface conflicts: using different interfaces
```

### **Example 3: Multi-Interface**
```bash
# Available interfaces: wlan0mon, wlan1, wlan2, wlan3
sudo python -m wifitex.gui

# Output:
# [+] Found 4 wireless interfaces: wlan0mon, wlan1, wlan2, wlan3
# [+] Selected probe interface: wlan0mon (monitor mode)
# [+] Selected rogue interface: wlan1 (managed mode)
# [+] Found 2 additional interfaces for multiple APs: wlan2, wlan3
# [+] Starting additional Evil Twin APs on multiple interfaces...
# [+] Evil Twin 1 started successfully on wlan2
# [+] Evil Twin 2 started successfully on wlan3
# [+] Successfully started 2 additional Evil Twin APs
# [+] Total Evil Twin APs running: 3
```

## Benefits of Multi-Interface Support

### **Enhanced Coverage**
- Multiple Evil Twin APs increase chances of victim connection
- Different interfaces can target different frequency bands
- Reduced interference between probe capture and AP hosting

### **Improved Performance**
- Dedicated interfaces for specific tasks
- No mode switching conflicts
- Better resource utilization

### **Advanced Attack Scenarios**
- Simultaneous attacks on multiple networks
- Different SSIDs on different interfaces
- Coordinated deauthentication and AP hosting

### **Flexibility**
- Works with any number of interfaces (1-4+)
- Automatic optimization based on available hardware
- User override capabilities

## Troubleshooting

### **Common Issues**

#### **No Interfaces Found**
```bash
# Check if wireless interfaces are available
iwconfig
airmon-ng

# Ensure interfaces are not blocked
rfkill list
sudo rfkill unblock wifi
```

#### **Interface Mode Conflicts**
```bash
# Check interface modes
iwconfig

# Switch interface to managed mode
sudo iwconfig wlan0mon mode managed

# Switch interface to monitor mode
sudo airmon-ng start wlan0
```

#### **Permission Issues**
```bash
# Ensure running as root
sudo python -m wifitex.gui

# Fix tun device permissions
sudo chmod 666 /dev/net/tun
```

### **Testing Multi-Interface Support**
```bash
# Run the multi-interface test script
sudo python3 test_multi_interface_karma.py
```

## Hardware Recommendations

### **Minimum Setup**
- 1 WiFi adapter (will work but with limitations)
- USB WiFi adapter recommended for flexibility

### **Optimal Setup**
- 2 WiFi adapters (one for probe capture, one for AP hosting)
- One adapter in monitor mode, one in managed mode

### **Advanced Setup**
- 3-4 WiFi adapters for maximum coverage
- Mix of USB and internal adapters
- Different frequency bands (2.4GHz and 5GHz)

## Security Considerations

- **Legal Compliance**: Ensure you have permission to test networks
- **Interface Management**: Properly manage multiple interfaces to avoid conflicts
- **Process Cleanup**: All processes are automatically cleaned up on exit
- **Resource Usage**: Multiple APs consume more system resources

## Future Enhancements

- **Dynamic Interface Assignment**: Automatic interface switching based on performance
- **Frequency Band Optimization**: Automatic selection of optimal channels
- **Load Balancing**: Distribute clients across multiple APs
- **Advanced Monitoring**: Real-time interface performance monitoring

The multi-interface KARMA attack provides a powerful and flexible solution for sophisticated WiFi security testing scenarios, automatically handling the complexities of multiple device management while providing optimal performance and coverage.
