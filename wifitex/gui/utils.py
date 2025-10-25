#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Utility functions and classes for the Wifitex GUI

This module contains utility functions for system operations, network management,
configuration handling, and other common tasks.
"""

import os
import sys
import json
import subprocess
import platform
import psutil
import requests
from typing import List, Dict, Optional, Any, Tuple
from pathlib import Path
from datetime import datetime

from PyQt6.QtCore import QStandardPaths, QSettings
from PyQt6.QtWidgets import QMessageBox, QApplication

from .error_handler import handle_errors, NetworkError, InterfaceError, ConfigurationError, ToolError
from .logger import get_logger

logger = get_logger('utils')


class SystemUtils:
    """Utility class for system operations"""
    
    @staticmethod
    def is_root() -> bool:
        """Check if running as root"""
        return os.geteuid() == 0
        
    @staticmethod
    def get_system_info() -> Dict[str, Any]:
        """Get system information"""
        return {
            'platform': platform.system(),
            'platform_version': platform.version(),
            'architecture': platform.architecture()[0],
            'processor': platform.processor(),
            'hostname': platform.node(),
            'python_version': sys.version,
            'is_root': SystemUtils.is_root()
        }
        
    @staticmethod
    @handle_errors(default=[], log_errors=True)
    def get_network_interfaces() -> List[Dict[str, str]]:
        """Get list of network interfaces"""
        interfaces = []
        
        try:
            # Get network interfaces using psutil
            net_if_addrs = psutil.net_if_addrs()
            net_if_stats = psutil.net_if_stats()
            
            for interface, addrs in net_if_addrs.items():
                # Skip loopback and virtual interfaces
                if interface.startswith('lo') or interface.startswith('docker'):
                    continue
                    
                # Get interface status
                stats = net_if_stats.get(interface)
                is_up = stats.isup if stats else False
                
                # Get IP address
                ip_address = None
                for addr in addrs:
                    if addr.family == 2:  # IPv4
                        ip_address = addr.address
                        break
                        
                interfaces.append({
                    'name': interface,
                    'ip_address': ip_address or 'N/A',
                    'status': 'UP' if is_up else 'DOWN',
                    'type': 'Wireless' if 'wlan' in interface or 'wifi' in interface else 'Ethernet'
                })
                
        except Exception as e:
            logger.error(f"Error getting network interfaces: {e}")
            
        return interfaces
        
    @staticmethod
    def get_wireless_interfaces(fast: bool = False) -> List[str]:
        """Get list of wireless interfaces.

        When fast=True, skip slow checks (rfkill, iwlist scan, dmesg, airmon-ng)
        and use shorter timeouts to keep UI refresh snappy.
        """
        interfaces: List[str] = []

        # 1) iwconfig quick probe (shorter timeout in fast mode)
        try:
            result = subprocess.run(['iwconfig'], capture_output=True, text=True, timeout=(0.7 if fast else 2))
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'IEEE 802.11' in line and not line.startswith(' '):
                        iface = line.split()[0]
                        if iface and iface not in interfaces:
                            interfaces.append(iface)
        except Exception as e:
            logger.debug(f"iwconfig method failed: {e}")

        # 2) ip link quick probe (shorter timeout in fast mode)
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=(0.5 if fast else 1))
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ': wl' in line or ': wlan' in line or ': wlp' in line:
                        iface = line.split(':')[1].strip()
                        if iface and iface not in interfaces:
                            interfaces.append(iface)
        except Exception as e:
            logger.debug(f"ip command method failed: {e}")

        # 3) airmon-ng (skip in fast mode due to overhead)
        if not fast:
            try:
                result = subprocess.run(['airmon-ng'], capture_output=True, text=True, timeout=1.0)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if '\t' in line and not line.startswith('PHY') and not line.startswith('Interface'):
                            parts = line.split('\t')
                            if len(parts) >= 2:
                                iface = parts[1].strip()
                                if iface and iface not in interfaces:
                                    interfaces.append(iface)
            except Exception as e:
                logger.debug(f"airmon-ng method failed: {e}")

        # 4) /sys/class/net probe (fast)
        try:
            net_path = '/sys/class/net'
            if os.path.exists(net_path):
                for iface in os.listdir(net_path):
                    if iface.startswith(('wl', 'wlan', 'wlp')):
                        wireless_path = os.path.join(net_path, iface, 'wireless')
                        if os.path.exists(wireless_path) and iface not in interfaces:
                            interfaces.append(iface)
        except Exception as e:
            logger.debug(f"/sys/class/net method failed: {e}")

        # Fallback via psutil
        if not interfaces:
            try:
                for iface in psutil.net_if_addrs().keys():
                    if any(p in iface.lower() for p in ['wlan', 'wifi', 'wlp', 'wlo']):
                        if iface not in interfaces:
                            interfaces.append(iface)
            except Exception as e:
                logger.debug(f"psutil fallback failed: {e}")

        if fast:
            # Light ordering: monitors first
            monitors = [i for i in interfaces if 'mon' in i]
            managed = [i for i in interfaces if 'mon' not in i]
            return monitors + managed

        # Slow path: prioritize by driver (light version, avoids dmesg)
        prioritized_interfaces = SystemUtils.prioritize_interfaces_by_driver_light(interfaces)

        # Sort by mode with reduced timeout
        monitor_interfaces: List[str] = []
        managed_interfaces: List[str] = []
        for iface in prioritized_interfaces:
            try:
                res = subprocess.run(['iwconfig', iface], capture_output=True, text=True, timeout=1.0)
                if res.returncode == 0 and 'Mode:Monitor' in res.stdout:
                    monitor_interfaces.append(iface)
                else:
                    managed_interfaces.append(iface)
            except Exception:
                managed_interfaces.append(iface)

        # Defer deep capability tests to on-demand flows (enable monitor / scan)
        return monitor_interfaces + managed_interfaces
    
    @staticmethod
    def test_interface_compatibility(interfaces: List[str]) -> List[str]:
        """Test interface compatibility for wireless scanning and reorder by working status"""
        if not interfaces:
            return interfaces
        
        # First, check and handle RF-kill blocking
        rfkill_result = SystemUtils.check_and_handle_rfkill()
        if rfkill_result['blocked'] and not rfkill_result['unblocked']:
            logger.warning(f"[INTERFACE] RF-kill blocking detected: {rfkill_result['message']}")
        
        working_interfaces = []
        problematic_interfaces = []
        
        for interface in interfaces:
            try:
                # Test if interface can perform basic scanning
                result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    output = result.stdout.lower()
                    
                    # Check if interface is working
                    if 'ieee 802.11' in output:
                        # Test if interface can scan (even in managed mode)
                        if 'mode:managed' in output:
                            # Try a quick iwlist scan test
                            test_result = subprocess.run(['iwlist', interface, 'scan'], 
                                                       capture_output=True, text=True, timeout=5)
                            if test_result.returncode == 0:
                                working_interfaces.append(interface)
                            else:
                                problematic_interfaces.append(interface)
                        else:
                            # Interface is in monitor mode, assume it works
                            working_interfaces.append(interface)
                    else:
                        problematic_interfaces.append(interface)
                else:
                    problematic_interfaces.append(interface)
                    
            except Exception:
                problematic_interfaces.append(interface)
        
        # Return working interfaces first, then problematic ones
        return working_interfaces + problematic_interfaces
    
    @staticmethod
    def check_and_handle_rfkill() -> Dict[str, Any]:
        """Check RF-kill status and handle blocking if needed"""
        result = {
            'blocked': False,
            'unblocked': False,
            'error': None,
            'message': ''
        }
        
        try:
            # Check RF-kill status
            rfkill_result = subprocess.run(['rfkill', 'list'], capture_output=True, text=True, timeout=5)
            if rfkill_result.returncode != 0:
                result['error'] = "Could not check RF-kill status"
                return result
            
            rfkill_output = rfkill_result.stdout
            result['message'] = "RF-kill status checked"
            
            # Check if wireless interfaces are blocked
            if 'Wireless LAN' in rfkill_output and 'Soft blocked: yes' in rfkill_output:
                result['blocked'] = True
                result['message'] = "Wireless interfaces are blocked by RF-kill"
                
                # Try to unblock
                unblock_result = subprocess.run(['rfkill', 'unblock', 'wifi'], capture_output=True, text=True, timeout=5)
                if unblock_result.returncode == 0:
                    result['unblocked'] = True
                    result['message'] = "RF-kill unblocked successfully"
                else:
                    result['error'] = "Failed to unblock RF-kill - requires root privileges"
                    result['message'] = "RF-kill blocking detected - please run: sudo rfkill unblock wifi"
            else:
                result['message'] = "RF-kill not blocking wireless interfaces"
                
        except subprocess.TimeoutExpired:
            result['error'] = "RF-kill check timed out"
        except Exception as e:
            result['error'] = f"RF-kill check failed: {str(e)}"
        
        return result
    
    @staticmethod
    def prioritize_interfaces_by_driver(interfaces: List[str]) -> List[str]:
        """Prioritize interfaces based on driver quality for wireless scanning"""
        if not interfaces:
            return interfaces
            
        # Driver quality mapping (higher number = better for scanning)
        driver_priority = {
            # Excellent drivers for scanning
            'ath9k': 100,         # Atheros AR9xxx - Excellent scanning
            'rt2800usb': 95,     # Ralink RT2800 - Good scanning
            'rtl8187': 90,       # Realtek RTL8187 - Good scanning
            
            # Good drivers
            'iwlwifi': 85,       # Intel WiFi - Good scanning
            'brcmfmac': 80,     # Broadcom - Good scanning
            'rtw88': 75,        # Realtek RTL88xx - Moderate scanning
            
            # MediaTek drivers (known issues with airodump-ng)
            'mt7921e': 60,      # MediaTek MT7921E - Monitor mode issues
            'mt7922': 60,       # MediaTek MT7922 - Monitor mode issues
            
            # Problematic drivers
            'rtw88_8822bu': 30,  # Realtek RTL8822BU - Limited scanning
            'rtl8821cu': 25,     # Realtek RTL8821CU - Limited scanning
            'rtl8821ae': 20,     # Realtek RTL8821AE - Limited scanning
        }
        
        # Get driver information for each interface
        interface_scores = []
        for interface in interfaces:
            score = 50  # Default score
            driver_name = SystemUtils.get_interface_driver(interface)
            
            if driver_name:
                # Check for exact driver match
                for driver_pattern, priority in driver_priority.items():
                    if driver_pattern in driver_name.lower():
                        score = priority
                        break
                        
            interface_scores.append((interface, score, driver_name))
        
        # Sort by score (highest first)
        interface_scores.sort(key=lambda x: x[1], reverse=True)
        
        # Return prioritized list
        prioritized = [iface[0] for iface in interface_scores]
        
        # Debug output (only show once to avoid log spam)
        if not hasattr(SystemUtils, '_interface_prioritization_logged'):
            logger.debug(f"[INTERFACE] Prioritized interfaces:")
            for iface, score, driver in interface_scores:
                logger.debug(f"  {iface}: {driver} (score: {score})")
            SystemUtils._interface_prioritization_logged = True
            
        return prioritized

    @staticmethod
    def prioritize_interfaces_by_driver_light(interfaces: List[str]) -> List[str]:
        """Lightweight prioritization using only /sys driver info (no dmesg)."""
        if not interfaces:
            return interfaces
        driver_priority = {
            'ath9k': 100,
            'rt2800': 90,
            'rtl8187': 90,
            'iwlwifi': 85,
            'brcmfmac': 80,
            'rtw88': 75,
            'mt7921': 60,
            'mt7922': 60,
        }
        scored = []
        for iface in interfaces:
            driver = SystemUtils._driver_from_sys(iface)
            score = 50
            dl = (driver or '').lower()
            for key, val in driver_priority.items():
                if key in dl:
                    score = val
                    break
            scored.append((iface, score))
        scored.sort(key=lambda x: x[1], reverse=True)
        return [i for i, _ in scored]

    @staticmethod
    def _driver_from_sys(interface: str) -> str:
        try:
            driver_path = f'/sys/class/net/{interface}/device/driver'
            if os.path.exists(driver_path):
                return os.path.basename(os.readlink(driver_path))
        except Exception:
            pass
        return "unknown"
    
    @staticmethod
    def get_interface_driver(interface: str) -> str:
        """Get the driver name for a network interface"""
        try:
            # Try to get driver from /sys/class/net
            driver_path = f'/sys/class/net/{interface}/device/driver'
            if os.path.exists(driver_path):
                driver_name = os.path.basename(os.readlink(driver_path))
                return driver_name
                
            # Try to get from dmesg
            result = subprocess.run(['dmesg'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if interface in line and 'driver' in line.lower():
                        # Extract driver name from dmesg line
                        if 'rtw88' in line:
                            return 'rtw88'
                        elif 'mt7921e' in line:
                            return 'mt7921e'
                        elif 'ath9k' in line:
                            return 'ath9k'
                        elif 'iwlwifi' in line:
                            return 'iwlwifi'
                            
        except Exception as e:
            logger.error(f"Error getting driver for {interface}: {e}")
            
        return "unknown"
    
    @staticmethod
    def get_dynamic_interface_name(base_interface: str, target_mode: str = 'monitor') -> str:
        """Dynamically detect the actual interface name after mode changes"""
        try:
            # Use system detection to find actual interfaces - no hardcoded names
            current_interfaces = SystemUtils.get_wireless_interfaces()
            
            if target_mode == 'monitor':
                # Look for monitor interfaces - prioritize exact matches
                monitor_interfaces = [iface for iface in current_interfaces if 'mon' in iface]
                
                # First try exact match
                for interface in monitor_interfaces:
                    if interface == base_interface:
                        return interface
                
                # Fallback to any monitor interface
                return monitor_interfaces[0] if monitor_interfaces else base_interface
            else:
                # For managed mode, look for non-monitor interfaces
                managed_interfaces = [iface for iface in current_interfaces if 'mon' not in iface]
                
                # First try exact match
                for interface in managed_interfaces:
                    if interface == base_interface:
                        return interface
                
                # Fallback to any managed interface
                return managed_interfaces[0] if managed_interfaces else base_interface
                
        except Exception as e:
            logger.error(f"Error getting dynamic interface name: {e}")
            return base_interface
    
    @staticmethod
    def get_interface_state(interface: str) -> Dict[str, Any]:
        """Get detailed state information for an interface"""
        state = {
            'name': interface,
            'mode': 'unknown',
            'status': 'unknown',
            'frequency': None,
            'essid': None,
            'mac': None,
            'power': None,
            'available': False
        }
        
        # Check if interface exists and is available
        try:
            result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                state['available'] = True
                output = result.stdout
                
                # Extract mode
                if 'Mode:Monitor' in output:
                    state['mode'] = 'monitor'
                elif 'Mode:Managed' in output:
                    state['mode'] = 'managed'
                elif 'Mode:Master' in output:
                    state['mode'] = 'master'
                else:
                    state['mode'] = 'unknown'
                
                # Extract ESSID
                if 'ESSID:' in output:
                    essid_part = output.split('ESSID:')[1].split()[0]
                    if essid_part != 'off/any':
                        state['essid'] = essid_part.strip('"')
                
                # Extract frequency
                if 'Frequency:' in output:
                    freq_part = output.split('Frequency:')[1].split()[0]
                    state['frequency'] = freq_part
                
                # Extract MAC address
                if 'Access Point:' in output:
                    mac_part = output.split('Access Point:')[1].split()[0]
                    if mac_part != 'Not-Associated':
                        state['mac'] = mac_part
                
                # Extract power level
                if 'Power:' in output:
                    power_part = output.split('Power:')[1].split()[0]
                    state['power'] = power_part
                
                # Determine status
                if 'IEEE 802.11' in output:
                    state['status'] = 'active'
                else:
                    state['status'] = 'inactive'
                    
            else:
                state['available'] = False
                
        except Exception as e:
            state['available'] = False
            logger.error(f"Error checking interface {interface}: {e}")
        
        return state
        
    @staticmethod
    def check_command_exists(command: str) -> bool:
        """Check if a command exists in PATH"""
        try:
            subprocess.run(['which', command], capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False
        except Exception:
            return False
    
    @staticmethod
    def check_command_works(command: str, test_args: Optional[List[str]] = None) -> bool:
        """Check if a command exists AND works properly"""
        try:
            # First check if command exists
            if not SystemUtils.check_command_exists(command):
                return False
            
            # Test if command actually works
            if test_args is None:
                test_args = ['--help']
            
            result = subprocess.run(
                [command] + test_args,
                capture_output=True,
                timeout=10
            )
            
            # Command works if it returns 0 or 1 (help usually returns 1)
            return result.returncode in [0, 1]
            
        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False
    
    @staticmethod
    def get_command_status(command: str, test_args: Optional[List[str]] = None) -> Dict[str, Any]:
        """Get detailed status information about a command"""
        status = {
            'exists': False,
            'works': False,
            'error': None,
            'output': None
        }
        
        try:
            # Check if command exists
            status['exists'] = SystemUtils.check_command_exists(command)
            
            if not status['exists']:
                status['error'] = f"Command '{command}' not found in PATH"
                return status
            
            # Test if command works
            if test_args is None:
                test_args = ['--help']
            
            result = subprocess.run(
                [command] + test_args,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            status['works'] = result.returncode in [0, 1]
            status['output'] = result.stderr if result.stderr else result.stdout
            
            if not status['works']:
                status['error'] = f"Command '{command}' failed with return code {result.returncode}"
                if result.stderr:
                    status['error'] += f": {result.stderr.strip()}"
            
        except subprocess.TimeoutExpired:
            status['error'] = f"Command '{command}' timed out"
        except Exception as e:
            status['error'] = f"Error testing '{command}': {str(e)}"
        
        return status
            
    @staticmethod
    def run_command(command: List[str], timeout: int = 30) -> Tuple[int, str, str]:
        """Run a command and return result"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)
            
    @staticmethod
    def get_package_manager() -> Optional[str]:
        """Detect the system's package manager"""
        package_managers = {
            'apt': ['apt', '--version'],
            'yum': ['yum', '--version'],
            'dnf': ['dnf', '--version'],
            'pacman': ['pacman', '--version'],
            'zypper': ['zypper', '--version']
        }
        
        for pm, cmd in package_managers.items():
            if SystemUtils.check_command_exists(pm):
                return pm
                
        return None


class NetworkUtils:
    """Utility class for network operations"""
    
    def __init__(self):
        self.interface = None
        self.monitor_mode = False
        
    def set_interface(self, interface: str):
        """Set the network interface"""
        self.interface = interface
        
        
    def enable_monitor_mode(self, interface: str) -> bool:
        """Enable monitor mode on interface using modern iwconfig approach"""
        try:
            # Check if interface is already in monitor mode
            result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                if 'Mode:Monitor' in result.stdout:
                    self.monitor_mode = True
                    self.interface = interface
                    return True
                elif 'Mode:Managed' in result.stdout:
                    pass  # Continue with enabling monitor mode
                else:
                    pass  # Continue with enabling monitor mode
            else:
                pass  # Continue with enabling monitor mode
            
            # Check and handle RF-kill blocking
            try:
                rfkill_result = subprocess.run(['rfkill', 'list'], capture_output=True, text=True, timeout=3)
                if rfkill_result.returncode == 0:
                    rfkill_output = rfkill_result.stdout
                    # Check if any wireless interfaces are blocked
                    if 'Wireless LAN' in rfkill_output and 'Soft blocked: yes' in rfkill_output:
                        unblock_result = subprocess.run(['rfkill', 'unblock', 'wifi'], capture_output=True, text=True, timeout=5)
                        if unblock_result.returncode != 0:
                            logger.warning("RF-kill is blocking wireless interfaces. Please run: sudo rfkill unblock wifi")
                            return False
                        else:
                            # Wait a moment for the interface to become available
                            import time
                            time.sleep(2)
            except subprocess.TimeoutExpired:
                pass  # Continue anyway
            except Exception:
                pass  # Continue anyway
            
            # First, bring down the interface
            try:
                subprocess.run(['ifconfig', interface, 'down'], capture_output=True, timeout=5)
            except subprocess.TimeoutExpired:
                pass  # Continue anyway
            
            # Set monitor mode using iwconfig
            try:
                result = subprocess.run(['iwconfig', interface, 'mode', 'monitor'], capture_output=True, text=True, timeout=10)
                
                if result.returncode != 0:
                    logger.error(f"Failed to set monitor mode: {result.stderr or result.stdout or 'Unknown error'}")
                    return False
            except subprocess.TimeoutExpired:
                logger.error("Monitor mode setting timed out")
                return False
            
            # Bring the interface back up
            try:
                result = subprocess.run(['ifconfig', interface, 'up'], capture_output=True, text=True, timeout=10)
                
                if result.returncode != 0:
                    print(f"Failed to bring interface up: {result.stderr or result.stdout or 'Unknown error'}")
                    return False
            except subprocess.TimeoutExpired:
                print("Interface up command timed out")
                return False
            
            # Verify monitor mode is enabled
            try:
                verify_result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=5)
                if verify_result.returncode == 0 and 'Mode:Monitor' in verify_result.stdout:
                    self.monitor_mode = True
                    self.interface = interface
                    return True
                else:
                    print("Monitor mode setup completed but verification failed")
                    return False
            except subprocess.TimeoutExpired:
                print("Monitor mode verification timed out")
                return False
                
        except subprocess.CalledProcessError as e:
            print(f"Command failed: {str(e)}")
            return False
        except Exception as e:
            print(f"Error enabling monitor mode: {e}")
            return False
            
    def disable_monitor_mode(self, interface: str) -> bool:
        """Disable monitor mode on interface using modern iwconfig approach"""
        try:
            # First, bring down the interface
            try:
                subprocess.run(['ifconfig', interface, 'down'], capture_output=True, timeout=5)
            except subprocess.TimeoutExpired:
                pass  # Continue anyway
            
            # Set managed mode using iwconfig
            try:
                result = subprocess.run(['iwconfig', interface, 'mode', 'managed'], capture_output=True, text=True, timeout=10)
                
                if result.returncode != 0:
                    print(f"Failed to set managed mode: {result.stderr or result.stdout or 'Unknown error'}")
                    return False
            except subprocess.TimeoutExpired:
                print("Managed mode setting timed out")
                return False
            
            # Bring the interface back up
            try:
                result = subprocess.run(['ifconfig', interface, 'up'], capture_output=True, text=True, timeout=10)
                
                if result.returncode != 0:
                    print(f"Failed to bring interface up: {result.stderr or result.stdout or 'Unknown error'}")
                    return False
            except subprocess.TimeoutExpired:
                print("Interface up command timed out")
                return False
            
            # Verify managed mode is enabled
            try:
                verify_result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=5)
                if verify_result.returncode == 0 and 'Mode:Managed' in verify_result.stdout:
                    self.monitor_mode = False
                    return True
                else:
                    print("Managed mode setup completed but verification failed")
                    return False
            except subprocess.TimeoutExpired:
                print("Managed mode verification timed out")
                return False
                
        except subprocess.CalledProcessError as e:
            print(f"Command failed: {str(e)}")
            return False
        except Exception as e:
            print(f"Error disabling monitor mode: {e}")
            return False
            
    def get_interface_info(self, interface: str) -> Dict[str, str]:
        """Get information about a network interface"""
        info = {
            'name': interface,
            'mode': 'Unknown',
            'channel': 'Unknown',
            'power': 'Unknown',
            'frequency': 'Unknown'
        }
        
        try:
            # Get interface info using iwconfig
            returncode, stdout, stderr = SystemUtils.run_command(['iwconfig', interface])
            
            if returncode == 0:
                lines = stdout.split('\n')
                for line in lines:
                    if 'Mode:' in line:
                        mode = line.split('Mode:')[1].split()[0]
                        info['mode'] = mode
                    elif 'Channel:' in line:
                        channel = line.split('Channel:')[1].split()[0]
                        info['channel'] = channel
                    elif 'Signal level=' in line:
                        power = line.split('Signal level=')[1].split()[0]
                        info['power'] = power
                    elif 'Frequency:' in line:
                        freq = line.split('Frequency:')[1].split()[0]
                        info['frequency'] = freq
                        
        except Exception as e:
            print(f"Error getting interface info: {e}")
            
        return info
        
    def scan_networks(self, interface: str, channel: Optional[int] = None, 
                     five_ghz: bool = False) -> List[Dict[str, Any]]:
        """Scan for wireless networks"""
        networks = []
        
        try:
            # Build airodump command using dynamic temp directory
            import tempfile
            temp_dir = tempfile.gettempdir()
            cmd = ['airodump-ng', interface, '-w', os.path.join(temp_dir, 'wifitex_scan')]
            
            if channel:
                cmd.extend(['-c', str(channel)])
                
            if five_ghz:
                cmd.extend(['--band', 'a'])
                
            # Run scan for a short time
            returncode, stdout, stderr = SystemUtils.run_command(cmd, timeout=10)
            
            if returncode == 0:
                # Parse output to extract network information
                networks = NetworkUtils._parse_airodump_output(stdout)
                
        except Exception as e:
            print(f"Error scanning networks: {e}")
            
        return networks
        
    @staticmethod
    def _parse_airodump_output(output: str) -> List[Dict[str, Any]]:
        """Parse airodump-ng output to extract network information"""
        networks = []
        
        try:
            lines = output.split('\n')
            parsing_networks = True
            
            for line in lines:
                line = line.strip()
                
                # Skip empty lines and headers
                if not line or 'BSSID' in line or 'Station' in line:
                    if 'Station' in line:
                        parsing_networks = False
                    continue
                    
                if parsing_networks and len(line.split()) >= 6:
                    parts = line.split()
                    try:
                        bssid = parts[0]
                        power = int(parts[3])
                        beacons = int(parts[4])
                        essid = ' '.join(parts[5:]) if len(parts) > 5 else 'Hidden'
                        
                        # Extract additional info if available
                        channel = 'Unknown'
                        encryption = 'Unknown'
                        
                        if len(parts) > 6:
                            for part in parts[6:]:
                                if part.isdigit() and int(part) <= 165:
                                    channel = part
                                elif any(enc in part for enc in ['WPA', 'WPS']):
                                    encryption = part
                                    
                        networks.append({
                            'bssid': bssid,
                            'essid': essid,
                            'channel': channel,
                            'power': power,
                            'beacons': beacons,
                            'encryption': encryption,
                            'clients': 0  # Would need separate parsing for clients
                        })
                        
                    except (ValueError, IndexError):
                        continue
                        
        except Exception as e:
            print(f"Error parsing airodump output: {e}")
            
        return networks


class ConfigManager:
    """Configuration manager for the application"""
    
    def __init__(self):
        self.config_dir = Path(QStandardPaths.writableLocation(
            QStandardPaths.StandardLocation.ConfigLocation
        )) / "wifitex"
        self.config_file = self.config_dir / "config.json"
        self.settings = QSettings("Wifitex", "GUI")
        
        # Create config directory if it doesn't exist
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
    def load_settings(self) -> Dict[str, Any]:
        """Load settings from file"""
        settings = {}
        
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    settings = json.load(f)
                    
        except Exception as e:
            print(f"Error loading settings: {e}")
            
        return settings
        
    def save_settings(self, settings: Dict[str, Any]) -> bool:
        """Save settings to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(settings, f, indent=2)
            return True
            
        except Exception as e:
            print(f"Error saving settings: {e}")
            return False
            
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a specific setting"""
        return self.settings.value(key, default)
        
    def set_setting(self, key: str, value: Any) -> None:
        """Set a specific setting"""
        self.settings.setValue(key, value)
        
    def reset_settings(self) -> None:
        """Reset all settings to defaults"""
        self.settings.clear()
        
    def export_settings(self, filename: str) -> bool:
        """Export settings to a file"""
        try:
            settings = self.load_settings()
            with open(filename, 'w') as f:
                json.dump(settings, f, indent=2)
            return True
            
        except Exception as e:
            print(f"Error exporting settings: {e}")
            return False
            
    def import_settings(self, filename: str) -> bool:
        """Import settings from a file"""
        try:
            with open(filename, 'r') as f:
                settings = json.load(f)
                
            return self.save_settings(settings)
            
        except Exception as e:
            print(f"Error importing settings: {e}")
            return False


class DependencyChecker:
    """Check and manage system dependencies"""
    
    # Required tools for basic functionality
    REQUIRED_TOOLS = [
        'iwconfig',           # For identifying wireless devices already in Monitor Mode
        'ifconfig',           # For starting/stopping wireless devices
        'airmon-ng',          # For enumerating and enabling Monitor Mode
        'aircrack-ng',        # For cracking WPA handshake captures
        'aireplay-ng',        # For deauthing access points, replaying capture files
        'airodump-ng',        # For target scanning & capture file generation
        'packetforge-ng'      # For forging capture files
    ]
    
    # Optional but recommended tools
    OPTIONAL_TOOLS = [
        'tshark',             # For detecting WPS networks and inspecting handshake captures
        'reaver',             # For WPS Pixie-Dust & brute-force attacks
        'bully',              # Alternative to Reaver for WPS attacks
        'cowpatty',           # For detecting handshake captures
        'hashcat',            # For cracking PMKID hashes
        'hcxdumptool',        # For capturing PMKID hashes
        'hcxpcapngtool',      # For converting PMKID packet captures (part of hcxtools)
        'hostapd',            # For creating rogue access points (KARMA attack)
        'dnsmasq'             # For DHCP and DNS services (KARMA attack)
    ]
    
    REQUIRED_PYTHON_PACKAGES = [
        'PyQt6', 'psutil', 'requests'
    ]
    
    @classmethod
    def check_all_dependencies(cls) -> Dict[str, Any]:
        """Check all system dependencies"""
        results = {
            'system': cls.check_system_requirements(),
            'tools': cls.check_required_tools(),
            'python_packages': cls.check_python_packages(),
            'permissions': cls.check_permissions(),
            'gpu': cls.check_gpu_support()
        }
        
        return results
    
    @classmethod
    def check_gpu_support(cls) -> Dict[str, Any]:
        """Check GPU support for hashcat (fast version)"""
        try:
            from wifitex.tools.hashcat import Hashcat
            
            gpu_info = {
                'available': False,
                'gpu_name': 'Unknown',
                'cuda_version': 'Unknown',
                'performance': 'Not tested',  # Don't run benchmark on startup
                'hashcat_ready': False
            }
            
            # Check if hashcat is available
            if Hashcat.exists():
                gpu_info['hashcat_ready'] = True
                
                # Quick GPU availability check (no benchmark)
                gpu_info['available'] = Hashcat.has_gpu()
                
                # Get basic GPU info (fast)
                detailed_info = Hashcat.get_gpu_info()
                gpu_info.update(detailed_info)
                
                # Skip performance test on startup - too slow
                # Performance will be tested when needed
            
            return gpu_info
            
        except ImportError:
            return {
                'available': False,
                'gpu_name': 'Unknown',
                'cuda_version': 'Unknown',
                'performance': 'Unknown',
                'hashcat_ready': False
            }
    
    @classmethod
    def test_gpu_performance(cls) -> str:
        """Test GPU performance (call when needed, not on startup)"""
        try:
            from wifitex.tools.hashcat import Hashcat
            
            perf_info = Hashcat.get_performance_info()
            return perf_info.get('wpa_speed', 'Unknown')
        except Exception:
            return 'Error testing'
        
    @classmethod
    def check_system_requirements(cls) -> Dict[str, bool]:
        """Check system requirements"""
        return {
            'is_linux': platform.system() == 'Linux',
            'has_wireless': len(SystemUtils.get_wireless_interfaces()) > 0,
            'has_root': SystemUtils.is_root(),
            'has_package_manager': SystemUtils.get_package_manager() is not None,
            'python_version_ok': cls.check_python_version()
        }
    
    @classmethod
    def check_python_version(cls) -> bool:
        """Check if Python version is compatible (Python 2.7+ or Python 3.6+)"""
        import sys
        version = sys.version_info
        
        # Python 2.7+ or Python 3.6+
        if version.major == 2:
            return version.minor >= 7
        elif version.major == 3:
            return version.minor >= 6
        else:
            return False
        
    @classmethod
    def check_required_tools(cls) -> Dict[str, bool]:
        """Check if required and optional tools are installed"""
        tools_status = {}
        
        # Check required tools
        for tool in cls.REQUIRED_TOOLS:
            tools_status[tool] = SystemUtils.check_command_exists(tool)
            
        # Check optional tools with enhanced testing for critical ones
        for tool in cls.OPTIONAL_TOOLS:
            if tool in ['hostapd', 'dnsmasq']:
                # Test if these tools actually work, not just exist
                tools_status[tool] = SystemUtils.check_command_works(tool)
            else:
                tools_status[tool] = SystemUtils.check_command_exists(tool)
            
        return tools_status
        
    @classmethod
    def check_python_packages(cls) -> Dict[str, bool]:
        """Check if required Python packages are installed"""
        packages_status = {}
        
        for package in cls.REQUIRED_PYTHON_PACKAGES:
            try:
                __import__(package)
                packages_status[package] = True
            except ImportError:
                packages_status[package] = False
                
        return packages_status
        
    @classmethod
    def check_permissions(cls) -> Dict[str, bool]:
        """Check system permissions"""
        return {
            'is_root': SystemUtils.is_root(),
            'can_access_network': True,  # Would need more sophisticated check
            'can_modify_interfaces': SystemUtils.is_root()
        }
        
    @classmethod
    def get_tool_status_details(cls) -> Dict[str, Dict[str, Any]]:
        """Get detailed status information for all tools"""
        tool_details = {}
        
        # Check all tools
        all_tools = cls.REQUIRED_TOOLS + cls.OPTIONAL_TOOLS
        
        for tool in all_tools:
            if tool in ['hostapd', 'dnsmasq']:
                # Get detailed status for critical tools
                tool_details[tool] = SystemUtils.get_command_status(tool)
            else:
                # Simple exists check for other tools
                tool_details[tool] = {
                    'exists': SystemUtils.check_command_exists(tool),
                    'works': SystemUtils.check_command_exists(tool),
                    'error': None if SystemUtils.check_command_exists(tool) else f"Command '{tool}' not found in PATH",
                    'output': None
                }
        
        return tool_details
    
    @classmethod
    def get_missing_dependencies(cls) -> Dict[str, List[str]]:
        """Get list of missing dependencies"""
        results = cls.check_all_dependencies()
        missing = {
            'tools': [],
            'python_packages': [],
            'system': []
        }
        
        # Check tools
        for tool, available in results['tools'].items():
            if not available:
                missing['tools'].append(tool)
                
        # Check Python packages
        for package, available in results['python_packages'].items():
            if not available:
                missing['python_packages'].append(package)
                
        # Check system requirements
        if not results['system']['is_linux']:
            missing['system'].append('Linux operating system required')
        if not results['system']['has_wireless']:
            missing['system'].append('Wireless network interface required')
        if not results['system']['has_root']:
            missing['system'].append('Root privileges required')
        if not results['system']['has_package_manager']:
            missing['system'].append('Package manager required')
        if not results['system']['python_version_ok']:
            missing['system'].append('Python 2.7+ or Python 3.6+ required')
            
        return missing
        
    @classmethod
    def install_missing_tools(cls, tools: List[str]) -> Dict[str, bool]:
        """Install missing tools using package manager"""
        package_manager = SystemUtils.get_package_manager()
        if not package_manager:
            return {tool: False for tool in tools}
            
        results = {}
        
        for tool in tools:
            try:
                if package_manager == 'apt':
                    cmd = ['apt', 'install', '-y', tool]
                elif package_manager == 'yum':
                    cmd = ['yum', 'install', '-y', tool]
                elif package_manager == 'dnf':
                    cmd = ['dnf', 'install', '-y', tool]
                elif package_manager == 'pacman':
                    cmd = ['pacman', '-S', '--noconfirm', tool]
                else:
                    results[tool] = False
                    continue
                    
                returncode, stdout, stderr = SystemUtils.run_command(cmd)
                results[tool] = returncode == 0
                
            except Exception:
                results[tool] = False
                
        return results


class UpdateChecker:
    """Check for application updates"""
    
    VERSION_URL = "https://api.github.com/repos/iga2x/wifitex/releases/latest"
    
    @classmethod
    def check_for_updates(cls) -> Dict[str, Any]:
        """Check for available updates"""
        try:
            response = requests.get(cls.VERSION_URL, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    'available': True,
                    'version': data.get('tag_name', 'Unknown'),
                    'download_url': data.get('html_url', ''),
                    'release_notes': data.get('body', '')
                }
            else:
                return {'available': False, 'error': 'Failed to fetch update info'}
                
        except Exception as e:
            return {'available': False, 'error': str(e)}
            
    @classmethod
    def get_current_version(cls) -> str:
        """Get current application version"""
        try:
            # Try to get version from wifitex config
            try:
                from ..config import Configuration
                return Configuration.version
            except ImportError:
                return "Unknown"
        except ImportError:
            return "Unknown"


class LogManager:
    """Manage application logging"""
    
    def __init__(self, log_file: Optional[str] = None):
        # Use dynamic temp directory for log file
        import tempfile
        temp_dir = tempfile.gettempdir()
        self.log_file = log_file or os.path.join(temp_dir, 'wifitex_gui.log')
        self.log_entries = []
        
    def log(self, message: str, level: str = "INFO"):
        """Add a log entry"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = {
            'timestamp': timestamp,
            'level': level,
            'message': message
        }
        
        self.log_entries.append(entry)
        
        # Write to file
        try:
            with open(self.log_file, 'a') as f:
                f.write(f"[{timestamp}] [{level}] {message}\n")
        except Exception as e:
            print(f"Error writing to log file: {e}")
            
    def get_logs(self, level: Optional[str] = None) -> List[Dict[str, str]]:
        """Get log entries"""
        if level:
            return [entry for entry in self.log_entries if entry['level'] == level]
        return self.log_entries
        
    def clear_logs(self):
        """Clear all log entries"""
        self.log_entries.clear()
        try:
            with open(self.log_file, 'w') as f:
                f.write("")
        except (OSError, IOError) as e:
            # Log file clear failed - this is not critical
            print(f"Warning: Could not clear log file {self.log_file}: {e}")
            pass
