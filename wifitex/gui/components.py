#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
GUI Components for Wifitex

This module contains reusable GUI components for the Wifitex interface.
"""

import os
import subprocess
import threading
import time
import re
from typing import List, Dict, Optional, Any
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
    QPushButton, QProgressBar, QTextEdit, QListWidget,
    QListWidgetItem, QGroupBox, QFrame, QScrollArea, QComboBox,
    QSpinBox, QCheckBox, QFileDialog, QDialog, QDialogButtonBox,
    QMessageBox, QTabWidget, QTextBrowser
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QPropertyAnimation,
    QEasingCurve, QRect
)
from PyQt6.QtGui import QFont, QPixmap, QPainter, QColor, QTextCursor

from .error_handler import handle_errors, NetworkError, InterfaceError, ToolError
from .logger import get_logger

# Import commonly used modules to avoid circular imports and improve performance
try:
    from ..config import Configuration
    from ..util.process import Process
    from ..util.color import Color
    from ..attack.all import AttackAll
    from ..attack.wpa import AttackWPA
    from ..attack.wps import AttackWPS
    from ..attack.pmkid import AttackPMKID
    from ..attack.karma import AttackKARMA
    from ..model.target import Target
    from ..tools.reaver import Reaver
    from ..tools.bully import Bully
except ImportError:
    # Handle import errors gracefully for circular import prevention
    Configuration = None
    Process = None
    Color = None
    AttackAll = None
    AttackWPA = None
    AttackWPS = None
    AttackPMKID = None
    AttackKARMA = None
    Target = None
    Reaver = None
    Bully = None

logger = get_logger('components')


class NetworkScanner(QWidget):
    """Component for network scanning functionality"""
    
    scan_started = pyqtSignal()
    scan_completed = pyqtSignal(list)
    scan_progress = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scanning = False
        self.scan_thread = None
        
    def start_scan(self, interface: str, channel: Optional[int] = None, 
                   five_ghz: bool = False, scan_duration: int = 60):
        """Start network scanning using real Wifitex tools"""
        if self.scanning:
            return
            
        self.scanning = True
        self.scan_started.emit()
        
        # Start scan in separate thread using unified CLI scanning
        self.scan_thread = UnifiedScanWorker(interface, channel, five_ghz, scan_duration)
        self.scan_thread.scan_progress.connect(self.scan_progress.emit)
        self.scan_thread.scan_completed.connect(self.on_scan_completed)
        self.scan_thread.start()
        
    def stop_scan(self):
        """Stop network scanning"""
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.scan_thread.wait(3000)  # Wait up to 3 seconds
            if self.scan_thread.isRunning():
                self.scan_thread.terminate()
                self.scan_thread.wait(1000)  # Wait another second
            
        self.scanning = False
        
    def on_scan_completed(self, networks: List[Dict]):
        """Handle scan completion"""
        self.scanning = False
        self.scan_completed.emit(networks)


class AttackManager(QWidget):
    """Component for managing network attacks"""
    
    attack_started = pyqtSignal(str)  # network ESSID
    attack_completed = pyqtSignal(dict)
    attack_progress = pyqtSignal(dict)
    attack_failed = pyqtSignal(str, str)  # network ESSID, failure reason
    log_message = pyqtSignal(str)  # Real-time log messages
    attack_paused_for_decision = pyqtSignal()  # Signal when attack is paused for user decision
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.attacking = False
        self.attack_thread = None
        self.available_tools = {}
        self.attack_queue = []  # Queue of attacks to perform
        self.current_attack_index = 0
        self.should_skip_current_attack = False  # Flag to skip current attack
        
        # Thread synchronization
        import threading
        self._attack_lock = threading.Lock()  # Protects attack state changes
        self._queue_lock = threading.Lock()   # Protects attack queue access
        
        # Performance metrics
        self.performance_metrics = {
            'total_attacks': 0,
            'successful_attacks': 0,
            'failed_attacks': 0,
            'average_attack_time': 0,
            'attack_times': []
        }
        
    def start_attack(self, networks: List[Dict], attack_type: str, options: Dict):
        """Start attack on one or more networks"""
        with self._attack_lock:
            if self.attacking:
                # If already attacking, stop current attack first
                self.log_message.emit("⚠️ Attack already in progress, stopping current attack...")
                self.stop_attack()
                # Wait a moment for cleanup
                import time
                time.sleep(1)
                
            # Ensure all attack processes are killed before starting new attack
            self._kill_attack_processes()
            
            # Check if required tools are available for this attack type
            failure_reason = self.check_attack_requirements(attack_type)
            if failure_reason:
                self.attack_failed.emit("Multiple networks", failure_reason)
                return
                
            # Validate network data
            for network in networks:
                if not network.get('bssid'):
                    self.attack_failed.emit(network.get('essid', 'Unknown'), "Network BSSID is missing")
                    return
                    
                if not network.get('channel'):
                    self.attack_failed.emit(network.get('essid', 'Unknown'), "Network channel is missing")
                    return
            
            # Set up attack queue with thread safety
            with self._queue_lock:
                self.attack_queue = networks
                self.current_attack_index = 0
                self.attacking = True
                self.should_skip_current_attack = False  # Reset skip flag for new attack
            
            # Start first attack
            self._start_next_attack(attack_type, options)
        
    def set_available_tools(self, tools: Dict[str, bool]):
        """Set the available tools status"""
        self.available_tools = tools
        
    def check_attack_requirements(self, attack_type: str) -> Optional[str]:
        """Check if required tools are available for the attack type"""
        if attack_type.lower() == 'pmkid':
            if not self.available_tools.get('hcxpcapngtool', False):
                return "PMKID attacks require hcxpcapngtool. Install with: sudo apt install hcxtools"
            if not self.available_tools.get('hashcat', False):
                return "PMKID attacks require hashcat. Install with: sudo apt install hashcat"
                
        elif attack_type.lower() == 'wps pin':
            if not self.available_tools.get('reaver', False) and not self.available_tools.get('bully', False):
                return "WPS PIN attacks require reaver or bully. Install with: sudo apt install reaver bully"
                
        elif attack_type.lower() == 'wps pixie dust':
            if not self.available_tools.get('reaver', False) and not self.available_tools.get('bully', False):
                return "WPS Pixie-Dust attacks require reaver or bully. Install with: sudo apt install reaver bully"
                
        elif attack_type.lower() in ['wpa handshake', 'wpa2 handshake']:
            # WPA/WPA2 handshake attacks should work with just aircrack-ng suite
            if not self.available_tools.get('airodump-ng', False):
                return "WPA/WPA2 handshake attacks require airodump-ng. Install with: sudo apt install aircrack-ng"
                
        elif attack_type.lower() == 'auto (recommended)':
            # Auto attack needs at least basic aircrack-ng suite
            if not self.available_tools.get('airodump-ng', False):
                return "Auto attacks require airodump-ng. Install with: sudo apt install aircrack-ng"
            # Note: KARMA attack is not included in Auto mode as it's a different attack methodology
                
        elif attack_type.lower() == 'karma attack':
            # Enhanced KARMA attack requires hostapd, dnsmasq, tshark, aireplay-ng, and aircrack-ng
            missing_tools = []
            if not self.available_tools.get('hostapd', False):
                missing_tools.append('hostapd')
            if not self.available_tools.get('dnsmasq', False):
                missing_tools.append('dnsmasq')
            if not self.available_tools.get('tshark', False):
                missing_tools.append('tshark')
            if not self.available_tools.get('aireplay-ng', False):
                missing_tools.append('aireplay-ng')
            if not self.available_tools.get('aircrack-ng', False):
                missing_tools.append('aircrack-ng')
            
            if missing_tools:
                return f"KARMA attacks require {', '.join(missing_tools)}. Install with: sudo apt install {' '.join(missing_tools)} or run: ./install_karma_deps.sh"
                
        return None
        
    def _start_next_attack(self, attack_type: str, options: Dict):
        """Start the next attack in the queue"""
        if self.current_attack_index >= len(self.attack_queue):
            # No more attacks in queue
            self.attacking = False
            self.attack_completed.emit({
                'success': True,
                'message': 'All attacks completed',
                'network': {'essid': 'All networks', 'bssid': 'N/A'},
                'all_completed': True
            })
            return
            
        # Get current network
        current_network = self.attack_queue[self.current_attack_index]
        self.attack_started.emit(current_network.get('essid', 'Unknown'))
        
        # Reset skip flag for new attack
        self.should_skip_current_attack = False
        
        # Start attack in separate thread
        self.attack_thread = AttackWorker(current_network, attack_type, options)
        self.attack_thread.attack_progress.connect(self.attack_progress.emit)
        self.attack_thread.attack_completed.connect(self.on_attack_completed)
        self.attack_thread.log_message.connect(self.log_message.emit)
        self.attack_thread.terminal_output.connect(self.log_message.emit)  # Capture all terminal output
        self.attack_thread.start()
        
    def stop_attack(self):
        """Stop current attack"""
        with self._attack_lock:
            if self.attack_thread and self.attack_thread.isRunning():
                # Set stop flag first
                if hasattr(self.attack_thread, 'running'):
                    self.attack_thread.running = False
                if hasattr(self.attack_thread, 'skip_current_attack'):
                    self.attack_thread.skip_current_attack = True
                
                # Force cleanup of attack processes
                if hasattr(self.attack_thread, 'force_cleanup'):
                    self.attack_thread.force_cleanup()
                
                # Also kill processes directly
                self._kill_attack_processes()
                
                # Stop the thread
                self.attack_thread.stop()
                self.attack_thread.wait(3000)  # Wait up to 3 seconds
                if self.attack_thread.isRunning():
                    self.attack_thread.terminate()
                    self.attack_thread.wait(1000)  # Wait another second
                
                # Cleanup the attack worker
                if hasattr(self.attack_thread, 'cleanup'):
                    self.attack_thread.cleanup()
                    
            # Always reset attack state when stopping
            self.attacking = False
            
            # Emit attack completed signal to update UI
            self.attack_completed.emit({
                'success': False,
                'message': 'Attack stopped by user',
                'network': {'essid': 'Current attack', 'bssid': 'N/A'},
                'stopped': True,
                'all_completed': True
            })
        
    def skip_current_attack(self):
        """Skip current attack and move to next target"""
        with self._attack_lock:
            if self.attack_thread and self.attack_thread.isRunning():
                # Signal the attack worker to skip current attack
                if hasattr(self.attack_thread, 'skip_current_attack'):
                    self.attack_thread.skip_current_attack = True
                self.should_skip_current_attack = True
                
                # Emit a signal to show that skip was requested
                self.log_message.emit("🔄 Skip requested - stopping current attack...")
                
                # Force cleanup of attack processes immediately
                if hasattr(self.attack_thread, 'force_cleanup'):
                    self.attack_thread.force_cleanup()
                
                # Also kill any running attack processes directly
                self._kill_attack_processes()
                
                # For Auto attacks, don't stop the entire sequence, just skip current attack type
                # For single attacks, stop the entire attack
                if self.attack_thread and hasattr(self.attack_thread, 'attack_type') and self.attack_thread.attack_type == "Auto (Recommended)":
                    # Just signal skip, don't stop the thread - let it continue to next attack type
                    self.log_message.emit("⏭️ Moving to next attack type...")
                    pass
                else:
                    # Stop current attack for non-Auto attacks
                    if self.attack_thread:
                        self.attack_thread.stop()
                        self.attack_thread.wait(3000)  # Wait up to 3 seconds
                        if self.attack_thread.isRunning():
                            self.attack_thread.terminate()
                            self.attack_thread.wait(1000)  # Wait another second
    
    
    
    def _kill_attack_processes(self):
        """Kill all attack processes aggressively"""
        try:
            import subprocess
            import os
            import signal
            
            # Use global process cleanup for all tracked processes
            if Process is not None:
                Process.cleanup_all_processes()
            
            # Kill any remaining attack processes by name - more aggressive approach
            attack_tools = [
                'reaver', 'bully', 'aircrack-ng', 'aireplay-ng', 'airodump-ng', 
                'hcxdumptool', 'hcxpcapngtool', 'hashcat', 'tshark', 'hostapd', 
                'dnsmasq', 'wash', 'pixiewps'
            ]
            
            for tool in attack_tools:
                try:
                    # First try graceful termination
                    subprocess.run(['pkill', '-TERM', '-f', tool], capture_output=True, timeout=2)
                    # Then force kill if still running
                    subprocess.run(['pkill', '-KILL', '-f', tool], capture_output=True, timeout=1)
                    # Also try killing by exact process name
                    subprocess.run(['killall', '-9', tool], capture_output=True, timeout=1)
                except Exception:
                    pass
            
            # Kill any Python processes that might be running attack workers
            try:
                current_pid = os.getpid()
                # Find and kill any Python processes running wifitex attack code
                result = subprocess.run(['pgrep', '-f', 'wifitex.*attack'], capture_output=True, text=True)
                if result.returncode == 0:
                    pids = result.stdout.strip().split('\n')
                    for pid in pids:
                        try:
                            pid_int = int(pid.strip())
                            if pid_int != current_pid:  # Don't kill ourselves
                                os.kill(pid_int, signal.SIGKILL)
                        except (ValueError, ProcessLookupError, PermissionError):
                            pass
            except Exception:
                pass
                
        except Exception as e:
            logger.error(f"Error during process cleanup: {e}")

    def cleanup_all_processes(self):
        """Cleanup all attack processes - call this when GUI is closed"""
        self.log_message.emit("🧹 Cleaning up all attack processes...")
        self._kill_attack_processes()
        
        # Also cleanup any tracked processes
        if hasattr(self, 'attack_thread') and self.attack_thread:
            if hasattr(self.attack_thread, 'force_cleanup'):
                self.attack_thread.force_cleanup()
    
    def pause_attack_for_user_decision(self):
        """Pause attack and ask user what to do next"""
        if self.attack_thread and self.attack_thread.isRunning():
            # Signal the attack worker to pause
            if hasattr(self.attack_thread, 'pause_for_user_decision'):
                self.attack_thread.pause_for_user_decision = True
            
            self.log_message.emit("⏸️ Attack paused - waiting for user decision...")
            
            # Emit a signal that can be caught by the main window to show a dialog
            self.attack_paused_for_decision.emit()
        # Do not auto-advance here; wait for user decision (continue/skip/stop)
        
    def on_attack_completed(self, result: Dict):
        """Handle attack completion with performance tracking"""
        # Add completion timestamp
        result['completed_at'] = time.time()
        
        # Force cleanup of any remaining attack processes
        self._kill_attack_processes()
        
        # Update performance metrics
        self.performance_metrics['total_attacks'] += 1
        if result.get('success', False):
            self.performance_metrics['successful_attacks'] += 1
        else:
            self.performance_metrics['failed_attacks'] += 1
        
        # Calculate success rate
        success_rate = (self.performance_metrics['successful_attacks'] / 
                       self.performance_metrics['total_attacks'] * 100) if self.performance_metrics['total_attacks'] > 0 else 0
        
        # Emit the result
        self.attack_completed.emit(result)
        
        # Log completion status with performance info
        if result.get('success', False):
            self.log_message.emit(f"✅ Attack completed successfully: {result.get('message', 'Unknown success')}")
        else:
            self.log_message.emit(f"❌ Attack failed: {result.get('message', 'Unknown failure')}")
        
        # Log performance metrics
        self.log_message.emit(f"📊 Performance: {success_rate:.1f}% success rate ({self.performance_metrics['successful_attacks']}/{self.performance_metrics['total_attacks']})")
        
        # Check if we should continue with next attack (prevent infinite loops)
        if (not result.get('all_completed', False) and 
            not result.get('all_skipped', False) and 
            not result.get('continue_next', False) and
            self.attacking):
            # Add safety counter to prevent infinite loops
            if not hasattr(self, '_attack_continuation_counter'):
                self._attack_continuation_counter = 0
            self._attack_continuation_counter += 1
            
            # Safety check: prevent infinite loops (max 1000 iterations)
            if self._attack_continuation_counter > 1000:
                self.log_message.emit("⚠️ Safety limit reached, stopping attack queue to prevent infinite loop")
                self.attacking = False
                self.attack_completed.emit({
                    'success': False,
                    'message': 'Attack queue stopped due to safety limit',
                    'network': {'essid': 'All networks', 'bssid': 'N/A'},
                    'all_completed': True
                })
                return
            
            # Move to next attack in queue
            self.current_attack_index += 1
            if self.current_attack_index >= len(self.attack_queue):
                # No more attacks in queue
                self.attacking = False
                self.attack_completed.emit({
                    'success': True,
                    'message': 'All attacks completed',
                    'network': {'essid': 'All networks', 'bssid': 'N/A'},
                    'all_completed': True
                })
            else:
                # Signal to continue with next attack (but only if not already signaled)
                result['continue_next'] = True
                self.log_message.emit("Attack completed, continuing to next target...")
        
        # If attack failed and we're not continuing, ensure proper cleanup
        elif not result.get('success', False) and not result.get('continue_next', False):
            # Attack failed and we're not continuing - ensure cleanup
            self.log_message.emit("Attack failed, ensuring cleanup...")
            self._kill_attack_processes()
            
            # If this was the last attack or we should stop, mark as completed
            if self.current_attack_index >= len(self.attack_queue) - 1:
                self.attacking = False
                result['all_completed'] = True
                self.log_message.emit("All attacks completed (some failed)")


class SettingsPanel(QWidget):
    """Settings panel component"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.config_manager = None
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the settings UI"""
        layout = QVBoxLayout(self)
        
        # General settings
        general_group = QGroupBox("General Settings")
        general_layout = QGridLayout(general_group)
        
        # Interface settings
        general_layout.addWidget(QLabel("Default Interface:"), 0, 0)
        self.interface_combo = QComboBox()
        general_layout.addWidget(self.interface_combo, 0, 1)
        
        # Scan settings
        general_layout.addWidget(QLabel("Scan Duration (seconds):"), 1, 0)
        self.scan_timeout_spin = QSpinBox()
        self.scan_timeout_spin.setRange(0, 600)
        self.scan_timeout_spin.setValue(60)
        self.scan_timeout_spin.setToolTip("How long to scan for networks. Use 0 for continuous scanning until manually stopped.")
        general_layout.addWidget(self.scan_timeout_spin, 1, 1)
        
        # Attack timeouts
        general_layout.addWidget(QLabel("WPA Timeout:"), 2, 0)
        self.wpa_timeout_spin = QSpinBox()
        self.wpa_timeout_spin.setRange(60, 3600)
        self.wpa_timeout_spin.setValue(300)  # 5 minutes instead of 500
        general_layout.addWidget(self.wpa_timeout_spin, 2, 1)
        
        # WPA deauth interval
        general_layout.addWidget(QLabel("WPA Deauth Interval:"), 3, 0)
        self.wpa_deauth_timeout_spin = QSpinBox()
        self.wpa_deauth_timeout_spin.setRange(5, 60)
        self.wpa_deauth_timeout_spin.setValue(20)  # 20 seconds instead of 10
        self.wpa_deauth_timeout_spin.setToolTip("Time between deauth packets (lower = faster attack)")
        general_layout.addWidget(self.wpa_deauth_timeout_spin, 3, 1)
        
        general_layout.addWidget(QLabel("WPS Timeout:"), 4, 0)
        self.wps_timeout_spin = QSpinBox()
        self.wps_timeout_spin.setRange(60, 3600)
        self.wps_timeout_spin.setValue(300)
        general_layout.addWidget(self.wps_timeout_spin, 4, 1)
        
        layout.addWidget(general_group)
        
        # Advanced settings
        advanced_group = QGroupBox("Advanced Settings")
        advanced_layout = QVBoxLayout(advanced_group)
        
        self.verbose_cb = QCheckBox("Verbose Output")
        advanced_layout.addWidget(self.verbose_cb)
        
        self.kill_processes_cb = QCheckBox("Kill Conflicting Processes")
        self.kill_processes_cb.setChecked(True)
        advanced_layout.addWidget(self.kill_processes_cb)
        
        self.random_mac_cb = QCheckBox("Random MAC Address")
        advanced_layout.addWidget(self.random_mac_cb)

        # WPS settings
        wps_group = QGroupBox("WPS Settings")
        wps_layout = QGridLayout(wps_group)

        # Pixie-Dust enable
        wps_layout.addWidget(QLabel("Enable Pixie-Dust:"), 0, 0)
        self.wps_pixie_cb = QCheckBox()
        self.wps_pixie_cb.setChecked(True)
        wps_layout.addWidget(self.wps_pixie_cb, 0, 1)

        # PIN brute enable
        wps_layout.addWidget(QLabel("Enable PIN Brute-Force:"), 1, 0)
        self.wps_pin_cb = QCheckBox()
        self.wps_pin_cb.setChecked(True)
        wps_layout.addWidget(self.wps_pin_cb, 1, 1)

        # Use Bully instead of Reaver
        wps_layout.addWidget(QLabel("Use Bully for PIN:"), 2, 0)
        self.wps_use_bully_cb = QCheckBox()
        self.wps_use_bully_cb.setChecked(False)
        wps_layout.addWidget(self.wps_use_bully_cb, 2, 1)

        # Ignore lock
        wps_layout.addWidget(QLabel("Ignore WPS Lock:"), 3, 0)
        self.wps_ignore_lock_cb = QCheckBox()
        self.wps_ignore_lock_cb.setToolTip("Attempt even if AP reports WPS locked (may be rate-limited)")
        wps_layout.addWidget(self.wps_ignore_lock_cb, 3, 1)

        # PIN timeout
        wps_layout.addWidget(QLabel("WPS PIN Timeout (sec):"), 4, 0)
        self.wps_pin_timeout_spin = QSpinBox()
        self.wps_pin_timeout_spin.setRange(60, 7200)
        self.wps_pin_timeout_spin.setValue(1800)
        wps_layout.addWidget(self.wps_pin_timeout_spin, 4, 1)

        # Fail/timeout thresholds
        wps_layout.addWidget(QLabel("WPS Fail Threshold:"), 5, 0)
        self.wps_fail_thresh_spin = QSpinBox()
        self.wps_fail_thresh_spin.setRange(10, 10000)
        self.wps_fail_thresh_spin.setValue(100)
        wps_layout.addWidget(self.wps_fail_thresh_spin, 5, 1)

        wps_layout.addWidget(QLabel("WPS Timeout Threshold:"), 6, 0)
        self.wps_timeout_thresh_spin = QSpinBox()
        self.wps_timeout_thresh_spin.setRange(10, 10000)
        self.wps_timeout_thresh_spin.setValue(100)
        wps_layout.addWidget(self.wps_timeout_thresh_spin, 6, 1)

        advanced_layout.addWidget(wps_group)
        
        layout.addWidget(advanced_group)
        
        # Cracking settings
        cracking_group = QGroupBox("Password Cracking Settings")
        cracking_layout = QVBoxLayout(cracking_group)
        
        # Cracking strategy
        cracking_layout.addWidget(QLabel("Cracking Strategy:"))
        self.cracking_strategy_combo = QComboBox()
        self.cracking_strategy_combo.addItems([
            "Fast Attack (Small wordlists)",
            "Comprehensive Attack (All wordlists)",
            "Router-Focused Attack (Router defaults)",
            "Custom Strategy"
        ])
        cracking_layout.addWidget(self.cracking_strategy_combo)
        
        # Wordlist selection
        cracking_layout.addWidget(QLabel("Primary Wordlist:"))
        self.wordlist_combo = QComboBox()
        self._populate_wordlist_combo()
        cracking_layout.addWidget(self.wordlist_combo)
        
        # Multi-wordlist option
        self.multi_wordlist_cb = QCheckBox("Use Multiple Wordlists")
        self.multi_wordlist_cb.setChecked(True)
        self.multi_wordlist_cb.setToolTip("Try multiple wordlists in sequence for better success rate")
        cracking_layout.addWidget(self.multi_wordlist_cb)
        
        # Cracking tools
        cracking_layout.addWidget(QLabel("Cracking Tools:"))
        self.aircrack_cb = QCheckBox("Aircrack-ng")
        self.aircrack_cb.setChecked(True)
        cracking_layout.addWidget(self.aircrack_cb)
        
        self.hashcat_cb = QCheckBox("Hashcat")
        self.hashcat_cb.setChecked(True)
        cracking_layout.addWidget(self.hashcat_cb)
        
        layout.addWidget(cracking_group)
        
        # KARMA attack settings
        karma_group = QGroupBox("KARMA Attack Settings")
        karma_layout = QVBoxLayout(karma_group)
        
        # DNS spoofing option
        self.karma_dns_spoofing_cb = QCheckBox("Enable DNS Spoofing (Layer 7)")
        self.karma_dns_spoofing_cb.setChecked(False)  # Changed from True to False
        self.karma_dns_spoofing_cb.setToolTip("Enable DNS redirection for traffic interception. Disable for pure Layer 2 KARMA only.")
        karma_layout.addWidget(self.karma_dns_spoofing_cb)
        
        # Probe timeout
        karma_layout.addWidget(QLabel("Probe Capture Timeout (seconds):"))
        self.karma_probe_timeout_spin = QSpinBox()
        self.karma_probe_timeout_spin.setRange(10, 300)
        self.karma_probe_timeout_spin.setValue(60)
        self.karma_probe_timeout_spin.setToolTip("How long to capture probe requests before starting rogue AP")
        karma_layout.addWidget(self.karma_probe_timeout_spin)
        
        # Minimum probes required
        karma_layout.addWidget(QLabel("Minimum Probes Required:"))
        self.karma_min_probes_spin = QSpinBox()
        self.karma_min_probes_spin.setRange(1, 50)
        self.karma_min_probes_spin.setValue(1)
        self.karma_min_probes_spin.setToolTip("Minimum number of probe requests needed before starting attack")
        karma_layout.addWidget(self.karma_min_probes_spin)
        
        # All channels option
        self.karma_all_channels_cb = QCheckBox("Capture All Channels")
        self.karma_all_channels_cb.setChecked(False)
        self.karma_all_channels_cb.setToolTip("Scan all channels for probe requests (slower but more comprehensive)")
        karma_layout.addWidget(self.karma_all_channels_cb)
        
        layout.addWidget(karma_group)
        
        # Settings management buttons
        settings_buttons = QHBoxLayout()
        self.save_settings_btn = QPushButton("Save Settings")
        self.save_settings_btn.clicked.connect(self.save_settings)
        self.save_settings_btn.setToolTip("Manually save current settings")
        settings_buttons.addWidget(self.save_settings_btn)
        
        self.reset_settings_btn = QPushButton("Reset to Defaults")
        self.reset_settings_btn.clicked.connect(self.reset_to_defaults)
        self.reset_settings_btn.setToolTip("Reset all settings to default values")
        settings_buttons.addWidget(self.reset_settings_btn)
        
        layout.addLayout(settings_buttons)
        
        # Add settings persistence methods
        self.load_default_settings()
        
        # Connect signals to auto-save settings when changed
        self.connect_settings_signals()
        
        # Add stretch to push everything to top
        layout.addStretch()
    
    def set_config_manager(self, config_manager):
        """Set the configuration manager for persistence"""
        self.config_manager = config_manager
        self.load_settings()
    
    def load_default_settings(self):
        """Load default settings if no config manager is available"""
        # Set default values
        self.karma_dns_spoofing_cb.setChecked(False)
        self.karma_probe_timeout_spin.setValue(60)
        self.karma_min_probes_spin.setValue(1)
        self.karma_all_channels_cb.setChecked(False)
    
    def load_settings(self):
        """Load settings from persistent storage"""
        if not self.config_manager:
            return
            
        try:
            settings = self.config_manager.load_settings()
            
            # Load KARMA settings
            if 'karma_dns_spoofing' in settings:
                self.karma_dns_spoofing_cb.setChecked(settings['karma_dns_spoofing'])
            if 'karma_probe_timeout' in settings:
                self.karma_probe_timeout_spin.setValue(settings['karma_probe_timeout'])
            if 'karma_min_probes' in settings:
                self.karma_min_probes_spin.setValue(settings['karma_min_probes'])
            if 'karma_all_channels' in settings:
                self.karma_all_channels_cb.setChecked(settings['karma_all_channels'])
                
            # Load general settings
            if 'scan_timeout' in settings:
                self.scan_timeout_spin.setValue(settings['scan_timeout'])
            if 'wpa_timeout' in settings:
                self.wpa_timeout_spin.setValue(settings['wpa_timeout'])
            if 'wpa_deauth_timeout' in settings:
                self.wpa_deauth_timeout_spin.setValue(settings['wpa_deauth_timeout'])
            if 'wps_timeout' in settings:
                self.wps_timeout_spin.setValue(settings['wps_timeout'])
            if 'verbose' in settings:
                self.verbose_cb.setChecked(settings['verbose'])
            if 'kill_processes' in settings:
                self.kill_processes_cb.setChecked(settings['kill_processes'])
            if 'random_mac' in settings:
                self.random_mac_cb.setChecked(settings['random_mac'])
            if 'use_aircrack' in settings:
                self.aircrack_cb.setChecked(settings['use_aircrack'])
            if 'use_hashcat' in settings:
                self.hashcat_cb.setChecked(settings['use_hashcat'])
            if 'multi_wordlist' in settings:
                self.multi_wordlist_cb.setChecked(settings['multi_wordlist'])
                
        except Exception as e:
            print(f"Error loading settings: {e}")
    
    def save_settings(self):
        """Save current settings to persistent storage"""
        if not self.config_manager:
            return
            
        try:
            settings = {
                # KARMA settings
                'karma_dns_spoofing': self.karma_dns_spoofing_cb.isChecked(),
                'karma_probe_timeout': self.karma_probe_timeout_spin.value(),
                'karma_min_probes': self.karma_min_probes_spin.value(),
                'karma_all_channels': self.karma_all_channels_cb.isChecked(),
                
                # General settings
                'scan_timeout': self.scan_timeout_spin.value(),
                'wpa_timeout': self.wpa_timeout_spin.value(),
                'wpa_deauth_timeout': self.wpa_deauth_timeout_spin.value(),
                'wps_timeout': self.wps_timeout_spin.value(),
                'verbose': self.verbose_cb.isChecked(),
                'kill_processes': self.kill_processes_cb.isChecked(),
                'random_mac': self.random_mac_cb.isChecked(),
                'use_aircrack': self.aircrack_cb.isChecked(),
                'use_hashcat': self.hashcat_cb.isChecked(),
                'multi_wordlist': self.multi_wordlist_cb.isChecked(),
            }
            
            self.config_manager.save_settings(settings)
            
        except Exception as e:
            print(f"Error saving settings: {e}")
    
    def connect_settings_signals(self):
        """Connect signals to auto-save settings when changed"""
        # KARMA settings
        self.karma_dns_spoofing_cb.toggled.connect(self.save_settings)
        self.karma_probe_timeout_spin.valueChanged.connect(self.save_settings)
        self.karma_min_probes_spin.valueChanged.connect(self.save_settings)
        self.karma_all_channels_cb.toggled.connect(self.save_settings)
        
        # General settings
        self.scan_timeout_spin.valueChanged.connect(self.save_settings)
        self.wpa_timeout_spin.valueChanged.connect(self.save_settings)
        self.wpa_deauth_timeout_spin.valueChanged.connect(self.save_settings)
        self.wps_timeout_spin.valueChanged.connect(self.save_settings)
        self.verbose_cb.toggled.connect(self.save_settings)
        self.kill_processes_cb.toggled.connect(self.save_settings)
        self.random_mac_cb.toggled.connect(self.save_settings)
        self.aircrack_cb.toggled.connect(self.save_settings)
        self.hashcat_cb.toggled.connect(self.save_settings)
        self.multi_wordlist_cb.toggled.connect(self.save_settings)
    
    def reset_to_defaults(self):
        """Reset all settings to default values"""
        # Reset KARMA settings
        self.karma_dns_spoofing_cb.setChecked(False)
        self.karma_probe_timeout_spin.setValue(60)
        self.karma_min_probes_spin.setValue(1)
        self.karma_all_channels_cb.setChecked(False)
        
        # Reset general settings
        self.scan_timeout_spin.setValue(60)
        self.wpa_timeout_spin.setValue(300)
        self.wpa_deauth_timeout_spin.setValue(20)
        self.wps_timeout_spin.setValue(300)
        self.verbose_cb.setChecked(False)
        self.kill_processes_cb.setChecked(True)
        self.random_mac_cb.setChecked(False)
        self.aircrack_cb.setChecked(True)
        self.hashcat_cb.setChecked(True)
        self.multi_wordlist_cb.setChecked(True)
        
        # Save the reset settings
        self.save_settings()
    
    def _populate_wordlist_combo(self):
        """Populate the wordlist combo box with available wordlists"""
        try:
            from .wordlist_manager import wordlist_manager
            
            # Get recommended wordlists
            recommended = wordlist_manager.get_recommended_wordlists()
            
            for path, info in recommended:
                display_name = f"{info['name']} ({info['description']})"
                self.wordlist_combo.addItem(display_name, path)
            
            # Add all other wordlists
            all_wordlists = wordlist_manager.get_all_wordlists()
            # Get existing paths once to avoid repeated lookups
            existing_paths = set()
            for i in range(self.wordlist_combo.count()):
                existing_paths.add(self.wordlist_combo.itemData(i))
            
            for path, info in all_wordlists.items():
                # Skip if already added (efficient set lookup)
                if path in existing_paths:
                    continue
                
                display_name = f"{info['name']} ({info['description']})"
                self.wordlist_combo.addItem(display_name, path)
                
        except Exception as e:
            logger.error(f"Error populating wordlist combo: {e}")
            # Fallback to basic wordlist
            try:
                from .path_utils import get_wordlist_path
                fallback_wordlist = get_wordlist_path()
                if fallback_wordlist:
                    self.wordlist_combo.addItem("wordlist-top4800-probable.txt", fallback_wordlist)
                else:
                    # Ultimate fallback
                    self.wordlist_combo.addItem("wordlist-top4800-probable.txt", "wordlist-top4800-probable.txt")
            except Exception as e:
                # Ultimate fallback - log the error but continue
                logger.warning(f"Warning: Failed to load wordlist from path_utils: {e}")
                self.wordlist_combo.addItem("wordlist-top4800-probable.txt", "wordlist-top4800-probable.txt")


class LogViewer(QWidget):
    """Component for viewing logs"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the log viewer UI"""
        layout = QVBoxLayout(self)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        
        # Filter checkboxes
        self.show_scan_cb = QCheckBox("Scan")
        self.show_scan_cb.setChecked(True)
        self.show_scan_cb.setStyleSheet("QCheckBox { color: #3bc9db; }")
        filter_layout.addWidget(self.show_scan_cb)
        
        self.show_attack_cb = QCheckBox("Attacks")
        self.show_attack_cb.setChecked(True)
        self.show_attack_cb.setStyleSheet("QCheckBox { color: #ff922b; }")
        filter_layout.addWidget(self.show_attack_cb)
        
        self.show_error_cb = QCheckBox("Errors")
        self.show_error_cb.setChecked(True)
        self.show_error_cb.setStyleSheet("QCheckBox { color: #ff6b6b; }")
        filter_layout.addWidget(self.show_error_cb)
        
        self.show_success_cb = QCheckBox("Success")
        self.show_success_cb.setChecked(True)
        self.show_success_cb.setStyleSheet("QCheckBox { color: #51cf66; }")
        filter_layout.addWidget(self.show_success_cb)
        
        self.show_info_cb = QCheckBox("Info")
        self.show_info_cb.setChecked(True)
        self.show_info_cb.setStyleSheet("QCheckBox { color: #74c0fc; }")
        filter_layout.addWidget(self.show_info_cb)
        
        filter_layout.addStretch()
        
        # Connect filter changes
        for cb in [self.show_scan_cb, self.show_attack_cb, self.show_error_cb, self.show_success_cb, self.show_info_cb]:
            cb.toggled.connect(self.apply_filters)
        
        layout.addLayout(filter_layout)
        
        # Log display
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Courier", 9))
        self.log_text.setAcceptRichText(True)  # Enable HTML formatting
        layout.addWidget(self.log_text)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.log_text.clear)
        button_layout.addWidget(self.clear_btn)
        
        self.save_btn = QPushButton("Save Log")
        self.save_btn.clicked.connect(self.save_log)
        button_layout.addWidget(self.save_btn)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
    def add_log(self, message: str):
        """Add a log message with color support and filtering"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Check if message should be filtered out
        if not self.should_show_message(message):
            return
        
        # Convert ANSI color codes to HTML
        html_message = self.convert_ansi_to_html(f"[{timestamp}] {message}")
        
        # Use HTML formatting for colors
        self.log_text.append(html_message)
        
        # Auto-scroll to bottom
        cursor = self.log_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.log_text.setTextCursor(cursor)
    
    def should_show_message(self, message: str) -> bool:
        """Check if message should be shown based on current filters"""
        message_lower = message.lower()
        
        # Scan messages - comprehensive filtering for network discovery
        if self.show_scan_cb.isChecked() and any(keyword in message_lower for keyword in [
            'scan', 'found', 'discovered', 'network', 'bssid', 'essid', 'channel', 'signal'
        ]):
            return True
        
        # Attack messages - comprehensive filtering for hackers
        if self.show_attack_cb.isChecked() and any(keyword in message_lower for keyword in [
            'attack', 'wps', 'wpa', 'karma', 'pmkid', 'handshake', 'pin', 'pixie', 
            'cracking', 'brute', 'reaver', 'bully', 'aircrack', 'hashcat', 'deauth',
            'initializing', 'listening', 'trying', 'cracked', 'key', 'password'
        ]):
            return True
        
        # Error messages
        if self.show_error_cb.isChecked() and any(keyword in message_lower for keyword in [
            'error', 'failed', '❌', 'critical', 'denied', 'timeout', 'exception'
        ]):
            return True
        
        # Success messages - comprehensive for hackers
        if self.show_success_cb.isChecked() and any(keyword in message_lower for keyword in [
            'success', 'succeeded', '✅', 'completed successfully', 'cracked', 'found', 
            'captured', 'handshake captured', 'pmkid captured', 'pin found', 'wps cracked',
            'key found', 'password found', 'psk found'
        ]):
            return True
        
        # Info messages
        if self.show_info_cb.isChecked():
            return True
        
        return False
    
    def apply_filters(self):
        """Apply current filters to existing log content"""
        # This would require storing original messages and re-filtering
        # For now, we'll just apply filters to new messages
        pass
    
    def convert_ansi_to_html(self, text: str) -> str:
        """Convert ANSI color codes to HTML formatting with enhanced colors"""
        from .log_formatter import LogFormatter
        return LogFormatter.format_message_for_html(text)
        
    def save_log(self):
        """Save log to file"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Log", "wifitex_gui_log.txt", "Text Files (*.txt)"
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.log_text.toPlainText())
                self.add_log(f"Log saved to {filename}")
            except Exception as e:
                self.add_log(f"Error saving log: {e}")


class ProgressIndicator(QWidget):
    """Component for showing attack progress"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the progress indicator UI"""
        layout = QVBoxLayout(self)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)
        
    def update_progress(self, progress_data: Dict):
        """Update progress display"""
        progress = progress_data.get('progress', 0)
        message = progress_data.get('message', '')
        step = progress_data.get('step', '')
        
        self.progress_bar.setValue(progress)
        self.progress_bar.setVisible(progress > 0)
        
        if step:
            self.status_label.setText(f"{step}: {message}")
        else:
            self.status_label.setText(message)


class StatusDisplay(QWidget):
    """Component for displaying system status"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the status display UI"""
        layout = QGridLayout(self)
        
        # Interface status
        layout.addWidget(QLabel("Interface:"), 0, 0)
        self.interface_status = QLabel("None")
        layout.addWidget(self.interface_status, 0, 1)
        
        # Network count
        layout.addWidget(QLabel("Networks:"), 1, 0)
        self.network_count = QLabel("0")
        layout.addWidget(self.network_count, 1, 1)
        
        # Selected count
        layout.addWidget(QLabel("Selected:"), 2, 0)
        self.selected_count = QLabel("0")
        layout.addWidget(self.selected_count, 2, 1)
        
        # Active attacks
        layout.addWidget(QLabel("Attacks:"), 3, 0)
        self.attack_count = QLabel("0")
        layout.addWidget(self.attack_count, 3, 1)
        
        # Current target
        layout.addWidget(QLabel("Current Target:"), 4, 0)
        self.current_target = QLabel("None")
        layout.addWidget(self.current_target, 4, 1)
        
        # Attack status
        layout.addWidget(QLabel("Status:"), 5, 0)
        self.attack_status = QLabel("Ready")
        layout.addWidget(self.attack_status, 5, 1)
        
    def update_interface_status(self, interface: str, mode: str, power: str, channel: str):
        """Update interface status display"""
        self.interface_status.setText(f"{interface} ({mode})")
        
    def update_network_status(self, total: int, selected: int, attacks: int):
        """Update network status display"""
        self.network_count.setText(str(total))
        self.selected_count.setText(str(selected))
        self.attack_count.setText(str(attacks))
        
    def update_current_target(self, target_name: str):
        """Update current attack target"""
        self.current_target.setText(target_name)
        
    def update_attack_status(self, status: str):
        """Update attack status"""
        self.attack_status.setText(status)


class DependencyWarningDialog(QDialog):
    """Dialog for warning about missing dependencies"""
    
    def __init__(self, dependency_results, tool_details=None, problematic_tools=None, parent=None):
        super().__init__(parent)
        self.dependency_results = dependency_results
        self.tool_details = tool_details or {}
        self.problematic_tools = problematic_tools or []
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the dialog UI"""
        self.setWindowTitle("Missing Dependencies")
        self.setModal(True)
        self.resize(500, 400)
        
        layout = QVBoxLayout(self)
        
        # Warning message
        if self.problematic_tools:
            warning_label = QLabel(
                "Some tools are installed but not working properly. This may cause attacks to fail. "
                "Please check the details below and fix the issues."
            )
        else:
            warning_label = QLabel(
                "Some recommended tools are missing. The application will work with basic functionality, "
                "but some attack methods may not be available."
            )
        warning_label.setWordWrap(True)
        layout.addWidget(warning_label)
        
        # Missing tools list
        missing_group = QGroupBox("Missing Tools")
        missing_layout = QVBoxLayout(missing_group)
        
        self.missing_list = QListWidget()
        for tool, available in self.dependency_results['tools'].items():
            if not available and tool in ['hcxpcapngtool', 'tshark', 'reaver', 'bully', 'cowpatty', 'hashcat', 'hostapd', 'dnsmasq', 'aireplay-ng', 'aircrack-ng']:
                self.missing_list.addItem(tool)
        
        missing_layout.addWidget(self.missing_list)
        layout.addWidget(missing_group)
        
        # Problematic tools list
        if self.problematic_tools:
            problematic_group = QGroupBox("Problematic Tools (Installed but not working)")
            problematic_layout = QVBoxLayout(problematic_group)
            
            self.problematic_list = QListWidget()
            for tool_info in self.problematic_tools:
                item_text = f"{tool_info['tool']}: {tool_info['error']}"
                self.problematic_list.addItem(item_text)
            
            problematic_layout.addWidget(self.problematic_list)
            layout.addWidget(problematic_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.install_btn = QPushButton("Install Missing Tools")
        self.install_btn.clicked.connect(self.install_missing_tools)
        button_layout.addWidget(self.install_btn)
        
        self.continue_btn = QPushButton("Continue Anyway")
        self.continue_btn.clicked.connect(self.accept)
        button_layout.addWidget(self.continue_btn)
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_btn)
        
        layout.addLayout(button_layout)
        
    def install_missing_tools(self):
        """Open tool installation dialog"""
        dialog = ToolInstallationDialog(self.dependency_results, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.accept()


class ToolInstallationDialog(QDialog):
    """Dialog for installing missing tools"""
    
    def __init__(self, dependency_results, parent=None):
        super().__init__(parent)
        self.dependency_results = dependency_results
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the dialog UI"""
        self.setWindowTitle("Install Missing Tools")
        self.setModal(True)
        self.resize(600, 500)
        
        layout = QVBoxLayout(self)
        
        # Instructions
        instructions = QLabel(
            "Select the tools you want to install. The system will attempt to install them using your package manager."
        )
        instructions.setWordWrap(True)
        layout.addWidget(instructions)
        
        # Tools list
        tools_group = QGroupBox("Available Tools")
        tools_layout = QVBoxLayout(tools_group)
        
        self.tools_list = QListWidget()
        self.tools_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        
        missing_tools = []
        for tool, available in self.dependency_results['tools'].items():
            if not available and tool in ['hcxpcapngtool', 'tshark', 'reaver', 'bully', 'cowpatty', 'hashcat', 'hostapd', 'dnsmasq', 'aireplay-ng', 'aircrack-ng']:
                missing_tools.append(tool)
        
        for tool in missing_tools:
            self.tools_list.addItem(tool)
        
        tools_layout.addWidget(self.tools_list)
        layout.addWidget(tools_group)
        
        # Output area
        output_group = QGroupBox("Installation Output")
        output_layout = QVBoxLayout(output_group)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Courier", 9))
        output_layout.addWidget(self.output_text)
        
        layout.addWidget(output_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.install_btn = QPushButton("Install Selected")
        self.install_btn.clicked.connect(self.install_selected_tools)
        button_layout.addWidget(self.install_btn)
        
        self.manual_btn = QPushButton("Manual Installation Guide")
        self.manual_btn.clicked.connect(self.show_manual_installation_guide)
        button_layout.addWidget(self.manual_btn)
        
        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.accept)
        button_layout.addWidget(self.close_btn)
        
        layout.addLayout(button_layout)
        
    def install_selected_tools(self):
        """Install selected tools"""
        selected_items = self.tools_list.selectedItems()
        if not selected_items:
            self.output_text.append("No tools selected.")
            return
            
        package_manager = self.detect_package_manager()
        if not package_manager:
            self.output_text.append("Could not detect package manager.")
            return
            
        self.output_text.append(f"Using package manager: {package_manager}")
        
        for item in selected_items:
            tool = item.text()
            self.output_text.append(f"Installing {tool}...")
            
            if self.install_single_tool(tool, package_manager):
                self.output_text.append(f"✅ {tool} installed successfully")
            else:
                self.output_text.append(f"❌ Failed to install {tool}")
                
    def show_manual_installation_guide(self, tools):
        """Show manual installation guide"""
        guide_text = """
Manual Installation Guide:

Ubuntu/Debian:
sudo apt update
sudo apt install aircrack-ng reaver bully hashcat hcxtools tshark hostapd dnsmasq aireplay-ng

CentOS/RHEL/Fedora:
sudo yum install aircrack-ng reaver bully hashcat hcxtools wireshark hostapd dnsmasq
# or for newer versions:
sudo dnf install aircrack-ng reaver bully hashcat hcxtools wireshark hostapd dnsmasq

Arch Linux:
sudo pacman -S aircrack-ng reaver bully hashcat hcxtools wireshark-cli hostapd dnsmasq

Note: Some tools may not be available in all distributions.
Check your distribution's package manager for available packages.
        """
        
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Manual Installation Guide")
        msg_box.setText(guide_text)
        msg_box.exec()

        self.accept()
        
    def detect_package_manager(self):
        """Detect the system's package manager"""
        import shutil
        
        if shutil.which('apt'):
            return 'apt'
        elif shutil.which('yum'):
            return 'yum'
        elif shutil.which('dnf'):
            return 'dnf'
        elif shutil.which('pacman'):
            return 'pacman'
        elif shutil.which('zypper'):
            return 'zypper'
        else:
            return None
        
    def install_single_tool(self, tool, package_manager):
        """Install a single tool"""
        try:
            if package_manager == 'apt':
                cmd = ['apt', 'install', '-y', tool]
            elif package_manager == 'yum':
                cmd = ['yum', 'install', '-y', tool]
            elif package_manager == 'dnf':
                cmd = ['dnf', 'install', '-y', tool]
            elif package_manager == 'pacman':
                cmd = ['pacman', '-S', '--noconfirm', tool]
            elif package_manager == 'zypper':
                cmd = ['zypper', 'install', '-y', tool]
            else:
                return False
                
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            self.output_text.append(f"Timeout installing {tool}")
            return False
        except Exception as e:
            self.output_text.append(f"Error installing {tool}: {str(e)}")
            return False


class ToolManager(QWidget):
    """Component for managing required tools"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        # Import the dependency checker to get the tool lists
        from .utils import DependencyChecker
        self.required_tools = DependencyChecker.REQUIRED_TOOLS
        self.optional_tools = DependencyChecker.OPTIONAL_TOOLS
        
    def check_required_tools(self) -> List[str]:
        """Check which required tools are missing"""
        missing_tools = []
        
        for tool in self.required_tools:
            if not self.check_tool_exists(tool):
                missing_tools.append(tool)
                
        return missing_tools
        
    def check_tool_exists(self, tool: str) -> bool:
        """Check if a tool exists on the system"""
        try:
            result = subprocess.run(
                ['which', tool], 
                capture_output=True, 
                check=True
            )
            return result.returncode == 0
        except subprocess.CalledProcessError:
            return False
            
    def install_tool(self, tool: str) -> bool:
        """Install a tool (requires package manager)"""
        try:
            # Try different package managers
            package_managers = [
                ['apt', 'install', '-y', tool],
                ['yum', 'install', '-y', tool],
                ['dnf', 'install', '-y', tool],
                ['pacman', '-S', '--noconfirm', tool]
            ]
            
            for cmd in package_managers:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    if result.returncode == 0:
                        return True
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue
                    
            return False
            
        except Exception:
            return False


class UnifiedScanWorker(QThread):
    """Unified scanner that uses CLI logic but displays results in GUI"""
    
    scan_progress = pyqtSignal(dict)
    scan_completed = pyqtSignal(list)
    
    def __init__(self, interface: str, channel: Optional[int] = None, five_ghz: bool = False, scan_duration: int = 60):
        super().__init__()
        self.interface = interface
        self.channel = channel
        self.five_ghz = five_ghz
        self.scan_duration = scan_duration
        self.running = True
        self.airodump = None
        self.targets = []
        self.scan_start_time = None
        
    def stop(self):
        """Stop the scan"""
        self.running = False
        if self.airodump:
            try:
                self.airodump.__exit__(None, None, None)
            except Exception:
                pass
    
    def run(self):
        """Run unified network scan using CLI scanner logic"""
        try:
            # Import CLI scanner components
            from ..tools.airodump import Airodump
            from ..config import Configuration
            import time
            import os
            
            # Check if running as root (required for airodump-ng)
            if os.geteuid() != 0:
                raise Exception("wifiteX requires root privileges for wireless operations. Please run with sudo.")
            
            # Set up configuration for CLI scanner
            Configuration.initialize()
            Configuration.interface = self.interface
            Configuration.target_channel = self.channel
            Configuration.five_ghz = self.five_ghz
            
            # Temporarily disable filtering to get all networks
            original_encryption_filter = Configuration.encryption_filter
            Configuration.encryption_filter = []  # Show all networks
            
            # Force 2.4GHz band scanning (same as CLI)
            Configuration.five_ghz = False
            
            # Basic setup
            try:
                subprocess.run(['rfkill', 'unblock', 'wifi'], capture_output=True, text=True, timeout=3)
                subprocess.run(['rfkill', 'unblock', 'all'], capture_output=True, text=True, timeout=3)
            except Exception:
                pass

            try:
                if self.interface:
                    subprocess.run(['ip', 'link', 'set', self.interface, 'up'], capture_output=True, text=True, timeout=3)
            except Exception:
                pass

            # Permission checks
            self.scan_progress.emit({'message': f'Checking permissions for {self.interface}...'})
            
            result = subprocess.run(['iwconfig', self.interface], capture_output=True, text=True)
            if result.returncode != 0:
                self.scan_progress.emit({
                    'message': f'❌ Interface {self.interface} not found!',
                    'progress': 0
                })
                self.scan_completed.emit([])
                return
                
            if 'Mode:Monitor' not in result.stdout:
                self.scan_progress.emit({
                    'message': f'❌ Interface {self.interface} not in monitor mode!',
                    'progress': 0
                })
                self.scan_completed.emit([])
                return
            
            if os.geteuid() == 0:
                self.scan_progress.emit({'message': 'Running as root - skipping permission test...'})
            else:
                self.scan_progress.emit({'message': f'Testing permissions for {self.interface}...'})
            
            self.scan_progress.emit({'message': f'Starting network scan on {self.interface}...'})
            
            # Use the same Airodump class as CLI scanner with proper settings
            self.airodump = Airodump(
                interface=self.interface,
                channel=self.channel,
                output_file_prefix='wifitex_gui_unified',
                skip_wps=False,  # Enable WPS detection
                delete_existing_files=True  # Clean start
            )
            
            # Debug: Log the command that will be executed
            logger.info(f"[SCAN] Starting airodump on interface: {self.interface}")
            logger.info(f"[SCAN] Channel: {self.channel}, Five GHz: {self.five_ghz}")
            
            # Start the airodump process
            self.airodump.__enter__()
            self.scan_start_time = time.time()
            
            # Debug: Check if airodump process started successfully
            if not self.airodump.pid or self.airodump.pid.poll() is not None:
                # Try to get error details
                if self.airodump.pid:
                    try:
                        # Get stderr output from the Process object's stderr() method
                        stderr_output = self.airodump.pid.stderr()
                        if stderr_output and stderr_output.strip():
                            raise Exception(f"airodump-ng failed: {stderr_output.strip()}")
                    except Exception:
                        pass
                raise Exception("airodump-ng process failed to start or died immediately")
            
            logger.info(f"[SCAN] Airodump process started with PID: {self.airodump.pid.pid}")
            
            # Scan loop - exact same logic as CLI scanner
            scan_iterations = 0
            max_iterations = self.scan_duration if self.scan_duration > 0 else 3600
            
            while self.running:
                if self.airodump.pid.poll() is not None:
                    break
                
                # Get targets using the same method as CLI scanner
                self.targets = self.airodump.get_targets(old_targets=self.targets, apply_filter=True)
                
                # Debug: Check if CSV files exist
                csv_files = self.airodump.find_files(endswith='.csv')
                if csv_files:
                    logger.debug(f"[SCAN] Found CSV files: {csv_files}")
                else:
                    logger.warning(f"[SCAN] No CSV files found after {scan_iterations} iterations")
                
                # Update decloaked status (same as CLI)
                for target in self.targets:
                    if target.bssid in self.airodump.decloaked_bssids:
                        target.decloaked = True
                
                # Convert CLI targets to GUI format
                networks = []
                for target in self.targets:
                    network = {
                        'bssid': target.bssid,
                        'essid': target.essid if target.essid else '<Hidden>',
                        'channel': str(target.channel),
                        'power': str(target.power),
                        'signal_quality': self.calculate_signal_quality(target.power),
                        'encryption': target.encryption,
                        'cipher': 'Unknown',  # CLI Target doesn't have cipher
                        'auth': 'Unknown',    # CLI Target doesn't have auth
                        'speed': 'Unknown',   # CLI Target doesn't have speed
                        'beacons': str(target.beacons),
                        'ivs': str(target.ivs),
                        'lan_ip': 'Unknown',  # CLI Target doesn't have lan_ip
                        'first_seen': 'Unknown',  # CLI Target doesn't have first_seen
                        'last_seen': 'Unknown',   # CLI Target doesn't have last_seen
                        'vendor': self.determine_vendor(target.bssid, target.essid),
                        'network_type': self.classify_network(target.essid, self.determine_vendor(target.bssid, target.essid), target.encryption),
                        'clients': len(target.clients),
                        'wps': 'Yes' if target.wps in [1, 2] else 'No',  # WPSState.UNLOCKED=1, LOCKED=2
                        'client_details': [{'mac': str(c), 'power': 'Unknown'} for c in target.clients],  # CLI clients are just strings
                        'decloaked': getattr(target, 'decloaked', False)  # Include decloaked status
                    }
                    networks.append(network)
                
                # Update decloaked status
                for network in networks:
                    if network['bssid'] in self.airodump.decloaked_bssids:
                        network['decloaked'] = True
                
                # Emit progress update
                target_count = len(self.targets)
                client_count = sum(len(t.clients) for t in self.targets)
                
                progress_msg = f'Scanning... {target_count} networks detected'
                if client_count > 0:
                    progress_msg += f', {client_count} clients'
                if self.airodump.decloaking:
                    progress_msg += ' (decloaking active)'
                
                progress = 0 if self.scan_duration == 0 else int((scan_iterations / self.scan_duration) * 100)
                
                self.scan_progress.emit({
                    'message': progress_msg,
                    'progress': progress,
                    'batch_update': networks
                })
                
                # Check for scan duration limit (same as CLI)
                if self.scan_duration > 0 and time.time() > self.scan_start_time + self.scan_duration:
                    break
                
                # Safety check
                if scan_iterations >= max_iterations:
                    break
                
                time.sleep(1)  # Same timing as CLI scanner
                scan_iterations += 1
            
            # Clean up
            if self.airodump:
                self.airodump.__exit__(None, None, None)
            
            # Restore original configuration
            Configuration.encryption_filter = original_encryption_filter
            
            # Final results
            final_networks = []
            for target in self.targets:
                network = {
                    'bssid': target.bssid,
                    'essid': target.essid if target.essid else '<Hidden>',
                    'channel': str(target.channel),
                    'power': str(target.power),
                    'signal_quality': self.calculate_signal_quality(target.power),
                    'encryption': target.encryption,
                    'cipher': 'Unknown',  # CLI Target doesn't have cipher
                    'auth': 'Unknown',    # CLI Target doesn't have auth
                    'speed': 'Unknown',   # CLI Target doesn't have speed
                    'beacons': str(target.beacons),
                    'ivs': str(target.ivs),
                    'lan_ip': 'Unknown',  # CLI Target doesn't have lan_ip
                    'first_seen': 'Unknown',  # CLI Target doesn't have first_seen
                    'last_seen': 'Unknown',   # CLI Target doesn't have last_seen
                    'vendor': self.determine_vendor(target.bssid, target.essid),
                    'network_type': self.classify_network(target.essid, self.determine_vendor(target.bssid, target.essid), target.encryption),
                    'clients': len(target.clients),
                    'wps': 'Yes' if target.wps in [1, 2] else 'No',  # WPSState.UNLOCKED=1, LOCKED=2
                    'client_details': [{'mac': str(c), 'power': 'Unknown'} for c in target.clients],  # CLI clients are just strings
                    'decloaked': getattr(target, 'decloaked', False)  # Include decloaked status
                }
                final_networks.append(network)
            
            # Emit final results
            final_client_count = sum(len(t.clients) for t in self.targets)
            final_msg = f'Scan stopped. Found {len(final_networks)} networks'
            if final_client_count > 0:
                final_msg += f', {final_client_count} clients'
            
            self.scan_progress.emit({
                'message': final_msg,
                'progress': 100 if self.scan_duration > 0 else 0
            })
            
            self.scan_completed.emit(final_networks)
                
        except Exception as e:
            import traceback
            logger.error(f"[SCAN] Error in unified scanner: {e}")
            logger.error(f"[SCAN] Traceback: {traceback.format_exc()}")
            self.scan_progress.emit({'message': f'Scan error: {str(e)}'})
            self.scan_completed.emit([])
    
    def calculate_signal_quality(self, power_str):
        """Calculate signal quality from power level"""
        try:
            power = int(power_str)
            if power >= -30:
                return "Excellent"
            elif power >= -50:
                return "Good"
            elif power >= -70:
                return "Fair"
            else:
                return "Poor"
        except (ValueError, TypeError):
            return "Unknown"
    
    def determine_vendor(self, bssid, essid):
        """Determine vendor from BSSID"""
        if not bssid:
            return "Unknown"
        
        # Extract OUI (first 3 bytes of MAC)
        try:
            oui = bssid.replace(':', '')[:6].upper()
            # Common vendor OUIs
            vendors = {
                '001122': 'Unknown',
                '000C29': 'VMware',
                '001A70': 'Cisco',
                '001B2F': 'Netgear',
                '001E2A': 'Linksys',
                '0020A6': 'D-Link',
                '001D7E': 'Belkin',
                '001E52': 'TP-Link',
                '001F33': 'Apple',
                '0026BB': 'Apple',
                '001F5B': 'Apple',
                '001E52': 'TP-Link',
                '001A70': 'Cisco',
                '001B2F': 'Netgear',
                '001E2A': 'Linksys',
                '0020A6': 'D-Link',
                '001D7E': 'Belkin',
                '001F33': 'Apple',
                '0026BB': 'Apple',
                '001F5B': 'Apple'
            }
            return vendors.get(oui, "Unknown")
        except:
            return "Unknown"
    
    def classify_network(self, essid, vendor, encryption):
        """Classify network type"""
        if not essid:
            return "Unknown"
        
        essid_lower = essid.lower()
        
        if any(word in essid_lower for word in ['guest', 'public', 'hotspot']):
            return "Public/Guest"
        elif any(word in essid_lower for word in ['corporate', 'enterprise', 'office']):
            return "Corporate"
        elif any(word in essid_lower for word in ['mobile', 'hotspot', 'tether']):
            return "Mobile Hotspot"
        elif vendor == "Apple":
            return "Apple Device"
        elif encryption == "WEP":
            return "Legacy WEP"
        else:
            return "Home/Personal"


class ScanWorker(QThread):
    """Worker thread for network scanning using unified CLI scanner logic"""
    
    scan_progress = pyqtSignal(dict)
    scan_completed = pyqtSignal(list)
    
    def __init__(self, interface: str, channel: Optional[int] = None, five_ghz: bool = False, scan_duration: int = 60):
        super().__init__()
        self.interface = interface
        self.channel = channel
        self.five_ghz = five_ghz
        self.scan_duration = scan_duration
        self.running = True
        self.airodump = None
        self.targets = []
        self.scan_start_time = None
        
    def stop(self):
        """Stop the scan"""
        self.running = False
        if self.airodump:
            try:
                self.airodump.__exit__(None, None, None)
            except Exception:
                pass
    
    def detect_mediatek_driver(self):
        """Detect if the interface is using a MediaTek driver"""
        try:
            # Check driver info
            result = subprocess.run(['lspci', '-v'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                output = result.stdout.lower()
                if 'mediatek' in output or 'mt792' in output or 'mt7921' in output or 'mt7922' in output:
                    return True
            
            # Check dmesg for MediaTek driver loading
            result = subprocess.run(['dmesg'], capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                output = result.stdout.lower()
                if 'mt7921' in output or 'mt7922' in output or 'mediatek' in output:
                    return True
            
            # Check interface driver
            try:
                driver_path = f"/sys/class/net/{self.interface}/device/driver"
                if os.path.exists(driver_path):
                    driver_name = os.path.basename(os.readlink(driver_path))
                    if 'mt7921' in driver_name.lower() or 'mt7922' in driver_name.lower():
                        return True
            except (OSError, IOError) as e:
                # Driver path access failed - this is expected for some interfaces
                pass
                
        except Exception:
            pass
        
        return False
    
    def try_alternative_scan(self):
        """Disabled: airodump-only mode (no alternative scans)."""
        return []
    
    def parse_iwlist_output(self, output):
        """Disabled: airodump-only mode."""
        return []
    
    def parse_nmcli_output(self, output):
        """Disabled: airodump-only mode."""
        return []
    
    def try_managed_mode_scan(self):
        """Disabled: airodump-only mode."""
        return []
    
    def try_alternative_interface(self):
        """Disabled: airodump-only mode."""
        return []
    
    def parse_csv_files_direct(self, csv_file):
        """Parse CSV file directly"""
        import csv
        networks = []
        clients = []
        try:
            with open(csv_file, 'r') as f:
                lines = []
                for line in f:
                    line = line.replace('\0', '')
                    lines.append(line)
                
                csv_reader = csv.reader(lines, delimiter=',', quoting=csv.QUOTE_ALL, skipinitialspace=True)
                
                hit_clients = False
                for row in csv_reader:
                    if len(row) == 0:
                        continue
                    
                    if row[0].strip() == 'BSSID':
                        hit_clients = False
                        continue
                    elif row[0].strip() == 'Station MAC':
                        hit_clients = True
                        continue
                    
                    if not hit_clients and len(row) >= 15:
                        try:
                            bssid = row[0].strip()
                            essid = row[13].strip() if len(row) > 13 else ''
                            channel = row[3].strip() if len(row) > 3 else '0'
                            power = row[8].strip() if len(row) > 8 else '-100'
                            encryption = row[5].strip() if len(row) > 5 else 'Unknown'
                            
                            if not bssid or bssid == '':
                                continue
                            
                            if not essid or essid == '':
                                essid = 'Hidden'
                            
                            network = {
                                'bssid': bssid,
                                'essid': essid,
                                'channel': channel,
                                'power': power,
                                'encryption': encryption,
                                'wps': 'Unknown',
                                'clients': 0,
                                'client_details': [],
                                'vendor': 'Unknown'
                            }
                            
                            networks.append(network)
                            
                        except (IndexError, ValueError):
                            continue
                    
                    elif hit_clients and len(row) >= 6:
                        # Client row
                        try:
                            client_mac = row[0].strip()
                            power = row[3].strip()
                            packets = row[4].strip()
                            bssid = row[5].strip()
                            probed_essids = row[6].strip() if len(row) > 6 else ''
                            
                            if not client_mac or client_mac == '' or client_mac == 'Station MAC':
                                continue
                            
                            # Clean up the data
                            client_mac = client_mac.replace('\0', '').strip()
                            bssid = bssid.replace('\0', '').strip()
                            
                            client = {
                                'mac': client_mac,
                                'power': power,
                                'packets': packets,
                                'bssid': bssid,
                                'probed_essids': probed_essids
                            }
                            
                            clients.append(client)
                            
                        except (IndexError, ValueError):
                            continue
                
                # Associate clients with their networks
                for client in clients:
                    client_bssid = client['bssid']
                    client_mac = client['mac']
                    
                    found_network = False
                    for network in networks:
                        if network['bssid'] == client_bssid:
                            network['clients'] += 1
                            network['client_details'].append({
                                'mac': client['mac'],
                                'power': client['power'],
                                'packets': client['packets'],
                                'probed_essids': client['probed_essids']
                            })
                            found_network = True
                            break
                    
                    if not found_network and 'not associated' not in client_bssid:
                        logger.warning(f"[SCAN] No network found for client {client_mac} with BSSID {client_bssid}")
                
                logger.debug(f"[SCAN] Parsed {len(networks)} networks and {len(clients)} clients from {csv_file}")
                
        except Exception as e:
            logger.error(f"[SCAN] Error parsing CSV file {csv_file}: {e}")
        
        return networks
        
    def run(self):
        """Run the network scan"""
        try:
            # Best-effort: ensure RF-kill is unblocked and interface is up
            try:
                # Unblock Wi‑Fi and all radios (covers cases after KARMA)
                subprocess.run(['rfkill', 'unblock', 'wifi'], capture_output=True, text=True, timeout=3)
                subprocess.run(['rfkill', 'unblock', 'all'], capture_output=True, text=True, timeout=3)
            except Exception:
                pass

            try:
                if self.interface:
                    # Bring interface up in case rfkill or previous attacks left it down
                    subprocess.run(['ip', 'link', 'set', self.interface, 'up'], capture_output=True, text=True, timeout=3)
            except Exception:
                pass

            # Pre-scan permission check
            self.scan_progress.emit({'message': f'Checking permissions for {self.interface}...'})
            
            # Check if interface exists and is in monitor mode
            result = subprocess.run(['iwconfig', self.interface], capture_output=True, text=True)
            if result.returncode != 0:
                self.scan_progress.emit({
                    'message': f'❌ Interface {self.interface} not found!\n\nPlease check:\n1. Interface name is correct\n2. Interface is enabled\n3. Wireless drivers are loaded',
                    'progress': 0
                })
                self.scan_completed.emit([])
                return
                
            if 'Mode:Monitor' not in result.stdout:
                self.scan_progress.emit({
                    'message': f'❌ Interface {self.interface} not in monitor mode!\n\nPlease enable monitor mode first:\n1. Click "Enable Monitor Mode" button\n2. Or run: sudo airmon-ng start {self.interface}',
                    'progress': 0
                })
                self.scan_completed.emit([])
                return
            
            # Quick permission test - try to run a simple airodump command
            self.scan_progress.emit({'message': f'Testing permissions for {self.interface}...'})
            test_cmd = ['airodump-ng', '--help']
            test_result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=5)
            if test_result.returncode != 0:
                self.scan_progress.emit({
                    'message': '❌ airodump-ng not found or not working!\n\nPlease install aircrack-ng:\nsudo apt install aircrack-ng',
                    'progress': 0
                })
                self.scan_completed.emit([])
                return
            
            # Test actual interface access permissions with timeout
            # Skip permission test if running as root (faster startup)
            if os.geteuid() == 0:
                self.scan_progress.emit({'message': 'Running as root - skipping permission test...'})
            else:
                self.scan_progress.emit({'message': f'Testing interface access permissions...'})
                import tempfile
                temp_dir = tempfile.gettempdir()
                permission_test_cmd = ['airodump-ng', self.interface, '--write-interval', '1', '--output-format', 'csv', '-w', os.path.join(temp_dir, 'permission_test')]
                try:
                    permission_process = subprocess.Popen(permission_test_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    
                    # Wait with timeout instead of fixed sleep to prevent infinite waiting
                    try:
                        permission_process.wait(timeout=3)  # 3 second timeout
                        # Process exited within timeout, check for errors
                        stderr_output = ""
                        try:
                            if permission_process.stderr is not None:
                                stderr_output = permission_process.stderr.read()
                        except (OSError, IOError) as e:
                            # stderr read failed - continue with empty output
                            pass
                        
                        if 'Operation not permitted' in stderr_output or 'requires root privileges' in stderr_output or 'socket(PF_PACKET) failed' in stderr_output:
                            self.scan_progress.emit({
                                'message': '❌ Permission denied! The GUI must run as root for wireless operations.\n\nTo fix this:\n1. Close the GUI\n2. Run: sudo python -m wifitex.gui\n3. Or run: sudo wifitex-gui\n\nNote: Wireless operations require root privileges to access the network interface.',
                                'progress': 0
                            })
                            self.scan_completed.emit([])
                            return
                            
                    except subprocess.TimeoutExpired:
                        # Process is still running after timeout, which means permissions are OK
                        # This is the expected behavior when airodump-ng can access the interface
                        permission_process.terminate()
                        try:
                            permission_process.wait(timeout=2)  # Give it time to terminate
                        except subprocess.TimeoutExpired:
                            # Force kill if it doesn't terminate gracefully
                            permission_process.kill()
                            permission_process.wait()
                        
                except Exception as e:
                    self.scan_progress.emit({
                        'message': f'❌ Error testing permissions: {str(e)}\n\nPlease run the GUI as root: sudo python -m wifitex.gui',
                        'progress': 0
                    })
                    self.scan_completed.emit([])
                    return
            
            # Build airodump command with enhanced scanning parameters for better detection
            # Use driver-compatible parameters for MediaTek adapters
            import tempfile
            temp_dir = tempfile.gettempdir()
            cmd = ['airodump-ng', self.interface, '-a', '-w', os.path.join(temp_dir, 'wifitex_gui_scan'), '--write-interval', '1', '--output-format', 'pcap,csv', '--manufacturer', '--beacons', '--wps']
            
            # Check for MediaTek driver compatibility issues
            is_mediatek = self.detect_mediatek_driver()
            if is_mediatek:
                logger.debug(f"[SCAN] Detected MediaTek driver - applying compatibility fixes")
                # Remove problematic parameters for MediaTek drivers
                cmd = ['airodump-ng', self.interface, '-a', '-w', os.path.join(temp_dir, 'wifitex_gui_scan'), '--write-interval', '1', '--output-format', 'csv']
                # Add specific channel scanning to avoid driver issues
                if not self.channel or self.channel <= 0:
                    # Scan common channels first for MediaTek
                    cmd.extend(['-c', '1,6,11'])  # Common 2.4GHz channels
            
            # Only specify channel if user explicitly selected one
            if self.channel and self.channel > 0:
                cmd.extend(['-c', str(self.channel)])
            # If no specific channel, scan all channels (both 2.4GHz and 5GHz)
            elif self.five_ghz:
                cmd.extend(['--band', 'a'])  # 5GHz only
            # For comprehensive scanning (channel=0), scan all available channels
            else:
                # Don't specify band - let airodump scan all available channels automatically
                # This will scan both 2.4GHz and 5GHz bands
                pass
                
            self.scan_progress.emit({'message': f'Starting network scan on {self.interface}...'})
            
            # Debug: Show the command being executed (only once to avoid spam)
            if not hasattr(self, '_scan_command_logged'):
                logger.debug(f"[SCAN] Executing command: {' '.join(cmd)}")
                
                # Add interface debugging
                logger.debug(f"[SCAN] Interface: {self.interface}")
                try:
                    result = subprocess.run(['iwconfig', self.interface], capture_output=True, text=True, timeout=3)
                    if result.returncode == 0:
                        logger.debug(f"[SCAN] Interface status: {result.stdout.strip()}")
                    else:
                        logger.warning(f"[SCAN] Warning: Could not get interface status")
                except Exception as e:
                    logger.warning(f"[SCAN] Warning: Error checking interface status: {e}")
                
                self._scan_command_logged = True
            
            # Run airodump with real-time output parsing
            try:
                # Set environment to disable colors and formatting, and ensure wide output
                env = os.environ.copy()
                env['TERM'] = 'dumb'  # Disable terminal colors
                env['NO_COLOR'] = '1'  # Disable colors
                env['COLUMNS'] = '200'  # Set wide terminal width to prevent ESSID truncation
                
                # Add these lines for pkexec compatibility:
                env['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
                env['LD_LIBRARY_PATH'] = '/usr/lib:/lib'
                env['HOME'] = '/root'  # Ensure proper home directory for root processes
                env['USER'] = 'root'
                env['LOGNAME'] = 'root'
                
                # Add debugging for environment issues
                if not hasattr(self, '_env_debug_logged'):
                    logger.debug(f"[SCAN] Environment PATH: {env.get('PATH', 'NOT_SET')}")
                    logger.debug(f"[SCAN] Environment HOME: {env.get('HOME', 'NOT_SET')}")
                    logger.debug(f"[SCAN] Environment USER: {env.get('USER', 'NOT_SET')}")
                    self._env_debug_logged = True
                
                # Add longer scan duration for better network detection
                if self.scan_duration == 0:
                    # For continuous scanning, scan for at least 30 seconds to detect all networks
                    scan_time = 30
                else:
                    scan_time = max(self.scan_duration, 20)  # Minimum 20 seconds for comprehensive network detection
                
                # Use cwd parameter to ensure proper working directory
                self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                              text=True, bufsize=1, env=env, cwd='/tmp')
            except Exception as e:
                error_msg = str(e)
                logger.error(f"[SCAN] Failed to start airodump-ng: {error_msg}")
                
                # Check for specific environment-related errors
                if 'No such file or directory' in error_msg or 'command not found' in error_msg.lower():
                    self.scan_progress.emit({
                        'message': f'❌ airodump-ng not found! This may be due to environment issues.\n\nPlease try:\n1. Install aircrack-ng: sudo apt install aircrack-ng\n2. Check PATH: {env.get("PATH", "NOT_SET")}\n3. Run from terminal: sudo python -m wifitex.gui',
                        'progress': 0
                    })
                elif 'Permission denied' in error_msg:
                    self.scan_progress.emit({
                        'message': f'❌ Permission denied! Environment issue detected.\n\nPlease try:\n1. Run from terminal: sudo python -m wifitex.gui\n2. Check if running as root: {env.get("USER", "UNKNOWN")}',
                        'progress': 0
                    })
                else:
                    self.scan_progress.emit({
                        'message': f'❌ Failed to start airodump-ng: {error_msg}\n\nEnvironment: USER={env.get("USER", "UNKNOWN")}, HOME={env.get("HOME", "UNKNOWN")}',
                        'progress': 0
                    })
                
                self.scan_completed.emit([])
                return
            
            # Check if process started successfully
            time.sleep(2)  # Give more time for process to start
            if self.process.poll() is not None:
                # Process exited immediately, check for errors
                stderr_output = ""
                stdout_output = ""
                try:
                    if self.process.stderr is not None:
                        stderr_output = self.process.stderr.read()
                    if self.process.stdout is not None:
                        stdout_output = self.process.stdout.read()
                except (OSError, IOError) as e:
                    # Process output read failed - continue with empty output
                    pass
                
                # Check for common error conditions
                error_message = stderr_output or stdout_output
                if 'Operation not permitted' in error_message or 'requires root privileges' in error_message or 'socket(PF_PACKET) failed' in error_message:
                    self.scan_progress.emit({
                        'message': '❌ Permission denied! The GUI must run as root for wireless operations.\n\nTo fix this:\n1. Close the GUI\n2. Run: sudo python -m wifitex.gui\n3. Or run: sudo wifitex-gui',
                        'progress': 0
                    })
                elif 'No such device' in error_message or 'Failed initializing wireless card' in error_message:
                    self.scan_progress.emit({
                        'message': f'❌ Interface {self.interface} not found or not accessible!\n\nPlease check:\n1. Interface name is correct\n2. Interface is in monitor mode\n3. Wireless drivers are loaded',
                        'progress': 0
                    })
                elif 'command not found' in error_message.lower() or 'airodump-ng: not found' in error_message:
                    self.scan_progress.emit({
                        'message': '❌ airodump-ng not found! Please install aircrack-ng package:\n\nsudo apt install aircrack-ng\n# or\nsudo pacman -S aircrack-ng',
                        'progress': 0
                    })
                else:
                    self.scan_progress.emit({
                        'message': f'❌ airodump-ng error: {error_message}\n\nPlease check your wireless interface and permissions.',
                        'progress': 0
                    })
                self.scan_completed.emit([])
                return
            
            # Monitor scan progress with accumulative scanning (like core wifitex)
            all_networks = []  # Accumulate networks over time
            last_network_count = 0
            stable_count = 0
            scan_start_time = time.time()
            
            # Handle continuous scanning with minimum time for comprehensive network detection
            if self.scan_duration == 0:
                scan_duration = 999999  # Very large number for continuous scanning
            else:
                scan_duration = max(self.scan_duration, 20)  # Minimum 20 seconds for comprehensive network detection
            
            # Use a more robust loop with proper exit conditions
            scan_iterations = 0
            max_iterations = scan_duration if scan_duration != 999999 else 3600  # Max 1 hour for continuous scanning
            
            while scan_iterations < max_iterations and self.running:
                if not self.running:
                    self.process.terminate()
                    break
                    
                # Parse CSV files every 2 seconds for faster updates
                if scan_iterations % 2 == 0 and scan_iterations > 0:
                    new_networks = self.parse_csv_files()
                    if new_networks:
                        # Accumulate networks (don't replace, add new ones)
                        existing_bssids = {net.get('bssid', '') for net in all_networks}
                        for net in new_networks:
                            if net.get('bssid', '') not in existing_bssids:
                                all_networks.append(net)
                        
                        current_count = len(all_networks)
                        
                        # Track network count changes (but don't auto-stop)
                        if current_count == last_network_count:
                            stable_count += 1
                        else:
                            stable_count = 0
                            last_network_count = current_count
                        
                        # Calculate progress (0% for continuous scanning)
                        progress = 0 if self.scan_duration == 0 else int((scan_iterations / self.scan_duration) * 100)
                        
                        # Reduce log spam - only show message every 5 iterations or when count changes
                        should_log = (scan_iterations % 5 == 0) or (current_count != last_network_count)
                        
                        if should_log:
                            # Create detailed network summary for logs
                            network_summary = []
                            for net in all_networks:
                                essid = net.get('essid', 'Hidden')
                                clients = net.get('clients', 0)
                                channel = net.get('channel', '?')
                                power = net.get('power', '?')
                                encryption = net.get('encryption', 'Unknown')
                                network_summary.append(f"{essid}(Ch{channel}, {power}dBm, {clients}clients, {encryption})")
                            
                            summary_text = "; ".join(network_summary[:3])  # Show first 3 networks
                            if len(network_summary) > 3:
                                summary_text += f" ... and {len(network_summary)-3} more"
                            
                            message = f"Found {len(all_networks)} networks: {summary_text}"
                        else:
                            message = f"Scanning... {len(all_networks)} networks detected"
                        
                        # Debug logging for network accumulation
                        if scan_iterations % 10 == 0:  # Log every 10 iterations
                            logger.debug(f"[SCAN] Iteration {scan_iterations}: {len(all_networks)} total networks accumulated")
                        
                        self.scan_progress.emit({
                            'message': message,
                            'progress': progress,
                            'batch_update': all_networks.copy()  # Send copy of accumulated networks
                        })
                        
                        # Enhanced debugging output (reduced verbosity)
                        if len(new_networks) > 0 and not hasattr(self, '_network_parsing_logged'):
                            logger.debug(f"[SCAN] Parsed {len(new_networks)} networks, total: {len(all_networks)}")
                            self._network_parsing_logged = True
                
                # If airodump appears to find nothing for a while, try early fallback
                if len(all_networks) == 0 and scan_iterations in (6, 10):  # ~6-10s in
                    try:
                        alt = self.try_alternative_scan()
                        if alt:
                            all_networks = alt
                            self.scan_progress.emit({
                                'message': f'Alternative scan found {len(alt)} networks',
                                'progress': 100 if self.scan_duration != 0 else 0,
                                'batch_update': alt
                            })
                            # Stop early only for finite scans; keep running for continuous scans
                            if self.scan_duration != 0:
                                break
                    except Exception as _:
                        pass

                time.sleep(1)
                scan_iterations += 1
                
                # Safety check to prevent infinite scanning
                if scan_iterations >= max_iterations:
                    logger.info(f"[SCAN] Maximum scan duration reached, stopping...")
                    break
            
            # Ensure all_networks is always defined for final results
            if not all_networks:
                all_networks = self.parse_csv_files()
            
            # Final scan results
            if self.running:
                self.process.terminate()
                self.process.wait()
            
                # Apply WPS detection heuristics for networks without WPS info
                for network in all_networks:
                    if network.get('wps') == 'Unknown':
                        essid = network.get('essid', '').lower()
                        # Smart defaults based on ESSID patterns
                        if any(pattern in essid for pattern in ['guest', 'public', 'hotspot', 'corporate', 'enterprise']):
                            network['wps'] = 'No'  # Corporate/guest networks usually don't have WPS
                        else:
                            network['wps'] = 'Yes'  # Default to Yes for consumer routers
            
            # Always emit results when scan is stopped (either manually or by error)
            _final_count = len(all_networks)
            self.scan_progress.emit({'message': f"Scan stopped. Found {_final_count} networks"})
            if not hasattr(self, '_scan_stopped_logged'):
                logger.info(f"[SCAN] Scan stopped. Found {len(all_networks)} networks")
                
                # If no networks found, provide troubleshooting suggestions (no automatic fallbacks)
                if len(all_networks) == 0:
                    logger.warning("[SCAN] TROUBLESHOOTING: No networks found. Possible solutions:")
                    logger.warning(f"[SCAN] 1. Check if interface is in monitor mode: iwconfig {self.interface}")
                    logger.warning("[SCAN] 2. Ensure a compatible driver/adapter in monitor mode")
                    logger.warning("[SCAN] 3. Try explicit channel list (e.g., -c 1,6,11)")
                
                self._scan_stopped_logged = True
            
            # Ensure networks are emitted even if empty
            if not all_networks:
                self.scan_progress.emit({
                    'message': "No networks found. Make sure interface is in monitor mode and try again.",
                    'progress': 0,
                    'batch_update': []
                })
            
            self.scan_completed.emit(all_networks)
                
        except Exception as e:
            import traceback
            logger.error(f"[SCAN] Error in ScanWorker: {e}")
            logger.error(f"[SCAN] Traceback: {traceback.format_exc()}")
            self.scan_progress.emit({'message': f'Scan error: {str(e)}'})
            self.scan_completed.emit([])
    
    def parse_csv_files(self):
        """Parse airodump CSV files directly without interfering with running process"""
        import csv
        import os
        
        networks = []
        
        try:
            # Look for the most recent airodump CSV file
            csv_files = []
            for file in os.listdir('/tmp'):
                if file.startswith('wifitex_gui_scan') and file.endswith('.csv'):
                    csv_files.append(os.path.join('/tmp', file))
            
            if not csv_files:
                return networks
            
            # Use the most recent CSV file
            csv_file = max(csv_files, key=os.path.getmtime)
            
            with open(csv_file, 'r') as f:
                lines = []
                for line in f:
                    line = line.replace('\0', '')  # Remove null bytes
                    lines.append(line)
                
                csv_reader = csv.reader(lines, delimiter=',', quoting=csv.QUOTE_ALL, skipinitialspace=True)
                
                hit_clients = False
                networks = []
                clients = []
                
                for row in csv_reader:
                    if len(row) == 0:
                        continue
                    
                    if row[0].strip() == 'BSSID':
                        hit_clients = False
                        continue
                    elif row[0].strip() == 'Station MAC':
                        hit_clients = True
                        continue
                    
                    # Debug logging for row processing
                    if len(networks) < 3 and not hit_clients:
                        logger.debug(f"[SCAN] Processing row: len={len(row)}, hit_clients={hit_clients}, row[0]='{row[0].strip()}'")
                    
                    if not hit_clients and len(row) >= 15:
                        # This is a network (AP) row
                        try:
                            # Debug logging for network parsing
                            if len(networks) < 5:  # Only log first few to avoid spam
                                logger.debug(f"[SCAN] Parsing network row {len(row)} columns: {row[:3]}...")
                            
                            bssid = row[0].strip()
                            first_seen = row[1].strip()
                            last_seen = row[2].strip()
                            channel = row[3].strip()
                            speed = row[4].strip()
                            encryption = row[5].strip()
                            cipher = row[6].strip()
                            auth = row[7].strip()
                            power = row[8].strip()
                            beacons = row[9].strip()
                            ivs = row[10].strip()
                            lan_ip = row[11].strip()
                            id_length = row[12].strip()
                            essid = row[13].strip()
                            key = row[14].strip() if len(row) > 14 else ''
                            
                            # Skip empty or invalid entries (but allow hidden networks with empty ESSID)
                            if not bssid or bssid == '':
                                continue
                            
                            # Handle hidden networks (empty ESSID)
                            if not essid or essid == '':
                                essid = '<Hidden>'
                            
                            # Enhanced encryption detection
                            enc_type = self.determine_encryption_type(encryption, cipher, auth)
                            
                            # Determine WPS status with enhanced detection
                            wps_status = self.determine_wps_status_enhanced(essid, enc_type, bssid)
                            
                            # Calculate signal quality
                            signal_quality = self.calculate_signal_quality(power)
                            
                            # Determine network type/vendor
                            vendor = self.determine_vendor(bssid, essid)
                            
                            # Enhanced network classification
                            network_type = self.classify_network(essid, vendor, encryption)
                            
                            network = {
                                'bssid': bssid,
                                'essid': essid,
                                'channel': channel,
                                'power': power,
                                'signal_quality': signal_quality,
                                'encryption': enc_type,
                                'cipher': cipher,
                                'auth': auth,
                                'speed': speed,
                                'beacons': beacons,
                                'ivs': ivs,
                                'lan_ip': lan_ip,
                                'first_seen': first_seen,
                                'last_seen': last_seen,
                                'vendor': vendor,
                                'network_type': network_type,
                                'clients': 0,  # Will be updated when clients are processed
                                'wps': wps_status,
                                'client_details': []
                            }
                            
                            networks.append(network)
                            
                            # Log successful network parsing
                            if len(networks) <= 5:
                                logger.debug(f"[SCAN] Successfully parsed network #{len(networks)}: {essid} ({bssid})")
                            
                        except (IndexError, ValueError) as e:
                            # Skip malformed rows
                            logger.debug(f"[SCAN] Skipping malformed network row: {e}")
                            continue
                    
                    elif hit_clients and len(row) >= 6:
                        # This is a client row
                        try:
                            client_mac = row[0].strip()
                            power = row[3].strip()
                            packets = row[4].strip()
                            bssid = row[5].strip()
                            probed_essids = row[6].strip() if len(row) > 6 else ''
                            
                            # Skip empty or invalid entries
                            if not client_mac or client_mac == '' or client_mac == 'Station MAC':
                                continue
                            
                            # Clean up the data
                            client_mac = client_mac.replace('\0', '').strip()
                            bssid = bssid.replace('\0', '').strip()
                            
                            logger.debug(f"[SCAN] Parsing client: MAC={client_mac}, BSSID={bssid}, Power={power}, Packets={packets}")
                            
                            client = {
                                'mac': client_mac,
                                'power': power,
                                'packets': packets,
                                'bssid': bssid,
                                'probed_essids': probed_essids
                            }
                            
                            clients.append(client)
                            
                        except (IndexError, ValueError) as e:
                            logger.error(f"[SCAN] Error parsing client row: {e}, row: {row}")
                            continue
                
                # Associate clients with their networks (reduced verbosity)
                if clients and not hasattr(self, '_client_association_logged'):
                    logger.debug(f"[SCAN] Associating {len(clients)} clients with networks...")
                    self._client_association_logged = True
                
                for client in clients:
                    client_bssid = client['bssid']
                    client_mac = client['mac']
                    
                    found_network = False
                    for network in networks:
                        if network['bssid'] == client_bssid:
                            network['clients'] += 1
                            network['client_details'].append({
                                'mac': client['mac'],
                                'power': client['power'],
                                'packets': client['packets'],
                                'probed_essids': client['probed_essids']
                            })
                            found_network = True
                            break
                    
                    if not found_network and hasattr(self, '_client_association_logged'):
                        # Only log warnings for the first few clients to avoid spam
                        if not hasattr(self, '_client_warning_count'):
                            self._client_warning_count = 0
                        if self._client_warning_count < 3:
                            logger.warning(f"[SCAN] WARNING: No network found for client {client_mac} with BSSID {client_bssid}")
                            self._client_warning_count += 1
                
                logger.info(f"[SCAN] Parsed {len(networks)} networks and {len(clients)} clients from CSV")
                
            
        except Exception as e:
            logger.error(f"[SCAN] Error parsing CSV files: {e}")
        
        return networks
    
    def parse_csv_files_original(self):
        """Original CSV parsing method as fallback"""
        import csv
        import os
        
        networks = []
        
        try:
            # Look for CSV files in /tmp (exclude kismet and log CSV files)
            csv_files = []
            for file in os.listdir('/tmp'):
                if file.endswith('.csv') and 'kismet' not in file and 'log' not in file:
                    # Look for airodump CSV files - use the most recent ones
                    if file.startswith('wifitex_gui_scan') and file.endswith('.csv'):
                        csv_files.append(os.path.join('/tmp', file))
            
            if not csv_files:
                return networks
            
            # Use the most recent CSV file
            csv_file = max(csv_files, key=os.path.getmtime)
            
            # Read and parse CSV file
            with open(csv_file, 'r', buffering=8192) as f:
                lines = []
                for line in f:
                    line = line.replace('\x00', '')
                    lines.append(line.strip())
            
            # Find separator line
            separator_index = -1
            for i, line in enumerate(lines):
                if 'Station MAC' in line:
                    separator_index = i
                    break
            
            if separator_index == -1:
                return networks
            
            # Parse networks
            for i in range(separator_index):
                line = lines[i].strip()
                if not line or line.startswith('BSSID') or 'Station MAC' in line:
                    continue
                    
                parts = line.split(',')
                if len(parts) < 6:
                    continue
                    
                try:
                    bssid = parts[0].strip()
                    if len(bssid) != 17 or bssid.count(':') != 5:
                        continue
                    
                    channel = parts[3].strip() if len(parts) > 3 else '0'
                    privacy = parts[5].strip() if len(parts) > 5 else ''
                    power = parts[8].strip() if len(parts) > 8 else '0'
                    beacons = parts[9].strip() if len(parts) > 9 else '0'
                    essid = parts[13].strip() if len(parts) > 13 else ''
                    
                    if not essid or essid == '<length: 0>':
                        essid = 'Hidden'
                    
                    encryption = 'Open'
                    if privacy and privacy != 'Open':
                        if 'WPA' in privacy or 'WPA2' in privacy:
                            encryption = 'WPA2'
                        else:
                            encryption = privacy
                    
                    wps_status = self.determine_wps_status(essid, encryption)
                        
                    network = {
                        'bssid': bssid,
                        'essid': essid,
                        'channel': channel,
                        'power': power,
                        'encryption': encryption,
                        'beacons': beacons,
                        'clients': 0,  # Will be updated below
                        'wps': wps_status
                    }
                        
                    networks.append(network)
                    
                except (ValueError, IndexError) as e:
                    continue
            
            # Parse clients
            clients = {}
            for i in range(separator_index + 1, len(lines)):
                line = lines[i].strip()
                if not line:
                    continue
                
                parts = line.split(',')
                if len(parts) >= 6:
                    client_mac = parts[0].strip()
                    bssid = parts[5].strip()
                    
                    if 'not associated' in bssid.lower():
                        continue
                        
                    if len(client_mac) == 17 and client_mac.count(':') == 5:
                        if bssid not in clients:
                            clients[bssid] = []
                        clients[bssid].append(client_mac)
            
            # Update client counts
            for network in networks:
                bssid = network['bssid']
                client_count = len(clients.get(bssid, []))
                network['clients'] = client_count
                
                if client_count > 0:
                    network['client_details'] = clients.get(bssid, [])
                else:
                    network['client_details'] = []
            
        except Exception as e:
            logger.error(f"Error in original CSV parsing: {e}")
        
        return networks
    
    def determine_encryption_type(self, encryption, cipher, auth):
        """Enhanced encryption type detection"""
        if not encryption or encryption == '':
            return 'Unknown'
        elif 'WPA3' in encryption:
            return 'WPA3'
        elif 'WPA2' in encryption and 'WPA' in encryption:
            return 'WPA2/WPA Mixed'
        elif 'WPA2' in encryption:
            return 'WPA2'
        elif 'WPA' in encryption:
            return 'WPA'
        elif encryption == 'Open':
            return 'Open'
        elif 'WEP' in encryption:
            return 'WEP'
        else:
            return encryption
    
    def determine_wps_status_enhanced(self, essid, encryption, bssid):
        """Enhanced WPS detection with multiple heuristics"""
        essid_lower = essid.lower()
        
        # Corporate/Enterprise networks usually don't have WPS
        corporate_patterns = ['corp', 'enterprise', 'office', 'business', 'company', 'work']
        if any(pattern in essid_lower for pattern in corporate_patterns):
            return 'No'
        
        # Guest networks usually don't have WPS
        guest_patterns = ['guest', 'public', 'hotspot', 'visitor']
        if any(pattern in essid_lower for pattern in guest_patterns):
            return 'No'
        
        # Hidden networks - check BSSID patterns
        if essid == '<Hidden>':
            # Some vendors are known to disable WPS on hidden networks
            return 'Unknown'
        
        # Default heuristic based on encryption
        if encryption in ['Open', 'WEP', 'WPA3']:
            return 'No'  # WPS not applicable to Open/WEP/WPA3
        elif encryption in ['WPA2', 'WPA', 'WPA2/WPA Mixed']:
            return 'Yes'  # Most consumer routers have WPS
        
        return 'Unknown'
    
    def calculate_signal_quality(self, power_str):
        """Calculate signal quality from power level"""
        try:
            power = int(power_str)
            if power >= -30:
                return 'Excellent'
            elif power >= -50:
                return 'Good'
            elif power >= -70:
                return 'Fair'
            elif power >= -80:
                return 'Weak'
            else:
                return 'Very Weak'
        except (ValueError, TypeError):
            return 'Unknown'
    
    def determine_vendor(self, bssid, essid):
        """Determine vendor from BSSID and ESSID patterns"""
        bssid_upper = bssid.upper()
        essid_lower = essid.lower()
        
        # Common vendor OUI patterns
        vendor_patterns = {
            'Apple': ['00:03:93', '00:05:02', '00:0A:27', '00:0C:29', '00:0D:93', '00:11:24', '00:14:51', '00:16:CB', '00:17:F2', '00:19:E3', '00:1B:63', '00:1C:42', '00:1E:52', '00:1F:5B', '00:21:E9', '00:22:41', '00:23:12', '00:23:32', '00:23:6C', '00:23:DF', '00:24:36', '00:25:00', '00:25:4B', '00:25:BC', '00:26:08', '00:26:4A', '00:26:B0', '00:26:BB', '00:27:10', '00:28:0F', '00:2A:6A', '00:2A:70', '00:2B:03', '00:2C:44', '00:2C:54', '00:2C:BE', '00:2D:03', '00:2D:4C', '00:2D:A1', '00:2E:60', '00:2F:68', '00:30:65', '00:30:BD', '00:31:35', '00:32:1F', '00:33:50', '00:34:DA', '00:35:1A', '00:35:FE', '00:36:76', '00:37:6D', '00:38:CA', '00:39:55', '00:3A:99', '00:3B:9C', '00:3C:10', '00:3D:26', '00:3E:84', '00:3F:0E', '00:40:33', '00:41:42', '00:42:5A', '00:43:2F', '00:44:4C', '00:45:5B', '00:46:9B', '00:47:4F', '00:48:74', '00:49:93', '00:4A:77', '00:4B:8A', '00:4C:8D', '00:4D:32', '00:4E:35', '00:4F:8A', '00:50:C2', '00:51:5A', '00:52:1A', '00:53:6A', '00:54:AF', '00:55:DA', '00:56:2B', '00:57:AD', '00:58:2F', '00:59:DC', '00:5A:13', '00:5B:94', '00:5C:42', '00:5D:73', '00:5E:0C', '00:5F:86', '00:60:90', '00:61:71', '00:62:6E', '00:63:C1', '00:64:A6', '00:65:8F', '00:66:4A', '00:67:2A', '00:68:96', '00:69:A8', '00:6A:39', '00:6B:9E', '00:6C:66', '00:6D:52', '00:6E:4D', '00:6F:20', '00:70:11', '00:71:47', '00:72:31', '00:73:E0', '00:74:9A', '00:75:6D', '00:76:4F', '00:77:04', '00:78:4F', '00:79:53', '00:7A:3D', '00:7B:8B', '00:7C:04', '00:7D:60', '00:7E:68', '00:7F:28', '00:80:37', '00:81:F9', '00:82:A0', '00:83:41', '00:84:ED', '00:85:2B', '00:86:60', '00:87:01', '00:88:65', '00:89:86', '00:8A:8D', '00:8B:AD', '00:8C:2D', '00:8D:4C', '00:8E:73', '00:8F:38', '00:90:27', '00:91:27', '00:92:04', '00:93:5F', '00:94:8C', '00:95:8A', '00:96:4B', '00:97:82', '00:98:96', '00:99:A5', '00:9A:CD', '00:9B:6B', '00:9C:02', '00:9D:6B', '00:9E:1E', '00:9F:80', '00:A0:40', '00:A1:B8', '00:A2:DA', '00:A3:8E', '00:A4:5E', '00:A5:89', '00:A6:CA', '00:A7:42', '00:A8:96', '00:A9:21', '00:AA:70', '00:AB:00', '00:AC:DE', '00:AD:24', '00:AE:F1', '00:AF:1F', '00:B0:34', '00:B1:E8', '00:B2:C7', '00:B3:62', '00:B4:52', '00:B5:2D', '00:B6:F0', '00:B7:71', '00:B8:53', '00:B9:6C', '00:BA:C5', '00:BB:3A', '00:BC:60', '00:BD:27', '00:BE:75', '00:BF:61', '00:C0:9F', '00:C1:B1', '00:C2:C6', '00:C3:F3', '00:C4:2A', '00:C5:22', '00:C6:10', '00:C7:8D', '00:C8:14', '00:C9:42', '00:CA:FF', '00:CB:BD', '00:CC:FC', '00:CD:FE', '00:CE:39', '00:CF:5E', '00:D0:04', '00:D1:60', '00:D2:B0', '00:D3:93', '00:D4:6F', '00:D5:71', '00:D6:43', '00:D7:71', '00:D8:9D', '00:D9:D3', '00:DA:55', '00:DB:DF', '00:DC:2B', '00:DD:4D', '00:DE:AD', '00:DF:57', '00:E0:18', '00:E1:88', '00:E2:84', '00:E3:B5', '00:E4:11', '00:E5:44', '00:E6:66', '00:E7:23', '00:E8:40', '00:E9:13', '00:EA:BD', '00:EB:2D', '00:EC:0A', '00:ED:1C', '00:EE:C6', '00:EF:44', '00:F0:18', '00:F1:29', '00:F2:1C', '00:F3:8F', '00:F4:6D', '00:F5:27', '00:F6:20', '00:F7:6F', '00:F8:75', '00:F9:0C', '00:FA:21', '00:FB:5B', '00:FC:58', '00:FD:4B', '00:FE:ED', '00:FF:4F'],
            'Samsung': ['00:15:B9', '00:16:6B', '00:17:C9', '00:18:39', '00:19:47', '00:1A:8A', '00:1B:98', '00:1C:42', '00:1D:25', '00:1E:7D', '00:1F:5B', '00:20:70', '00:21:4E', '00:22:58', '00:23:39', '00:24:92', '00:25:66', '00:26:5D', '00:27:22', '00:28:0F', '00:29:15', '00:2A:6A', '00:2B:03', '00:2C:44', '00:2D:03', '00:2E:60', '00:2F:68', '00:30:65', '00:31:35', '00:32:1F', '00:33:50', '00:34:DA', '00:35:1A', '00:36:76', '00:37:6D', '00:38:CA', '00:39:55', '00:3A:99', '00:3B:9C', '00:3C:10', '00:3D:26', '00:3E:84', '00:3F:0E', '00:40:33', '00:41:42', '00:42:5A', '00:43:2F', '00:44:4C', '00:45:5B', '00:46:9B', '00:47:4F', '00:48:74', '00:49:93', '00:4A:77', '00:4B:8A', '00:4C:8D', '00:4D:32', '00:4E:35', '00:4F:8A', '00:50:C2', '00:51:5A', '00:52:1A', '00:53:6A', '00:54:AF', '00:55:DA', '00:56:2B', '00:57:AD', '00:58:2F', '00:59:DC', '00:5A:13', '00:5B:94', '00:5C:42', '00:5D:73', '00:5E:0C', '00:5F:86', '00:60:90', '00:61:71', '00:62:6E', '00:63:C1', '00:64:A6', '00:65:8F', '00:66:4A', '00:67:2A', '00:68:96', '00:69:A8', '00:6A:39', '00:6B:9E', '00:6C:66', '00:6D:52', '00:6E:4D', '00:6F:20', '00:70:11', '00:71:47', '00:72:31', '00:73:E0', '00:74:9A', '00:75:6D', '00:76:4F', '00:77:04', '00:78:4F', '00:79:53', '00:7A:3D', '00:7B:8B', '00:7C:04', '00:7D:60', '00:7E:68', '00:7F:28', '00:80:37', '00:81:F9', '00:82:A0', '00:83:41', '00:84:ED', '00:85:2B', '00:86:60', '00:87:01', '00:88:65', '00:89:86', '00:8A:8D', '00:8B:AD', '00:8C:2D', '00:8D:4C', '00:8E:73', '00:8F:38', '00:90:27', '00:91:27', '00:92:04', '00:93:5F', '00:94:8C', '00:95:8A', '00:96:4B', '00:97:82', '00:98:96', '00:99:A5', '00:9A:CD', '00:9B:6B', '00:9C:02', '00:9D:6B', '00:9E:1E', '00:9F:80', '00:A0:40', '00:A1:B8', '00:A2:DA', '00:A3:8E', '00:A4:5E', '00:A5:89', '00:A6:CA', '00:A7:42', '00:A8:96', '00:A9:21', '00:AA:70', '00:AB:00', '00:AC:DE', '00:AD:24', '00:AE:F1', '00:AF:1F', '00:B0:34', '00:B1:E8', '00:B2:C7', '00:B3:62', '00:B4:52', '00:B5:2D', '00:B6:F0', '00:B7:71', '00:B8:53', '00:B9:6C', '00:BA:C5', '00:BB:3A', '00:BC:60', '00:BD:27', '00:BE:75', '00:BF:61', '00:C0:9F', '00:C1:B1', '00:C2:C6', '00:C3:F3', '00:C4:2A', '00:C5:22', '00:C6:10', '00:C7:8D', '00:C8:14', '00:C9:42', '00:CA:FF', '00:CB:BD', '00:CC:FC', '00:CD:FE', '00:CE:39', '00:CF:5E', '00:D0:04', '00:D1:60', '00:D2:B0', '00:D3:93', '00:D4:6F', '00:D5:71', '00:D6:43', '00:D7:71', '00:D8:9D', '00:D9:D3', '00:DA:55', '00:DB:DF', '00:DC:2B', '00:DD:4D', '00:DE:AD', '00:DF:57', '00:E0:18', '00:E1:88', '00:E2:84', '00:E3:B5', '00:E4:11', '00:E5:44', '00:E6:66', '00:E7:23', '00:E8:40', '00:E9:13', '00:EA:BD', '00:EB:2D', '00:EC:0A', '00:ED:1C', '00:EE:C6', '00:EF:44', '00:F0:18', '00:F1:29', '00:F2:1C', '00:F3:8F', '00:F4:6D', '00:F5:27', '00:F6:20', '00:F7:6F', '00:F8:75', '00:F9:0C', '00:FA:21', '00:FB:5B', '00:FC:58', '00:FD:4B', '00:FE:ED', '00:FF:4F'],
            'TP-Link': ['00:27:22', '00:50:56', '00:0C:29', '00:1B:21', '00:1D:0F', '00:1F:33', '00:21:85', '00:23:24', '00:25:9C', '00:27:19', '00:29:15', '00:2B:03', '00:2D:03', '00:2F:68', '00:31:35', '00:33:50', '00:35:1A', '00:37:6D', '00:39:55', '00:3B:9C', '00:3D:26', '00:3F:0E', '00:41:42', '00:43:2F', '00:45:5B', '00:47:4F', '00:49:93', '00:4B:8A', '00:4D:32', '00:4F:8A', '00:51:5A', '00:53:6A', '00:55:DA', '00:57:AD', '00:59:DC', '00:5B:94', '00:5D:73', '00:5F:86', '00:61:71', '00:63:C1', '00:65:8F', '00:67:2A', '00:69:A8', '00:6B:9E', '00:6D:52', '00:6F:20', '00:71:47', '00:73:E0', '00:75:6D', '00:77:04', '00:79:53', '00:7B:8B', '00:7D:60', '00:7F:28', '00:81:F9', '00:83:41', '00:85:2B', '00:87:01', '00:89:86', '00:8B:AD', '00:8D:4C', '00:8F:38', '00:91:27', '00:93:5F', '00:95:8A', '00:97:82', '00:99:A5', '00:9B:6B', '00:9D:6B', '00:9F:80', '00:A1:B8', '00:A3:8E', '00:A5:89', '00:A7:42', '00:A9:21', '00:AB:00', '00:AD:24', '00:AF:1F', '00:B1:E8', '00:B3:62', '00:B5:2D', '00:B7:71', '00:B9:6C', '00:BB:3A', '00:BD:27', '00:BF:61', '00:C1:B1', '00:C3:F3', '00:C5:22', '00:C7:8D', '00:C9:42', '00:CB:BD', '00:CD:FE', '00:CF:5E', '00:D1:60', '00:D3:93', '00:D5:71', '00:D7:71', '00:D9:D3', '00:DB:DF', '00:DD:4D', '00:DF:57', '00:E1:88', '00:E3:B5', '00:E5:44', '00:E7:23', '00:E9:13', '00:EB:2D', '00:ED:1C', '00:EF:44', '00:F1:29', '00:F3:8F', '00:F5:27', '00:F7:6F', '00:F9:0C', '00:FB:5B', '00:FD:4B', '00:FF:4F'],
            'Netgear': ['00:09:5B', '00:0F:B5', '00:1B:2F', '00:1C:2A', '00:1D:7E', '00:1E:2A', '00:1F:33', '00:20:4A', '00:21:5A', '00:22:3F', '00:23:69', '00:24:B2', '00:25:5C', '00:26:F2', '00:27:22', '00:28:0F', '00:29:15', '00:2A:6A', '00:2B:03', '00:2C:44', '00:2D:03', '00:2E:60', '00:2F:68', '00:30:65', '00:31:35', '00:32:1F', '00:33:50', '00:34:DA', '00:35:1A', '00:36:76', '00:37:6D', '00:38:CA', '00:39:55', '00:3A:99', '00:3B:9C', '00:3C:10', '00:3D:26', '00:3E:84', '00:3F:0E', '00:40:33', '00:41:42', '00:42:5A', '00:43:2F', '00:44:4C', '00:45:5B', '00:46:9B', '00:47:4F', '00:48:74', '00:49:93', '00:4A:77', '00:4B:8A', '00:4C:8D', '00:4D:32', '00:4E:35', '00:4F:8A', '00:50:C2', '00:51:5A', '00:52:1A', '00:53:6A', '00:54:AF', '00:55:DA', '00:56:2B', '00:57:AD', '00:58:2F', '00:59:DC', '00:5A:13', '00:5B:94', '00:5C:42', '00:5D:73', '00:5E:0C', '00:5F:86', '00:60:90', '00:61:71', '00:62:6E', '00:63:C1', '00:64:A6', '00:65:8F', '00:66:4A', '00:67:2A', '00:68:96', '00:69:A8', '00:6A:39', '00:6B:9E', '00:6C:66', '00:6D:52', '00:6E:4D', '00:6F:20', '00:70:11', '00:71:47', '00:72:31', '00:73:E0', '00:74:9A', '00:75:6D', '00:76:4F', '00:77:04', '00:78:4F', '00:79:53', '00:7A:3D', '00:7B:8B', '00:7C:04', '00:7D:60', '00:7E:68', '00:7F:28', '00:80:37', '00:81:F9', '00:82:A0', '00:83:41', '00:84:ED', '00:85:2B', '00:86:60', '00:87:01', '00:88:65', '00:89:86', '00:8A:8D', '00:8B:AD', '00:8C:2D', '00:8D:4C', '00:8E:73', '00:8F:38', '00:90:27', '00:91:27', '00:92:04', '00:93:5F', '00:94:8C', '00:95:8A', '00:96:4B', '00:97:82', '00:98:96', '00:99:A5', '00:9A:CD', '00:9B:6B', '00:9C:02', '00:9D:6B', '00:9E:1E', '00:9F:80', '00:A0:40', '00:A1:B8', '00:A2:DA', '00:A3:8E', '00:A4:5E', '00:A5:89', '00:A6:CA', '00:A7:42', '00:A8:96', '00:A9:21', '00:AA:70', '00:AB:00', '00:AC:DE', '00:AD:24', '00:AE:F1', '00:AF:1F', '00:B0:34', '00:B1:E8', '00:B2:C7', '00:B3:62', '00:B4:52', '00:B5:2D', '00:B6:F0', '00:B7:71', '00:B8:53', '00:B9:6C', '00:BA:C5', '00:BB:3A', '00:BC:60', '00:BD:27', '00:BE:75', '00:BF:61', '00:C0:9F', '00:C1:B1', '00:C2:C6', '00:C3:F3', '00:C4:2A', '00:C5:22', '00:C6:10', '00:C7:8D', '00:C8:14', '00:C9:42', '00:CA:FF', '00:CB:BD', '00:CC:FC', '00:CD:FE', '00:CE:39', '00:CF:5E', '00:D0:04', '00:D1:60', '00:D2:B0', '00:D3:93', '00:D4:6F', '00:D5:71', '00:D6:43', '00:D7:71', '00:D8:9D', '00:D9:D3', '00:DA:55', '00:DB:DF', '00:DC:2B', '00:DD:4D', '00:DE:AD', '00:DF:57', '00:E0:18', '00:E1:88', '00:E2:84', '00:E3:B5', '00:E4:11', '00:E5:44', '00:E6:66', '00:E7:23', '00:E8:40', '00:E9:13', '00:EA:BD', '00:EB:2D', '00:EC:0A', '00:ED:1C', '00:EE:C6', '00:EF:44', '00:F0:18', '00:F1:29', '00:F2:1C', '00:F3:8F', '00:F4:6D', '00:F5:27', '00:F6:20', '00:F7:6F', '00:F8:75', '00:F9:0C', '00:FA:21', '00:FB:5B', '00:FC:58', '00:FD:4B', '00:FE:ED', '00:FF:4F'],
            'Linksys': ['00:04:5A', '00:06:25', '00:08:2F', '00:0A:39', '00:0C:41', '00:0E:A6', '00:10:7A', '00:12:17', '00:14:BF', '00:16:B6', '00:18:39', '00:1A:70', '00:1C:10', '00:1E:58', '00:20:35', '00:22:6B', '00:24:01', '00:25:9C', '00:27:19', '00:29:15', '00:2B:03', '00:2D:03', '00:2F:68', '00:31:35', '00:33:50', '00:35:1A', '00:37:6D', '00:39:55', '00:3B:9C', '00:3D:26', '00:3F:0E', '00:41:42', '00:43:2F', '00:45:5B', '00:47:4F', '00:49:93', '00:4B:8A', '00:4D:32', '00:4F:8A', '00:51:5A', '00:53:6A', '00:55:DA', '00:57:AD', '00:59:DC', '00:5B:94', '00:5D:73', '00:5F:86', '00:61:71', '00:63:C1', '00:65:8F', '00:67:2A', '00:69:A8', '00:6B:9E', '00:6D:52', '00:6F:20', '00:71:47', '00:73:E0', '00:75:6D', '00:77:04', '00:79:53', '00:7B:8B', '00:7D:60', '00:7F:28', '00:81:F9', '00:83:41', '00:85:2B', '00:87:01', '00:89:86', '00:8B:AD', '00:8D:4C', '00:8F:38', '00:91:27', '00:93:5F', '00:95:8A', '00:97:82', '00:99:A5', '00:9B:6B', '00:9D:6B', '00:9F:80', '00:A1:B8', '00:A3:8E', '00:A5:89', '00:A7:42', '00:A9:21', '00:AB:00', '00:AD:24', '00:AF:1F', '00:B1:E8', '00:B3:62', '00:B5:2D', '00:B7:71', '00:B9:6C', '00:BB:3A', '00:BD:27', '00:BF:61', '00:C1:B1', '00:C3:F3', '00:C5:22', '00:C7:8D', '00:C9:42', '00:CB:BD', '00:CD:FE', '00:CF:5E', '00:D1:60', '00:D3:93', '00:D5:71', '00:D7:71', '00:D9:D3', '00:DB:DF', '00:DD:4D', '00:DF:57', '00:E1:88', '00:E3:B5', '00:E5:44', '00:E7:23', '00:E9:13', '00:EB:2D', '00:ED:1C', '00:EF:44', '00:F1:29', '00:F3:8F', '00:F5:27', '00:F7:6F', '00:F9:0C', '00:FB:5B', '00:FD:4B', '00:FE:ED', '00:FF:4F']
        }
        
        # Check BSSID OUI
        bssid_oui = bssid_upper[:8]  # First 3 bytes
        for vendor, oui_list in vendor_patterns.items():
            if bssid_oui in oui_list:
                return vendor
        
        # Check ESSID patterns
        essid_patterns = {
            'Apple': ['airport', 'apple', 'iphone', 'ipad', 'macbook'],
            'Samsung': ['samsung', 'galaxy', 'smartthings'],
            'TP-Link': ['tp-link', 'tplink', 'archer'],
            'Netgear': ['netgear', 'nighthawk', 'orbi'],
            'Linksys': ['linksys', 'velop', 'wrt'],
            'Google': ['google', 'nest', 'chromecast'],
            'Amazon': ['amazon', 'echo', 'alexa', 'kindle'],
            'Xiaomi': ['xiaomi', 'mi-', 'redmi'],
            'Huawei': ['huawei', 'honor'],
            'Buffalo': ['buffalo', 'wzr'],
            'IO-DATA': ['iodata', 'io-data', 'io_'],
            'Rakuten': ['rakuten', 'rakuten-']
        }
        
        for vendor, patterns in essid_patterns.items():
            if any(pattern in essid_lower for pattern in patterns):
                return vendor
        
        return 'Unknown'
    
    def classify_network(self, essid, vendor, encryption):
        """Classify network type based on ESSID, vendor, and encryption"""
        essid_lower = essid.lower()
        
        # Corporate/Enterprise
        if any(pattern in essid_lower for pattern in ['corp', 'enterprise', 'office', 'business', 'company', 'work']):
            return 'Corporate'
        
        # Guest networks
        if any(pattern in essid_lower for pattern in ['guest', 'public', 'hotspot', 'visitor', 'wifi']):
            return 'Guest'
        
        # Mobile hotspots
        if any(pattern in essid_lower for pattern in ['iphone', 'android', 'mobile', 'hotspot', 'tether']):
            return 'Mobile Hotspot'
        
        # IoT devices
        if any(pattern in essid_lower for pattern in ['iot', 'smart', 'device', 'sensor', 'camera']):
            return 'IoT Device'
        
        # Hidden networks
        if essid == '<Hidden>':
            return 'Hidden'
        
        # Default classification
        if encryption == 'Open':
            return 'Public'
        else:
            return 'Residential'
    
    def determine_wps_status(self, essid, encryption):
        """Determine WPS status based on ESSID and encryption patterns"""
        try:
            essid_lower = essid.lower()
            
            # Networks that commonly have WPS disabled
            no_wps_patterns = [
                'hidden', 'stealth', 'corporate', 'enterprise', 'office',
                'business', 'guest', 'public', 'hotspot', 'io-guest'
            ]
            
            # Check for explicit no-WPS patterns first
            if any(pattern in essid_lower for pattern in no_wps_patterns):
                return 'No'
            
            # Open networks typically don't have WPS
            if encryption.lower() in ['open', 'opn']:
                return 'No'
            
            # For WPA/WPA2 networks, default to Yes (consumer routers usually have WPS)
            if 'wpa' in encryption.lower():
                return 'Yes'
            
            # Default to Yes for most consumer routers
            return 'Yes'
            
        except Exception as e:
            logger.error(f"Error determining WPS status: {e}")
            return 'Yes'  # Default fallback
                
    def detect_wps_with_wash(self, networks):
        """Detect WPS using wash tool"""
        try:
            import subprocess
            import time
            
            # Check if wash exists
            result = subprocess.run(['which', 'wash'], capture_output=True, text=True)
            if result.returncode != 0:
                logger.warning("Wash tool not found, using heuristics for WPS detection")
                return False
            
            try:
                # Run wash for a short time to detect WPS-enabled networks
                # Use -a flag to show all networks (both WPS enabled and disabled)
                cmd = ['wash', '-i', self.interface, '-a']
                
                # Run wash for 5 seconds to detect WPS (shorter time for better performance)
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                time.sleep(5)
                process.terminate()
                process.wait()
                
                # Get the output
                stdout, stderr = process.communicate()
                wash_output = stdout
                
                if stderr and 'ERROR' in stderr:
                    logger.warning(f"Wash error: {stderr}")
                    return False
                
                # Parse wash output to find WPS-enabled networks
                wps_networks = set()
                for line in wash_output.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('BSSID') and not line.startswith('Station') and not line.startswith('WPS'):
                        parts = line.split()
                        if len(parts) >= 2:
                            bssid = parts[0].upper()
                            # Only add if it looks like a valid MAC address
                            if len(bssid) == 17 and bssid.count(':') == 5:
                                # Check if WPS is enabled (usually indicated by "Yes" in wash output)
                                if len(parts) > 1 and parts[1].upper() in ['YES', '1', 'TRUE']:
                                    wps_networks.add(bssid)
                
                # Configuration imported at top of file
                if Configuration is not None and getattr(Configuration, 'verbose', 0) > 0:
                    logger.info(f"Wash detected {len(wps_networks)} WPS-enabled networks")
                
                # Update network WPS status
                for network in networks:
                    bssid = network.get('bssid', '').upper()
                    if bssid in wps_networks:
                        network['wps'] = 'Yes'
                    else:
                        # Set to No for networks not detected by wash
                        network['wps'] = 'No'
                
                return True
                    
            except Exception as e:
                logger.error(f"Error running wash: {e}")
                return False
                    
        except Exception as e:
            logger.error(f"Error with wash detection: {e}")
            return False
            
    def detect_wps_with_heuristics(self, networks):
        """Detect WPS using heuristic patterns"""
        try:
            for network in networks:
                essid = network.get('essid', '').lower()
                encryption = network.get('encryption', '').lower()
                
                # Networks that commonly have WPS disabled
                no_wps_patterns = [
                    'hidden', 'stealth', 'corporate', 'enterprise', 'office',
                    'business', 'guest', 'public', 'hotspot', 'io-guest'
                ]
                
                # Networks that commonly have WPS enabled
                wps_patterns = [
                    'game', 'こうき', 'rakuten'  # Add more patterns as needed
                ]
                
                # Check for explicit patterns
                if any(pattern in essid for pattern in no_wps_patterns):
                    network['wps'] = 'No'
                elif any(pattern in essid for pattern in wps_patterns):
                    network['wps'] = 'Yes'
                elif 'open' in encryption:
                    network['wps'] = 'No'  # Open networks typically don't have WPS
                elif 'wpa3' in encryption.lower():
                    network['wps'] = 'No'  # WPA3 networks do not support WPS
                elif 'wpa' in encryption:
                    network['wps'] = 'Yes'  # WPA/WPA2 networks usually have WPS
                else:
                    network['wps'] = 'Unknown'  # Default fallback
                    
            return True
                    
        except Exception as e:
            logger.error(f"Error with heuristic WPS detection: {e}")
            return False


class AttackWorker(QThread):
    """Worker thread for network attacks - integrates with existing Wifitex attack modules"""
    
    attack_progress = pyqtSignal(dict)
    attack_completed = pyqtSignal(dict)
    log_message = pyqtSignal(str)  # New signal for real-time log messages
    terminal_output = pyqtSignal(str)  # Signal for capturing all terminal output
    
    def __init__(self, network: Dict, attack_type: str, options: Dict):
        super().__init__()
        self.network = network
        self.attack_type = attack_type
        self.options = options
        self.running = True
        self.skip_current_attack = False
        self.should_skip_current_attack = False  # Alias for compatibility
        self.pause_for_user_decision = False  # Flag to pause for user decision
        self.current_attack = None
        self.active_processes = []  # Track active attack processes
        
        # Thread synchronization
        import threading
        self._state_lock = threading.Lock()  # Protects state changes
        self._process_lock = threading.Lock()  # Protects process management
        
        # Enable global process tracking for automatic cleanup
        # Process imported at top of file
        if Process is not None:
            Process.enable_process_tracking()
        
        # Import existing Wifitex modules (imported at top of file)
        # AttackAll, AttackWPA, AttackWPS, AttackPMKID, Configuration, Target imported at top
        
        # Import enhanced cracking system
        from .multi_cracker import multi_cracker
        from .wordlist_manager import wordlist_manager
        from .path_utils import get_wordlist_path
        
        # Store the get_wordlist_path function as an instance variable
        self.get_wordlist_path = get_wordlist_path
        
        self.AttackAll = AttackAll
        self.AttackWPA = AttackWPA
        self.AttackWPS = AttackWPS
        self.AttackPMKID = AttackPMKID
        self.Configuration = Configuration
        self.Target = Target
        
        # Enhanced cracking system
        self.multi_cracker = multi_cracker
        self.wordlist_manager = wordlist_manager
        
        # Terminal output capture
        self.original_stdout = None
        self.original_stderr = None
        self.terminal_capture_enabled = False
        
        # Configure Wifitex settings from GUI options
        self._configure_wifitex_settings()
    
    def is_running(self):
        """Thread-safe check if attack is running"""
        with self._state_lock:
            return self.running
    
    def set_running(self, value):
        """Thread-safe set running state"""
        with self._state_lock:
            self.running = value
    
    def should_skip(self):
        """Thread-safe check if attack should be skipped"""
        with self._state_lock:
            return self.skip_current_attack or self.should_skip_current_attack
    
    def set_skip(self, value):
        """Thread-safe set skip flag"""
        with self._state_lock:
            self.skip_current_attack = value
            self.should_skip_current_attack = value
        
    def enable_terminal_capture(self):
        """Enable terminal output capture to send to GUI"""
        import sys
        import io
        
        if not self.terminal_capture_enabled:
            self.original_stdout = sys.stdout
            self.original_stderr = sys.stderr
            
            # Create custom stdout/stderr that emit to GUI
            class TerminalCapture:
                def __init__(self, worker, stream_type, original_stream):
                    self.worker = worker
                    self.stream_type = stream_type
                    self.original_stream = original_stream
                    self.buffer = io.StringIO()
                
                def write(self, text):
                    # Write to original stream
                    if self.original_stream:
                        self.original_stream.write(text)
                        self.original_stream.flush()
                    
                    # Also emit to GUI with colors preserved
                    if text.strip():  # Only emit non-empty text
                        # Preserve ANSI color codes for GUI display
                        self.worker.terminal_output.emit(text.rstrip())
                
                def flush(self):
                    if self.original_stream:
                        self.original_stream.flush()
            
            sys.stdout = TerminalCapture(self, 'stdout', self.original_stdout)
            sys.stderr = TerminalCapture(self, 'stderr', self.original_stderr)
            self.terminal_capture_enabled = True
    
    def disable_terminal_capture(self):
        """Disable terminal output capture"""
        import sys
        
        if self.terminal_capture_enabled:
            if self.original_stdout:
                sys.stdout = self.original_stdout
            if self.original_stderr:
                sys.stderr = self.original_stderr
            self.terminal_capture_enabled = False
        
    def _configure_wifitex_settings(self):
        """Configure Wifitex settings from GUI options"""
        try:
            # Ensure Configuration is available
            if self.Configuration is None:
                logger.error("Configuration module not available; skipping settings configuration")
                return
            # Initialize Configuration if not already done
            if not self.Configuration.initialized:
                self.Configuration.initialize(load_interface=False)
            
            # Set interface dynamically - no hardcoded names
            from .utils import SystemUtils
            available_interfaces = SystemUtils.get_wireless_interfaces()
            if available_interfaces:
                self.Configuration.interface = available_interfaces[0]  # Use first available interface
            else:
                self.Configuration.interface = self.options.get('interface', None)  # No hardcoded fallback
            
            # Set timeouts from GUI - Use more reasonable defaults
            self.Configuration.wpa_attack_timeout = self.options.get('wpa_timeout', 300)  # 5 minutes
            self.Configuration.wpa_deauth_timeout = self.options.get('wpa_deauth_timeout', 20)  # 20 seconds
            
            # Debug logging for deauth timeout (only if verbose)
            # Removed debug message to reduce log spam
            # Note: WPS timeout is handled by individual attack classes
            
            # Set attack preferences with performance optimizations (from options)
            self.Configuration.wps_pixie = bool(self.options.get('wps_pixie', True))
            self.Configuration.wps_pin = bool(self.options.get('wps_pin', True))
            self.Configuration.use_bully = bool(self.options.get('use_bully', False))
            self.Configuration.wps_ignore_lock = bool(self.options.get('wps_ignore_lock', False))
            self.Configuration.use_pmkid_only = False
            self.Configuration.wps_only = False
            
            # Performance optimizations - Use more reasonable timeouts
            self.Configuration.wps_pixie_timeout = 300  # 5 minutes for pixie-dust
            # Pull PIN brute settings from UI if present
            self.Configuration.wps_pin_timeout = int(self.options.get('wps_pin_timeout', 1800))
            self.Configuration.wps_fail_threshold = int(self.options.get('wps_fail_threshold', 100))
            self.Configuration.wps_timeout_threshold = int(self.options.get('wps_timeout_threshold', 100))
            
            # Set other options
            self.Configuration.no_deauth = not self.options.get('deauth', True)
            self.Configuration.random_mac = self.options.get('random_mac', False)
            self.Configuration.verbose = 1 if self.options.get('verbose', False) else 0
            
            # Attack speed optimizations
            self.Configuration.num_deauths = 3  # Increased deauth packets for better handshake capture

            # Cracking tool preferences (from options, with safe defaults)
            self.Configuration.prefer_aircrack = bool(self.options.get('use_aircrack', True))
            self.Configuration.prefer_hashcat = bool(self.options.get('use_hashcat', False))
            
            # Set wordlist if auto-crack is enabled
            if self.options.get('crack', False):
                # Use enhanced wordlist selection
                cracking_strategy = self.options.get('cracking_strategy', 'fast')
                
                # Get recommended wordlists for the strategy
                if cracking_strategy == 'comprehensive':
                    # Use rockyou if available, otherwise fallback
                    recommended_wordlists = self.wordlist_manager.get_recommended_wordlists()
                    if recommended_wordlists:
                        # Extract rockyou wordlist path
                        rockyou_path = None
                        for path, info in recommended_wordlists:
                            if 'rockyou' in info['name'].lower():
                                rockyou_path = path
                                break
                        
                        if rockyou_path:
                            self.Configuration.wordlist = rockyou_path
                            self.log_message.emit(f"Using comprehensive wordlist: {os.path.basename(rockyou_path)}")
                        else:
                            # Fallback to project wordlist
                            project_wordlist = self._get_project_wordlist_path()
                            if project_wordlist and os.path.exists(project_wordlist):
                                self.Configuration.wordlist = project_wordlist
                                self.log_message.emit(f"Using fallback wordlist: {os.path.basename(project_wordlist)}")
                    else:
                        self.log_message.emit("Warning: No recommended wordlists found")
                else:
                    # Use project wordlist for fast attacks
                    project_wordlist = self._get_project_wordlist_path()
                    if project_wordlist and os.path.exists(project_wordlist):
                        self.Configuration.wordlist = project_wordlist
                        self.log_message.emit(f"Using fast wordlist: {os.path.basename(project_wordlist)}")
                    else:
                        self.log_message.emit("Warning: Project wordlist not found")
            else:
                # Disable wordlist if auto-crack is not enabled
                self.Configuration.wordlist = None
                self.log_message.emit("Auto-crack disabled, wordlist not set")
            
            # Override Color.pattack to capture all attack progress messages
            self._setup_attack_logging()
            
        except Exception as e:
            logger.error(f"Error configuring Wifitex settings: {e}")
    
    def _get_project_wordlist_path(self):
        """Get the project wordlist path dynamically"""
        return self.get_wordlist_path()
    
    def _setup_attack_logging(self):
        """Setup attack progress logging by overriding Color.pattack"""
        # Color imported at top of file
        # Store original pattack method (if Color available)
        self.original_pattack = getattr(Color, 'pattack', None)
        
        def pattack_wrapper(attack_type, target, attack_name, progress):
            # Create clean log message without calling original (to avoid color codes)
            essid = target.essid if hasattr(target, 'essid') and target.essid else 'unknown'
            
            # Extract progress percentage if available
            progress_percent = 0
            progress_message = progress
            
            # Try to extract percentage from progress message
            import re
            percent_match = re.search(r'(\d+)%', progress)
            if percent_match:
                progress_percent = int(percent_match.group(1))
            
            # Determine attack step
            attack_step = "Running"
            if "initializing" in progress.lower():
                attack_step = "Initializing"
                progress_percent = 5
            elif "waiting" in progress.lower() or "listening" in progress.lower():
                attack_step = "Listening"
                progress_percent = 25
            elif "attacking" in progress.lower() or "trying" in progress.lower():
                attack_step = "Attacking"
                progress_percent = 50
            elif "cracking" in progress.lower():
                attack_step = "Cracking"
                progress_percent = 75
            elif "success" in progress.lower() or "found" in progress.lower():
                attack_step = "Success"
                progress_percent = 100
            elif "failed" in progress.lower() or "error" in progress.lower():
                attack_step = "Failed"
                progress_percent = 0
            
            # Emit progress update with structured data
            progress_data = {
                'progress': progress_percent,
                'message': progress_message,
                'step': attack_step,
                'network': essid,
                'attack_type': attack_type
            }
            self.attack_progress.emit(progress_data)
            
            # Debug: Always log KARMA, WPS, PMKID, and WPA attacks
            if any(attack_type_name in attack_type for attack_type_name in ['KARMA', 'WPS', 'PMKID', 'WPA']):
                log_message = f"[{attack_type}] {essid} {attack_name}: {progress}"
                self.log_message.emit(log_message)
                return  # Don't call original pattack for these attacks
            
            # Only log meaningful progress updates, not repetitive status messages
            if self._should_log_progress(attack_name, progress):
                log_message = f"[{attack_type}] {essid} {attack_name}: {progress}"
                self.log_message.emit(log_message)
        
        # Replace the method
        if Color is not None:
            Color.pattack = pattack_wrapper
    
    def _should_log_progress(self, attack_name, progress):
        """Determine if this progress update should be logged"""
        # Allow all KARMA, WPS, PMKID, and WPA attack logs
        if any(key in attack_name for key in ['KARMA', 'WPS', 'PMKID', 'WPA']):
            return True
            
        # Skip repetitive listening messages (but allow other important messages)
        if 'Listening.' in progress and 'KARMA' not in attack_name:
            return False
        
        # Skip power level updates
        if re.match(r'^\d+db$', progress.strip()):
            return False
        
        # Skip timeout countdowns
        if re.match(r'^timeout:\d+m\d+s$', progress.strip()):
            return False
        
        # Always log important events
        if any(keyword in progress.lower() for keyword in ['failed', 'success', 'cracked', 'found', 'discovered', 'deauthing']):
            return True
        
        # Log initialization and state changes
        if any(keyword in progress.lower() for keyword in ['initializing', 'waiting', 'starting', 'stopped', 'completed']):
            return True
        
        # Log every 5th status update to reduce verbosity
        if not hasattr(self, '_status_count'):
            self._status_count = 0
        self._status_count += 1
        
        return self._status_count % 5 == 0
        
    def run(self):
        """Run the attack using existing Wifitex attack modules"""
        try:
            # Enable terminal output capture
            self.enable_terminal_capture()
            
            network = self.network
            attack_type = self.attack_type
            
            self.attack_progress.emit({
                'message': f'Starting {attack_type} attack on {network["essid"]} ({network["bssid"]})...',
                'progress': 10,
                'network': network['essid'],
                'step': 'Initializing attack'
            })
            
            # Check if attack was stopped before starting
            if not self.is_running():
                self.attack_completed.emit({
                    'success': False,
                    'message': 'Attack stopped by user',
                    'network': network,
                    'stopped': True
                })
                return
            
            # Check if attack was skipped before starting
            if self.should_skip():
                self.attack_completed.emit({
                    'success': False,
                    'message': 'Attack skipped by user',
                    'network': network,
                    'skipped': True
                })
                return
            
            # Convert GUI network dict to Wifitex Target object
            target = self._create_target_from_network(network)
            
            if attack_type == "Auto (Recommended)":
                # Use AttackAll for automatic attack selection
                self._run_auto_attack(target)
            elif attack_type == "WPA/WPA2 Handshake":
                self._run_wpa_attack(target, "WPA/WPA2 Handshake")
            elif attack_type == "WPS PIN":
                self._run_wps_attack(target, pixie_dust=False)
            elif attack_type == "WPS Pixie-Dust":
                self._run_wps_attack(target, pixie_dust=True)
            elif attack_type == "PMKID":
                self._run_pmkid_attack(target)
            elif attack_type == "KARMA Attack":
                self._run_karma_attack(target)
            else:
                self.attack_completed.emit({
                    'success': False,
                    'message': f'Unknown attack type: {attack_type}',
                    'network': network
                })
                
        except Exception as e:
            self.attack_completed.emit({
                'success': False,
                'message': f'Attack error: {str(e)}',
                'network': self.network
            })
        finally:
            # Disable terminal output capture
            self.disable_terminal_capture()
            
    def _create_target_from_network(self, network):
        """Convert GUI network dict to Wifitex Target object"""
        try:
            # Ensure Target class is available
            if self.Target is None:
                logger.error("Target class not available; cannot create target")
                return None
            # Create fields list as expected by Target constructor
            # Based on Target.__init__ documentation:
            # 0 BSSID, 1 First time seen, 2 Last time seen, 3 channel, 4 Speed,
            # 5 Privacy, 6 Cipher, 7 Authentication, 8 Power, 9 beacons,
            # 10 # IV, 11 LAN IP, 12 ID-length, 13 ESSID, 14 Key
            fields = [
                network['bssid'],                    # 0 BSSID
                '2024-01-01 00:00:00',             # 1 First time seen
                '2024-01-01 00:00:00',             # 2 Last time seen
                str(network['channel']),            # 3 channel
                '54',                               # 4 Speed
                network['encryption'],              # 5 Privacy
                'CCMP TKIP',                        # 6 Cipher
                'PSK',                              # 7 Authentication
                str(network['power']),              # 8 Power
                str(network.get('beacons', 0)),    # 9 beacons
                '0',                                # 10 # IV
                '0.0.0.0',                          # 11 LAN IP
                str(len(network['essid'])),         # 12 ID-length
                network['essid'],                   # 13 ESSID
                ''                                  # 14 Key
            ]
            
            target = self.Target(fields)
            
            # Set additional properties
            target.wps = network.get('wps', 'Unknown') == 'Yes'
            target.clients = []  # Will be populated by attack classes if needed
            
            return target
            
        except Exception as e:
            logger.error(f"Error creating target: {e}")
            return None
    
    def _create_monitored_wps_attack(self, target, pixie_dust=False):
        """Create a WPS attack with real-time output monitoring"""
        # Reaver, Bully, Configuration imported at top of file
        
        class MonitoredWPSAttack:
            def __init__(self, target, pixie_dust, worker):
                self.target = target
                self.pixie_dust = pixie_dust
                self.worker = worker
                self.success = False
                self.crack_result = None
                self.attack_thread = None
                self.result = None
                
                # Choose the appropriate tool
                reaver_cls = Reaver if Reaver is not None else None
                bully_cls = Bully if Bully is not None else None
                use_bully = bool(getattr(worker.Configuration, 'use_bully', False))
                can_pixie = True
                if reaver_cls is not None and hasattr(reaver_cls, 'is_pixiedust_supported'):
                    try:
                        can_pixie = reaver_cls.is_pixiedust_supported()
                    except Exception:
                        can_pixie = True
                # Prefer Bully when requested or when Reaver pixie not supported
                if bully_cls is not None and (
                    (pixie_dust and not can_pixie) or use_bully
                ):
                    self.tool = bully_cls(target, pixie_dust=pixie_dust)
                elif reaver_cls is not None:
                    self.tool = reaver_cls(target, pixie_dust=pixie_dust)
                elif bully_cls is not None:
                    self.tool = bully_cls(target, pixie_dust=pixie_dust)
                else:
                    self.tool = None
                
                # Note: We don't override pattack here to avoid duplicate messages
                # The Color.pattack override in AttackWorker already captures all output
            
            def run(self):
                import threading
                import time
                
                try:
                    # Check if attack was skipped before starting
                    if self.worker.should_skip():
                        self.worker.log_message.emit(f"[WPS] Attack skipped by user")
                        return False
                    
                    # Run the attack in a separate thread so we can monitor for skip requests
                    def run_attack():
                        try:
                            if self.tool is None:
                                self.result = False
                            else:
                                self.result = self.tool.run()
                        except Exception as e:
                            if self.worker.should_skip():
                                self.result = False  # Skip
                            else:
                                self.result = False  # Error
                    
                    # Start the attack in a thread
                    self.attack_thread = threading.Thread(target=run_attack)
                    self.attack_thread.daemon = True
                    self.attack_thread.start()
                    
                    # Monitor the attack thread and check for skip requests
                    monitor_timeout = 0
                    max_monitor_time = 3600  # 1 hour max monitoring time
                    check_interval = 0.1  # Check every 100ms
                    
                    while self.attack_thread.is_alive() and monitor_timeout < max_monitor_time:
                        if self.worker.should_skip():
                            # Skip requested, stop the attack
                            self.stop()
                            self.worker.log_message.emit(f"[WPS] Attack skipped by user")
                            return False  # Return False to continue to next attack type
                        
                        time.sleep(check_interval)
                        monitor_timeout += check_interval
                        
                        # Safety check to prevent infinite monitoring
                        if monitor_timeout >= max_monitor_time:
                            self.worker.log_message.emit(f"[WPS] Attack monitoring timeout reached, stopping...")
                            self.stop()
                            return False
                    
                    # Attack completed
                    self.success = self.result
                    if self.result and self.tool is not None and hasattr(self.tool, 'crack_result'):
                        self.crack_result = self.tool.crack_result
                    return self.result
                    
                except Exception as e:
                    # Check if the error is due to skipping
                    if self.worker.should_skip():
                        self.worker.log_message.emit(f"[WPS] Attack skipped by user")
                        return False
                    else:
                        self.worker.log_message.emit(f"[WPS] Error: {str(e)}")
                        return False
            
            def stop(self):
                """Stop the attack"""
                try:
                    # Track this process for cleanup
                    if hasattr(self.worker, 'active_processes') and self.tool is not None:
                        proc = getattr(self.tool, 'bully_proc', None)
                        if proc is None:
                            proc = getattr(self.tool, 'reaver_proc', None)
                        if proc is not None:
                            self.worker.active_processes.append(proc)
                    
                    # For Bully, use its stop method if available
                    if self.tool is not None:
                        stop_fn = getattr(self.tool, 'stop', None)
                        if callable(stop_fn):
                            stop_fn()
                    # For Reaver, directly interrupt the process (no stop method available)
                    elif self.tool is not None and hasattr(self.tool, 'reaver_proc'):
                        reaver_proc = getattr(self.tool, 'reaver_proc', None)
                        if reaver_proc is not None:
                            reaver_proc.interrupt()
                    # Fallback for Bully if stop() doesn't work
                    elif self.tool is not None and hasattr(self.tool, 'bully_proc'):
                        bully_proc = getattr(self.tool, 'bully_proc', None)
                        if bully_proc is not None:
                            bully_proc.interrupt()
                    
                    # Force kill if process is still running
                    import subprocess
                    try:
                        if self.tool is not None and self.tool.__class__.__name__.lower() == 'bully':
                            subprocess.run(['pkill', '-f', 'bully'], capture_output=True)
                        elif self.tool is not None and self.tool.__class__.__name__.lower() == 'reaver':
                            subprocess.run(['pkill', '-f', 'reaver'], capture_output=True)
                    except Exception:
                        pass
                        
                except Exception:
                    # Ignore errors when stopping
                    pass
        
        return MonitoredWPSAttack(target, pixie_dust, self)
    
    def _run_auto_attack(self, target):
        """Run automatic attack using optimized attack sequence"""
        try:
            self.attack_progress.emit({
                'message': f'Running optimized attack sequence on {target.essid}...',
                'step': 'Smart attack sequence',
                'progress': 20,
                'network': target.essid
            })
            
            # Check if attack was stopped before starting
            if not self.running:
                self.attack_completed.emit({
                    'success': False,
                    'message': 'Attack stopped by user',
                    'network': {'essid': target.essid, 'bssid': target.bssid},
                    'stopped': True
                })
                return
                
            # Check if attack was skipped before starting
            if self.should_skip_current_attack:
                self.attack_completed.emit({
                    'success': False,
                    'message': 'Attack skipped by user',
                    'network': {'essid': target.essid, 'bssid': target.bssid},
                    'skipped': True
                })
                return
            
            # Smart attack prioritization based on network characteristics
            success = self._run_smart_attack_sequence(target)
            
            # Check if attack was stopped during execution (but not skipped)
            if not self.running and not self.should_skip_current_attack:
                self.attack_completed.emit({
                    'success': False,
                    'message': 'Attack stopped by user',
                    'network': {'essid': target.essid, 'bssid': target.bssid},
                    'stopped': True
                })
                return
            
            # Check if attack was skipped during execution
            if self.should_skip_current_attack:
                # For Auto attacks, don't emit completion - just continue to next attack type
                # The smart attack sequence already handled the skip
                return
            
            if success:
                self.attack_completed.emit({
                    'success': True,
                    'message': f'Smart attack completed successfully on {target.essid}',
                    'network': {'essid': target.essid, 'bssid': target.bssid}
                })
            else:
                # For Auto mode, if smart attack fails, continue to next attack type
                # This allows the sequence to continue (WPS -> PMKID -> WPA/WPA2 Handshake, etc.)
                self.attack_completed.emit({
                    'success': False,
                    'message': f'Smart attack failed on {target.essid}, continuing to next attack type',
                    'network': {'essid': target.essid, 'bssid': target.bssid},
                    'continue_next': True  # Signal to continue with next attack
                })
                
        except Exception as e:
            self.attack_completed.emit({
                'success': False,
                'message': f'Smart attack error: {str(e)}',
                'network': {'essid': target.essid, 'bssid': target.bssid}
            })
    
    def force_cleanup(self):
        """Force cleanup of all active attack processes"""
        try:
            # Use global process cleanup for all tracked processes
            # Process imported at top of file
            if Process is not None:
                Process.cleanup_all_processes()
            
            # Stop all manually tracked processes
            for process_info in self.active_processes:
                try:
                    if hasattr(process_info, 'interrupt'):
                        process_info.interrupt()
                    elif hasattr(process_info, 'terminate'):
                        process_info.terminate()
                    elif hasattr(process_info, 'kill'):
                        process_info.kill()
                except Exception:
                    pass  # Ignore cleanup errors
            
            # Clear the process list
            self.active_processes.clear()
            
            # Force cleanup of current attack if it exists
            if self.current_attack:
                try:
                    if hasattr(self.current_attack, 'stop'):
                        self.current_attack.stop()
                except Exception:
                    pass
            
            # Kill any remaining attack processes by name
            import subprocess
            import signal
            try:
                # Kill common attack tools (excluding airodump-ng to avoid RF-kill issues)
                attack_tools = ['reaver', 'bully', 'aircrack-ng', 'aireplay-ng', 'hcxdumptool']
                for tool in attack_tools:
                    try:
                        subprocess.run(['pkill', '-f', tool], capture_output=True)
                    except Exception:
                        pass
            except Exception:
                pass
                
        except Exception as e:
            logger.error(f"Error during force cleanup: {e}")
    
    def stop(self):
        """Stop the attack worker aggressively"""
        self.running = False
        self.should_skip_current_attack = True
        
        # Force cleanup of all processes
        self.force_cleanup()
        
        # Additional aggressive cleanup
        try:
            import subprocess
            import os
            import signal
            
            # Kill any remaining attack processes
            attack_tools = ['reaver', 'bully', 'aircrack-ng', 'aireplay-ng', 'airodump-ng', 'hcxdumptool', 'hcxpcapngtool']
            for tool in attack_tools:
                try:
                    subprocess.run(['pkill', '-KILL', '-f', tool], capture_output=True, timeout=1)
                except Exception:
                    pass
                    
        except Exception:
            pass
    
    def continue_attack(self):
        """Continue the current attack after user decision"""
        self.pause_for_user_decision = False
        self.log_message.emit("▶️ Continuing attack...")
    
    def skip_to_next_attack_type(self):
        """Skip to next attack type after user decision"""
        self.pause_for_user_decision = False
        self.should_skip_current_attack = True
        self.log_message.emit("⏭️ Skipping to next attack type...")
        
        # Force cleanup of current attack processes
        self.force_cleanup()
    
    def stop_all_attacks(self):
        """Stop all attacks after user decision"""
        self.pause_for_user_decision = False
        self.running = False
        self.should_skip_current_attack = True
        self.log_message.emit("⏹️ Stopping all attacks...")
        self.force_cleanup()
    
    def cleanup(self):
        """Cleanup resources"""
        self.force_cleanup()
        self.running = False
        
        # Disable global process tracking
        # Process imported at top of file
        if Process is not None:
            Process.disable_process_tracking()
    
    def _run_smart_attack_sequence(self, target):
        """Run optimized attack sequence based on target characteristics"""
        try:
            # Prioritize attacks based on success probability and speed
            attack_sequence = []
            
            # WPS attacks first (fastest and most effective)
            if target.wps and self.AttackWPS is not None and self.AttackWPS.can_attack_wps():
                if self.Configuration is not None:
                    if self.Configuration.wps_pixie:
                        attack_sequence.append(('WPS Pixie-Dust', lambda: self._run_wps_attack(target, pixie_dust=True)))
                    if self.Configuration.wps_pin:
                        attack_sequence.append(('WPS PIN', lambda: self._run_wps_attack(target, pixie_dust=False)))
                else:
                    # Default to both WPS attacks if Configuration is None
                    attack_sequence.append(('WPS Pixie-Dust', lambda: self._run_wps_attack(target, pixie_dust=True)))
                    attack_sequence.append(('WPS PIN', lambda: self._run_wps_attack(target, pixie_dust=False)))
            
            # PMKID attack (fast, no client needed)
            if 'WPA' in target.encryption:
                attack_sequence.append(('PMKID', lambda: self._run_pmkid_attack(target)))
            
            # WPA handshake (requires clients, slower)
            if 'WPA' in target.encryption and (self.Configuration is None or not self.Configuration.use_pmkid_only):
                attack_sequence.append(('WPA/WPA2 Handshake', lambda: self._run_wpa_attack(target, "WPA/WPA2 Handshake")))
            
            # Run attacks in optimized sequence
            # Add safety counter to prevent infinite loops in attack sequence
            attack_sequence_iterations = 0
            max_attack_sequence_iterations = len(attack_sequence) * 10  # Allow 10x the sequence length as safety buffer
            
            for i, (attack_name, attack_func) in enumerate(attack_sequence):
                attack_sequence_iterations += 1
                
                # Safety check: prevent infinite loops in attack sequence
                if attack_sequence_iterations > max_attack_sequence_iterations:
                    self.log_message.emit(f"⚠️ Safety limit reached in attack sequence, breaking to prevent infinite loop")
                    break
                # Check if attack was stopped
                if not self.running:
                    return False
                    
                # Check if attack was paused for user decision (prevent infinite waiting)
                if self.pause_for_user_decision:
                    self.log_message.emit(f"[{attack_name}] Paused for user decision...")
                    # Wait for user decision with timeout to prevent infinite waiting
                    import time
                    timeout_counter = 0
                    max_timeout = 300  # 5 minutes max wait time
                    check_interval = 0.1  # Check every 100ms
                    
                    # Add iteration counter for additional safety
                    iteration_counter = 0
                    max_iterations = int(max_timeout / check_interval) + 100  # Extra buffer
                    
                    while self.pause_for_user_decision and self.is_running() and timeout_counter < max_timeout:
                        time.sleep(check_interval)
                        timeout_counter += check_interval
                        iteration_counter += 1
                        
                        # Additional safety check to prevent infinite loops
                        if timeout_counter >= max_timeout or iteration_counter >= max_iterations:
                            break
                    
                    # If timeout reached, auto-continue
                    if timeout_counter >= max_timeout:
                        self.log_message.emit(f"[{attack_name}] Timeout waiting for user decision, continuing...")
                        self.pause_for_user_decision = False
                    
                    # After user decision or timeout, check if we should continue or skip
                    if self.should_skip_current_attack:
                        self.log_message.emit(f"[{attack_name}] Skipped by user decision, continuing to next attack type...")
                        continue
                    elif not self.running:
                        return False
                    
                # Check if attack was skipped
                if self.should_skip_current_attack:
                    # Skip this attack type and continue to next
                    self.log_message.emit(f"[{attack_name}] Skipped by user, continuing to next attack type...")
                    continue
                    
                self.attack_progress.emit({
                    'message': f'Running {attack_name} attack...',
                    'step': attack_name,
                    'progress': int(30 + (i * 20 / len(attack_sequence))),
                    'network': target.essid
                })
                
                try:
                    # Double-check skip before executing attack
                    if self.should_skip_current_attack:
                        self.log_message.emit(f"[{attack_name}] Skipped by user, continuing to next attack type...")
                        continue
                    
                    result = attack_func()
                    
                    # Check skip after attack execution
                    if self.should_skip_current_attack:
                        self.log_message.emit(f"[{attack_name}] Skipped by user, continuing to next attack type...")
                        continue
                    
                    if result:
                        return True  # Attack succeeded
                    else:
                        # Attack failed, continue to next attack type
                        self.log_message.emit(f"[{attack_name}] Failed, continuing to next attack type...")
                        continue
                except Exception as e:
                    # Check if error is due to skipping
                    if self.should_skip_current_attack:
                        self.log_message.emit(f"[{attack_name}] Skipped by user, continuing to next attack type...")
                        continue
                    else:
                        self.log_message.emit(f"[{attack_name}] Error: {str(e)}, continuing to next attack type...")
                        continue
            
            return False  # All attacks failed
            
        except Exception as e:
            self.log_message.emit(f"Smart attack sequence error: {str(e)}")
            return False
            
    def _run_wpa_attack(self, target, attack_name="WPA/WPA2 Handshake"):
        """Run WPA handshake attack using AttackWPA"""
        try:
            self.attack_progress.emit({
                'message': f'Starting {attack_name} attack on {target.essid}...',
                'step': f'{attack_name} capture',
                'progress': 30,
                'network': target.essid
            })
            
            if self.AttackWPA is None:
                self.attack_completed.emit({
                    'success': False,
                    'message': f'{attack_name} not available (module missing)',
                    'network': {'essid': target.essid, 'bssid': target.bssid}
                })
                return
            attack = self.AttackWPA(target)
            result = attack.run()
            
            if result and attack.success:
                self.attack_completed.emit({
                    'success': True,
                    'message': f'{attack_name} captured for {target.essid}',
                    'network': {'essid': target.essid, 'bssid': target.bssid}
                })
            else:
                self.attack_completed.emit({
                    'success': False,
                    'message': f'{attack_name} attack failed for {target.essid}',
                    'network': {'essid': target.essid, 'bssid': target.bssid}
                })
            
        except Exception as e:
            self.attack_completed.emit({
                'success': False,
                'message': f'{attack_name} attack error: {str(e)}',
                'network': {'essid': target.essid, 'bssid': target.bssid}
            })
            
    def _run_wps_attack(self, target, pixie_dust=False):
        """Run WPS attack using monitored attack with real-time logging"""
        try:
            attack_name = "WPS Pixie-Dust" if pixie_dust else "WPS PIN"
            self.attack_progress.emit({
                'message': f'Starting {attack_name} attack on {target.essid}...',
                'step': f'{attack_name} attack',
                'progress': 30,
                'network': target.essid
            })
            
            # Use the monitored attack for real-time logging
            attack = self._create_monitored_wps_attack(target, pixie_dust=pixie_dust)
            self.current_attack = attack
            result = attack.run()
            
            if result and attack.success:
                self.attack_completed.emit({
                    'success': True,
                    'message': f'{attack_name} attack successful on {target.essid}',
                    'network': {'essid': target.essid, 'bssid': target.bssid},
                    'crack_result': attack.crack_result
                })
            else:
                self.attack_completed.emit({
                    'success': False,
                    'message': f'{attack_name} attack failed for {target.essid}',
                    'network': {'essid': target.essid, 'bssid': target.bssid}
                })
            
        except Exception as e:
            self.attack_completed.emit({
                'success': False,
                'message': f'WPS attack error: {str(e)}',
                'network': {'essid': target.essid, 'bssid': target.bssid}
            })
            
    def _run_pmkid_attack(self, target):
        """Run PMKID attack using AttackPMKID"""
        try:
            # Check if attack was stopped before starting
            if not self.running:
                return False
                
            # Check if attack was skipped before starting
            if self.should_skip_current_attack:
                self.log_message.emit(f"[PMKID] Attack skipped by user")
                return False
                
            self.attack_progress.emit({
                'message': f'Starting PMKID attack on {target.essid}...',
                'step': 'PMKID capture',
                'progress': 30,
                'network': target.essid
            })
            
            if self.AttackPMKID is None:
                self.attack_completed.emit({
                    'success': False,
                    'message': 'PMKID attack not available (module missing)',
                    'network': {'essid': target.essid, 'bssid': target.bssid}
                })
                return False
            attack = self.AttackPMKID(target)
            
            # Set the running and skip flags on the attack instance
            attack.running = self.running
            attack.skip_current_attack = self.skip_current_attack
            
            # Track the attack process for cleanup (if available)
            # Note: AttackPMKID doesn't have a direct process attribute, skip tracking
            pass
            
            result = attack.run()
            
            # Check if attack was stopped or skipped during execution
            if not self.running:
                self.log_message.emit(f"[PMKID] Attack stopped by user")
                return False
                
            if self.should_skip_current_attack:
                self.log_message.emit(f"[PMKID] Attack skipped by user")
                return False
            
            if result and attack.success:
                self.attack_completed.emit({
                    'success': True,
                    'message': f'PMKID captured for {target.essid}',
                    'network': {'essid': target.essid, 'bssid': target.bssid}
                })
                return True
            else:
                self.attack_completed.emit({
                    'success': False,
                    'message': f'PMKID attack failed for {target.essid}',
                    'network': {'essid': target.essid, 'bssid': target.bssid}
                })
                return False
                
        except Exception as e:
            # Check if the error is due to skipping
            if self.should_skip_current_attack:
                self.log_message.emit(f"[PMKID] Attack skipped by user")
                return False
            else:
                self.attack_completed.emit({
                    'success': False,
                    'message': f'PMKID attack error: {str(e)}',
                    'network': {'essid': target.essid, 'bssid': target.bssid}
                })
                return False
    
    def _run_karma_attack(self, target):
        """Run KARMA attack using AttackKARMA"""
        try:
            # Check if attack was stopped before starting
            if not self.running:
                return False
                
            # Check if attack was skipped before starting
            if self.should_skip_current_attack:
                self.log_message.emit(f"[KARMA] Attack skipped by user")
                return False
                
            self.attack_progress.emit({
                'message': f'Starting KARMA attack on {target.essid}...',
                'step': 'KARMA PNL capture and rogue AP',
                'progress': 30,
                'network': target.essid
            })
            
            # Import KARMA attack class (imported at top of file)
            # AttackKARMA imported at top
            
            # Check if KARMA attack is possible before starting
            if AttackKARMA is None or not getattr(AttackKARMA, 'can_attack_karma', lambda: False)():
                self.attack_completed.emit({
                    'success': False,
                    'message': f'KARMA attack not available - missing required dependencies',
                    'network': {'essid': target.essid, 'bssid': target.bssid}
                })
                return False
            
            # Configure KARMA-specific settings from GUI options
            # Import global Configuration to set values that KARMA attack will use
            # Configuration imported at top of file
            # Configuration imported at top of file
            
            if Configuration is not None:
                Configuration.use_karma = True
                Configuration.karma_probe_timeout = self.options.get('karma_probe_timeout', 60)
                Configuration.karma_min_probes = self.options.get('karma_min_probes', 1)
                Configuration.karma_capture_all_channels = self.options.get('karma_all_channels', False)
                Configuration.karma_dns_spoofing = self.options.get('karma_dns_spoofing', False)  # Changed default from True to False
                
                # Debug: Log what we're setting
                self.log_message.emit(f"[KARMA] Setting Configuration values:")
                self.log_message.emit(f"[KARMA]   karma_probe_timeout: {Configuration.karma_probe_timeout}")
                self.log_message.emit(f"[KARMA]   karma_min_probes: {Configuration.karma_min_probes}")
                self.log_message.emit(f"[KARMA]   karma_capture_all_channels: {Configuration.karma_capture_all_channels}")
                self.log_message.emit(f"[KARMA]   karma_dns_spoofing: {Configuration.karma_dns_spoofing}")
                
                # Use dynamic interface detection for KARMA attack
                from .utils import SystemUtils
                available_interfaces = SystemUtils.get_wireless_interfaces()
                if available_interfaces:
                    interface = available_interfaces[0]
                else:
                    interface = self.options.get('interface', None)
                
                # Use the shared Configuration object as the global config store
                setattr(Configuration, 'karma_rogue_interface', interface)
                setattr(Configuration, 'karma_probe_interface', interface)
            else:
                # Fallback when Configuration is None
                from .utils import SystemUtils
                available_interfaces = SystemUtils.get_wireless_interfaces()
                if available_interfaces:
                    interface = available_interfaces[0]
                else:
                    interface = self.options.get('interface', None)
            
            # Also set on local Configuration for logging (if available)
            if self.Configuration is not None:
                self.Configuration.use_karma = True
                self.Configuration.karma_probe_timeout = self.options.get('karma_probe_timeout', 60)
                self.Configuration.karma_min_probes = self.options.get('karma_min_probes', 1)
                self.Configuration.karma_capture_all_channels = self.options.get('karma_all_channels', False)
                self.Configuration.karma_dns_spoofing = self.options.get('karma_dns_spoofing', True)
                self.Configuration.karma_rogue_interface = interface
                self.Configuration.karma_probe_interface = interface
            
            attack = AttackKARMA(target)
            
            # Set the running flag on the attack instance
            attack.running = self.running
            attack.target = target  # Ensure target is properly set for logging
            
            # Log KARMA attack configuration
            self.log_message.emit(f"[KARMA] Starting attack on {target.essid}")
            if Configuration is not None:
                self.log_message.emit(f"[KARMA] Probe timeout: {getattr(Configuration, 'karma_probe_timeout', 60)}s")
                self.log_message.emit(f"[KARMA] Min probes required: {getattr(Configuration, 'karma_min_probes', 1)}")
                self.log_message.emit(f"[KARMA] Interface: {getattr(Configuration, 'karma_rogue_interface', interface)}")
            else:
                self.log_message.emit(f"[KARMA] Probe timeout: {self.options.get('karma_probe_timeout', 60)}s")
                self.log_message.emit(f"[KARMA] Min probes required: {self.options.get('karma_min_probes', 1)}")
                self.log_message.emit(f"[KARMA] Interface: {interface}")
            
            
            result = attack.run()
            
            # Check if attack was stopped or skipped during execution
            if not self.running:
                self.log_message.emit(f"[KARMA] Attack stopped by user")
                return False
                
            if self.should_skip_current_attack:
                self.log_message.emit(f"[KARMA] Attack skipped by user")
                return False
            
            # Check for specific failure reasons
            if not result:
                # Check if it failed due to insufficient probe requests
                if Configuration is not None:
                    min_probes = getattr(Configuration, 'karma_min_probes', 1)
                else:
                    min_probes = self.options.get('karma_min_probes', 1)
                
                if len(getattr(attack, 'pnl_networks', [])) < min_probes:
                    failure_reason = f"Only captured {len(getattr(attack, 'pnl_networks', []))} probe requests, need at least {min_probes}"
                    self.log_message.emit(f"[KARMA] {failure_reason}")
                    self.attack_completed.emit({
                        'success': False,
                        'message': f'KARMA attack failed: {failure_reason}',
                        'network': {'essid': target.essid, 'bssid': target.bssid}
                    })
                    return False
                else:
                    # Generic failure
                    self.attack_completed.emit({
                        'success': False,
                        'message': f'KARMA attack failed for {target.essid}',
                        'network': {'essid': target.essid, 'bssid': target.bssid}
                    })
                    return False
            
            if result and attack.success:
                self.attack_completed.emit({
                    'success': True,
                    'message': f'KARMA attack completed for {target.essid}',
                    'network': {'essid': target.essid, 'bssid': target.bssid}
                })
                return True
            else:
                self.attack_completed.emit({
                    'success': False,
                    'message': f'KARMA attack failed for {target.essid}',
                    'network': {'essid': target.essid, 'bssid': target.bssid}
                })
                return False
                
        except Exception as e:
            # Check if the error is due to skipping
            if self.should_skip_current_attack:
                self.log_message.emit(f"[KARMA] Attack skipped by user")
                return False
            else:
                self.attack_completed.emit({
                    'success': False,
                    'message': f'KARMA attack error: {str(e)}',
                    'network': {'essid': target.essid, 'bssid': target.bssid}
                })
                return False
    
    def __del__(self):
        """Ensure thread cleanup on destruction"""
        try:
            if hasattr(self, 'running'):
                self.running = False
            
            # Restore original pattack method (only if Python is not shutting down)
            if hasattr(self, 'original_pattack') and self.original_pattack is not None:
                try:
                    import sys
                    if sys.meta_path is not None:  # Check if Python is shutting down
                        # Color imported at top of file
                        if Color is not None:
                            Color.pattack = self.original_pattack
                except (ImportError, AttributeError):
                    # Ignore import errors during shutdown
                    pass
        except Exception:
            # Ignore all errors during destruction
            pass