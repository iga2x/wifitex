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
import shutil
import uuid
from pathlib import Path
from typing import List, Dict, Optional, Any, Callable, Tuple
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
    QPushButton, QProgressBar, QTextEdit, QListWidget,
    QListWidgetItem, QGroupBox, QFrame, QScrollArea, QComboBox,
    QSpinBox, QCheckBox, QFileDialog, QDialog, QDialogButtonBox,
    QMessageBox, QTabWidget, QTextBrowser, QLineEdit, QApplication
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QPropertyAnimation,
    QEasingCurve, QRect, QObject
)
from PyQt6.QtGui import QFont, QPixmap, QPainter, QColor, QTextCursor

from .error_handler import handle_errors, NetworkError, InterfaceError, ToolError
from .logger import get_logger
from .log_formatter import LogFormatter
from .utils import SystemUtils

# Import commonly used modules to avoid circular imports and improve performance
try:
    from ..config import Configuration
    from ..util.process import Process
    from ..util.color import Color
    from ..attack.all import AttackAll
    from ..attack.wpa import AttackWPA
    from ..attack.wps import AttackWPS
    from ..attack.pmkid import AttackPMKID
    from ..model.target import Target, WPSState
    from ..model.handshake import Handshake
    from ..model.wpa_result import CrackResultWPA
    from ..model.pmkid_result import CrackResultPMKID
    from ..model.result import CrackResult
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
    Target = None
    WPSState = None
    Handshake = None
    CrackResultWPA = None
    CrackResultPMKID = None
    CrackResult = None
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
                   scan_24: bool = True, scan_5: bool = False, scan_6: bool = False,
                   scan_duration: int = 60):
        """Start network scanning using real Wifitex tools"""
        if self.scanning:
            return
            
        self.scanning = True
        self.scan_started.emit()
        
        # Start scan in separate thread using unified CLI scanning
        self.scan_thread = UnifiedScanWorker(
            interface,
            channel,
            scan_24=scan_24,
            scan_5=scan_5,
            scan_6=scan_6,
            scan_duration=scan_duration
        )
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
                
            # Reset global abort flag before starting new attacks
            try:
                if Configuration is not None:
                    Configuration.abort_requested = False
            except Exception:
                pass

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
        
        # Ensure channel is passed to options for 5GHz network attacks
        if current_network.get('channel'):
            options['channel'] = current_network['channel']
        
        # Start attack in separate thread
        self.attack_thread = AttackWorker(current_network, attack_type, options, all_networks=self.attack_queue)
        self.attack_thread.attack_progress.connect(self.attack_progress.emit)
        self.attack_thread.attack_completed.connect(self.on_attack_completed)
        self.attack_thread.log_message.connect(self.log_message.emit)
        self.attack_thread.terminal_output.connect(self.log_message.emit)  # Capture all terminal output
        self.attack_thread.start()
        
    def stop_attack(self):
        """Stop current attack instantly - same as CLI Ctrl+C behavior."""
        self.log_message.emit("🛑 Stop requested (GUI) — killing attack processes immediately...")

        try:
            if Configuration is not None:
                Configuration.abort_requested = True
        except Exception:
            pass

        attack_thread_to_stop = None
        lock_acquired = False

        try:
            try:
                lock_acquired = self._attack_lock.acquire(timeout=0.1)  # Reduced from 0.5
            except TypeError:
                try:
                    lock_acquired = self._attack_lock.acquire(blocking=False)
                except Exception:
                    lock_acquired = False

            if lock_acquired:
                attack_thread_to_stop = self.attack_thread
                self.attacking = False
            else:
                self.attacking = False
                attack_thread_to_stop = getattr(self, 'attack_thread', None)
        finally:
            if lock_acquired:
                try:
                    self._attack_lock.release()
                except Exception:
                    pass

        # Immediately force cleanup all processes (like CLI)
        if attack_thread_to_stop:
            try:
                if hasattr(attack_thread_to_stop, 'stop'):
                    attack_thread_to_stop.stop()
            except Exception:
                pass

            try:
                if hasattr(attack_thread_to_stop, 'force_cleanup'):
                    attack_thread_to_stop.force_cleanup()
            except Exception:
                pass

            try:
                if hasattr(attack_thread_to_stop, 'set_skip'):
                    attack_thread_to_stop.set_skip(True)
            except Exception:
                pass

            try:
                attack_thread_to_stop.should_skip_current_attack = True
                attack_thread_to_stop.skip_current_attack = True
            except Exception:
                pass

            try:
                if hasattr(attack_thread_to_stop, 'set_running'):
                    attack_thread_to_stop.set_running(False)
                else:
                    attack_thread_to_stop.running = False
            except Exception:
                pass

            try:
                attack_thread_to_stop.stop_requested = True
            except Exception:
                pass

            try:
                if hasattr(attack_thread_to_stop, 'disable_terminal_capture'):
                    attack_thread_to_stop.disable_terminal_capture()
            except Exception:
                pass

            try:
                attack_thread_to_stop.terminate()
            except Exception:
                pass

        # Force cleanup all tracked processes immediately
        try:
            from ..util.process import Process
            Process.cleanup_all_processes()
        except Exception:
            pass

        self.attack_thread = None

        try:
            self.attack_completed.emit({
                'success': False,
                'message': 'Attack stopped by user',
                'network': {'essid': 'Current attack', 'bssid': 'N/A'},
                'stopped': True,
                'all_completed': True
            })
        except Exception:
            pass

        self.log_message.emit("✅ Attack stopped")
    
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
    def cleanup_all_processes(self):
        """Cleanup all attack processes - call this when GUI is closed"""
        self.log_message.emit("🧹 Cleaning up attack worker state...")
        
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
        
        if result.get('stopped', False):
            self.attacking = False
            self.attack_completed.emit(result)
            self.log_message.emit("🛑 Attack stopped by user (graceful).")
            return
        
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
                # Launch next attack immediately using previous context
                if hasattr(self, 'attack_thread') and self.attack_thread:
                    next_type = getattr(self.attack_thread, 'attack_type', None)
                    next_options = getattr(self.attack_thread, 'options', None)
                    if next_type and next_options is not None:
                        # Ensure we are not still referencing old thread
                        self.attack_thread = None
                        self._start_next_attack(next_type, next_options)
                    else:
                        self.log_message.emit("⚠️ Unable to continue: missing attack context")
        
        # If attack failed and we're not continuing, ensure proper cleanup
        elif not result.get('success', False) and not result.get('continue_next', False):
            # Attack failed and we're not continuing - ensure cleanup
            self.log_message.emit("Attack failed, cleaning up tracked processes...")
            
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
        general_layout.setColumnStretch(1, 1)  # Make second column expandable
        
        # Interface settings
        general_layout.addWidget(QLabel("Default Interface:"), 0, 0)
        self.interface_combo = QComboBox()
        general_layout.addWidget(self.interface_combo, 0, 1)
        
        # Attack timeouts
        general_layout.addWidget(QLabel("WPA Timeout:"), 1, 0)
        self.wpa_timeout_spin = QSpinBox()
        self.wpa_timeout_spin.setRange(60, 3600)
        self.wpa_timeout_spin.setValue(300)  # 5 minutes instead of 500
        general_layout.addWidget(self.wpa_timeout_spin, 1, 1)

        # Scan band selection
        general_layout.addWidget(QLabel("Scan Bands:"), 2, 0)
        band_layout = QHBoxLayout()
        band_layout.setContentsMargins(0, 0, 0, 0)
        self.scan_24_cb = QCheckBox("2.4 GHz")
        self.scan_24_cb.setChecked(True)
        band_layout.addWidget(self.scan_24_cb)
        self.scan_5_cb = QCheckBox("5 GHz")
        self.scan_5_cb.setChecked(True)
        band_layout.addWidget(self.scan_5_cb)
        self.scan_6_cb = QCheckBox("6 GHz")
        self.scan_6_cb.setChecked(False)
        band_layout.addWidget(self.scan_6_cb)
        band_layout.addStretch()
        general_layout.addLayout(band_layout, 2, 1)
        
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
        wps_layout.setColumnStretch(1, 1)  # Make second column expandable

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
        
        # Update GPU info when UI is shown
        from PyQt6.QtCore import QTimer
        QTimer.singleShot(500, self._update_gpu_info)
        
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
        
        # Brute Force Attack section
        brute_group = QGroupBox("Brute Force Attack (GPU-Accelerated)")
        brute_layout = QVBoxLayout(brute_group)
        
        # Enable brute force
        self.brute_force_cb = QCheckBox("Enable Brute Force Attack")
        self.brute_force_cb.setChecked(False)
        self.brute_force_cb.setToolTip("Try all possible password combinations using mask patterns (requires GPU for good performance)")
        brute_layout.addWidget(self.brute_force_cb)
        
        # Brute force mode
        brute_mode_layout = QHBoxLayout()
        brute_mode_layout.addWidget(QLabel("Attack Mode:"))
        self.brute_mode_combo = QComboBox()
        self.brute_mode_combo.addItems([
            "Dictionary Attack (Mode 0)",
            "Pure Brute Force (Mode 3)",
            "Hybrid: Wordlist + Mask (Mode 6)",
            "Hybrid: Mask + Wordlist (Mode 7)"
        ])
        brute_mode_layout.addWidget(self.brute_mode_combo)
        brute_layout.addLayout(brute_mode_layout)
        
        # Pre-defined mask patterns
        self.mask_patterns = {
            # Digits (Fast)
            "6 Digits (Very Fast)": "?d?d?d?d?d?d",
            "8 Digits Only (Fast)": "?d?d?d?d?d?d?d?d",
            "10 Digits (Phone/ID)": "?d?d?d?d?d?d?d?d?d?d",
            "12 Digits (Credit Card)": "?d?d?d?d?d?d?d?d?d?d?d?d",
            "13 Digits (Common ID)": "?d?d?d?d?d?d?d?d?d?d?d?d?d",
            
            # Lowercase (Medium Speed)
            "6 Lowercase": "?l?l?l?l?l?l",
            "8 Lowercase (Common)": "?l?l?l?l?l?l?l?l",
            "10 Lowercase": "?l?l?l?l?l?l?l?l?l?l",
            
            # Uppercase
            "8 Uppercase": "?u?u?u?u?u?u?u?u",
            
            # Mixed Case (Common Pattern)
            "8 Mixed Case (First Upper)": "?u?l?l?l?l?l?l?l",
            "8 Mixed Case (2 Upper)": "?u?u?l?l?l?l?l?l",
            "8 Mixed Case (Random)": "?u?l?l?u?l?l?u?l",
            
            # Mixed Case + Digits (Very Common)
            "8 Mixed + 1 Digit": "?u?l?l?l?l?l?l?d",
            "8 Mixed + 2 Digits": "?u?l?l?l?l?d?d",
            "8 Lowercase + 2 Digits": "?l?l?l?l?l?l?d?d",
            "10 Lowercase + 2 Digits": "?l?l?l?l?l?l?l?l?d?d",
            
            # With Special Characters
            "8 Mixed + Special": "?u?l?l?l?l?l?l?s",
            "8 Mixed + Digit + Special": "?u?l?l?l?l?l?d?s",
            "10 Complex Password": "?u?l?l?l?l?l?d?d?s?l",
            
            # Common Patterns
            "Year Pattern (20XX)": "?d?d?d?d",
            "PIN + Letters": "?d?d?d?d?l?l?l?l",
            "Name + Year": "?u?l?l?l?d?d?d?d",
            "Password + Numbers": "?l?l?l?l?l?l?l?d?d",
            
            # Length Variants
            "12 Mixed + Digits": "?u?l?l?l?l?l?l?l?d?d?d",
            "16 Mixed + Digits": "?u?l?l?l?l?l?l?l?l?l?l?l?d?d?d?d",
            "20 Mixed + Special": "?u?l?l?l?l?l?l?l?l?l?l?l?l?l?l?l?l?l?s?s",
            
            # Slow but Comprehensive
            "6 All ASCII": "?a?a?a?a?a?a",
            "8 All ASCII (Slow)": "?a?a?a?a?a?a?a?a",
            "10 All ASCII (Very Slow)": "?a?a?a?a?a?a?a?a?a?a",
            
            # Custom Pattern (User-defined)
            "Custom Pattern": ""
        }
        
        mask_layout = QHBoxLayout()
        mask_layout.addWidget(QLabel("Mask Pattern:"))
        self.mask_combo = QComboBox()
        self.mask_combo.addItems(list(self.mask_patterns.keys()))
        self.mask_combo.currentTextChanged.connect(self._on_mask_combo_changed)
        mask_layout.addWidget(self.mask_combo)
        brute_layout.addLayout(mask_layout)
        
        # Custom mask input (hidden by default)
        custom_mask_layout = QHBoxLayout()
        custom_mask_layout.addWidget(QLabel("Custom Mask:"))
        self.custom_mask_edit = QLineEdit()
        self.custom_mask_edit.setPlaceholderText("e.g. ?d?d?d?d?l?l?l?l")
        self.custom_mask_edit.setVisible(False)
        custom_mask_layout.addWidget(self.custom_mask_edit)
        brute_layout.addLayout(custom_mask_layout)
        
        # Password length constraints
        length_layout = QHBoxLayout()
        length_layout.addWidget(QLabel("Min Length:"))
        self.brute_min_length_spin = QSpinBox()
        self.brute_min_length_spin.setRange(8, 64)
        self.brute_min_length_spin.setValue(8)
        self.brute_min_length_spin.setToolTip("Minimum password length (WPA minimum is 8)")
        length_layout.addWidget(self.brute_min_length_spin)
        
        length_layout.addWidget(QLabel("Max Length:"))
        self.brute_max_length_spin = QSpinBox()
        self.brute_max_length_spin.setRange(8, 64)
        self.brute_max_length_spin.setValue(20)
        self.brute_max_length_spin.setToolTip("Maximum password length (WPA maximum is 64)")
        length_layout.addWidget(self.brute_max_length_spin)
        brute_layout.addLayout(length_layout)
        
        # Timeout
        timeout_layout = QHBoxLayout()
        timeout_layout.addWidget(QLabel("Timeout (minutes):"))
        self.brute_timeout_spin = QSpinBox()
        self.brute_timeout_spin.setRange(1, 1440)  # 1 minute to 24 hours
        self.brute_timeout_spin.setValue(60)  # 1 hour default
        self.brute_timeout_spin.setToolTip("Maximum time to spend on brute force before giving up")
        timeout_layout.addWidget(self.brute_timeout_spin)
        brute_layout.addLayout(timeout_layout)
        
        # GPU info
        self.gpu_info_label = QLabel("GPU: Checking...")
        self.gpu_info_label.setStyleSheet("color: #888")
        brute_layout.addWidget(self.gpu_info_label)
        
        cracking_layout.addWidget(brute_group)
        
        # Update GPU info after UI is setup
        self._update_gpu_info()
        
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
        
        # Custom wordlist folder selection
        self.custom_wordlist_enabled_cb = QCheckBox("Enable Custom Wordlist Folder")
        self.custom_wordlist_enabled_cb.setChecked(False)
        self.custom_wordlist_enabled_cb.setToolTip("Add additional wordlists from a custom folder")
        cracking_layout.addWidget(self.custom_wordlist_enabled_cb)
        
        # Custom folder path selection
        custom_folder_layout = QHBoxLayout()
        self.custom_wordlist_path_label = QLabel("Custom Folder: Not selected")
        self.custom_wordlist_path_label.setStyleSheet("color: #888")
        custom_folder_layout.addWidget(self.custom_wordlist_path_label)
        
        self.browse_wordlist_btn = QPushButton("Browse...")
        self.browse_wordlist_btn.clicked.connect(self._browse_wordlist_folder)
        self.browse_wordlist_btn.setEnabled(False)
        custom_folder_layout.addWidget(self.browse_wordlist_btn)
        cracking_layout.addLayout(custom_folder_layout)
        
        # Connect checkbox to enable/disable browse button
        self.custom_wordlist_enabled_cb.toggled.connect(self._on_custom_wordlist_toggled)
        
        # Store custom wordlist paths
        self.custom_wordlist_paths = []
        self.custom_wordlist_folder = None
        
        # Cracking tools
        cracking_layout.addWidget(QLabel("Cracking Tools:"))
        self.aircrack_cb = QCheckBox("Aircrack-ng")
        self.aircrack_cb.setChecked(True)
        cracking_layout.addWidget(self.aircrack_cb)
        
        self.hashcat_cb = QCheckBox("Hashcat")
        self.hashcat_cb.setChecked(True)
        cracking_layout.addWidget(self.hashcat_cb)
        
        layout.addWidget(cracking_group)
        
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
        
        # Populate interfaces before loading settings
        self._populate_interface_combo()

        # Add settings persistence methods
        self.load_default_settings()
        
        # Connect signals to auto-save settings when changed
        self.connect_settings_signals()
        
        # Add stretch to push everything to top
        layout.addStretch()
        
        # Set proper sizing for form elements
        self.setup_form_sizing()
    
    def setup_form_sizing(self):
        """Setup proper sizing for form elements"""
        # Set minimum widths for combo boxes and spin boxes
        self.interface_combo.setMinimumWidth(150)
        self.wpa_timeout_spin.setMinimumWidth(80)
        self.wpa_deauth_timeout_spin.setMinimumWidth(80)
        self.wps_timeout_spin.setMinimumWidth(80)
        self.wps_pin_timeout_spin.setMinimumWidth(80)
        self.wps_fail_thresh_spin.setMinimumWidth(80)
        self.wps_timeout_thresh_spin.setMinimumWidth(80)
        self.cracking_strategy_combo.setMinimumWidth(200)
        self.wordlist_combo.setMinimumWidth(250)
    
    def _populate_interface_combo(self, preferred: Optional[str] = None):
        """Populate the default interface combo box with available interfaces."""
        interfaces: List[str] = []
        try:
            interfaces = SystemUtils.get_wireless_interfaces() or []
        except Exception as exc:
            logger.warning(f"Failed to enumerate wireless interfaces: {exc}")
            interfaces = []
        
        current_text = preferred or self.interface_combo.currentText()
        self.interface_combo.blockSignals(True)
        self.interface_combo.clear()
        
        if interfaces:
            seen = set()
            for iface in interfaces:
                if iface and iface not in seen:
                    self.interface_combo.addItem(iface)
                    seen.add(iface)
        else:
            # Leave an empty entry to avoid saving placeholder text as interface name
            self.interface_combo.addItem("")
        
        if current_text:
            index = self.interface_combo.findText(current_text)
            if index >= 0:
                self.interface_combo.setCurrentIndex(index)
            elif preferred and preferred not in interfaces:
                # Append preferred interface if it is not currently available
                self.interface_combo.addItem(preferred)
                self.interface_combo.setCurrentIndex(self.interface_combo.count() - 1)
        
        self.interface_combo.blockSignals(False)
    
    def _update_custom_wordlist_label(self):
        """Update the custom wordlist label and styling based on current paths."""
        if not self.custom_wordlist_enabled_cb.isChecked():
            self.custom_wordlist_path_label.setText("Custom Folder: Not selected")
            self.custom_wordlist_path_label.setStyleSheet("color: #888")
            return
        
        paths = [p for p in (self.custom_wordlist_paths or []) if p]
        folder = self.custom_wordlist_folder
        if not folder and paths:
            folder = os.path.dirname(paths[0])
        
        if paths:
            folder_name = os.path.basename(folder) if folder else "Custom"
            self.custom_wordlist_path_label.setText(
                f"Custom Folder: {folder_name} ({len(paths)} wordlists found)"
            )
            self.custom_wordlist_path_label.setStyleSheet("color: #51cf66")
        elif folder:
            folder_name = os.path.basename(folder)
            self.custom_wordlist_path_label.setText(
                f"Custom Folder: {folder_name} (No wordlists found)"
            )
            self.custom_wordlist_path_label.setStyleSheet("color: #ffa94d")
        else:
            self.custom_wordlist_path_label.setText("Custom Folder: Not selected")
            self.custom_wordlist_path_label.setStyleSheet("color: #888")
    
    def set_config_manager(self, config_manager):
        """Set the configuration manager for persistence"""
        self.config_manager = config_manager
        self.load_settings()
    
    def load_default_settings(self):
        """Load default settings if no config manager is available"""
        self.reset_to_defaults()
    
    def load_settings(self):
        """Load settings from persistent storage"""
        if not self.config_manager:
            return
            
        try:
            settings = self.config_manager.load_settings()
            
            preferred_interface = settings.get('default_interface')
            self._populate_interface_combo(preferred_interface)

            # Load general settings
            if 'default_interface' in settings:
                index = self.interface_combo.findText(settings['default_interface'])
                if index >= 0:
                    self.interface_combo.setCurrentIndex(index)
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
            if 'scan_band_24ghz' in settings:
                self.scan_24_cb.setChecked(bool(settings['scan_band_24ghz']))
            if 'scan_band_5ghz' in settings:
                self.scan_5_cb.setChecked(bool(settings['scan_band_5ghz']))
            if 'scan_band_6ghz' in settings:
                self.scan_6_cb.setChecked(bool(settings['scan_band_6ghz']))
                
            # Load WPS settings
            if 'wps_pixie_dust' in settings:
                self.wps_pixie_cb.setChecked(settings['wps_pixie_dust'])
            if 'wps_pin_brute_force' in settings:
                self.wps_pin_cb.setChecked(settings['wps_pin_brute_force'])
            if 'wps_use_bully' in settings:
                self.wps_use_bully_cb.setChecked(settings['wps_use_bully'])
            if 'wps_ignore_lock' in settings:
                self.wps_ignore_lock_cb.setChecked(settings['wps_ignore_lock'])
            if 'wps_pin_timeout' in settings:
                self.wps_pin_timeout_spin.setValue(settings['wps_pin_timeout'])
            if 'wps_fail_threshold' in settings:
                self.wps_fail_thresh_spin.setValue(settings['wps_fail_threshold'])
            if 'wps_timeout_threshold' in settings:
                self.wps_timeout_thresh_spin.setValue(settings['wps_timeout_threshold'])
                
            # Load password cracking settings
            if 'cracking_strategy' in settings:
                index = self.cracking_strategy_combo.findText(settings['cracking_strategy'])
                if index >= 0:
                    self.cracking_strategy_combo.setCurrentIndex(index)
            if 'primary_wordlist' in settings:
                index = self.wordlist_combo.findData(settings['primary_wordlist'])
                if index >= 0:
                    self.wordlist_combo.setCurrentIndex(index)
            if 'use_aircrack' in settings:
                self.aircrack_cb.setChecked(settings['use_aircrack'])
            if 'use_hashcat' in settings:
                self.hashcat_cb.setChecked(settings['use_hashcat'])
            if 'multi_wordlist' in settings:
                self.multi_wordlist_cb.setChecked(settings['multi_wordlist'])
            if 'custom_wordlist_enabled' in settings:
                self.custom_wordlist_enabled_cb.blockSignals(True)
                self.custom_wordlist_enabled_cb.setChecked(settings['custom_wordlist_enabled'])
                self.custom_wordlist_enabled_cb.blockSignals(False)
                self.browse_wordlist_btn.setEnabled(self.custom_wordlist_enabled_cb.isChecked())
            if 'custom_wordlist_folder' in settings:
                self.custom_wordlist_folder = settings['custom_wordlist_folder']
            if 'custom_wordlist_paths' in settings:
                paths = settings['custom_wordlist_paths'] or []
                if isinstance(paths, list):
                    self.custom_wordlist_paths = [p for p in paths if isinstance(p, str)]
                else:
                    self.custom_wordlist_paths = []
                if self.custom_wordlist_enabled_cb.isChecked():
                    self._populate_wordlist_combo()
            self._update_custom_wordlist_label()
            
            # Load brute force settings
            if 'use_brute_force' in settings:
                self.brute_force_cb.setChecked(settings['use_brute_force'])
            if 'brute_force_mode' in settings:
                index = settings['brute_force_mode']
                if 0 <= index < self.brute_mode_combo.count():
                    self.brute_mode_combo.setCurrentIndex(index)
            if 'brute_force_mask' in settings:
                mask = settings['brute_force_mask']
                # Check if it's a custom mask or predefined
                found = False
                for key, value in self.mask_patterns.items():
                    if value == mask and key != "Custom Pattern":
                        self.mask_combo.setCurrentText(key)
                        found = True
                        break
                if not found:
                    self.mask_combo.setCurrentText("Custom Pattern")
                    self.custom_mask_edit.setText(mask)
            if 'brute_min_length' in settings:
                self.brute_min_length_spin.setValue(settings['brute_min_length'])
            if 'brute_max_length' in settings:
                self.brute_max_length_spin.setValue(settings['brute_max_length'])
            if 'brute_force_timeout' in settings:
                timeout_val = settings['brute_force_timeout']
                try:
                    timeout_val = int(timeout_val)
                except (TypeError, ValueError):
                    timeout_val = None
                if timeout_val is not None:
                    if timeout_val <= 0:
                        minutes = 1
                    elif timeout_val <= 1440:
                        # Legacy configs stored minutes directly
                        minutes = timeout_val
                    else:
                        minutes = max(1, min(1440, timeout_val // 60))
                    self.brute_timeout_spin.setValue(minutes)
            
        except Exception as e:
            print(f"Error loading settings: {e}")
    
    def save_settings(self):
        """Save current settings to persistent storage"""
        if not self.config_manager:
            return
            
        try:
            settings = {
                # General settings
                'default_interface': self.interface_combo.currentText(),
                'wpa_timeout': self.wpa_timeout_spin.value(),
                'wpa_deauth_timeout': self.wpa_deauth_timeout_spin.value(),
                'wps_timeout': self.wps_timeout_spin.value(),
                'verbose': self.verbose_cb.isChecked(),
                'kill_processes': self.kill_processes_cb.isChecked(),
                'random_mac': self.random_mac_cb.isChecked(),
                'scan_band_24ghz': self.scan_24_cb.isChecked(),
                'scan_band_5ghz': self.scan_5_cb.isChecked(),
                'scan_band_6ghz': self.scan_6_cb.isChecked(),
                
                # WPS settings
                'wps_pixie_dust': self.wps_pixie_cb.isChecked(),
                'wps_pin_brute_force': self.wps_pin_cb.isChecked(),
                'wps_use_bully': self.wps_use_bully_cb.isChecked(),
                'wps_ignore_lock': self.wps_ignore_lock_cb.isChecked(),
                'wps_pin_timeout': self.wps_pin_timeout_spin.value(),
                'wps_fail_threshold': self.wps_fail_thresh_spin.value(),
                'wps_timeout_threshold': self.wps_timeout_thresh_spin.value(),
                
                # Password cracking settings
                'cracking_strategy': self.cracking_strategy_combo.currentText(),
                'primary_wordlist': self.wordlist_combo.currentData(),
                'use_aircrack': self.aircrack_cb.isChecked(),
                'use_hashcat': self.hashcat_cb.isChecked(),
                'multi_wordlist': self.multi_wordlist_cb.isChecked(),
                'custom_wordlist_enabled': self.custom_wordlist_enabled_cb.isChecked(),
                'custom_wordlist_paths': list(self.custom_wordlist_paths or []),
                'custom_wordlist_folder': self.custom_wordlist_folder,
                
                # Brute force settings
                'use_brute_force': self.brute_force_cb.isChecked(),
                'brute_force_mode': self.brute_mode_combo.currentIndex(),
                'brute_force_mask': self.mask_combo.currentText() == "Custom Pattern" and self.custom_mask_edit.text() or self.mask_patterns.get(self.mask_combo.currentText(), "?d?d?d?d?d?d"),
                'brute_min_length': self.brute_min_length_spin.value(),
                'brute_max_length': self.brute_max_length_spin.value(),
                'brute_force_timeout': self.brute_timeout_spin.value() * 60,
            }
            
            existing_settings = self.config_manager.load_settings() or {}
            existing_settings.update(settings)
            self.config_manager.save_settings(existing_settings)
            
        except Exception as e:
            print(f"Error saving settings: {e}")
    
    def get_current_settings(self):
        """Get current settings as a dictionary without saving"""
        try:
            return {
                # General settings
                'default_interface': self.interface_combo.currentText(),
                'wpa_timeout': self.wpa_timeout_spin.value(),
                'wpa_deauth_timeout': self.wpa_deauth_timeout_spin.value(),
                'wps_timeout': self.wps_timeout_spin.value(),
                'verbose': self.verbose_cb.isChecked(),
                'kill_processes': self.kill_processes_cb.isChecked(),
                'random_mac': self.random_mac_cb.isChecked(),
                'scan_band_24ghz': self.scan_24_cb.isChecked(),
                'scan_band_5ghz': self.scan_5_cb.isChecked(),
                'scan_band_6ghz': self.scan_6_cb.isChecked(),
                
                # WPS settings
                'wps_pixie_dust': self.wps_pixie_cb.isChecked(),
                'wps_pin_brute_force': self.wps_pin_cb.isChecked(),
                'wps_use_bully': self.wps_use_bully_cb.isChecked(),
                'wps_ignore_lock': self.wps_ignore_lock_cb.isChecked(),
                'wps_pin_timeout': self.wps_pin_timeout_spin.value(),
                'wps_fail_threshold': self.wps_fail_thresh_spin.value(),
                'wps_timeout_threshold': self.wps_timeout_thresh_spin.value(),
                
                # Password cracking settings
                'cracking_strategy': self.cracking_strategy_combo.currentText(),
                'primary_wordlist': self.wordlist_combo.currentData(),
                'use_aircrack': self.aircrack_cb.isChecked(),
                'use_hashcat': self.hashcat_cb.isChecked(),
                'multi_wordlist': self.multi_wordlist_cb.isChecked(),
                'custom_wordlist_enabled': self.custom_wordlist_enabled_cb.isChecked(),
                'custom_wordlist_paths': list(getattr(self, 'custom_wordlist_paths', []) or []),
                'custom_wordlist_folder': self.custom_wordlist_folder,
                
                # Brute force settings
                'use_brute_force': self.brute_force_cb.isChecked(),
                'brute_force_mode': self.brute_mode_combo.currentIndex(),
                'brute_force_mask': self.mask_combo.currentText() == "Custom Pattern" and self.custom_mask_edit.text() or self.mask_patterns.get(self.mask_combo.currentText(), "?d?d?d?d?d?d"),
                'brute_min_length': self.brute_min_length_spin.value(),
                'brute_max_length': self.brute_max_length_spin.value(),
                'brute_force_timeout': self.brute_timeout_spin.value() * 60,
            }
        except Exception as e:
            print(f"Error getting current settings: {e}")
            return {}
    
    def connect_settings_signals(self):
        """Connect signals to auto-save settings when changed"""
        # General settings
        self.interface_combo.currentTextChanged.connect(self.save_settings)
        self.wpa_timeout_spin.valueChanged.connect(self.save_settings)
        self.wpa_deauth_timeout_spin.valueChanged.connect(self.save_settings)
        self.wps_timeout_spin.valueChanged.connect(self.save_settings)
        self.verbose_cb.toggled.connect(self.save_settings)
        self.kill_processes_cb.toggled.connect(self.save_settings)
        self.random_mac_cb.toggled.connect(self.save_settings)
        self.scan_24_cb.toggled.connect(self.save_settings)
        self.scan_5_cb.toggled.connect(self.save_settings)
        self.scan_6_cb.toggled.connect(self.save_settings)
        
        # WPS settings
        self.wps_pixie_cb.toggled.connect(self.save_settings)
        self.wps_pin_cb.toggled.connect(self.save_settings)
        self.wps_use_bully_cb.toggled.connect(self.save_settings)
        self.wps_ignore_lock_cb.toggled.connect(self.save_settings)
        self.wps_pin_timeout_spin.valueChanged.connect(self.save_settings)
        self.wps_fail_thresh_spin.valueChanged.connect(self.save_settings)
        self.wps_timeout_thresh_spin.valueChanged.connect(self.save_settings)
        
        # Password cracking settings
        self.cracking_strategy_combo.currentTextChanged.connect(self.save_settings)
        self.wordlist_combo.currentTextChanged.connect(self.save_settings)
        self.aircrack_cb.toggled.connect(self.save_settings)
        self.hashcat_cb.toggled.connect(self.save_settings)
        self.multi_wordlist_cb.toggled.connect(self.save_settings)
        self.custom_wordlist_enabled_cb.toggled.connect(self.save_settings)
        
        # Brute force settings
        self.brute_force_cb.toggled.connect(self.save_settings)
        self.brute_mode_combo.currentIndexChanged.connect(self.save_settings)
        self.mask_combo.currentTextChanged.connect(self.save_settings)
        self.custom_mask_edit.textChanged.connect(self.save_settings)
        self.brute_min_length_spin.valueChanged.connect(self.save_settings)
        self.brute_max_length_spin.valueChanged.connect(self.save_settings)
        self.brute_timeout_spin.valueChanged.connect(self.save_settings)
        
    def reset_to_defaults(self):
        """Reset all settings to default values"""
        # Reset general settings
        self.wpa_timeout_spin.setValue(300)
        self.wpa_deauth_timeout_spin.setValue(20)
        self.wps_timeout_spin.setValue(300)
        self.verbose_cb.setChecked(False)
        self.kill_processes_cb.setChecked(True)
        self.random_mac_cb.setChecked(False)
        self.scan_24_cb.setChecked(True)
        self.scan_5_cb.setChecked(True)
        self.scan_6_cb.setChecked(False)

        # Reset WPS settings
        self.wps_pixie_cb.setChecked(True)
        self.wps_pin_cb.setChecked(True)
        self.wps_use_bully_cb.setChecked(False)
        self.wps_ignore_lock_cb.setChecked(False)
        self.wps_pin_timeout_spin.setValue(1800)
        self.wps_fail_thresh_spin.setValue(100)
        self.wps_timeout_thresh_spin.setValue(100)

        # Reset cracking settings
        self.aircrack_cb.setChecked(True)
        self.hashcat_cb.setChecked(True)
        self.multi_wordlist_cb.setChecked(True)
        self.cracking_strategy_combo.setCurrentIndex(0)
        if self.wordlist_combo.count() > 0:
            self.wordlist_combo.setCurrentIndex(0)

        # Reset brute-force settings
        self.brute_force_cb.setChecked(False)
        self.brute_mode_combo.setCurrentIndex(0)
        self.mask_combo.setCurrentIndex(0)
        self.custom_mask_edit.clear()
        self.custom_mask_edit.setVisible(False)
        self.brute_min_length_spin.setValue(8)
        self.brute_max_length_spin.setValue(20)
        self.brute_timeout_spin.setValue(60)
        
        # Save the reset settings
        self.save_settings()
    
    def _on_mask_combo_changed(self, text):
        """Handle mask pattern selection"""
        if text == "Custom Pattern":
            self.custom_mask_edit.setVisible(True)
            self.mask_combo.blockSignals(True)
            self.mask_combo.setCurrentIndex(self.mask_combo.findText("Custom Pattern"))
            self.mask_combo.blockSignals(False)
        else:
            self.custom_mask_edit.setVisible(False)
            if text in self.mask_patterns and text != "Custom Pattern":
                mask = self.mask_patterns[text]
                if self.custom_mask_edit:
                    self.custom_mask_edit.setText(mask)
    
    def _update_gpu_info(self):
        """Update GPU information display"""
        try:
            from ..tools.hashcat import Hashcat
            if Hashcat.has_gpu():
                gpu_info = Hashcat.get_gpu_info()
                gpu_name = gpu_info.get('gpu_name') or gpu_info.get('cuda_gpu') or 'GPU Accelerator'
                self.gpu_info_label.setText(f"GPU: {gpu_name} ✓")
                self.gpu_info_label.setStyleSheet("color: #4CAF50")
            else:
                self.gpu_info_label.setText("GPU: Not Available (CPU only - very slow)")
                self.gpu_info_label.setStyleSheet("color: #f44336")
        except Exception as e:
            self.gpu_info_label.setText(f"GPU: {str(e)}")
            self.gpu_info_label.setStyleSheet("color: #888")
    
    def _populate_wordlist_combo(self):
        """Populate the wordlist combo box with available wordlists from wifitex/wordlists only"""
        try:
            import os
            
            current_data = self.wordlist_combo.currentData()
            current_text = self.wordlist_combo.currentText()
            
            # Get wifitex package directory to identify default wordlists
            # The wordlists are in the same directory as wordlist_manager (wifitex/gui/wordlist_manager.py)
            # So we need to go: wifitex/gui -> wifitex -> wifitex/wordlists
            wifitex_package_dir = os.path.dirname(os.path.dirname(__file__))
            wifitex_wordlists_dir = os.path.join(wifitex_package_dir, 'wordlists')
            
            # Clear existing items
            self.wordlist_combo.clear()
            
            # ONLY scan wifitex/wordlists folder (no system-wide scanning)
            if os.path.exists(wifitex_wordlists_dir) and os.path.isdir(wifitex_wordlists_dir):
                # Scan all .txt, .lst, .gz files in wifitex/wordlists folder
                for root, dirs, files in os.walk(wifitex_wordlists_dir):
                    for file in files:
                        if any(ext in file.lower() for ext in ['.txt', '.lst', '.gz']):
                            wordlist_path = os.path.join(root, file)
                            display_name = f"📁 {file}"
                            self.wordlist_combo.addItem(display_name, wordlist_path)
            
            # Add custom wordlist paths if enabled
            if (
                hasattr(self, 'custom_wordlist_enabled_cb') and
                hasattr(self, 'custom_wordlist_paths') and
                self.custom_wordlist_enabled_cb.isChecked()
            ):
                unique_paths = []
                for wordlist_path in self.custom_wordlist_paths:
                    if wordlist_path and os.path.exists(wordlist_path):
                        if wordlist_path not in unique_paths:
                            unique_paths.append(wordlist_path)
                for wordlist_path in unique_paths:
                    display_name = f"🗂️ {os.path.basename(wordlist_path)}"
                    self.wordlist_combo.addItem(display_name, wordlist_path)
            
            # Restore previous selection when possible
            restored = False
            if current_data:
                index = self.wordlist_combo.findData(current_data)
                if index >= 0:
                    self.wordlist_combo.setCurrentIndex(index)
                    restored = True
            if not restored and current_text:
                index = self.wordlist_combo.findText(current_text)
                if index >= 0:
                    self.wordlist_combo.setCurrentIndex(index)
                
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
    
    def _on_custom_wordlist_toggled(self, checked):
        """Handle custom wordlist checkbox toggle"""
        self.browse_wordlist_btn.setEnabled(checked)
        if not checked:
            # Clear custom paths when disabled
            self.custom_wordlist_paths = []
            self.custom_wordlist_folder = None
            self._update_custom_wordlist_label()
            # Repopulate combo to remove custom wordlists
            self._populate_wordlist_combo()
        else:
            self._update_custom_wordlist_label()
            self._populate_wordlist_combo()
        
        self.save_settings()
    
    def _browse_wordlist_folder(self):
        """Browse for a custom wordlist folder"""
        from PyQt6.QtWidgets import QFileDialog
        import os
        
        # Get the starting directory (home or current working directory)
        start_dir = os.path.expanduser("~")
        
        # Open folder selection dialog
        folder_path = QFileDialog.getExistingDirectory(
            self,
            "Select Wordlist Folder",
            start_dir,
            QFileDialog.Option.ShowDirsOnly
        )
        
        if folder_path:
            # Scan the folder for .txt, .lst, .gz files
            collected_paths = []
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    if any(ext in file.lower() for ext in ['.txt', '.lst', '.gz']):
                        wordlist_path = os.path.join(root, file)
                        collected_paths.append(wordlist_path)
            
            self.custom_wordlist_folder = folder_path
            self.custom_wordlist_paths = list(dict.fromkeys(collected_paths))
            self._update_custom_wordlist_label()
            self._populate_wordlist_combo()
            self.save_settings()
    
    def get_all_wordlist_paths(self):
        """Get all wordlist paths (from wifitex/wordlists and custom folder if enabled)"""
        wordlist_paths = []
        
        # Get primary wordlist
        primary_path = self.wordlist_combo.currentData()
        if primary_path:
            wordlist_paths.append(primary_path)
        
        # If multi-wordlist is enabled, get all paths
        if self.multi_wordlist_cb.isChecked():
            # Get all items from combo (excluding already added primary)
            for i in range(self.wordlist_combo.count()):
                path = self.wordlist_combo.itemData(i)
                if path and path != primary_path:
                    wordlist_paths.append(path)
        
        return wordlist_paths

    def get_scan_band_settings(self) -> Dict[str, bool]:
        """Return the current scan band preferences."""
        return {
            'scan_24ghz': self.scan_24_cb.isChecked(),
            'scan_5ghz': self.scan_5_cb.isChecked(),
            'scan_6ghz': self.scan_6_cb.isChecked(),
        }

    def get_bruteforce_options(self) -> Dict[str, Any]:
        """Return the currently configured brute-force options."""
        mode_map = {
            0: '0',
            1: '3',
            2: '6',
            3: '7',
        }
        mode_value = mode_map.get(self.brute_mode_combo.currentIndex(), '3')
        # Allow comma-separated values for future configurability
        modes = [entry.strip() for entry in str(mode_value).split(',') if entry.strip()]

        if self.mask_combo.currentText() == "Custom Pattern":
            mask_value = self.custom_mask_edit.text().strip() or None
        else:
            mask_value = self.mask_patterns.get(self.mask_combo.currentText(), None)

        timeout_minutes = self.brute_timeout_spin.value()
        return {
            'enabled': self.brute_force_cb.isChecked(),
            'modes': modes,
            'mask': mask_value,
            'min_length': self.brute_min_length_spin.value(),
            'max_length': self.brute_max_length_spin.value(),
            'timeout_minutes': timeout_minutes,
            'timeout_seconds': timeout_minutes * 60 if timeout_minutes else None,
        }


class HandshakeCrackerTab(QWidget):
    """GUI tab that cracks captured handshakes using existing CLI tooling."""

    log_message = pyqtSignal(str)
    status_message = pyqtSignal(str)
    crack_saved = pyqtSignal(dict)

    def __init__(
            self,
            get_default_wordlists: Callable[[], List[str]],
            get_bruteforce_options: Optional[Callable[[], Dict[str, Any]]] = None,
            parent=None):
        super().__init__(parent)
        self._get_default_wordlists = get_default_wordlists
        self._get_bruteforce_options = get_bruteforce_options
        self.worker: Optional[HandshakeCrackWorker] = None
        self._current_job: Optional[Dict[str, Any]] = None
        self._build_ui()
        QTimer.singleShot(300, self.refresh_handshakes)

    def _build_ui(self):
        layout = QVBoxLayout(self)

        top_bar = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_handshakes)
        self.open_btn = QPushButton("Open Handshake…")
        self.open_btn.clicked.connect(self._pick_external)
        top_bar.addWidget(self.refresh_btn)
        top_bar.addWidget(self.open_btn)
        top_bar.addStretch()
        layout.addLayout(top_bar)

        self.handshake_list = QListWidget()
        self.handshake_list.itemSelectionChanged.connect(self._show_details)
        layout.addWidget(self.handshake_list)

        form = QGridLayout()
        form.addWidget(QLabel("Selected file:"), 0, 0)
        self.file_label = QLabel("—")
        self.file_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        form.addWidget(self.file_label, 0, 1)

        form.addWidget(QLabel("ESSID / BSSID:"), 1, 0)
        self.meta_label = QLabel("—")
        self.meta_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        form.addWidget(self.meta_label, 1, 1)

        form.addWidget(QLabel("Wordlists:"), 2, 0)
        self.wordlist_summary = QLabel("Using Settings → Password Cracking wordlists")
        self.wordlist_summary.setWordWrap(True)
        form.addWidget(self.wordlist_summary, 2, 1)

        form.addWidget(QLabel("Tool:"), 3, 0)
        self.tool_combo = QComboBox()
        self.tool_combo.addItems(["aircrack-ng", "hashcat"])
        form.addWidget(self.tool_combo, 3, 1)

        layout.addLayout(form)

        buttons = QHBoxLayout()
        self.start_btn = QPushButton("Start Crack")
        self.start_btn.clicked.connect(self.start_crack)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_crack)
        buttons.addWidget(self.start_btn)
        buttons.addWidget(self.stop_btn)
        buttons.addStretch()
        layout.addLayout(buttons)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setAcceptRichText(True)
        self.output.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.output.setFont(QFont("Consolas", 9))
        layout.addWidget(self.output)

        self.status_bar = QLabel("Ready.")
        layout.addWidget(self.status_bar)

    def _emit_log(self, message: str, level: str = "info", color: Optional[str] = None):
        """Emit a colorized handshake log message to GUI and shared logger."""
        if color:
            if not re.search(r'\{[A-Z]+\}', message):
                message = f"{color}{message}{{W}}"
            else:
                message = f"{color}{message}"
                if not message.endswith("{W}"):
                    message += "{W}"
        elif not re.search(r'\{[A-Z]+\}', message):
            message = f"{{B}}{message}{{W}}"

        formatted = f"{{P}}[HANDSHAKE]{{W}} {message}"

        if level == "error":
            logger.error(formatted)
        elif level == "warning":
            logger.warning(formatted)
        else:
            logger.info(formatted)

        self.log_message.emit(formatted)

    def _classify_status(self, text: str) -> Tuple[str, str]:
        """Determine color tag and log level for status text."""
        lower = text.lower()
        if any(keyword in lower for keyword in ("fail", "error", "missing", "unable")):
            return "{R}", "error"
        if any(keyword in lower for keyword in ("stop", "stopped", "cancel", "abort")):
            return "{O}", "warning"
        if any(keyword in lower for keyword in ("cracked", "saved", "success", "found", "ready")):
            return "{G}", "info"
        return "{C}", "info"

    def cleanup(self):
        """Stop background worker on shutdown."""
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(2000)
        self.worker = None
        self._refresh_wordlist_summary()

    def refresh_handshakes(self):
        """Populate list with captured handshakes from configured directory."""
        try:
            if Configuration is None:
                raise RuntimeError("Configuration unavailable; cannot enumerate handshakes.")

            Configuration.initialize(load_interface=False)
            hs_dir = Path(Configuration.wpa_handshake_dir).expanduser().resolve()

            cracked_entries = set()
            if CrackResult:
                try:
                    cracked_entries = {
                        os.path.basename(entry.get('handshake_file', '') or entry.get('pmkid_file', ''))
                        for entry in CrackResult.load_all()
                    }
                except Exception as exc:
                    self._emit_log(f"Failed to read cracked results: {exc}", level="warning", color="{O}")

            items = []
            if hs_dir.is_dir():
                patterns = ["handshake_*.*", "pmkid_*.*", "*.22000", "*.16800"]
                candidates = set()
                for pattern in patterns:
                    candidates.update(hs_dir.glob(pattern))
                for path in sorted(candidates, key=lambda p: p.stat().st_mtime, reverse=True):
                    entry = self._parse_filename(path)
                    if entry:
                        entry['path'] = str(path)
                        entry['cracked'] = os.path.basename(path) in cracked_entries
                        items.append(entry)

            self.handshake_list.clear()
            for entry in items:
                label = f"{entry.get('essid', 'Unknown')} ({entry.get('bssid', '—')}) [{entry['type']}]"
                item = QListWidgetItem(label)
                if entry.get('cracked'):
                    item.setForeground(QColor("#51cf66"))
                item.setData(Qt.ItemDataRole.UserRole, entry)
                self.handshake_list.addItem(item)

            cracked_count = sum(1 for entry in items if entry.get('cracked'))
            summary = f"Loaded {{G}}{len(items)}{{W}} handshakes/PMKID files from {{B}}{hs_dir}{{W}}"
            if cracked_count:
                summary += f" ({{G}}{cracked_count}{{W}} cracked)"
            self._emit_log(summary)
        except Exception as exc:
            self._emit_log(f"Refresh failed: {exc}", level="error", color="{R}")

    def _parse_filename(self, path: Path) -> Optional[Dict[str, Any]]:
        parts = path.stem.split('_')
        if len(parts) < 4:
            return {
                'essid': path.stem,
                'bssid': '',
                'type': 'PMKID' if path.suffix in ('.22000', '.16800') else '4-WAY'
            }
        _, essid, bssid, *_ = parts
        return {
            'essid': essid,
            'bssid': bssid.replace('-', ':'),
            'type': 'PMKID' if path.suffix in ('.22000', '.16800') else '4-WAY'
        }

    def _pick_external(self):
        """Allow user to select external handshake capture."""
        start_dir = Path(Configuration.wpa_handshake_dir).expanduser() if Configuration else Path.home()
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select handshake capture",
            str(start_dir),
            "Handshake (*.cap *.pcap *.pcapng *.22000 *.16800)"
        )
        if not file_path:
            return

        entry = self._parse_filename(Path(file_path))
        if entry:
            entry['path'] = file_path
            item = QListWidgetItem(
                f"{entry.get('essid', Path(file_path).name)} ({entry.get('bssid', '—')}) [{entry['type']}]"
            )
            item.setData(Qt.ItemDataRole.UserRole, entry)
            self.handshake_list.addItem(item)
            self.handshake_list.setCurrentItem(item)
            self._emit_log(f"Added external handshake {Path(file_path).name}", color="{B}")

    def _refresh_wordlist_summary(self):
        paths = []
        if callable(self._get_default_wordlists):
            defaults = self._get_default_wordlists()
            if isinstance(defaults, dict):
                primary = defaults.get('primary_wordlist')
                defaults = [primary] if isinstance(primary, str) else []
            if isinstance(defaults, list):
                paths = [os.path.abspath(p) for p in defaults if isinstance(p, str)]
        if not paths:
            self.wordlist_summary.setText("No wordlists configured. Update them in Settings → Password Cracking.")
            return
        display = "\n".join(os.path.basename(path) for path in paths)
        self.wordlist_summary.setText(f"Using wordlists from Settings:\n{display}")

    def _show_details(self):
        item = self.handshake_list.currentItem()
        if not item:
            self.file_label.setText("—")
            self.meta_label.setText("—")
            self._current_job = None
            return

        info = item.data(Qt.ItemDataRole.UserRole)
        self._current_job = info
        self.file_label.setText(info.get('path', '—'))
        self.meta_label.setText(f"{info.get('essid', '—')} / {info.get('bssid', '—')}")
        if info.get('cracked'):
            self.status_bar.setText("Already cracked. See cracked results list.")
        else:
            self.status_bar.setText("Ready to crack.")

    def start_crack(self):
        if self.worker and self.worker.isRunning():
            self._emit_log("Handshake cracking already in progress.", color="{C}")
            return
        if not self._current_job:
            self.status_bar.setText("Select a handshake first.")
            self._emit_log("Select a handshake first.", level="warning", color="{Y}")
            return

        wordlists: List[str] = []
        if callable(self._get_default_wordlists):
            defaults = self._get_default_wordlists()
            if isinstance(defaults, dict):
                primary = defaults.get('primary_wordlist')
                defaults = [primary] if isinstance(primary, str) else []
            if isinstance(defaults, list):
                wordlists.extend([d for d in defaults if isinstance(d, str)])

        wordlists = [os.path.abspath(w) for w in wordlists]
        wordlists = list(dict.fromkeys(wordlists))
        missing = [w for w in wordlists if not os.path.isfile(w)]
        wordlists = [w for w in wordlists if os.path.isfile(w)]

        if missing:
            for path in missing:
                self._append_output(f"{{Y}}⚠️ Missing wordlist: {path}{{W}}")
            self._append_output("")

        tool_choice = self.tool_combo.currentText()
        brute_options: Dict[str, Any] = {}
        if callable(self._get_bruteforce_options):
            try:
                brute_options = self._get_bruteforce_options() or {}
            except Exception as exc:
                self._emit_log(f"Failed to load brute-force settings: {exc}", level="warning", color="{O}")
                brute_options = {}

        if tool_choice.lower() != 'hashcat':
            brute_options = {}

        brute_enabled = bool(brute_options.get('enabled'))
        brute_modes = brute_options.get('modes') or []
        modes_requiring_wordlist = {mode for mode in brute_modes if mode in {'0', '6', '7'}}
        requires_wordlist = (
            tool_choice.lower() == 'aircrack-ng'
            or (tool_choice.lower() == 'hashcat' and (not brute_enabled or bool(modes_requiring_wordlist)))
        )

        if not wordlists and requires_wordlist:
            self.status_bar.setText("No valid wordlists available. Add or configure wordlists first.")
            self._emit_log(
                "No valid wordlists available. Add or configure wordlists first.",
                level="warning",
                color="{Y}"
            )
            return
        elif not wordlists and brute_enabled:
            self._append_output("{C}ℹ️ No wordlists configured; proceeding with mask-only brute force.{W}")

        self.output.clear()
        self._refresh_wordlist_summary()
        start_msg = (
            f"Starting {tool_choice} on {self._current_job.get('essid', 'unknown')} "
            f"with {len(wordlists)} wordlist(s)…"
        )
        if brute_enabled and tool_choice.lower() == 'hashcat':
            start_msg += " Brute force enabled."
        self._append_output(f"{{O}}{start_msg}{{W}}")
        self._emit_log(start_msg, color="{O}")
        self.worker = HandshakeCrackWorker(
            self._current_job,
            wordlists,
            tool=tool_choice,
            bruteforce_options=brute_options
        )
        self.worker.progress.connect(self._append_output)
        self.worker.status.connect(self._set_status)
        self.worker.failed.connect(self._handle_failure)
        self.worker.finished.connect(self._handle_finished)
        self.worker.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_bar.setText("Cracking in progress…")

    def stop_crack(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(2000)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_bar.setText("Cracking stopped.")
        self.worker = None
        self._emit_log("Cracking stopped.", level="warning", color="{O}")

    def _append_output(self, line: str):
        if line is None:
            return

        text = str(line).replace("\r\n", "\n")

        if not text.strip():
            self.output.append("")
            self.output.moveCursor(QTextCursor.MoveOperation.End)
            return

        while text.startswith("\n"):
            self.output.append("")
            text = text[1:]

        if text:
            html = LogFormatter.format_message_for_html(text)
            html = html.replace("\n", "<br/>")
            self.output.append(html)

        self.output.moveCursor(QTextCursor.MoveOperation.End)

    def _set_status(self, text: str):
        self.status_bar.setText(text)
        color, level = self._classify_status(text)
        self._emit_log(text, level=level, color=color)

    def _handle_failure(self, message: str):
        self._append_output("")
        self._append_output(f"{{R}}❌ {message}{{W}}")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_message.emit(message)
        self.status_bar.setText("Cracking failed.")
        self._emit_log(f"Crack worker failed: {message}", level="error", color="{R}")

    def _handle_finished(self, success: bool, data: Dict[str, Any]):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

        if self.worker:
            self.worker = None

        if success and data.get('key'):
            key = data['key']
            self._append_output("")
            self._append_output(f"{{G}}✅ Key found: {key}{{W}}")
            saved = False
            try:
                if data.get('type') == 'PMKID' and CrackResultPMKID:
                    result = CrackResultPMKID(data['bssid'], data['essid'], data['path'], key)
                elif CrackResultWPA:
                    result = CrackResultWPA(data['bssid'], data['essid'], data['path'], key)
                else:
                    result = None

                if result:
                    result.save()
                    saved = True
            except Exception as exc:
                self._append_output("")
                self._append_output(f"{{Y}}⚠️ Failed to save crack result: {exc}{{W}}")
                self._emit_log(f"Failed to save crack result: {exc}", level="warning", color="{O}")

            if saved:
                self.crack_saved.emit(data)
                self.status_message.emit("Handshake cracked and saved.")
                self.status_bar.setText("Handshake cracked and saved.")
                self._emit_log(
                    f"Handshake cracked for {{B}}{data.get('essid', 'unknown')}{{W}} / "
                    f"{{B}}{data.get('bssid', '—')}{{W}} and saved to results.",
                    color="{G}"
                )
            else:
                self.status_message.emit("Handshake cracked (not saved).")
                self.status_bar.setText("Handshake cracked.")
                self._emit_log(
                    f"Handshake cracked for {{B}}{data.get('essid', 'unknown')}{{W}} / "
                    f"{{B}}{data.get('bssid', '—')}{{W}} but could not save result.",
                    color="{G}"
                )
        else:
            self._append_output("")
            self._append_output("{Y}⚠️ Passphrase not found in wordlist.{W}")
            self.status_message.emit("No match in wordlist.")
            self.status_bar.setText("No match in wordlist.")
            wordlist_used = data.get('wordlist')
            if wordlist_used:
                self._append_output(f"{{B}}Last wordlist attempted: {wordlist_used}{{W}}")
            miss_msg = "No key found in provided wordlists."
            if wordlist_used:
                miss_msg += f" Last wordlist: {os.path.basename(wordlist_used)}"
            self._emit_log(miss_msg, level="warning", color="{Y}")

        QTimer.singleShot(500, self.refresh_handshakes)


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
        self.log_text.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        document = self.log_text.document()
        if document is not None:
            document.setMaximumBlockCount(2000)
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
            'attack', 'wps', 'wpa', 'pmkid', 'handshake', 'pin', 'pixie', 
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
    
    def __init__(self, interface: str, channel: Optional[int] = None,
                 scan_24: bool = True, scan_5: bool = False, scan_6: bool = False,
                 scan_duration: int = 60):
        super().__init__()
        self.interface = interface
        self.channel = channel
        self.scan_24 = scan_24
        self.scan_5 = scan_5
        self.scan_6 = scan_6
        self.scan_duration = scan_duration
        self.running = True
        self.airodump = None
        self.process = None
        self.targets = []
        self.scan_start_time = None
        self.active_bands = set()
        self._notified_scan6_fallback = False
        
    def stop(self):
        """Stop the scan"""
        self.running = False
        if self.airodump:
            try:
                self.airodump.__exit__(None, None, None)
            except Exception:
                pass
        # Also terminate spawned airodump-ng process if present (kill whole group)
        try:
            if hasattr(self, 'process') and self.process:
                try:
                    import os, signal
                    pgid = os.getpgid(self.process.pid)
                    os.killpg(pgid, signal.SIGTERM)
                except Exception:
                    try:
                        self.process.terminate()
                    except Exception:
                        pass
                try:
                    self.process.wait(timeout=2)
                except Exception:
                    pass
                if self.process.poll() is None:
                    try:
                        import os, signal
                        pgid = os.getpgid(self.process.pid)
                        os.killpg(pgid, signal.SIGKILL)
                    except Exception:
                        try:
                            self.process.kill()
                        except Exception:
                            pass
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
                raise Exception("Wifitex requires root privileges for wireless operations. Please run with sudo.")
            
            # Set up configuration for CLI scanner
            Configuration.initialize()
            Configuration.interface = self.interface
            Configuration.target_channel = self.channel
            Configuration.five_ghz = self.scan_5
            if hasattr(Configuration, "six_ghz"):
                Configuration.six_ghz = self.scan_6
            if hasattr(Configuration, "scan_band_24"):
                Configuration.scan_band_24 = self.scan_24
            if hasattr(Configuration, "scan_band_5"):
                Configuration.scan_band_5 = self.scan_5
            if hasattr(Configuration, "scan_band_6"):
                Configuration.scan_band_6 = self.scan_6
            
            # Temporarily disable filtering to get all networks
            original_encryption_filter = Configuration.encryption_filter
            Configuration.encryption_filter = []  # Show all networks
            
            # Keep user's band settings - already pushed into Configuration above
            
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
                    'message': f'❌ Interface {self.interface} not in monitor mode!\n\nPlease:\n1. Click "Enable Monitor Mode" button\n2. Or run: sudo airmon-ng start {self.interface}',
                    'progress': 0
                })
                self.scan_completed.emit([])
                return
            
            if os.geteuid() == 0:
                self.scan_progress.emit({'message': 'Running as root - skipping permission test...'})
            else:
                self.scan_progress.emit({'message': f'Testing permissions for {self.interface}...'})
            
            self.scan_progress.emit({'message': f'Starting network scan on {self.interface}...'})
            
            band = self._determine_band()
            self.active_bands = self._bands_from_band_arg(band)
            if self.scan_6 and '6' not in self.active_bands and not self._notified_scan6_fallback:
                self.scan_progress.emit({
                    'message': '6 GHz scan requested, but adapter/driver cannot combine it with other bands. Continuing without 6 GHz.',
                    'progress': 0
                })
                self._notified_scan6_fallback = True

            # Use the same Airodump class as CLI scanner with proper settings
            try:
                self.airodump = Airodump(
                    interface=self.interface,
                    channel=self.channel,
                    output_file_prefix='wifitex_gui_unified',
                    skip_wps=False,  # Enable WPS detection
                    delete_existing_files=True,  # Clean start
                    band=band
                )
                self.airodump.__enter__()
            except Exception as start_error:
                if self.scan_6 and band == '6':
                    self.scan_progress.emit({
                        'message': f"6 GHz scan failed ({start_error}). Verify adapter and aircrack-ng support 6 GHz.",
                        'progress': 0
                    })
                    self.scan_completed.emit([])
                    return
                raise
            
            # Debug: Log the command that will be executed
            logger.info(f"[SCAN] Starting airodump on interface: {self.interface}")
            logger.info(
                f"[SCAN] Channel: {self.channel}, Bands -> "
                f"2.4GHz:{self.scan_24} 5GHz:{self.scan_5} 6GHz:{self.scan_6} "
                f"(band arg: {band or 'default'})"
            )
            
            self.scan_start_time = time.time()
            
            # Debug: Check if airodump process started successfully
            if not self.airodump.pid or self.airodump.pid.poll() is not None:
                # Try to get error details
                if self.airodump.pid:
                    try:
                        # Get stderr output from the Process object's stderr() method
                        stderr_output = self.airodump.pid.stderr()
                        if stderr_output and stderr_output.strip():
                            error_msg = f"airodump-ng failed: {stderr_output.strip()}"
                            logger.error(f"[SCAN] {error_msg}")
                            raise Exception(error_msg)
                    except Exception as e:
                        logger.error(f"[SCAN] Failed to get airodump stderr: {e}")
                        raise Exception("airodump-ng process failed to start or died immediately")
                else:
                    raise Exception("airodump-ng process failed to start - no PID created")
            
            logger.info(f"[SCAN] Airodump process started with PID: {self.airodump.pid.pid}")
            
            # Give airodump a moment to initialize and create initial CSV file
            import time
            time.sleep(2)
            
            # Scan loop - exact same logic as CLI scanner (runs continuously until stopped)
            scan_iterations = 0
            max_iterations = 3600  # Ignore scan_duration - run continuously until manually stopped
            
            while self.running:
                if self.airodump.pid.poll() is not None:
                    # Airodump process died - check for CSV files one last time before breaking
                    logger.warning(f"[SCAN] Airodump process died, checking for CSV files...")
                    self.targets = self.airodump.get_targets(old_targets=self.targets, apply_filter=True)
                    self.targets = [t for t in self.targets if self._allow_target_by_band(t)]
                    csv_files = self.airodump.find_files(endswith='.csv')
                    if csv_files:
                        logger.debug(f"[SCAN] Found CSV files: {csv_files}")
                    else:
                        logger.error(f"[SCAN] No CSV files found - airodump may have failed to start")
                        self.scan_progress.emit({'message': '❌ Airodump process failed - no networks detected'})
                    break
                
                # Get targets using the same method as CLI scanner
                self.targets = self.airodump.get_targets(old_targets=self.targets, apply_filter=True)
                self.targets = [t for t in self.targets if self._allow_target_by_band(t)]
                
                # Debug: Check if CSV files exist (but skip warning on first iteration to avoid spam)
                csv_files = self.airodump.find_files(endswith='.csv')
                if csv_files:
                    logger.debug(f"[SCAN] Found CSV files: {csv_files}")
                elif scan_iterations > 0:  # Only warn after first iteration
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
                
                # Emit progress update with color codes
                target_count = len(self.targets)
                client_count = sum(len(t.clients) for t in self.targets)
                
                progress_msg = f'{{C}}Scanning...{{W}} {{G}}{target_count}{{W}} networks detected'
                if client_count > 0:
                    progress_msg += f', {{B}}{client_count}{{W}} clients'
                if self.airodump.decloaking:
                    progress_msg += ' {{Y}}(decloaking active){{W}}'
                
                # Always show 0 progress (continuous scan like CLI) - no auto-stop
                progress = 0
                
                self.scan_progress.emit({
                    'message': progress_msg,
                    'progress': progress,
                    'batch_update': networks
                })
                
                # No scan duration limit - run continuously until manually stopped (match CLI behavior)
                
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
            self.targets = [t for t in self.targets if self._allow_target_by_band(t)]
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
                'progress': 0  # Always 0 - continuous scan (match CLI behavior)
            })
            
            self.scan_completed.emit(final_networks)
                
        except Exception as e:
            import traceback
            logger.error(f"[SCAN] Error in unified scanner: {e}")
            logger.error(f"[SCAN] Traceback: {traceback.format_exc()}")
            self.scan_progress.emit({'message': f'Scan error: {str(e)}'})
            self.scan_completed.emit([])
    
    def _determine_band(self) -> Optional[str]:
        """
        Determine the airodump --band argument based on enabled scan bands when
        scanning all channels.
        """
        if self.channel:
            return None

        tokens = []
        if self.scan_5:
            tokens.append('a')
        if self.scan_24:
            tokens.extend(['b', 'g'])
        if self.scan_6 and not tokens:
            tokens.append('6')

        if not tokens:
            if self.scan_6:
                return '6'
            return None

        deduped = []
        for token in tokens:
            if token not in deduped:
                deduped.append(token)
        return ''.join(deduped) if deduped else None

    def _bands_from_band_arg(self, band_arg: Optional[str]) -> set:
        """Infer which bands are actively scanned given the airodump band argument."""
        active = set()

        if self.channel:
            band = self._channel_band(self.channel)
            if band:
                active.add(band)
            return active

        mapping = {'a': '5', 'b': '2.4', 'g': '2.4', '6': '6'}

        if not band_arg:
            if self.scan_24:
                active.add('2.4')
            if self.scan_5:
                active.add('5')
            if self.scan_6:
                active.add('6')
            if not active:
                active.update({'2.4', '5'})
            return active

        for char in band_arg:
            band = mapping.get(char)
            if band:
                active.add(band)

        return active

    def _channel_band(self, channel: Any) -> Optional[str]:
        """Classify a channel number into 2.4/5/6 GHz bands."""
        try:
            ch = int(str(channel).strip())
        except (TypeError, ValueError):
            return None

        if ch <= 0:
            return None
        if ch <= 14:
            return '2.4'
        if 36 <= ch <= 165:
            return '5'
        if ch >= 166:
            return '6'
        # Channels such as 34, 35 are rarely used; treat them as 5 GHz
        if 15 <= ch < 36:
            return '5'
        return None

    def _allow_target_by_band(self, target) -> bool:
        """Filter targets based on the selected scan bands."""
        band = self._channel_band(getattr(target, 'channel', None))
        if band and self.active_bands and band not in self.active_bands:
            return False
        if band == '2.4':
            return self.scan_24
        if band == '5':
            return self.scan_5
        if band == '6':
            return self.scan_6
        return True

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
    
    def __init__(self, interface: str, channel: Optional[int] = None,
                 scan_24: bool = True, scan_5: bool = False, scan_6: bool = False,
                 scan_duration: int = 60):
        super().__init__()
        self.interface = interface
        self.channel = channel
        self.scan_24 = scan_24
        self.scan_5 = scan_5
        self.scan_6 = scan_6
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
                            
                            # Determine WPS status (default Unknown; set No for 5 GHz)
                            wps_status = 'Unknown'
                            try:
                                ch_val = int(channel)
                                if ch_val >= 36:
                                    wps_status = 'No'
                            except Exception:
                                pass

                            network = {
                                'bssid': bssid,
                                'essid': essid,
                                'channel': channel,
                                'power': power,
                                'encryption': encryption,
                                'wps': wps_status,
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
                
                # Associate clients with their networks (filter out unassociated clients to match CLI behavior)
                for client in clients:
                    client_bssid = client['bssid'].lower()
                    client_mac = client['mac']
                    
                    # Skip unassociated clients (match CLI behavior - don't show unassociated)
                    if ('not associated' in client_bssid or 
                        client_bssid == '' or 
                        client_bssid == '(not associated)'):
                        continue
                    
                    found_network = False
                    for network in networks:
                        if network['bssid'].lower() == client_bssid:
                            network['clients'] += 1
                            network['client_details'].append({
                                'mac': client['mac'],
                                'power': client['power'],
                                'packets': client['packets'],
                                'probed_essids': client['probed_essids']
                            })
                            found_network = True
                            break
                
                # Filter out UNASSOCIATED networks to match CLI behavior
                networks = [n for n in networks if n['bssid'].upper() != 'UNASSOCIATED' 
                           and 'unassociated' not in n['essid'].lower()]
                
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
                    # Scan common 2.4 GHz and starter 5 GHz channels to avoid missing 5G entirely
                    cmd.extend(['-c', '1,6,11,36,40,44,48'])
            
            # Only specify channel if user explicitly selected one
            if self.channel and self.channel > 0:
                cmd.extend(['-c', str(self.channel)])
            # For comprehensive scanning, scan ALL bands (2.4GHz, 5GHz, 6GHz, 7GHz)
            # Don't specify band - let airodump scan all available channels automatically
            else:
                # By default, airodump scans 2.4GHz and 5GHz
                # Additional bands (6GHz, 7GHz) are automatically detected if supported
                # No need to specify bands - let airodump handle it
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
                
                # Run continuously until manually stopped (match CLI behavior - no auto-stop)
                # Ignore scan_duration - always run until user clicks Stop
                scan_time = 30  # Minimum initial scan time for network detection, then continue
                
                # Use cwd parameter to ensure proper working directory
                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    env=env,
                    cwd='/tmp',
                    start_new_session=True
                )
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
            # Run continuously until manually stopped (match CLI behavior - no auto-stop)
            # Ignore scan_duration parameter - scans run until user clicks Stop
            scan_duration = 999999  # Very large number for continuous scanning
            
            # Use a more robust loop with proper exit conditions
            scan_iterations = 0
            max_iterations = 3600  # Max iterations per loop cycle (continue looping until stopped)
            
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
                                'progress': 0,  # Always 0 - continuous scan
                                'batch_update': alt
                            })
                            # Don't stop - keep running continuously until manually stopped (match CLI behavior)
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
                            # Force WPS to No on 5 GHz channels (registrar usually 2.4G only)
                            try:
                                ch_val = int(channel)
                                if ch_val >= 36:
                                    wps_status = 'No'
                            except Exception:
                                pass
                            
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
                    # Default based on wash result
                    wps = 'Yes' if bssid in wps_networks else 'No'
                    # Force 5 GHz to No (most registrars are 2.4G only)
                    try:
                        ch_val = int(str(network.get('channel', '0')).split(',')[0])
                        if ch_val >= 36:
                            wps = 'No'
                    except Exception:
                        pass
                    network['wps'] = wps
                
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


class HandshakeCrackWorker(QThread):
    """Worker that cracks captured handshakes without running full attacks."""

    progress = pyqtSignal(str)
    finished = pyqtSignal(bool, dict)
    failed = pyqtSignal(str)
    status = pyqtSignal(str)

    def __init__(
            self,
            job: Dict[str, Any],
            wordlists: List[str],
            tool: str = 'aircrack-ng',
            bruteforce_options: Optional[Dict[str, Any]] = None,
            parent: Optional[QObject] = None):
        super().__init__(parent)
        self.job = job
        self.wordlists = wordlists
        self.tool = tool
        self.bruteforce = bruteforce_options or {}
        self._stop_event = threading.Event()
        self._process: Optional[subprocess.Popen] = None

    def stop(self):
        """Request the cracking process to stop."""
        self._stop_event.set()
        if self._process and self._process.poll() is None:
            try:
                self._process.terminate()
                self._process.wait(timeout=2)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass

    def run(self):
        try:
            if Configuration is None or Handshake is None:
                raise RuntimeError("Configuration or handshake model unavailable.")

            Configuration.initialize(load_interface=False)

            tool_path = shutil.which(self.tool)
            if self.job.get('type') == 'PMKID':
                # PMKID always requires hashcat regardless of user selection.
                if self.tool.lower() != 'hashcat':
                    tool_path = shutil.which('hashcat')
                    if not tool_path:
                        raise RuntimeError("Required tool 'hashcat' is not installed or not in PATH.")
                    self.tool = 'hashcat'
            if tool_path is None:
                raise RuntimeError(f"Required tool '{self.tool}' is not installed or not in PATH.")

            candidates: List[str] = []
            for path in self.wordlists:
                abs_path = os.path.abspath(path)
                if os.path.isfile(abs_path):
                    candidates.append(abs_path)

            path = os.path.abspath(self.job['path'])
            handshake = Handshake(
                path,
                bssid=self.job.get('bssid'),
                essid=self.job.get('essid')
            )
            handshake.divine_bssid_and_essid()

            tasks = self._build_tasks(candidates)
            if not tasks:
                raise FileNotFoundError("No cracking tasks were generated.")

            total = len(tasks)
            last_data = None
            for index, task in enumerate(tasks, start=1):
                if self._stop_event.is_set():
                    self.status.emit("Cracking stopped by user.")
                    self.finished.emit(False, last_data or {})
                    return

                label = task.get('label') or f"Task {index}"
                self.status.emit(f"{label} ({index}/{total})")
                self.progress.emit(f"\n{{P}}➡️ {label}{{W}}")

                if task['type'] == 'hashcat':
                    result = self._run_hashcat(
                        handshake,
                        wordlist=task.get('wordlist'),
                        mode=task.get('mode', '0'),
                        mask=task.get('mask'),
                        source=task.get('source'),
                        options=task.get('options') or {},
                        task_label=label,
                        task_dict=task
                    )
                else:
                    result = self._run_aircrack(
                        handshake,
                        task.get('wordlist'),
                        source_label=task.get('source'),
                        task_label=label
                    )

                if result is None:
                    self.status.emit("Cracking stopped by user.")
                    self.finished.emit(False, last_data or {})
                    return

                success, data = result
                last_data = data
                if success:
                    self.finished.emit(True, data)
                    return

            self.finished.emit(False, last_data or {
                'essid': handshake.essid,
                'bssid': handshake.bssid,
                'path': handshake.capfile,
                'type': self.job.get('type', '4-WAY')
            })

        except Exception as exc:
            self.failed.emit(str(exc))

    def _build_tasks(self, wordlists: List[str]) -> List[Dict[str, Any]]:
        """Compile a list of cracking tasks based on tool selection and brute-force settings."""
        tasks: List[Dict[str, Any]] = []
        tool_choice = (self.tool or '').lower()
        job_type = (self.job.get('type') or '').lower()

        if job_type == 'pmkid':
            tool_choice = 'hashcat'

        if tool_choice == 'aircrack-ng':
            if not wordlists:
                raise FileNotFoundError("Aircrack-ng requires at least one wordlist.")
            for wordlist in wordlists:
                base = os.path.basename(wordlist)
                tasks.append({
                    'type': 'aircrack',
                    'mode': None,
                    'wordlist': wordlist,
                    'mask': None,
                    'source': base,
                    'label': f"aircrack-ng ({base})",
                    'options': {},
                })
            return tasks

        if tool_choice != 'hashcat':
            raise RuntimeError(f"Unsupported cracking tool: {self.tool}")

        brute = self.bruteforce if isinstance(self.bruteforce, dict) else {}
        try:
            from ..tools.hashcat import Hashcat
            base_tasks = Hashcat._build_hashcat_tasks(wordlists, brute)
        except FileNotFoundError as exc:
            raise FileNotFoundError(str(exc)) from exc

        default_mask = brute.get('mask') or '?d?d?d?d?d?d?d?d'

        for task in base_tasks:
            mode = task.get('mode', '0')
            wordlist = task.get('wordlist')
            mask_value = task.get('mask') or default_mask
            options = task.get('options') or {}

            if mode == '3':
                label = "Mask brute force"
                if mask_value:
                    label = f"{label} ({mask_value})"
                source = mask_value
            elif mode == '6':
                base_name = os.path.basename(wordlist) if wordlist else 'wordlist'
                label = f"Hybrid wordlist+mask ({base_name} + {mask_value})"
                source = f"{base_name} + {mask_value}"
            elif mode == '7':
                base_name = os.path.basename(wordlist) if wordlist else 'wordlist'
                label = f"Hybrid mask+wordlist ({mask_value} + {base_name})"
                source = f"{mask_value} + {base_name}"
            else:
                base_name = os.path.basename(wordlist) if wordlist else 'dictionary'
                label = f"Dictionary ({base_name})"
                source = base_name
                mask_value = None

            tasks.append({
                'type': 'hashcat',
                'mode': mode,
                'wordlist': wordlist,
                'mask': mask_value,
                'source': source,
                'label': label,
                'options': options,
            })
        return tasks

    def _run_aircrack(self, handshake, wordlist, source_label=None, task_label=None):
        if Configuration is None:
            raise RuntimeError("Configuration unavailable.")
        key_file = os.path.join(Configuration.temp(), f"gui_aircrack_{uuid.uuid4().hex}.key")
        command = [
            'aircrack-ng',
            '-a', '2',
            '-w', wordlist,
            '--bssid', handshake.bssid,
            '-l', key_file,
            handshake.capfile
        ]
        return self._execute(
            command,
            key_file,
            handshake,
            key_field='handshake_file',
            source_label=source_label or wordlist,
            task_label=task_label
        )

    def _run_hashcat(
            self,
            handshake,
            wordlist: Optional[str] = None,
            mode: str = '0',
            mask: Optional[str] = None,
            source: Optional[str] = None,
            options: Optional[Dict[str, Any]] = None,
            task_label: Optional[str] = None,
            task_dict: Optional[Dict[str, Any]] = None):
        if Configuration is None:
            raise RuntimeError("Configuration unavailable.")
        key_file = os.path.join(Configuration.temp(), f"gui_hashcat_{uuid.uuid4().hex}.key")

        temporary_input = None
        hash_input = handshake.capfile
        hash_mode = '22000'

        if handshake.capfile.lower().endswith('.22000'):
            hash_mode = '22000'
        elif handshake.capfile.lower().endswith('.16800'):
            hash_mode = '16800'
        else:
            try:
                from ..tools.hashcat import Hashcat, HcxPcapTool
                temporary_input = HcxPcapTool.generate_22000_file(handshake, show_command=False)
                hash_input = temporary_input
            except Exception as exc:
                raise RuntimeError(f"Failed to prepare handshake for hashcat: {exc}") from exc

        attack_mode = mode if mode in {'0', '3', '6', '7'} else '0'
        mask_value = mask or '?d?d?d?d?d?d?d?d'

        try:
            from ..tools.hashcat import Hashcat
            command = ['hashcat', '-m', hash_mode]
            command.extend(['-a', attack_mode])
            command.append(hash_input)

            if attack_mode == '3':
                command.append(mask_value)
            elif attack_mode == '6':
                if not wordlist:
                    raise ValueError("Hybrid mode 6 requires a wordlist.")
                command.append(wordlist)
                command.append(mask_value)
            elif attack_mode == '7':
                if not wordlist:
                    raise ValueError("Hybrid mode 7 requires a wordlist.")
                command.append(mask_value)
                command.append(wordlist)
            else:
                if not wordlist:
                    raise ValueError("Dictionary mode requires a wordlist.")
                command.append(wordlist)

            command.extend([
                '--outfile', key_file,
                '--outfile-format', '2',
                '--status',
                '--status-json',
            ])

            runtime_seconds = None
            if options:
                runtime_seconds = options.get('timeout_seconds')
            if runtime_seconds:
                try:
                    runtime_int = int(runtime_seconds)
                    if runtime_int > 0:
                        command.extend(['--runtime', str(runtime_int)])
                except (TypeError, ValueError):
                    pass

            session_name = None
            if isinstance(task_dict, dict):
                session_name = task_dict.get('session')
            if not session_name:
                session_name = f"wifitex_gui_{uuid.uuid4().hex[:12]}"
                if isinstance(task_dict, dict):
                    task_dict['session'] = session_name
            command.extend(['--session', session_name])

            if Hashcat.should_use_force():
                command.append('--force')
            key_field = 'pmkid_file' if hash_mode == '16800' else 'handshake_file'
            display_source = source or wordlist or mask_value
            return self._execute(
                command,
                key_file,
                handshake,
                key_field=key_field,
                source_label=display_source,
                task_label=task_label
            )
        finally:
            if temporary_input and os.path.exists(temporary_input):
                try:
                    os.remove(temporary_input)
                except Exception:
                    pass

    def _execute(self, command, key_file, handshake, key_field, source_label, task_label=None):
        try:
            self._process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            if self._process.stdout:
                for line in self._process.stdout:
                    if self._stop_event.is_set():
                        return None
                    if line.strip():
                        self.progress.emit(line.rstrip())

            return_code = self._process.wait()

            if self._stop_event.is_set():
                return None

            data: Dict[str, Any] = {
                'essid': handshake.essid,
                'bssid': handshake.bssid,
                'path': handshake.capfile,
                'type': self.job.get('type', '4-WAY'),
                'wordlist': source_label
            }
            if task_label:
                data['task'] = task_label

            if os.path.exists(key_file):
                with open(key_file, 'r', encoding='utf-8', errors='ignore') as key_fd:
                    key = key_fd.readline().strip()
                data['key'] = key
                data[key_field] = handshake.capfile
                os.remove(key_file)
                return True, data
            elif return_code == 0 or (return_code == 1 and self.tool.lower() == 'hashcat'):
                return False, data
            else:
                raise RuntimeError(f"{self.tool} exited with code {return_code}")
        finally:
            if os.path.exists(key_file):
                try:
                    os.remove(key_file)
                except Exception:
                    pass


class AttackWorker(QThread):
    """Worker thread for network attacks - integrates with existing Wifitex attack modules"""
    
    attack_progress = pyqtSignal(dict)
    attack_completed = pyqtSignal(dict)
    log_message = pyqtSignal(str)  # New signal for real-time log messages
    terminal_output = pyqtSignal(str)  # Signal for capturing all terminal output

    def __init__(self, network: Dict, attack_type: str, options: Dict, all_networks=None):
        super().__init__()
        self.network = network
        self.attack_type = attack_type
        self.options = options
        self.all_networks = all_networks or []  # All scanned networks for companion detection
        self.skip_current_attack = False
        self.should_skip_current_attack = False  # Alias for compatibility
        self.pause_for_user_decision = False  # Flag to pause for user decision
        self.current_attack = None
        self.active_processes = []  # Track active attack processes
        self.stop_requested = False
        
        # Thread synchronization
        import threading
        self._state_lock = threading.Lock()  # Protects state changes
        self.set_running(True)
        self._process_lock = threading.Lock()  # Protects process management
        self._config_prepared = False
        
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
            
            # Apply scan band preferences from options (defaults emulate legacy behaviour)
            scan_24 = bool(self.options.get('scan_band_24ghz', True))
            scan_5 = bool(self.options.get('scan_band_5ghz', True))
            scan_6 = bool(self.options.get('scan_band_6ghz', False))

            if hasattr(self.Configuration, 'scan_band_24'):
                self.Configuration.scan_band_24 = scan_24
            if hasattr(self.Configuration, 'scan_band_5'):
                self.Configuration.scan_band_5 = scan_5
            if hasattr(self.Configuration, 'scan_band_6'):
                self.Configuration.scan_band_6 = scan_6

            # Set target channel and automatically enable higher bands when needed
            target_channel = self.options.get('channel')
            if target_channel:
                try:
                    channel_num = int(target_channel)
                    self.Configuration.target_channel = channel_num
                    if channel_num >= 36:
                        scan_5 = True
                    # Basic heuristic for 6GHz (channel numbers 1-233 in 6GHz band)
                    if channel_num > 200:
                        scan_6 = True
                except (ValueError, TypeError):
                    self.Configuration.target_channel = target_channel

            self.Configuration.five_ghz = scan_5
            if hasattr(self.Configuration, 'six_ghz'):
                self.Configuration.six_ghz = scan_6
            
            # Set timeouts from GUI - Use more reasonable defaults
            self.Configuration.wpa_attack_timeout = self.options.get('wpa_timeout', 300)  # 5 minutes
            self.Configuration.wpa_deauth_timeout = self.options.get('wpa_deauth_timeout', 20)  # 20 seconds
            
            # Debug logging for deauth timeout (only if verbose)
            # Removed debug message to reduce log spam
            # Note: WPS timeout is handled by individual attack classes
            
            # Set attack preferences with performance optimizations (from options)
            # Map GUI setting keys to Configuration keys
            self.Configuration.wps_pixie = bool(self.options.get('wps_pixie_dust', 
                                    self.options.get('wps_pixie', True)))
            self.Configuration.wps_pin = bool(self.options.get('wps_pin_brute_force',
                                    self.options.get('wps_pin', True)))
            self.Configuration.use_bully = bool(self.options.get('wps_use_bully',
                                    self.options.get('use_bully', False)))
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
            
            # Brute force settings (from options)
            self.Configuration.use_brute_force = bool(self.options.get('use_brute_force', False))
            if self.Configuration.use_brute_force:
                # Map GUI mode index to hashcat mode string
                mode_index = self.options.get('brute_force_mode', 1)  # Default to mode 3
                mode_map = {
                    0: '0',  # Dictionary
                    1: '3',  # Pure brute force
                    2: '6',  # Hybrid wordlist + mask
                    3: '7'   # Hybrid mask + wordlist
                }
                self.Configuration.brute_force_mode = mode_map.get(mode_index, '3')
                self.Configuration.brute_force_mask = self.options.get('brute_force_mask', '?a?a?a?a?a?a?a?a')
                self.Configuration.brute_force_timeout = int(self.options.get('brute_force_timeout', 3600))  # Default 1 hour
                
                # Log brute force configuration
                if self.Configuration.brute_force_mode == '3':
                    self.log_message.emit(f"Brute force enabled: Pure brute force with mask {self.Configuration.brute_force_mask}")
                elif self.Configuration.brute_force_mode in ['6', '7']:
                    self.log_message.emit(f"Brute force enabled: Hybrid mode {self.Configuration.brute_force_mode} with mask {self.Configuration.brute_force_mask}")
            
            # Set wordlist if auto-crack is enabled OR if brute force needs it OR if KARMA handshake cracking is enabled
            needs_wordlist = False
            if self.options.get('crack', False):
                needs_wordlist = True
                self.log_message.emit("Auto-crack enabled: wordlist will be used")
            elif self.Configuration.use_brute_force:
                # Check if brute force mode requires a wordlist (modes 0, 6, 7)
                brute_mode = self.Configuration.brute_force_mode
                if brute_mode in ['0', '6', '7']:
                    needs_wordlist = True
                    self.log_message.emit(f"Brute force mode {brute_mode} requires wordlist")
            
            if needs_wordlist:
                # PRIORITY 1: Use user-selected wordlist from GUI (if set)
                primary_wordlist = self.options.get('primary_wordlist')
                if primary_wordlist and os.path.exists(primary_wordlist):
                    self.Configuration.wordlist = primary_wordlist
                    self.log_message.emit(f"[WORDLIST] Using user-selected wordlist: {os.path.basename(primary_wordlist)}")
                else:
                    # PRIORITY 2: Use wordlist from wifitex/wordlists/ folder (default)
                    wifitex_wordlist = self._get_wifitex_wordlist()
                    if wifitex_wordlist:
                        self.Configuration.wordlist = wifitex_wordlist
                        self.log_message.emit(f"[WORDLIST] Using default wordlist from wifitex/wordlists/: {os.path.basename(wifitex_wordlist)}")
                    else:
                        # PRIORITY 3: Use enhanced wordlist selection based on strategy
                        cracking_strategy = self.options.get('cracking_strategy', 'fast')
                        
                        if cracking_strategy == 'comprehensive':
                            # Try rockyou if available, otherwise fallback
                            try:
                                recommended_wordlists = self.wordlist_manager.get_recommended_wordlists()
                                if recommended_wordlists:
                                    # Extract rockyou wordlist path
                                    rockyou_path = None
                                    for path, info in recommended_wordlists:
                                        if 'rockyou' in info['name'].lower():
                                            rockyou_path = path
                                            break
                                    
                                    if rockyou_path and os.path.exists(rockyou_path):
                                        self.Configuration.wordlist = rockyou_path
                                        self.log_message.emit(f"[WORDLIST] Using comprehensive wordlist: {os.path.basename(rockyou_path)}")
                                    else:
                                        # Fallback to project wordlist
                                        project_wordlist = self._get_project_wordlist_path()
                                        if project_wordlist and os.path.exists(project_wordlist):
                                            self.Configuration.wordlist = project_wordlist
                                            self.log_message.emit(f"[WORDLIST] Using fallback wordlist: {os.path.basename(project_wordlist)}")
                                else:
                                    self.log_message.emit("[WORDLIST] Warning: No recommended wordlists found")
                            except Exception as e:
                                self.log_message.emit(f"[WORDLIST] Error getting recommended wordlists: {e}")
                        else:
                            # Use project wordlist for fast attacks
                            project_wordlist = self._get_project_wordlist_path()
                            if project_wordlist and os.path.exists(project_wordlist):
                                self.Configuration.wordlist = project_wordlist
                                self.log_message.emit(f"[WORDLIST] Using fast wordlist: {os.path.basename(project_wordlist)}")
                            else:
                                self.log_message.emit("[WORDLIST] Warning: Project wordlist not found")
            else:
                # No wordlist needed (pure brute force mode 3 only)
                self.Configuration.wordlist = None
                if self.Configuration.use_brute_force and self.Configuration.brute_force_mode == '3':
                    self.log_message.emit("Pure brute force mode - no wordlist needed")
                else:
                    self.log_message.emit("Auto-crack disabled, wordlist not set")
            
            # Apply GUI settings to Configuration from options
            # Get multi-wordlist and custom wordlist settings from options
            if Configuration and 'multi_wordlist' in self.options:
                Configuration.multi_wordlist = self.options['multi_wordlist']
                if Configuration.multi_wordlist:
                    self.log_message.emit("[WORDLIST] Multi-wordlist mode enabled")
            
            # Apply custom wordlist paths from options
            if Configuration and 'custom_wordlist_paths' in self.options:
                custom_paths = self.options['custom_wordlist_paths']
                if custom_paths:
                    Configuration.custom_wordlist_paths = custom_paths
                    self.log_message.emit(f"[WORDLIST] Applied {len(custom_paths)} custom wordlist path(s) from GUI settings")
                    if Configuration.verbose > 0:
                        # Show first few paths for debugging
                        for i, cp in enumerate(custom_paths[:3], 1):
                            self.log_message.emit(f"  {i}. {os.path.basename(cp) if os.path.isfile(cp) else cp}")
                        if len(custom_paths) > 3:
                            self.log_message.emit(f"  ... and {len(custom_paths) - 3} more")
                else:
                    Configuration.custom_wordlist_paths = []
                    self.log_message.emit("[WORDLIST] No custom wordlist paths in options")
            
            # Override Color.pattack to capture all attack progress messages
            self._setup_attack_logging()
            
        except Exception as e:
            logger.error(f"Error configuring Wifitex settings: {e}")
    
    def _get_project_wordlist_path(self):
        """Get the project wordlist path dynamically"""
        return self.get_wordlist_path()
    
    def _get_wifitex_wordlist(self):
        """Get default wordlist from wifitex/wordlists/ folder"""
        try:
            import os
            # Get wifitex package directory
            wifitex_package_dir = os.path.dirname(os.path.dirname(__file__))
            wifitex_wordlists_dir = os.path.join(wifitex_package_dir, 'wordlists')
            
            if os.path.exists(wifitex_wordlists_dir) and os.path.isdir(wifitex_wordlists_dir):
                # Look for wordlist files in wifitex/wordlists/
                wordlist_files = []
                for root, dirs, files in os.walk(wifitex_wordlists_dir):
                    for file in files:
                        if any(ext in file.lower() for ext in ['.txt', '.lst', '.gz']):
                            wordlist_path = os.path.join(root, file)
                            if os.path.exists(wordlist_path):
                                wordlist_files.append(wordlist_path)
                
                # Prefer wordlist-top4800-probable.txt, otherwise use first available
                for wordlist in wordlist_files:
                    if 'wordlist-top4800-probable' in os.path.basename(wordlist).lower():
                        return wordlist
                
                # Return first available wordlist if no preferred one found
                if wordlist_files:
                    return wordlist_files[0]
            
            return None
        except Exception as e:
            # Log warning if verbose mode enabled (but don't fail if Configuration not available)
            try:
                verbose = getattr(Configuration, 'verbose', 0) if Configuration else 0
                if verbose > 0:
                    logger.warning(f"Error getting wifitex wordlist: {e}")
            except:
                pass
            return None
    
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
            network = self.network
            attack_type = self.attack_type
            essid = network.get('essid', 'Unknown') if isinstance(network, dict) else str(network)
            bssid = network.get('bssid', 'N/A') if isinstance(network, dict) else 'N/A'

            if not self._config_prepared:
                self.attack_progress.emit({
                    'message': f'Preparing environment for {attack_type} attack on {essid}...',
                    'progress': 5,
                    'network': essid,
                    'step': 'Preparing environment'
                })
                self._configure_wifitex_settings()
                self._config_prepared = True

            # Enable terminal output capture
            self.enable_terminal_capture()
            
            self.attack_progress.emit({
                'message': f'Starting {attack_type} attack on {essid} ({bssid})...',
                'progress': 10,
                'network': essid,
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
            
            # Convert all networks to targets for companion detection
            all_targets = self._create_all_targets_from_networks()
            
            if attack_type == "Auto (Recommended)":
                # Use AttackAll for automatic attack selection
                self._run_auto_attack(target, all_targets)
            elif attack_type == "WPA/WPA2 Handshake":
                self._run_wpa_attack(target, "WPA/WPA2 Handshake")
            elif attack_type == "WPS PIN":
                self._run_wps_attack(target, pixie_dust=False)
            elif attack_type == "WPS Pixie-Dust":
                self._run_wps_attack(target, pixie_dust=True)
            elif attack_type == "PMKID":
                self._run_pmkid_attack(target)
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
            
            # Set additional properties - convert WPS string to WPSState enum
            # WPSState values: NONE=0, UNLOCKED=1, LOCKED=2, UNKNOWN=3
            wps_status = network.get('wps', 'Unknown')
            if wps_status == 'Yes':
                target.wps = 1  # WPSState.UNLOCKED
            elif wps_status == 'Locked':
                target.wps = 2  # WPSState.LOCKED
            elif wps_status == 'No':
                target.wps = 0  # WPSState.NONE
            elif isinstance(wps_status, int):
                # Already a WPSState integer value
                target.wps = wps_status
            else:
                target.wps = 3  # WPSState.UNKNOWN
            
            target.clients = []  # Will be populated by attack classes if needed
            
            return target
            
        except Exception as e:
            logger.error(f"Error creating target: {e}")
            return None
    
    def _create_all_targets_from_networks(self):
        """Convert all scanned networks to Target objects for companion detection"""
        all_targets = []
        for network in self.all_networks:
            target = self._create_target_from_network(network)
            if target:
                all_targets.append(target)
        return all_targets
    
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
                self.stopped_by_gui = False
                
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
                        self.stopped_by_gui = True
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
                            self.stopped_by_gui = True
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
                        self.stopped_by_gui = True
                        self.worker.log_message.emit(f"[WPS] Attack skipped by user")
                        return False
                    else:
                        self.worker.log_message.emit(f"[WPS] Error: {str(e)}")
                        return False
            
            def stop(self):
                """Stop the attack"""
                self.stopped_by_gui = True
                try:
                    if hasattr(self.worker, 'active_processes') and self.tool is not None:
                        proc = getattr(self.tool, 'bully_proc', None) or getattr(self.tool, 'reaver_proc', None)
                        if proc is not None:
                            self.worker.active_processes.append(proc)

                    # Prefer native stop() if available (Bully implements this)
                    if self.tool is not None:
                        stop_fn = getattr(self.tool, 'stop', None)
                        if callable(stop_fn):
                            stop_fn()

                    # Handle Reaver specifically by interrupting the underlying process
                    reaver_proc = None
                    if self.tool is not None and hasattr(self.tool, 'reaver_proc'):
                        reaver_proc = getattr(self.tool, 'reaver_proc', None)
                    if reaver_proc is not None:
                        try:
                            reaver_proc.interrupt(wait_time=1.0)
                        except Exception:
                            try:
                                reaver_proc.terminate()
                            except Exception:
                                try:
                                    reaver_proc.kill()
                                except Exception:
                                    pass

                    # Fallback for Bully process objects without stop()
                    bully_proc = None
                    if self.tool is not None and hasattr(self.tool, 'bully_proc'):
                        bully_proc = getattr(self.tool, 'bully_proc', None)
                    if bully_proc is not None:
                        try:
                            bully_proc.interrupt()
                        except Exception:
                            try:
                                bully_proc.terminate()
                            except Exception:
                                try:
                                    bully_proc.kill()
                                except Exception:
                                    pass

                except Exception:
                    pass
        
        return MonitoredWPSAttack(target, pixie_dust, self)
    
    def _run_auto_attack(self, target, all_targets=None):
        """Run automatic attack using optimized attack sequence"""
        try:
            self.attack_progress.emit({
                'message': f'Running optimized attack sequence on {target.essid}...',
                'step': 'Smart attack sequence',
                'progress': 20,
                'network': target.essid
            })
            
            # Check if attack was stopped before starting
            if not self.is_running():
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
            success = self._run_smart_attack_sequence(target, all_targets)
            
            # Check if attack was stopped during execution (but not skipped)
            if not self.is_running() and not self.should_skip_current_attack:
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
        """Force cleanup of all active attack processes - instant kill like CLI"""
        def _emit_log(message: str) -> None:
            if hasattr(self, 'log_message'):
                try:
                    self.log_message.emit(message)
                except Exception:
                    pass

        try:
            cfg = getattr(self, 'Configuration', None)
            if cfg is not None:
                try:
                    setattr(cfg, 'abort_requested', True)
                except Exception as exc:
                    _emit_log(f"⚠️ Failed to set abort flag: {exc}")
        except Exception:
            pass

        attack_obj = getattr(self, 'current_attack', None)
        if attack_obj is not None and hasattr(attack_obj, 'stop'):
            try:
                _emit_log("Killing attack processes...")
                attack_obj.stop()
            except Exception as exc:
                _emit_log(f"⚠️ current_attack.stop() failed: {exc}")

        self.current_attack = None

        # REMOVED: No sleep delay - instant kill like CLI
        # try:
        #     time.sleep(0.2)
        # except Exception:
        #     pass

        # Kill all active processes immediately
        for process_info in list(self.active_processes):
            try:
                # Try kill() first for instant termination (like CLI SIGKILL)
                if hasattr(process_info, 'kill'):
                    process_info.kill()
                elif hasattr(process_info, 'terminate'):
                    process_info.terminate()
                elif hasattr(process_info, 'interrupt'):
                    process_info.interrupt()
            except Exception:
                pass

        self.active_processes.clear()

        # Immediately cleanup all tracked processes
        try:
            if Process is not None:
                Process.cleanup_all_processes()
        except Exception as exc:
            _emit_log(f"⚠️ Process.cleanup_all_processes() failed: {exc}")

        # Reset abort flag after cleanup so future attacks can run
        try:
            cfg = getattr(self, 'Configuration', None)
            if cfg is not None:
                setattr(cfg, 'abort_requested', False)
        except Exception:
            pass
    
    def stop(self):
        """Request the attack worker to stop instantly - same as CLI Ctrl+C."""
        try:
            self.stop_requested = True
        except Exception:
            pass

        try:
            self.set_running(False)
        except Exception:
            pass

        try:
            self.should_skip_current_attack = True
            self.skip_current_attack = True
        except Exception:
            pass

        try:
            self.disable_terminal_capture()
        except Exception:
            pass

        # Immediate cleanup - no delays
        try:
            self.force_cleanup()
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
        self.set_running(False)
        self.should_skip_current_attack = True
        self.log_message.emit("⏹️ Stopping all attacks...")
        self.force_cleanup()
    
    def cleanup(self):
        """Cleanup resources"""
        self.force_cleanup()
        self.set_running(False)
        
        # Disable global process tracking
        # Process imported at top of file
        if Process is not None:
            Process.disable_process_tracking()
    
    def _find_companion_for_wps(self, target, all_targets=None):
        """Find 2.4GHz companion for 5GHz WPS target"""
        if not all_targets or not self.AttackAll:
            return target

        companion = None
        find_partner = getattr(self.AttackAll, "_find_dualband_partner", None)

        if callable(find_partner):
            companion = find_partner(target, all_targets)
        else:
            try:
                target_essid = getattr(target, "essid", None)
                for candidate in all_targets:
                    if candidate is target:
                        continue
                    if target_essid and getattr(candidate, "essid", None) != target_essid:
                        continue
                    channel_value = getattr(candidate, "channel", None)
                    if channel_value is None:
                        continue
                    try:
                        channel_num = int(channel_value)
                    except (TypeError, ValueError):
                        continue
                    if 1 <= channel_num <= 14:
                        companion = candidate
                        break
            except Exception:
                companion = None

        if companion:
            companion_bssid = getattr(companion, "bssid", "unknown")
            self.log_message.emit(
                f"[+] Found 2.4GHz companion {companion_bssid} for {target.essid} (WPS more reliable on 2.4GHz)"
            )
            return companion
        return target
    
    def _run_smart_attack_sequence(self, target, all_targets=None):
        """Run optimized attack sequence based on target characteristics"""
        try:
            # Prioritize attacks based on success probability and speed
            attack_sequence = []
            
            # WPS attacks first (fastest and most effective)
            if target.wps and self.AttackWPS is not None and self.AttackWPS.can_attack_wps():
                # Add companion detection for 5GHz WPS attacks
                wps_target = self._find_companion_for_wps(target, all_targets)
                
                if self.Configuration is not None:
                    if self.Configuration.wps_pixie:
                        attack_sequence.append(('WPS Pixie-Dust', lambda: self._run_wps_attack(wps_target, pixie_dust=True)))
                    if self.Configuration.wps_pin:
                        attack_sequence.append(('WPS PIN', lambda: self._run_wps_attack(wps_target, pixie_dust=False)))
                else:
                    # Default to both WPS attacks if Configuration is None
                    attack_sequence.append(('WPS Pixie-Dust', lambda: self._run_wps_attack(wps_target, pixie_dust=True)))
                    attack_sequence.append(('WPS PIN', lambda: self._run_wps_attack(wps_target, pixie_dust=False)))
            
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
                if not self.is_running():
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
                    elif not self.is_running():
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
            self.current_attack = attack
            result = False
            try:
                result = attack.run()
            except KeyboardInterrupt:
                self.stop_requested = True
                self.current_attack = None
                self.attack_completed.emit({
                    'success': False,
                    'message': f'{attack_name} attack stopped by user for {target.essid}',
                    'network': {'essid': target.essid, 'bssid': target.bssid},
                    'stopped': True
                })
                return
            finally:
                self.current_attack = None

            if getattr(self, 'stop_requested', False):
                self.attack_completed.emit({
                    'success': False,
                    'message': f'{attack_name} attack stopped by user for {target.essid}',
                    'network': {'essid': target.essid, 'bssid': target.bssid},
                    'stopped': True
                })
                return
            
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
            result = False
            stopped_by_gui = False
            try:
                result = attack.run()
            except KeyboardInterrupt:
                self.stop_requested = True
                self.current_attack = None
                self.attack_completed.emit({
                    'success': False,
                    'message': f'{attack_name} attack stopped by user for {target.essid}',
                    'network': {'essid': target.essid, 'bssid': target.bssid},
                    'stopped': True
                })
                return
            finally:
                stopped_by_gui = getattr(attack, 'stopped_by_gui', False)
                self.current_attack = None

            stopped_by_gui = stopped_by_gui or getattr(self, 'stop_requested', False)
            
            if stopped_by_gui:
                self.attack_completed.emit({
                    'success': False,
                    'message': f'{attack_name} attack stopped by user for {target.essid}',
                    'network': {'essid': target.essid, 'bssid': target.bssid},
                    'stopped': True
                })
                return

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
            if not self.is_running():
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
            self.current_attack = attack
            result = False
            
            # Set the running and skip flags on the attack instance
            attack.running = self.is_running()
            attack.skip_current_attack = self.skip_current_attack
            
            try:
                result = attack.run()
            except KeyboardInterrupt:
                self.stop_requested = True
                self.current_attack = None
                self.attack_completed.emit({
                    'success': False,
                    'message': f'PMKID attack stopped by user for {target.essid}',
                    'network': {'essid': target.essid, 'bssid': target.bssid},
                    'stopped': True
                })
                return False
            finally:
                self.current_attack = None

            if getattr(self, 'stop_requested', False):
                self.attack_completed.emit({
                    'success': False,
                    'message': f'PMKID attack stopped by user for {target.essid}',
                    'network': {'essid': target.essid, 'bssid': target.bssid},
                    'stopped': True
                })
                return
            
            # Check if attack was stopped or skipped during execution
            if not self.is_running():
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
    
    def __del__(self):
        """Ensure thread cleanup on destruction"""
        try:
            if hasattr(self, 'set_running'):
                self.set_running(False)
            
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


class CleanupProgressDialog(QDialog):
    """Dialog showing cleanup progress during application shutdown"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Cleaning Up...")
        self.setModal(True)
        self.resize(500, 300)
        
        # Apply dark theme styling immediately to prevent black screen
        from .styles import DarkTheme
        self.setStyleSheet(DarkTheme.get_stylesheet())
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the dialog UI"""
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("Cleaning up and shutting down...")
        title.setFont(QFont("", 12, weight=QFont.Weight.Bold))
        layout.addWidget(title)
        
        # Progress text area
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Courier", 9))
        layout.addWidget(self.log_text)
        
        # Progress bar (optional, hidden by default)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)
        
        # Force immediate rendering to prevent black screen
        QApplication.processEvents()
    
    def add_log(self, message: str):
        """Add a log message to the text area"""
        self.log_text.append(message)
        # Auto-scroll to bottom
        self.log_text.moveCursor(QTextCursor.MoveOperation.End)
    
    def set_done(self):
        """Mark cleanup as done"""
        self.add_log("✓ Cleanup complete!")
    
    def show_progress(self):
        """Show progress bar"""
        self.progress_bar.show()
    
    def hide_progress(self):
        """Hide progress bar"""
        self.progress_bar.hide()


class CleanupWorker(QThread):
    """Worker thread for performing cleanup operations"""
    
    progress = pyqtSignal(str)
    error = pyqtSignal(str)
    finished = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window: Optional[Any] = parent  # Type: Any to avoid type checking issues with dynamic attributes
        self.running = True
    
    def run(self):
        """Execute cleanup operations"""
        try:
            self.progress.emit("Stopping all processes...")
            time.sleep(0.2)
            
            # Call the main window's comprehensive cleanup
            if self.main_window and hasattr(self.main_window, '_comprehensive_cleanup'):
                self.main_window._comprehensive_cleanup()  # type: ignore[attr-defined]
            
            self.progress.emit("Cleanup completed successfully")
            
        except Exception as e:
            self.error.emit(f"Error during cleanup: {str(e)}")
        finally:
            self.finished.emit()
    
    def stop(self):
        """Stop the cleanup worker"""
        self.running = False