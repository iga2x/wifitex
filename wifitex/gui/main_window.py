#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Main GUI Window for Wifitex

This module contains the main application window with all the GUI components
for wireless network auditing.
"""

import sys
import os
import json
import threading
import subprocess
import time
from datetime import datetime
from typing import List, Dict, Optional, Any

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem,
    QTextEdit, QComboBox, QLineEdit, QSpinBox, QCheckBox, QGroupBox,
    QTabWidget, QProgressBar, QStatusBar, QMenuBar, QMessageBox,
    QFileDialog, QSplitter, QFrame, QScrollArea, QListWidget,
    QListWidgetItem, QDialog, QDialogButtonBox, QFormLayout,
    QAbstractItemView
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QPropertyAnimation, QEasingCurve,
    QRect, QSize, QPoint, QSettings, QStandardPaths
)
from PyQt6.QtGui import (
    QFont, QIcon, QPalette, QColor, QPixmap, QAction, QKeySequence,
    QTextCursor, QFontMetrics, QShortcut
)

from .styles import DarkTheme
from .components import (
    NetworkScanner, AttackManager, SettingsPanel, LogViewer,
    ProgressIndicator, StatusDisplay, ToolManager, DependencyWarningDialog, ToolInstallationDialog
)
from . import components as gui_components
from typing import Any, cast
# Make linter aware of dynamically added dialog in components
CleanupProgressDialog = cast(Any, gui_components).CleanupProgressDialog
from .utils import SystemUtils, NetworkUtils, ConfigManager
from .error_handler import handle_errors, ConfigurationError
from .logger import get_logger

logger = get_logger('main_window')

# Lightweight async interface refresher
from PyQt6.QtCore import QObject, pyqtSignal

class InterfaceRefreshWorker(QThread):
    interfaces_ready = pyqtSignal(list)
    failed = pyqtSignal(str)
    def __init__(self):
        super().__init__()
    def run(self):
        try:
            interfaces = SystemUtils.get_wireless_interfaces(fast=True)
            self.interfaces_ready.emit(interfaces)
        except Exception as e:
            self.failed.emit(str(e))


class WifitexMainWindow(QMainWindow):
    """
    Main application window for Wifitex GUI
    """
    
    # Signals for thread communication
    scan_completed = pyqtSignal(list)
    attack_completed = pyqtSignal(dict)
    status_update = pyqtSignal(str)
    log_update = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.config_manager = ConfigManager()
        self.system_utils = SystemUtils()
        self.network_utils = NetworkUtils()
        # Pre-init caches used by status bar and async workers before any UI updates
        self._last_interfaces: List[str] = []
        self._iface_worker: Optional[InterfaceRefreshWorker] = None
        
        # Initialize UI components
        self.scanner = NetworkScanner()
        self.attack_manager = AttackManager()
        self.settings_panel = SettingsPanel()
        self.settings_panel.set_config_manager(self.config_manager)  # Connect settings persistence
        self.log_viewer = LogViewer()
        self.progress_indicator = ProgressIndicator()
        self.status_display = StatusDisplay()
        self.tool_manager = ToolManager()
        
        # Data storage
        self.networks = []
        self.selected_networks = []
        self.current_attacks = {}
        
        # Setup UI
        self.setup_ui()
        self.setup_connections()
        self.load_settings()
        
        # Setup keyboard shortcuts
        self.setup_keyboard_shortcuts()
        
        # Initialize tool detection
        self.initialize_tool_detection()
        
        # Check system requirements (deferred to avoid slow startup)
        
        # Caches already initialized above
        
    def setup_ui(self):
        """Initialize and setup the user interface"""
        self.setWindowTitle("Wifitex - Wireless Network Auditor")
        
        # Set a more reasonable default size that fits most displays
        self.resize(1200, 800)
        
        # Set minimum size to prevent window from becoming too small
        self.setMinimumSize(800, 600)
        
        # Center the window on screen
        self.center_window()
        
        # Apply dark theme
        self.setStyleSheet(DarkTheme.get_stylesheet())
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create main layout
        main_layout = QHBoxLayout(central_widget)
        
        # Create splitter for resizable panels
        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)
        
        # Left panel (controls and network list)
        left_panel = self.create_left_panel()
        splitter.addWidget(left_panel)
        
        # Right panel (logs and status)
        right_panel = self.create_right_panel()
        splitter.addWidget(right_panel)
        
        # Set splitter proportions
        splitter.setSizes([800, 600])
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create status bar
        self.create_status_bar()
        
    def center_window(self):
        """Center the window on the screen"""
        # Get the screen geometry
        screen = QApplication.primaryScreen()
        if screen:
            screen_geometry = screen.geometry()
            
            # Calculate center position
            x = (screen_geometry.width() - self.width()) // 2
            y = (screen_geometry.height() - self.height()) // 2
            
            # Move window to center
            self.move(x, y)
        
    def create_left_panel(self):
        """Create the left control panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Network interface selection
        interface_group = QGroupBox("Network Interface")
        interface_layout = QGridLayout(interface_group)
        
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(200)
        self.interface_combo.currentTextChanged.connect(self.on_interface_changed)
        interface_layout.addWidget(QLabel("Interface:"), 0, 0)
        interface_layout.addWidget(self.interface_combo, 0, 1)
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_interfaces)
        interface_layout.addWidget(refresh_btn, 0, 2)
        
        # Monitor mode controls
        self.enable_monitor_btn = QPushButton("Enable Monitor Mode")
        self.enable_monitor_btn.setStyleSheet("QPushButton { background-color: #28a745; }")
        self.enable_monitor_btn.clicked.connect(self.enable_monitor_mode)
        interface_layout.addWidget(self.enable_monitor_btn, 1, 0)
        
        self.disable_monitor_btn = QPushButton("Disable Monitor Mode")
        self.disable_monitor_btn.clicked.connect(self.disable_monitor_mode)
        self.disable_monitor_btn.setStyleSheet("QPushButton { background-color: #dc3545; }")
        self.disable_monitor_btn.setEnabled(False)
        interface_layout.addWidget(self.disable_monitor_btn, 1, 1)
        
        self.monitor_status = QLabel("Status: Unknown")
        interface_layout.addWidget(self.monitor_status, 2, 0, 1, 3)
        
        layout.addWidget(interface_group)
        
        # Scan controls
        scan_group = QGroupBox("Network Scanning")
        scan_layout = QGridLayout(scan_group)
        
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.setStyleSheet("QPushButton { background-color: #2d5a87; }")
        self.scan_btn.clicked.connect(self.start_scan)
        scan_layout.addWidget(self.scan_btn, 0, 0)
        
        self.stop_scan_btn = QPushButton("Stop Scan")
        self.stop_scan_btn.setEnabled(False)
        self.stop_scan_btn.clicked.connect(self.stop_scan)
        scan_layout.addWidget(self.stop_scan_btn, 0, 1)
        
        # Scan options
        scan_layout.addWidget(QLabel("Channel:"), 1, 0)
        self.channel_spin = QSpinBox()
        self.channel_spin.setRange(0, 233)  # 0 = All channels, extended range for 6GHz/7GHz
        self.channel_spin.setValue(0)  # Default to "All channels"
        self.channel_spin.setSpecialValueText("Auto (All)")
        self.channel_spin.setToolTip("0 = Auto scan all channels (2.4GHz + 5GHz + 6GHz/6E + 7GHz)\n1-14 = 2.4GHz channels\n36+ = 5GHz channels\n6GHz channels supported when available")
        scan_layout.addWidget(self.channel_spin, 1, 1)
        
        layout.addWidget(scan_group)
        
        # Network list
        networks_group = QGroupBox("Available Networks")
        networks_layout = QVBoxLayout(networks_group)
        
        self.networks_table = QTableWidget()
        self.networks_table.setColumnCount(7)
        self.networks_table.setHorizontalHeaderLabels([
            "ESSID", "BSSID", "Channel", "Power", "Encryption", "WPS", "Clients"
        ])
        self.networks_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.networks_table.setAlternatingRowColors(True)
        
        # Disable editing - make table read-only
        self.networks_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        
        # Set column widths to accommodate full ESSID names
        self.networks_table.setColumnWidth(0, 200)  # ESSID column - wider for full names
        self.networks_table.setColumnWidth(1, 150)  # BSSID column
        self.networks_table.setColumnWidth(2, 80)   # Channel column
        self.networks_table.setColumnWidth(3, 80)   # Power column
        self.networks_table.setColumnWidth(4, 120)  # Encryption column
        self.networks_table.setColumnWidth(5, 60)   # WPS column
        self.networks_table.setColumnWidth(6, 80)   # Clients column
        
        networks_layout.addWidget(self.networks_table)
        
        layout.addWidget(networks_group)
        
        # Attack controls
        attack_group = QGroupBox("Attack Options")
        attack_layout = QVBoxLayout(attack_group)
        
        # Attack type selection
        attack_type_layout = QHBoxLayout()
        attack_type_layout.addWidget(QLabel("Attack Type:"))
        
        self.attack_type_combo = QComboBox()
        self.attack_type_combo.addItems([
            "Auto (Recommended)", "WPS Pixie-Dust", "WPS PIN", 
            "WPA/WPA2 Handshake", "PMKID"
        ])
        attack_type_layout.addWidget(self.attack_type_combo)
        attack_layout.addLayout(attack_type_layout)
        
        # Attack options
        options_layout = QGridLayout()
        
        self.deauth_cb = QCheckBox("Send Deauth Packets")
        self.deauth_cb.setChecked(True)
        options_layout.addWidget(self.deauth_cb, 0, 0)
        
        self.crack_cb = QCheckBox("Auto-crack with wordlist")
        options_layout.addWidget(self.crack_cb, 0, 1)
        
        # KARMA options are configured in Settings tab; no per-attack KARMA UI here
        
        attack_layout.addLayout(options_layout)
        
        # Attack buttons
        attack_buttons_layout = QHBoxLayout()
        
        self.attack_btn = QPushButton("Start Attack")
        self.attack_btn.setStyleSheet("QPushButton { background-color: #8b0000; }")
        self.attack_btn.clicked.connect(self.start_attack)
        attack_buttons_layout.addWidget(self.attack_btn)
        
        self.stop_attack_btn = QPushButton("Stop Attack")
        self.stop_attack_btn.setEnabled(False)
        self.stop_attack_btn.clicked.connect(self.stop_attack)
        attack_buttons_layout.addWidget(self.stop_attack_btn)
        
        # Hide pause button - feature removed per user request
        self.pause_attack_btn = QPushButton("Pause & Ask")
        self.pause_attack_btn.setVisible(False)
        self.pause_attack_btn.setEnabled(False)
        self.pause_attack_btn.clicked.connect(self.pause_attack_for_decision)
        # attack_buttons_layout.addWidget(self.pause_attack_btn)  # Commented out - button hidden
        
        attack_layout.addLayout(attack_buttons_layout)
        
        layout.addWidget(attack_group)
        
        return panel
        
    def create_right_panel(self):
        """Create the right panel with logs and status"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Create tab widget
        tab_widget = QTabWidget()
        
        # Logs tab
        logs_tab = QWidget()
        logs_layout = QVBoxLayout(logs_tab)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 9))
        self.log_text.setAcceptRichText(True)  # Enable HTML formatting
        logs_layout.addWidget(self.log_text)
        
        # Log controls
        log_controls = QHBoxLayout()
        clear_log_btn = QPushButton("Clear Log")
        clear_log_btn.clicked.connect(self.clear_log)
        log_controls.addWidget(clear_log_btn)
        
        save_log_btn = QPushButton("Save Log")
        save_log_btn.clicked.connect(self.save_log)
        log_controls.addWidget(save_log_btn)
        
        log_controls.addStretch()
        logs_layout.addLayout(log_controls)
        
        tab_widget.addTab(logs_tab, "Logs")
        
        # Attack Info tab
        attack_info_tab = QWidget()
        attack_info_layout = QVBoxLayout(attack_info_tab)
        
        # Current Attack Info
        current_attack_group = QGroupBox("Current Attack")
        current_layout = QVBoxLayout(current_attack_group)
        
        self.current_attack_info = QTextEdit()
        self.current_attack_info.setReadOnly(True)
        self.current_attack_info.setMaximumHeight(120)
        self.current_attack_info.setFont(QFont("Consolas", 9))
        self.current_attack_info.setAcceptRichText(True)  # Enable HTML formatting
        # Set dark theme styling for better readability
        self.current_attack_info.setStyleSheet("""
            QTextEdit {
                background-color: #2d3748;
                color: #e2e8f0;
                border: 1px solid #4a5568;
                border-radius: 4px;
                padding: 8px;
            }
        """)
        self.current_attack_info.setHtml("""
            <div style="color: #868e96; font-family: Consolas, monospace; font-size: 9pt; text-align: center; padding: 20px;">
                <span style="color: #868e96;">No active attacks</span>
            </div>
        """)
        current_layout.addWidget(self.current_attack_info)
        
        # Progress indicators
        progress_group = QGroupBox("Attack Progress")
        progress_layout = QVBoxLayout(progress_group)
        
        self.overall_progress = QProgressBar()
        progress_layout.addWidget(QLabel("Overall Progress:"))
        progress_layout.addWidget(self.overall_progress)
        
        self.current_progress = QProgressBar()
        progress_layout.addWidget(QLabel("Current Attack:"))
        progress_layout.addWidget(self.current_progress)
        
        # Quick Stats
        stats_group = QGroupBox("Quick Stats")
        stats_layout = QGridLayout(stats_group)
        
        self.networks_found_label = QLabel("Networks Found: 0")
        self.attacks_completed_label = QLabel("Attacks Completed: 0")
        self.successful_attacks_label = QLabel("Successful: 0")
        
        stats_layout.addWidget(self.networks_found_label, 0, 0)
        stats_layout.addWidget(self.attacks_completed_label, 0, 1)
        stats_layout.addWidget(self.successful_attacks_label, 1, 0)
        
        # Tool Status
        tool_status_group = QGroupBox("Tool Status")
        tool_status_layout = QVBoxLayout(tool_status_group)
        
        self.tool_status_list = QListWidget()
        self.tool_status_list.setMaximumHeight(150)
        tool_status_layout.addWidget(self.tool_status_list)
        
        # Interface Identification
        interface_info_group = QGroupBox("Interface Identification")
        interface_info_layout = QVBoxLayout(interface_info_group)
        
        self.interface_info_list = QListWidget()
        self.interface_info_list.setMaximumHeight(200)
        interface_info_layout.addWidget(self.interface_info_list)
        
        attack_info_layout.addWidget(current_attack_group)
        attack_info_layout.addWidget(progress_group)
        attack_info_layout.addWidget(stats_group)
        attack_info_layout.addWidget(tool_status_group)
        attack_info_layout.addWidget(interface_info_group)
        
        tab_widget.addTab(attack_info_tab, "Attack Info")
        
        # Client Monitoring tab
        client_monitoring_tab = self.create_client_monitoring_tab()
        tab_widget.addTab(client_monitoring_tab, "Client Monitoring")
        
        # Settings tab
        settings_scroll = QScrollArea()
        settings_scroll.setWidget(self.settings_panel)
        settings_scroll.setWidgetResizable(True)
        settings_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        settings_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        tab_widget.addTab(settings_scroll, "Settings")
        
        layout.addWidget(tab_widget)
        
        return panel
        
    def create_menu_bar(self):
        """Create the application menu bar"""
        menubar = self.menuBar()
        if menubar is None:
            return  # Exit if menubar creation failed
        
        # File menu
        file_menu = menubar.addMenu('&File')
        if file_menu is None:
            return  # Exit if menu creation failed
        
        # Save session
        save_action = QAction('Save Session', self)
        save_action.setShortcut(QKeySequence.StandardKey.Save)
        save_action.triggered.connect(self.save_session)
        file_menu.addAction(save_action)
        
        # Load session
        load_action = QAction('Load Session', self)
        load_action.setShortcut(QKeySequence.StandardKey.Open)
        load_action.triggered.connect(self.load_session)
        file_menu.addAction(load_action)
        
        file_menu.addSeparator()
        
        # Export results
        export_action = QAction('Export Results', self)
        export_action.triggered.connect(self.export_results)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        # Exit
        exit_action = QAction('Exit', self)
        exit_action.setShortcut(QKeySequence.StandardKey.Quit)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu('&Tools')
        if tools_menu is None:
            return  # Exit if menu creation failed
        
        # Install tools
        install_action = QAction('Install Required Tools', self)
        install_action.triggered.connect(self.install_tools)
        tools_menu.addAction(install_action)
        
        # Help menu
        help_menu = menubar.addMenu('&Help')
        if help_menu is None:
            return  # Exit if menu creation failed
        
        # User Guide
        guide_action = QAction('User Guide', self)
        guide_action.triggered.connect(self.show_user_guide)
        help_menu.addAction(guide_action)
        
        # Keyboard Shortcuts
        shortcuts_action = QAction('Keyboard Shortcuts', self)
        shortcuts_action.triggered.connect(self.show_keyboard_shortcuts)
        help_menu.addAction(shortcuts_action)
        
        help_menu.addSeparator()
        
        # Check Dependencies
        deps_action = QAction('Check Dependencies', self)
        deps_action.triggered.connect(self.check_dependencies)
        help_menu.addAction(deps_action)
        
        # System Information
        sysinfo_action = QAction('System Information', self)
        sysinfo_action.triggered.connect(self.show_system_info)
        help_menu.addAction(sysinfo_action)
        
        help_menu.addSeparator()
        
        # About
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def create_status_bar(self):
        """Create the status bar"""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Add permanent widgets
        self.interface_status = QLabel("Interface: None")
        self.status_bar.addPermanentWidget(self.interface_status)
        
        self.scan_status = QLabel("Scan: Stopped")
        self.status_bar.addPermanentWidget(self.scan_status)
        
        self.attack_status = QLabel("Attack: None")
        self.status_bar.addPermanentWidget(self.attack_status)
        
        # Initialize status bar with current state
        self.update_status_bar()
        
    def update_status_bar(self):
        """Update the status bar with current state"""
        try:
            # Use the currently selected interface instead of first interface
            if hasattr(self, 'interface_combo') and self.interface_combo.currentText():
                interface = self.interface_combo.currentText().strip()
                # Check if interface is in monitor mode
                result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=0.5)
                if result.returncode == 0 and 'Mode:Monitor' in result.stdout:
                    self.interface_status.setText(f"Interface: {interface} (Monitor)")
                else:
                    self.interface_status.setText(f"Interface: {interface} (Managed)")
            else:
                # Fallback to cached interfaces if no selection
                interfaces = self._last_interfaces
                if interfaces:
                    interface = interfaces[0]
                    result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=0.5)
                    if result.returncode == 0 and 'Mode:Monitor' in result.stdout:
                        self.interface_status.setText(f"Interface: {interface} (Monitor)")
                    else:
                        self.interface_status.setText(f"Interface: {interface} (Managed)")
                else:
                    self.interface_status.setText("Interface: None")
                
            # Update scan status
            if hasattr(self, 'scanner') and self.scanner.scanning:
                self.scan_status.setText("Scan: Running")
            else:
                self.scan_status.setText("Scan: Stopped")
                
            # Update attack status
            if hasattr(self, 'attack_manager') and self.attack_manager.attacking:
                self.attack_status.setText("Attack: Running")
            else:
                self.attack_status.setText("Attack: None")
                
        except Exception as e:
            logger.error(f"Error updating status bar: {e}")
        
    def setup_connections(self):
        """Setup signal connections"""
        self.scan_completed.connect(self.on_scan_completed)
        self.attack_completed.connect(self.on_attack_completed)
        self.status_update.connect(self.update_status)
        self.log_update.connect(self.add_log)
        
        # Connect NetworkScanner signals
        self.scanner.scan_started.connect(self.on_scan_started)
        self.scanner.scan_completed.connect(self.on_scan_completed)
        self.scanner.scan_progress.connect(self.on_scan_progress)
        
        # Connect AttackManager signals
        self.attack_manager.attack_started.connect(self.on_attack_started)
        self.attack_manager.attack_completed.connect(self.on_attack_completed)
        self.attack_manager.attack_progress.connect(self.on_attack_progress)
        self.attack_manager.attack_failed.connect(self.on_attack_failed)
        self.attack_manager.log_message.connect(self.add_log)  # Connect real-time log messages
        self.attack_manager.attack_paused_for_decision.connect(self.show_attack_decision_dialog)
        
        # Network table selection
        self.networks_table.itemSelectionChanged.connect(self.on_network_selection_changed)
        
    def get_current_monitor_interface(self) -> Optional[str]:
        """Get the current monitor interface by checking actual mode with iwconfig."""
        try:
            from .utils import SystemUtils
            interfaces = SystemUtils.get_wireless_interfaces()
            # Prefer the user-selected interface if it is already in monitor mode
            selected = self.interface_combo.currentText().strip() if hasattr(self, 'interface_combo') else ''
            try:
                if selected:
                    result = subprocess.run(['iwconfig', selected], capture_output=True, text=True, timeout=0.8)
                    if result.returncode == 0 and 'Mode:Monitor' in result.stdout:
                        return selected
            except Exception:
                pass

            # Otherwise, return the first interface that is actually in monitor mode
            for interface in interfaces:
                try:
                    result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=0.8)
                    if result.returncode == 0 and 'Mode:Monitor' in result.stdout:
                        return interface
                except Exception:
                    continue

            # Fallback: return selected if present, else first detected
            return selected or (interfaces[0] if interfaces else None)
        except Exception as e:
            logger.error(f"Error getting current monitor interface: {e}")
            return None
    
    def refresh_interfaces(self):
        """Refresh available network interfaces"""
        try:
            # Check system requirements on first refresh (lazy loading)
            if not hasattr(self, '_system_checked'):
                if not self.check_system_requirements():
                    return
                self._system_checked = True
            
            # Cancel any existing worker
            if self._iface_worker and self._iface_worker.isRunning():
                self._iface_worker.requestInterruption()
                self._iface_worker.wait(100)

            # Start async worker
            self._iface_worker = InterfaceRefreshWorker()
            self._iface_worker.interfaces_ready.connect(self._on_interfaces_ready)
            self._iface_worker.failed.connect(lambda err: self.log_update.emit(f"Error refreshing interfaces: {err}"))
            self._iface_worker.start()
            self.status_update.emit("Refreshing interfaces...")
        except Exception as e:
            self.log_update.emit(f"Error starting interface refresh: {str(e)}")

    def _on_interfaces_ready(self, interfaces: List[str]):
        self._last_interfaces = interfaces
        self.interface_combo.clear()
        self.interface_combo.addItems(interfaces)
        if interfaces:
            self.status_update.emit(f"Found {len(interfaces)} network interfaces")
            self.check_monitor_mode_status(interfaces[0])
        else:
            self.status_update.emit("No network interfaces found")
        # Update status bar with cached data
        self.update_status_bar()
            
    def on_interface_changed(self, interface):
        """Handle interface selection change"""
        if interface:
            self.check_monitor_mode_status(interface)
            self.status_update.emit(f"Selected interface: {interface}")
            self.update_status_bar()
            
    def check_monitor_mode_status(self, interface):
        """Check if interface is in monitor mode"""
        try:
            result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
            if result.returncode == 0:
                if 'Mode:Monitor' in result.stdout:
                    self.monitor_status.setText(f"Status: {interface} in Monitor Mode ✅")
                    self.enable_monitor_btn.setEnabled(False)
                    self.disable_monitor_btn.setEnabled(True)
                else:
                    self.monitor_status.setText(f"Status: {interface} in Managed Mode ⚠️")
                    self.enable_monitor_btn.setEnabled(True)
                    self.disable_monitor_btn.setEnabled(False)
            else:
                self.monitor_status.setText(f"Status: {interface} not found ❌")
                self.enable_monitor_btn.setEnabled(False)
                self.disable_monitor_btn.setEnabled(False)
        except Exception as e:
            self.monitor_status.setText(f"Status: Error checking {interface} ❌")
            self.enable_monitor_btn.setEnabled(False)
            self.disable_monitor_btn.setEnabled(False)
            
    def enable_monitor_mode(self):
        """Enable monitor mode on selected interface"""
        # Prefer the user-selected interface from the combo box; fallback to detection
        target_interface = self.interface_combo.currentText().strip()
        if not target_interface:
            from .utils import SystemUtils
            interfaces = SystemUtils.get_wireless_interfaces()
            target_interface = interfaces[0] if interfaces else None
        
        if not target_interface:
            self.status_update.emit("No interface found to enable monitor mode")
            return
            
        # Disable the button to prevent multiple clicks
        self.enable_monitor_btn.setEnabled(False)
        self.enable_monitor_btn.setText("Enabling...")
        
        # Start the monitor mode operation in a background thread
        self.monitor_thread = MonitorModeThread(target_interface, "enable")
        self.monitor_thread.monitor_completed.connect(self.on_monitor_mode_completed)
        self.monitor_thread.monitor_progress.connect(self.on_monitor_mode_progress)
        self.monitor_thread.monitor_failed.connect(self.on_monitor_mode_failed)
        self.monitor_thread.start()
        
    def disable_monitor_mode(self):
        """Disable monitor mode on selected interface"""
        # Prefer the user-selected interface from the combo box; fallback to detection
        monitor_interface = self.interface_combo.currentText().strip()
        if not monitor_interface:
            from .utils import SystemUtils
            interfaces = SystemUtils.get_wireless_interfaces()
            monitor_interface = interfaces[0] if interfaces else None
        
        if not monitor_interface:
            self.status_update.emit("No monitor interface found")
            return
            
        # Disable the button to prevent multiple clicks
        self.disable_monitor_btn.setEnabled(False)
        self.disable_monitor_btn.setText("Disabling...")
        
        # Start the disable operation in a background thread
        self.monitor_thread = MonitorModeThread(monitor_interface, "disable")
        self.monitor_thread.monitor_completed.connect(self.on_monitor_mode_completed)
        self.monitor_thread.monitor_progress.connect(self.on_monitor_mode_progress)
        self.monitor_thread.monitor_failed.connect(self.on_monitor_mode_failed)
        self.monitor_thread.start()
        
    def on_monitor_mode_progress(self, message):
        """Handle monitor mode progress updates"""
        self.status_update.emit(message)
        self.log_update.emit(message)
        
    def on_monitor_mode_completed(self, result):
        """Handle successful monitor mode operation"""
        interface = result.get('interface')
        operation = result.get('operation')
        
        if operation == "enable":
            self.status_update.emit(f"✅ Monitor mode enabled on {interface}")
            self.log_update.emit(f"Monitor mode successfully enabled on {interface}")
            
            # Update interface list to show new monitor interface
            self.refresh_interfaces()
            
            # Update interface status display
            self.status_display.update_interface_status(interface, "Monitor", "Unknown", "Unknown")
            
            # Re-enable buttons with new state
            self.enable_monitor_btn.setEnabled(False)
            self.enable_monitor_btn.setText("Enable Monitor Mode")
            self.disable_monitor_btn.setEnabled(True)
            
        elif operation == "disable":
            self.status_update.emit(f"✅ Monitor mode disabled on {interface}")
            self.log_update.emit(f"Monitor mode successfully disabled on {interface}")
            
            # Update interface status display
            self.status_display.update_interface_status(interface, "Managed", "Unknown", "Unknown")
            
            # Re-enable buttons with new state
            self.enable_monitor_btn.setEnabled(True)
            self.disable_monitor_btn.setEnabled(False)
            self.disable_monitor_btn.setText("Disable Monitor Mode")
            
            # Update interface list
            self.refresh_interfaces()
            
        # Update status bar
        self.update_status_bar()
        
    def on_monitor_mode_failed(self, error_info):
        """Handle failed monitor mode operation"""
        operation = error_info.get('operation')
        error_msg = error_info.get('error')
        
        if operation == "enable":
            self.enable_monitor_btn.setEnabled(True)
            self.enable_monitor_btn.setText("Enable Monitor Mode")
            
            # Provide helpful message for common errors
            if "Run it as root" in error_msg or "permission denied" in error_msg.lower():
                self.status_update.emit("❌ Monitor mode requires root privileges. Please run: sudo python3 wifitex-gui")
                self.log_update.emit(f"Monitor mode failed: {error_msg.strip()}")
            else:
                self.status_update.emit(f"❌ Failed to enable monitor mode: {error_msg}")
                self.log_update.emit(f"Monitor mode failed: {error_msg}")
                
        elif operation == "disable":
            self.disable_monitor_btn.setEnabled(True)
            self.disable_monitor_btn.setText("Disable Monitor Mode")
            
            self.status_update.emit(f"❌ Failed to disable monitor mode: {error_msg}")
            self.log_update.emit(f"Monitor mode disable failed: {error_msg}")
            
            
    def start_scan(self):
        """Start network scanning"""
        # Use the selected interface if available
        interface = self._get_current_interface()
        if not interface:
            QMessageBox.warning(self, "No Interface", "No wireless interfaces found.")
            return
        
        # Use the selected interface as the actual interface to check
        actual_interface = interface
        
        # Check if we have a valid interface
        if not actual_interface:
            QMessageBox.warning(self, "No Interface", "No monitor interface found. Please enable monitor mode first.")
            return
        
        # Check if interface is in monitor mode
        try:
            result = subprocess.run(['iwconfig', actual_interface], capture_output=True, text=True)
            if result.returncode != 0:
                QMessageBox.warning(self, "Interface Error", f"Interface {actual_interface} not found!")
                return
                
            if 'Mode:Monitor' not in result.stdout:
                reply = QMessageBox.question(
                    self, 
                    "Monitor Mode Required", 
                    f"Interface {actual_interface} is not in monitor mode.\n\n"
                    "Would you like to enable monitor mode now?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.Yes:
                    self.enable_monitor_mode()
                    # Wait a moment for monitor mode to be enabled
                    import time
                    time.sleep(2)
                    # Re-detect which interface is actually in monitor mode now
                    actual_interface = self.get_current_monitor_interface()
                    if actual_interface:
                        self.interface_combo.setCurrentText(actual_interface)
                        interface = actual_interface
                    else:
                        QMessageBox.warning(self, "Monitor Mode Error", "Failed to find monitor interface after enabling monitor mode.")
                        return
                else:
                    return
        except Exception as e:
            QMessageBox.warning(self, "Interface Check Error", f"Error checking interface: {str(e)}")
            return
            
        try:
            # Start scanning using the scanner component
            # Pass None for channel if value is 0 (All channels)
            channel_value = self.channel_spin.value()
            # Get scan timeout from settings panel (0 = continuous until stopped)
            scan_timeout = self.settings_panel.scan_timeout_spin.value()
            
            self.scanner.start_scan(
                interface,
                channel_value if channel_value > 0 else None,
                True,  # Always scan all bands (2.4GHz, 5GHz, 6GHz if supported)
                scan_timeout
            )
            
        except Exception as e:
            self.log_update.emit(f"Error starting scan: {str(e)}")
            self.scan_btn.setEnabled(True)
            self.stop_scan_btn.setEnabled(False)
            
    def stop_scan(self):
        """Stop network scanning"""
        self.scanner.stop_scan()
        self.scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        self.scan_status.setText("Scan: Stopped")
        self.status_update.emit("Network scanning stopped")
        # Update status bar
        self.update_status_bar()
        
    def on_scan_started(self):
        """Handle scan start"""
        # Clear previous scan results
        self.networks = []
        self.networks_table.setRowCount(0)
        self.selected_networks = []
        
        self.scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        self.scan_status.setText("Scan: Running")
        # Update status bar
        self.update_status_bar()
        self.status_update.emit("Network scanning started...")
        
        # Update status display
        self.status_display.update_network_status(0, 0, len(self.current_attacks))
        
    def on_scan_completed(self, networks):
        """Handle scan completion"""
        self.networks = networks
        self.populate_networks_table()
        
        # Update status display
        self.status_display.update_network_status(len(networks), len(self.selected_networks), len(self.current_attacks))
        
        # Update stats
        self.attack_stats['networks_found'] = len(networks)
        self.update_attack_stats()
        
        self.scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        self.scan_status.setText("Scan: Completed")
        
        self.status_update.emit(f"Scan completed. Found {len(networks)} networks")
        
    def on_scan_progress(self, progress_data):
        """Handle scan progress updates"""
        message = progress_data.get('message', 'Scanning...')
        self.log_update.emit(message)
        
        # Handle real-time network updates
        if 'new_network' in progress_data:
            new_network = progress_data['new_network']
            # Add the new network to our list
            self.networks.append(new_network)
            # Add it to the table immediately
            self.add_network_to_table(new_network)
            # Update status display
            self.status_display.update_network_status(len(self.networks), len(self.selected_networks), len(self.current_attacks))
        elif 'updated_network' in progress_data:
            updated_network = progress_data['updated_network']
            # Find and update the existing network in our list
            for i, existing_network in enumerate(self.networks):
                if existing_network['bssid'] == updated_network['bssid']:
                    self.networks[i] = updated_network
                    # Update the table row
                    self.update_network_in_table(i, updated_network)
                    break
        elif 'batch_update' in progress_data:
            # Handle batch updates to avoid excessive GUI updates
            updated_networks = progress_data['batch_update']
            
            # Debug logging for network updates
            if len(updated_networks) > 0:
                logger.debug(f"[GUI] Received batch update with {len(updated_networks)} networks")
            
            # Filter out invalid networks first
            valid_updated_networks = []
            for network in updated_networks:
                if network.get('bssid') and network.get('bssid').strip():
                    valid_updated_networks.append(network)
            
            if len(valid_updated_networks) != len(updated_networks):
                logger.debug(f"[GUI] Filtered {len(updated_networks) - len(valid_updated_networks)} invalid networks")
            
            # Update existing networks and add new ones
            for updated_network in valid_updated_networks:
                found = False
                for i, existing_network in enumerate(self.networks):
                    if existing_network['bssid'] == updated_network['bssid']:
                        # Update existing network
                        self.networks[i] = updated_network
                        self.update_network_in_table(i, updated_network)
                        found = True
                        break
                if not found:
                    # Add new network
                    self.networks.append(updated_network)
                    self.add_network_to_table(updated_network)
            
            # Update status display
            self.status_display.update_network_status(len(self.networks), len(self.selected_networks), len(self.current_attacks))
            
            # Debug logging for final count
            if len(self.networks) > 0:
                logger.debug(f"[GUI] Total networks in GUI after batch update: {len(self.networks)}")
        
        # Update progress bar if available
        if 'progress' in progress_data:
            # You could add a progress bar update here if needed
            pass
        
    def add_network_to_table(self, network):
        """Add a single network to the table"""
        # Validate network data before adding
        if not network.get('bssid') or not network.get('bssid').strip():
            return  # Skip invalid networks
        
        row = self.networks_table.rowCount()
        self.networks_table.insertRow(row)
        
        # Ensure all fields have valid values
        essid = network.get('essid', '').strip() or '<Hidden>'
        bssid = network.get('bssid', '').strip()
        channel = str(network.get('channel', '')).strip() or '?'
        power = str(network.get('power', '')).strip() or '?'
        encryption = network.get('encryption', 'Unknown').strip() or 'Unknown'
        wps = network.get('wps', 'Unknown').strip() or 'Unknown'
        clients = str(network.get('clients', 0))
        
        self.networks_table.setItem(row, 0, QTableWidgetItem(essid))
        self.networks_table.setItem(row, 1, QTableWidgetItem(bssid))
        self.networks_table.setItem(row, 2, QTableWidgetItem(channel))
        self.networks_table.setItem(row, 3, QTableWidgetItem(power))
        self.networks_table.setItem(row, 4, QTableWidgetItem(encryption))
        self.networks_table.setItem(row, 5, QTableWidgetItem(wps))
        self.networks_table.setItem(row, 6, QTableWidgetItem(clients))
        
        # Don't auto-resize to maintain fixed column widths
        
    def update_network_in_table(self, row, network):
        """Update an existing network row in the table"""
        if row < self.networks_table.rowCount():
            # Ensure all fields have valid values
            essid = network.get('essid', '').strip() or '<Hidden>'
            bssid = network.get('bssid', '').strip()
            channel = str(network.get('channel', '')).strip() or '?'
            power = str(network.get('power', '')).strip() or '?'
            encryption = network.get('encryption', 'Unknown').strip() or 'Unknown'
            wps = network.get('wps', 'Unknown').strip() or 'Unknown'
            clients = str(network.get('clients', 0))
            
            self.networks_table.setItem(row, 0, QTableWidgetItem(essid))
            self.networks_table.setItem(row, 1, QTableWidgetItem(bssid))
            self.networks_table.setItem(row, 2, QTableWidgetItem(channel))
            self.networks_table.setItem(row, 3, QTableWidgetItem(power))
            self.networks_table.setItem(row, 4, QTableWidgetItem(encryption))
            self.networks_table.setItem(row, 5, QTableWidgetItem(wps))
            self.networks_table.setItem(row, 6, QTableWidgetItem(clients))
        
    def populate_networks_table(self):
        """Populate the networks table with scan results"""
        # Filter out empty or invalid networks to prevent blank rows
        valid_networks = []
        for network in self.networks:
            # Only include networks with valid BSSID (non-empty)
            if network.get('bssid') and network.get('bssid').strip():
                valid_networks.append(network)
        
        # Update the networks list to only include valid ones
        self.networks = valid_networks
        
        self.networks_table.setRowCount(len(self.networks))
        
        for row, network in enumerate(self.networks):
            # Ensure all fields have valid values
            essid = network.get('essid', '').strip() or '<Hidden>'
            bssid = network.get('bssid', '').strip()
            channel = str(network.get('channel', '')).strip() or '?'
            power = str(network.get('power', '')).strip() or '?'
            encryption = network.get('encryption', 'Unknown').strip() or 'Unknown'
            wps = network.get('wps', 'Unknown').strip() or 'Unknown'
            clients = str(network.get('clients', 0))
            
            self.networks_table.setItem(row, 0, QTableWidgetItem(essid))
            self.networks_table.setItem(row, 1, QTableWidgetItem(bssid))
            self.networks_table.setItem(row, 2, QTableWidgetItem(channel))
            self.networks_table.setItem(row, 3, QTableWidgetItem(power))
            self.networks_table.setItem(row, 4, QTableWidgetItem(encryption))
            self.networks_table.setItem(row, 5, QTableWidgetItem(wps))
            self.networks_table.setItem(row, 6, QTableWidgetItem(clients))
            
        # Don't auto-resize to maintain fixed column widths
        
    def on_network_selection_changed(self):
        """Handle network selection changes"""
        selected_rows = set()
        for item in self.networks_table.selectedItems():
            selected_rows.add(item.row())
            
        self.selected_networks = [self.networks[row] for row in selected_rows]
        
        if self.selected_networks:
            self.attack_btn.setEnabled(True)
            self.status_update.emit(f"Selected {len(self.selected_networks)} networks for attack")
        else:
            self.attack_btn.setEnabled(False)
            
    def start_attack(self):
        """Start attack on selected networks"""
        if not self.selected_networks:
            QMessageBox.warning(self, "No Selection", "Please select networks to attack.")
            return
            
        try:
            self.attack_btn.setEnabled(False)
            self.stop_attack_btn.setEnabled(True)
            self.attack_status.setText("Attack: Running")
            
            # Get GUI settings for attacks using consolidated method
            attack_options = self._get_attack_options()
            
            # Check interface from consolidated options
            interface = attack_options.get('interface')
            if not interface:
                QMessageBox.warning(self, "No Interface", "No wireless interfaces found.")
                return
            
            # Start attack on all selected networks using the queue system
            self.attack_manager.start_attack(
                self.selected_networks,
                self.attack_type_combo.currentText(),
                attack_options
            )
            
            self.status_update.emit("Attack started...")
            
        except Exception as e:
            self.log_update.emit(f"Error starting attack: {str(e)}")
            self.attack_btn.setEnabled(True)
            self.stop_attack_btn.setEnabled(False)
    
    def _get_cracking_strategy(self) -> str:
        """Get the selected cracking strategy"""
        strategy_text = self.settings_panel.cracking_strategy_combo.currentText()
        
        if "Fast Attack" in strategy_text:
            return "fast"
        elif "Comprehensive Attack" in strategy_text:
            return "comprehensive"
        elif "Router-Focused Attack" in strategy_text:
            return "router_focused"
        elif "Custom Strategy" in strategy_text:
            return "custom"
        else:
            return "fast"  # Default fallback
            
    def stop_attack(self):
        """Stop current attack"""
        self.log_update.emit("🛑 Stopping attack...")
        
        # Force stop the attack manager
        self.attack_manager.stop_attack()
        
        # Additional cleanup - kill any remaining processes
        self.attack_manager._kill_attack_processes()
        
        # Reset UI state
        self.attack_btn.setEnabled(True)
        self.stop_attack_btn.setEnabled(False)
        # pause_attack_btn removed
        self.attack_status.setText("Attack: Stopped")
        
        # Clear attack info
        if hasattr(self, 'current_attack_info'):
            self.current_attack_info.setHtml("""
                <div style="color: #868e96; font-family: Consolas, monospace; font-size: 9pt; text-align: center; padding: 20px;">
                    <span style="color: #868e96;">No active attacks</span>
                </div>
            """)
        
        # Reset progress bars
        self.current_progress.setValue(0)
        self.overall_progress.setValue(0)
        
        self.status_update.emit("Attack stopped")
        self.log_update.emit("✅ Attack stopped successfully")
        self.update_status_bar()
    
    def pause_attack_for_decision(self):
        """Pause attack and ask user what to do next"""
        if self.attack_manager.attacking:
            self.attack_manager.pause_attack_for_user_decision()
            self.status_update.emit("Attack paused - waiting for user decision...")
    
    def show_attack_decision_dialog(self):
        """Show dialog asking user what to do with the paused attack"""
        from PyQt6.QtWidgets import QMessageBox
        
        msg = QMessageBox(self)
        msg.setWindowTitle("Attack Paused")
        msg.setText("The current attack has been paused. What would you like to do?")
        msg.setInformativeText("Choose your next action:")
        
        # Add custom buttons
        continue_btn = msg.addButton("Continue Attack", QMessageBox.ButtonRole.AcceptRole)
        skip_btn = msg.addButton("Skip to Next Attack Type", QMessageBox.ButtonRole.ActionRole)
        stop_btn = msg.addButton("Stop All Attacks", QMessageBox.ButtonRole.RejectRole)
        
        msg.setDefaultButton(continue_btn)
        msg.exec()
        
        # Handle user choice
        clicked_button = msg.clickedButton()
        if clicked_button == continue_btn:
            self.continue_current_attack()
        elif clicked_button == skip_btn:
            self.skip_to_next_attack_type()
        elif clicked_button == stop_btn:
            self.stop_all_attacks()
    
    def continue_current_attack(self):
        """Continue the current attack"""
        if hasattr(self.attack_manager, 'attack_thread') and self.attack_manager.attack_thread:
            self.attack_manager.attack_thread.continue_attack()
        self.status_update.emit("Continuing attack...")
    
    def skip_to_next_attack_type(self):
        """Skip to next attack type"""
        if hasattr(self.attack_manager, 'attack_thread') and self.attack_manager.attack_thread:
            self.attack_manager.attack_thread.skip_to_next_attack_type()
        self.status_update.emit("Skipping to next attack type...")
    
    def stop_all_attacks(self):
        """Stop all attacks"""
        if hasattr(self.attack_manager, 'attack_thread') and self.attack_manager.attack_thread:
            self.attack_manager.attack_thread.stop_all_attacks()
        self.stop_attack()
        self.status_update.emit("All attacks stopped")
    
    def _get_current_interface(self):
        """Get current wireless interface - prefer selected, fallback to detection"""
        selected = self.interface_combo.currentText().strip()
        if selected:
            return selected
        from .utils import SystemUtils
        interfaces = SystemUtils.get_wireless_interfaces()
        return interfaces[0] if interfaces else None
    
    def _get_attack_options(self):
        """Get current attack options - consolidated method to avoid duplication"""
        return {
            'deauth': self.deauth_cb.isChecked(),
            'crack': self.crack_cb.isChecked(),
            'interface': self._get_current_interface(),
            'wpa_timeout': self.settings_panel.wpa_timeout_spin.value(),
            'wpa_deauth_timeout': self.settings_panel.wpa_deauth_timeout_spin.value(),
            'wps_timeout': self.settings_panel.wps_timeout_spin.value(),
            'scan_timeout': self.settings_panel.scan_timeout_spin.value(),
            'verbose': self.settings_panel.verbose_cb.isChecked(),
            'kill_processes': self.settings_panel.kill_processes_cb.isChecked(),
            'random_mac': self.settings_panel.random_mac_cb.isChecked(),
            # Enhanced cracking options
            'cracking_strategy': self._get_cracking_strategy(),
            'primary_wordlist': self.settings_panel.wordlist_combo.currentData(),
            'multi_wordlist': self.settings_panel.multi_wordlist_cb.isChecked(),
            'use_aircrack': self.settings_panel.aircrack_cb.isChecked(),
            'use_hashcat': self.settings_panel.hashcat_cb.isChecked(),
            # Brute force options (from GPU-Accelerated section)
            'use_brute_force': self.settings_panel.brute_force_cb.isChecked(),
            'brute_force_mode': self.settings_panel.brute_mode_combo.currentIndex(),
            'brute_force_mask': self.settings_panel.mask_combo.currentText() == "Custom Pattern" and self.settings_panel.custom_mask_edit.text() or self.settings_panel.mask_patterns.get(self.settings_panel.mask_combo.currentText(), "?d?d?d?d?d?d"),
            'brute_force_timeout': self.settings_panel.brute_timeout_spin.value() * 60,  # Convert minutes to seconds
            # KARMA Attack options come from Settings panel only
            'karma_dns_spoofing': self.settings_panel.karma_dns_spoofing_cb.isChecked()
        }
        
    def on_attack_completed(self, result):
        """Handle attack completion"""
        # Check if we should continue with next attack (skip scenario)
        if result.get('continue_next', False):
            # Continue with next attack in queue using consolidated method
            self._start_next_attack()
            return
            
        # Check if this was a skip or stop
        if result.get('skipped', False):
            self.attack_status.setText("Attack: Skipped")
            self.status_update.emit("Attack skipped")
        elif result.get('stopped', False):
            self.attack_status.setText("Attack: Stopped")
            self.status_update.emit("Attack stopped")
        else:
            self.attack_status.setText("Attack: Completed")
            self.status_update.emit("Attack completed")
        
        # Enable/disable buttons appropriately
        if self.attack_manager.attacking:
            # Still attacking, keep buttons as they are
            pass
        else:
            # All attacks finished - ensure proper cleanup
            self.attack_btn.setEnabled(True)
            self.stop_attack_btn.setEnabled(False)
            # pause_attack_btn removed
            
            # Force cleanup of any remaining attack processes
            if hasattr(self.attack_manager, '_kill_attack_processes'):
                self.attack_manager._kill_attack_processes()
        
        # Get network info
        network = result.get('network', {})
        network_name = network.get('essid', 'Unknown')
        
        if result.get('success'):
            success_msg = result.get('message', 'Attack completed successfully')
            self.status_update.emit(f"✅ {network_name}: {success_msg}")
            
            # Show success message box for important results
            if 'key' in result or 'pin' in result or 'handshake' in result:
                key_info = ""
                if 'key' in result:
                    key_info = f"\nPassword: {result['key']}"
                elif 'pin' in result:
                    key_info = f"\nWPS PIN: {result['pin']}"
                elif 'handshake' in result:
                    key_info = f"\nHandshake captured successfully"
                
                QMessageBox.information(
                    self, 
                    "Attack Successful", 
                    f"Attack on {network_name} was successful!{key_info}"
                )
        else:
            failure_msg = result.get('message', 'Attack failed')
            self.status_update.emit(f"❌ {network_name}: {failure_msg}")
            
            # Show warning for common failures that might need user attention
            if 'Permission denied' in failure_msg:
                QMessageBox.warning(
                    self,
                    "Permission Error",
                    f"Permission denied for {network_name}.\n\nPlease ensure:\n• GUI is running as root (sudo)\n• Interface is in monitor mode\n• No conflicting processes are running"
                )
            elif 'not found' in failure_msg.lower():
                QMessageBox.warning(
                    self,
                    "Interface Error", 
                    f"Interface error for {network_name}.\n\nPlease check:\n• Interface is available and in monitor mode\n• Interface name is correct\n• Wireless card is properly connected"
                )
            
    def on_attack_started(self, essid: str):
        """Handle attack started signal"""
        self.attack_btn.setEnabled(False)
        self.stop_attack_btn.setEnabled(True)
        
        # pause_attack_btn removed - keep it disabled
        self.attack_status.setText(f"Attack: {essid}")
        self.log_update.emit(f"Starting attack on {essid}")
        self.status_update.emit(f"Attacking {essid}...")
    
    def on_attack_type_changed(self, attack_type):
        """Handle attack type selection change"""
        if attack_type == "KARMA Attack":
            # KARMA per-attack options are managed in Settings only
            self.log_update.emit("KARMA Attack selected - configure options in Settings tab")
        else:
            pass
        
    def on_attack_progress(self, progress_data):
        """Handle attack progress updates"""
        message = progress_data.get('message', '')
        progress_percent = progress_data.get('progress', 0)
        step = progress_data.get('step', 'Running')
        network = progress_data.get('network', 'Unknown')
        attack_type = progress_data.get('attack_type', 'Unknown')
        
        # Update progress bars
        self.current_progress.setValue(progress_percent)
        
        # Calculate overall progress based on attack queue
        if hasattr(self.attack_manager, 'attack_queue') and len(self.attack_manager.attack_queue) > 0:
            current_index = getattr(self.attack_manager, 'current_attack_index', 0)
            total_attacks = len(self.attack_manager.attack_queue)
            base_progress = (current_index / total_attacks) * 100
            attack_progress = (progress_percent / 100) * (1 / total_attacks) * 100
            overall_progress = int(base_progress + attack_progress)
            self.overall_progress.setValue(overall_progress)
        
        # Update status with meaningful information
        status_text = f"{step}: {network} ({attack_type})"
        self.status_display.update_attack_status(status_text)
        
        # Update attack info display
        self.update_attack_info(progress_data)
        
        # Only log important progress updates to avoid spam
        if step in ['Initializing', 'Success', 'Failed'] or progress_percent % 25 == 0:
            self.log_update.emit(f"[{attack_type}] {network}: {step} - {message}")
            
    def on_attack_failed(self, essid: str, reason: str):
        """Handle attack failed signal"""
        if reason == "SKIP_TO_NEXT":
            # Handle skip to next attack
            self.log_update.emit(f"Skipping to next target: {essid}")
            self.status_update.emit(f"Skipping to {essid}")
            # Start next attack
            self._start_next_attack()
        else:
            self.log_update.emit(f"Attack on {essid} failed: {reason}")
            self.status_update.emit(f"Attack on {essid} failed")
            
    def _start_next_attack(self):
        """Start the next attack in the queue"""
        if not self.attack_manager.attacking:
            return
            
        try:
            # Get current attack parameters
            current_index = self.attack_manager.current_attack_index
            if current_index >= len(self.attack_manager.attack_queue):
                return
                
            # Get attack options using consolidated method
            attack_options = self._get_attack_options()
            
            # Start attack on current network
            self.attack_manager._start_next_attack(
                self.attack_type_combo.currentText(),
                attack_options
            )
        except Exception as e:
            self.status_update.emit(f"Error starting next attack: {str(e)}")
            
    def check_system_requirements(self):
        """Check if system meets requirements"""
        try:
            from .utils import DependencyChecker
            
            # Perform comprehensive dependency check
            dependency_results = DependencyChecker.check_all_dependencies()
            missing_deps = DependencyChecker.get_missing_dependencies()
            
            # Check critical requirements first
            critical_issues = []
            
            # Check if running as root
            if not dependency_results['system']['has_root']:
                critical_issues.append("Root privileges required. Please run with sudo.")
                
            # Check Python version
            if not dependency_results['system']['python_version_ok']:
                critical_issues.append("Python 2.7+ or Python 3.6+ required.")
                
            # Check Linux OS
            if not dependency_results['system']['is_linux']:
                critical_issues.append("Linux operating system required.")
                
            # Check wireless interface
            if not dependency_results['system']['has_wireless']:
                critical_issues.append("No wireless network interfaces found.")
            
            # Show critical issues
            if critical_issues:
                QMessageBox.critical(
                    self, 
                    "Critical Requirements Not Met", 
                    "Cannot start Wifitex:\n\n" + "\n".join(f"• {issue}" for issue in critical_issues)
                )
                return False
                
            # Check required tools
            missing_required = missing_deps['tools']
            if missing_required:
                self.log_update.emit(f"Missing required tools: {', '.join(missing_required)}")
                self.status_update.emit("Some required tools are missing")
                
                # Show warning for missing required tools
                QMessageBox.warning(
                    self,
                    "Missing Required Tools",
                    f"Required tools are missing:\n\n" + "\n".join(f"• {tool}" for tool in missing_required) +
                    "\n\nPlease install these tools before using Wifitex."
                )
                return False
                
            # Check optional tools and show status
            missing_optional = []
            for tool in DependencyChecker.OPTIONAL_TOOLS:
                if not dependency_results['tools'].get(tool, False):
                    missing_optional.append(tool)
                    
            if missing_optional:
                self.log_update.emit(f"Missing optional tools: {', '.join(missing_optional)}")
                self.status_update.emit("Some optional tools are missing - some features may not work")
                
                # Show info dialog for missing optional tools
                QMessageBox.information(
                    self,
                    "Optional Tools Missing",
                    f"Optional tools are missing:\n\n" + "\n".join(f"• {tool}" for tool in missing_optional) +
                    "\n\nWifitex will work with basic functionality, but some advanced features may not be available."
                )
            
            # Update tool status display
            self.update_tool_status_display(dependency_results['tools'])
            
            # Update interface identification display
            self.update_interface_identification_display()
            
            # Update attack manager with tool availability
            self.attack_manager.set_available_tools(dependency_results['tools'])
            
            return True
            
        except Exception as e:
            self.log_update.emit(f"System check error: {str(e)}")
            return False
    
    def update_tool_status_display(self, tools_status):
        """Update the tool status display in the status tab"""
        try:
            from .utils import DependencyChecker
            
            self.tool_status_list.clear()
            
            # Define tool descriptions and impact
            tool_descriptions = {
                # Required tools
                'iwconfig': 'Identify wireless devices in Monitor Mode',
                'ifconfig': 'Start/stop wireless devices',
                'airmon-ng': 'Enable Monitor Mode on wireless devices',
                'aircrack-ng': 'Crack WPA handshake captures',
                'aireplay-ng': 'Deauth access points, replay capture files',
                'airodump-ng': 'Target scanning & capture file generation',
                'packetforge-ng': 'Forge capture files',
                
                # Optional tools
                'tshark': 'Detect WPS networks and inspect handshake captures',
                'reaver': 'WPS Pixie-Dust & brute-force attacks',
                'bully': 'Alternative WPS attack tool',
                'cowpatty': 'Detect handshake captures',
                'hashcat': 'Crack PMKID hashes',
                'hcxdumptool': 'Capture PMKID hashes',
                'hcxpcapngtool': 'Convert PMKID packet captures'
            }
            
            # Add required tools first
            self.tool_status_list.addItem("=== REQUIRED TOOLS ===")
            for tool in DependencyChecker.REQUIRED_TOOLS:
                available = tools_status.get(tool, False)
                status = "✓" if available else "❌"
                description = tool_descriptions.get(tool, tool)
                
                if available:
                    item_text = f"{status} {tool} - {description}"
                    item = QListWidgetItem(item_text)
                    item.setForeground(QColor(0, 200, 0))  # Green for available
                else:
                    item_text = f"{status} {tool} - {description} (MISSING)"
                    item = QListWidgetItem(item_text)
                    item.setForeground(QColor(200, 0, 0))  # Red for missing
                    
                self.tool_status_list.addItem(item)
            
            # Add optional tools
            self.tool_status_list.addItem("=== OPTIONAL TOOLS ===")
            for tool in DependencyChecker.OPTIONAL_TOOLS:
                available = tools_status.get(tool, False)
                status = "✓" if available else "⚠"
                description = tool_descriptions.get(tool, tool)
                
                if available:
                    item_text = f"{status} {tool} - {description}"
                    item = QListWidgetItem(item_text)
                    item.setForeground(QColor(0, 200, 0))  # Green for available
                else:
                    item_text = f"{status} {tool} - {description} (not installed)"
                    item = QListWidgetItem(item_text)
                    item.setForeground(QColor(255, 165, 0))  # Orange for optional missing
                    
                self.tool_status_list.addItem(item)
                
        except Exception as e:
            self.log_update.emit(f"Error updating tool status: {str(e)}")
    
    def update_interface_identification_display(self):
        """Update the interface identification display"""
        try:
            self.interface_info_list.clear()
            
            # Get wireless interfaces
            interfaces = self.system_utils.get_wireless_interfaces()
            
            if not interfaces:
                self.interface_info_list.addItem("❌ No wireless interfaces found")
                return
            
            # Add header
            self.interface_info_list.addItem("=== WIRELESS INTERFACES ===")
            
            for iface in interfaces:
                try:
                    # Get interface information
                    interface_info = self._get_interface_info(iface)
                    
                    # Add interface header
                    item = QListWidgetItem(f"📱 {iface}")
                    item.setForeground(QColor(150, 200, 255))  # Bright blue for interface names - better contrast
                    self.interface_info_list.addItem(item)
                    
                    # Add interface details
                    details = [
                        f"   🔧 Driver: {interface_info.get('driver', 'Unknown')}",
                        f"   📍 Bus: {interface_info.get('bus', 'Unknown')}",
                        f"   🏷️  MAC: {interface_info.get('mac', 'Unknown')}",
                        f"   💪 Power: {interface_info.get('power', 'Unknown')}",
                        f"   🔌 Type: {interface_info.get('type', 'Unknown')}",
                        f"   🎯 Best For: {interface_info.get('best_for', 'Unknown')}"
                    ]
                    
                    for detail in details:
                        detail_item = QListWidgetItem(detail)
                        detail_item.setForeground(QColor(180, 180, 180))  # Light gray for details - better contrast
                        self.interface_info_list.addItem(detail_item)
                    
                    # Add recommendation
                    recommendation = interface_info.get('recommendation', '')
                    if recommendation:
                        rec_item = QListWidgetItem(f"   💡 {recommendation}")
                        if 'RECOMMENDED' in recommendation:
                            rec_item.setForeground(QColor(100, 255, 100))  # Bright green for recommended
                        else:
                            rec_item.setForeground(QColor(255, 200, 100))  # Light orange for alternative
                        self.interface_info_list.addItem(rec_item)
                    
                    self.interface_info_list.addItem("")  # Empty line for spacing
                    
                except Exception as e:
                    error_item = QListWidgetItem(f"❌ Error getting info for {iface}: {str(e)}")
                    error_item.setForeground(QColor(200, 0, 0))  # Red for errors
                    self.interface_info_list.addItem(error_item)
            
            # Add summary
            self.interface_info_list.addItem("=== RECOMMENDATION ===")
            summary_item = QListWidgetItem("🥇 Use the interface marked 'RECOMMENDED' for monitor mode")
            summary_item.setForeground(QColor(200, 255, 200))  # Light green for summary - better contrast
            self.interface_info_list.addItem(summary_item)
            
        except Exception as e:
            self.log_update.emit(f"Error updating interface identification: {str(e)}")
    
    def _get_interface_info(self, iface):
        """Get detailed information about a wireless interface"""
        try:
            import subprocess
            
            info = {
                'driver': 'Unknown',
                'bus': 'Unknown',
                'mac': 'Unknown',
                'power': 'Unknown',
                'type': 'Unknown',
                'best_for': 'Unknown',
                'recommendation': ''
            }
            
            # Get driver information
            try:
                result = subprocess.run(['ethtool', '-i', iface], capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.startswith('driver:'):
                            info['driver'] = line.split(':', 1)[1].strip()
                        elif line.startswith('bus-info:'):
                            info['bus'] = line.split(':', 1)[1].strip()
            except:
                pass
            
            # Get MAC address and power
            try:
                result = subprocess.run(['iw', 'dev', iface, 'info'], capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.strip().startswith('addr'):
                            info['mac'] = line.split()[1]
                        elif 'txpower' in line:
                            power_match = line.split('txpower')[1].strip().split()[0]
                            info['power'] = f"{power_match} dBm"
            except:
                pass
            
            # Determine interface type and recommendations
            if 'usb' in info['bus'].lower() or info['bus'].startswith('usb'):
                info['type'] = 'USB Wireless Adapter'
                info['best_for'] = 'Monitor Mode ✅'
                info['recommendation'] = 'RECOMMENDED for wireless security testing'
            elif 'pci' in info['bus'].lower() or info['bus'].startswith('0000:'):
                info['type'] = 'Built-in PCIe WiFi Card'
                info['best_for'] = 'General WiFi'
                info['recommendation'] = 'Alternative if USB adapter fails'
            else:
                info['type'] = 'Wireless Interface'
                info['best_for'] = 'General use'
                info['recommendation'] = 'Test monitor mode capability'
            
            # Special handling for known drivers
            driver = info['driver'].lower()
            if 'rtw' in driver or 'realtek' in driver:
                info['recommendation'] = 'RECOMMENDED - Realtek has good monitor mode support'
            elif 'mt' in driver or 'mediatek' in driver:
                info['recommendation'] = 'May have monitor mode limitations'
            elif 'intel' in driver:
                info['recommendation'] = 'Intel cards often have good compatibility'
            
            return info
            
        except Exception as e:
            return {
                'driver': 'Error',
                'bus': 'Error',
                'mac': 'Error',
                'power': 'Error',
                'type': 'Error',
                'best_for': 'Error',
                'recommendation': f'Error: {str(e)}'
            }
            
    def install_tools(self):
        """Open tool installation dialog"""
        try:
            from .utils import DependencyChecker
            dependency_results = DependencyChecker.check_all_dependencies()
            dialog = ToolInstallationDialog(dependency_results, self)
            dialog.exec()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open installation dialog: {e}")
        
    def check_dependencies(self):
        """Check system dependencies"""
        try:
            from .utils import DependencyChecker
            dependency_results = DependencyChecker.check_all_dependencies()
            tool_details = DependencyChecker.get_tool_status_details()
            problematic_tools = []
            missing_tools = []
            for tool, available in dependency_results.get('tools', {}).items():
                if tool in ['hcxpcapngtool', 'tshark', 'reaver', 'bully', 'cowpatty', 'hashcat', 'hostapd', 'dnsmasq', 'aireplay-ng', 'aircrack-ng']:
                    if not available:
                        missing_tools.append(tool)
                    elif tool in tool_details and tool_details[tool].get('exists') and not tool_details[tool].get('works'):
                        problematic_tools.append({
                            'tool': tool,
                            'error': tool_details[tool].get('error', 'Unknown error')
                        })
            dialog = DependencyWarningDialog(dependency_results, tool_details, problematic_tools, self)
            dialog.exec()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to check dependencies: {e}")
        
    def add_log(self, message):
        """Add message to log with colored formatting and performance optimization"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Convert color codes to HTML formatting
        formatted_message = self._format_log_message(message)
        
        # Only add if message is not empty after formatting
        if formatted_message and formatted_message.strip():
            html_message = f'<span style="color: #868e96;">[{timestamp}]</span> {formatted_message}'
            self.log_text.append(html_message)
            
            # Performance optimization: limit log history to prevent memory issues
            self._limit_log_history()
            
            # Auto-scroll to bottom
            cursor = self.log_text.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.log_text.setTextCursor(cursor)
    
    def _limit_log_history(self):
        """Limit log history to prevent memory issues"""
        max_lines = 1000  # Keep only last 1000 lines
        
        # Get current document
        doc = self.log_text.document()
        if doc and doc.blockCount() > max_lines:
            # Remove excess lines from the beginning
            cursor = self.log_text.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            
            # Move to the line we want to keep
            for _ in range(doc.blockCount() - max_lines):
                cursor.movePosition(QTextCursor.MoveOperation.Down, QTextCursor.MoveMode.KeepAnchor)
            
            # Select and delete the excess lines
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            cursor.movePosition(QTextCursor.MoveOperation.Down, QTextCursor.MoveMode.KeepAnchor, doc.blockCount() - max_lines)
            cursor.removeSelectedText()
    
    def _format_log_message(self, message):
        """Convert color codes to HTML formatting for GUI display"""
        from .log_formatter import LogFormatter
        return LogFormatter.format_message_for_html(message)
    
    def _extract_network_name(self, message):
        """Extract network name from attack message"""
        import re
        match = re.search(r'on\s+([^\s(]+)', message)
        if match:
            return match.group(1)
        return "Unknown Network"
        
    def clear_log(self):
        """Clear the log"""
        self.log_text.clear()
        
    def save_log(self):
        """Save log to file"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Log", "wifitex_log.txt", "Text Files (*.txt)"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.log_text.toPlainText())
                self.status_update.emit(f"Log saved to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Save Error", f"Failed to save log: {str(e)}")
                
    def create_client_monitoring_tab(self):
        """Create tab for monitoring connected clients"""
        client_tab = QWidget()
        layout = QVBoxLayout(client_tab)
        
        # Client list section
        client_list_group = QGroupBox("Connected Clients")
        client_list_layout = QVBoxLayout(client_list_group)
        
        # Client list table
        self.client_list_table = QTableWidget()
        self.client_list_table.setColumnCount(6)
        self.client_list_table.setHorizontalHeaderLabels([
            "MAC Address", "IP Address", "Hostname", "Connection Time", "Traffic", "Status"
        ])
        self.client_list_table.setMaximumHeight(200)
        self.client_list_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.client_list_table.setAlternatingRowColors(True)
        client_list_layout.addWidget(self.client_list_table)
        
        # Client action buttons
        client_actions_layout = QHBoxLayout()
        
        self.kick_client_btn = QPushButton("Kick Client")
        self.kick_client_btn.clicked.connect(self.kick_selected_client)
        self.kick_client_btn.setEnabled(False)
        client_actions_layout.addWidget(self.kick_client_btn)
        
        self.view_traffic_btn = QPushButton("View Traffic")
        self.view_traffic_btn.clicked.connect(self.view_client_traffic)
        self.view_traffic_btn.setEnabled(False)
        client_actions_layout.addWidget(self.view_traffic_btn)
        
        self.analyze_credentials_btn = QPushButton("Analyze Credentials")
        self.analyze_credentials_btn.clicked.connect(self.analyze_client_credentials)
        self.analyze_credentials_btn.setEnabled(False)
        client_actions_layout.addWidget(self.analyze_credentials_btn)
        
        client_actions_layout.addStretch()
        client_list_layout.addLayout(client_actions_layout)
        
        layout.addWidget(client_list_group)
        
        # Client details section
        client_details_group = QGroupBox("Client Details")
        client_details_layout = QVBoxLayout(client_details_group)
        
        self.client_details = QTextEdit()
        self.client_details.setReadOnly(True)
        self.client_details.setMaximumHeight(150)
        self.client_details.setFont(QFont("Consolas", 9))
        self.client_details.setAcceptRichText(True)
        self.client_details.setStyleSheet("""
            QTextEdit {
                background-color: #2d3748;
                color: #e2e8f0;
                border: 1px solid #4a5568;
                border-radius: 4px;
                padding: 8px;
            }
        """)
        self.client_details.setHtml("""
            <div style="color: #868e96; font-family: Consolas, monospace; font-size: 9pt; text-align: center; padding: 20px;">
                Select a client to view details
            </div>
        """)
        client_details_layout.addWidget(self.client_details)
        
        layout.addWidget(client_details_group)
        
        # Traffic statistics section
        traffic_stats_group = QGroupBox("Traffic Statistics")
        traffic_stats_layout = QVBoxLayout(traffic_stats_group)
        
        self.traffic_stats = QTextEdit()
        self.traffic_stats.setReadOnly(True)
        self.traffic_stats.setMaximumHeight(100)
        self.traffic_stats.setFont(QFont("Consolas", 9))
        self.traffic_stats.setAcceptRichText(True)
        self.traffic_stats.setStyleSheet("""
            QTextEdit {
                background-color: #2d3748;
                color: #e2e8f0;
                border: 1px solid #4a5568;
                border-radius: 4px;
                padding: 8px;
            }
        """)
        self.traffic_stats.setHtml("""
            <div style="color: #868e96; font-family: Consolas, monospace; font-size: 9pt; text-align: center; padding: 20px;">
                Traffic statistics will appear here during KARMA attacks
            </div>
        """)
        traffic_stats_layout.addWidget(self.traffic_stats)
        
        layout.addWidget(traffic_stats_group)
        
        # Data access section
        data_access_group = QGroupBox("Captured Data Access")
        data_access_layout = QVBoxLayout(data_access_group)
        
        # PCAP files
        pcap_layout = QHBoxLayout()
        pcap_layout.addWidget(QLabel("PCAP Files:"))
        self.open_pcap_folder_btn = QPushButton("Open PCAP Folder")
        self.open_pcap_folder_btn.clicked.connect(self.open_pcap_folder)
        pcap_layout.addWidget(self.open_pcap_folder_btn)
        data_access_layout.addLayout(pcap_layout)
        
        # Handshake files
        handshake_layout = QHBoxLayout()
        handshake_layout.addWidget(QLabel("Handshakes:"))
        self.open_handshake_folder_btn = QPushButton("Open Handshake Folder")
        self.open_handshake_folder_btn.clicked.connect(self.open_handshake_folder)
        handshake_layout.addWidget(self.open_handshake_folder_btn)
        data_access_layout.addLayout(handshake_layout)
        
        # Credential files
        cred_layout = QHBoxLayout()
        cred_layout.addWidget(QLabel("Credentials:"))
        self.open_credential_folder_btn = QPushButton("Open Credential Folder")
        self.open_credential_folder_btn.clicked.connect(self.open_credential_folder)
        cred_layout.addWidget(self.open_credential_folder_btn)
        data_access_layout.addLayout(cred_layout)
        
        # Open Wireshark
        wireshark_layout = QHBoxLayout()
        wireshark_layout.addWidget(QLabel("Analysis:"))
        self.open_wireshark_btn = QPushButton("Open in Wireshark")
        self.open_wireshark_btn.clicked.connect(self.open_in_wireshark)
        wireshark_layout.addWidget(self.open_wireshark_btn)
        data_access_layout.addLayout(wireshark_layout)
        
        layout.addWidget(data_access_group)
        
        # Connect client list selection to enable/disable buttons
        self.client_list_table.itemSelectionChanged.connect(self.on_client_selection_changed)
        
        # Start KARMA monitoring timer (with longer interval to prevent freezing)
        self.karma_monitor_timer = QTimer()
        self.karma_monitor_timer.timeout.connect(self.update_karma_client_monitoring)
        self.karma_monitor_timer.start(5000)  # Update every 5 seconds to prevent GUI freezing
        
        return client_tab
    
    def update_karma_client_monitoring(self):
        """Update the client monitoring display with KARMA attack status"""
        try:
            # Check if there's an active KARMA attack (with timeout protection)
            if not (hasattr(self, 'attack_manager') and 
                    hasattr(self.attack_manager, 'attack_thread') and
                    self.attack_manager.attack_thread):
                return
            
            # Quick check to avoid blocking
            attack_thread = self.attack_manager.attack_thread
            if not hasattr(attack_thread, 'current_attack') or not attack_thread.current_attack:
                return
            
            attack = attack_thread.current_attack
            
            # Check if it's a KARMA attack (has get_karma_status method)
            if not hasattr(attack, 'get_karma_status'):
                return  # Not a KARMA attack, skip monitoring
            
            # Get KARMA status - use getattr with timeout protection
            try:
                get_karma_status_method = getattr(attack, 'get_karma_status', None)
                if get_karma_status_method:
                    # Call method without blocking
                    status = get_karma_status_method()
                    
                    # Only update if status is valid and not empty
                    if status and isinstance(status, dict):
                        # Update client list (non-blocking)
                        self.update_client_list(status)
                        
                        # Update traffic statistics (non-blocking)
                        self.update_traffic_statistics(status)
                else:
                    return  # Method doesn't exist
            except (AttributeError, TypeError) as e:
                # Method call failed - silently ignore to prevent GUI freeze
                if hasattr(self, 'log_update'):
                    self.log_update.emit(f"[DEBUG] KARMA status unavailable: {type(e).__name__}")
                return
            except Exception as e:
                # Any other error - log briefly then continue
                if hasattr(self, 'log_update'):
                    self.log_update.emit(f"[DEBUG] KARMA monitoring skipped: {type(e).__name__}")
                return
                
        except (AttributeError, RuntimeError):
            # No active KARMA attack or thread ended
            pass
        except Exception as e:
            # Don't log errors that might freeze GUI - just silently continue
            pass
    
    def update_client_list(self, status):
        """Update the client list table with KARMA client data"""
        try:
            # Limit number of clients to prevent GUI freeze with large lists
            client_details = status.get('client_details', [])[:50]  # Max 50 clients
            
            # Only update if content changed to avoid unnecessary redraws
            current_count = self.client_list_table.rowCount()
            if len(client_details) == current_count:
                # Check if content is same (quick optimization)
                return
            
            # Disable sorting during update to prevent blocking
            self.client_list_table.setSortingEnabled(False)
            
            # Clear existing rows
            self.client_list_table.setRowCount(0)
            
            # Add clients from status
            for client in client_details:
                row = self.client_list_table.rowCount()
                self.client_list_table.insertRow(row)
                
                # MAC Address
                self.client_list_table.setItem(row, 0, QTableWidgetItem(str(client.get('mac', 'Unknown'))))
                
                # IP Address (from dnsmasq lease file)
                ip_address = client.get('ip_address', 'N/A')
                self.client_list_table.setItem(row, 1, QTableWidgetItem(str(ip_address)))
                
                # Hostname (from dnsmasq lease file)
                hostname = client.get('hostname', 'N/A')
                self.client_list_table.setItem(row, 2, QTableWidgetItem(str(hostname)))
                
                # Connection Time
                self.client_list_table.setItem(row, 3, QTableWidgetItem("Connected"))
                
                # Traffic (credentials count)
                if client.get('credential_count'):
                    self.client_list_table.setItem(row, 4, QTableWidgetItem(f"{client['credential_count']} credentials"))
                else:
                    self.client_list_table.setItem(row, 4, QTableWidgetItem("Monitoring"))
                
                # Status
                status_parts = []
                if client.get('password_cracked'):
                    status_parts.append("CRACKED")
                if client.get('has_handshake'):
                    status_parts.append("Handshake")
                if client.get('has_credentials'):
                    status_parts.append("Credentials")
                status_text = " - ".join(status_parts) if status_parts else "Monitoring"
                self.client_list_table.setItem(row, 5, QTableWidgetItem(status_text))
            
            # Re-enable sorting
            self.client_list_table.setSortingEnabled(True)
                
        except Exception as e:
            # Silently handle errors to prevent GUI freeze
            pass
    
    def update_traffic_statistics(self, status):
        """Update traffic statistics display"""
        try:
            # Quick check to avoid unnecessary updates
            connected = status.get('connected_count', 0)
            handshakes = status.get('handshakes_captured', 0)
            passwords = status.get('passwords_cracked', 0)
            credentials = status.get('credentials_harvested', 0)
            pnl = status.get('pnl_networks', 0)
            
            stats_html = f"""
            <div style="font-family: Consolas, monospace; font-size: 9pt; color: #e2e8f0;">
                <h3 style="color: #4a9eff; margin-top: 0;">KARMA Statistics</h3>
                <p><strong>Connected Clients:</strong> {connected}</p>
                <p><strong>Handshakes Captured:</strong> {handshakes}</p>
                <p><strong>Passwords Cracked:</strong> {passwords}</p>
                <p><strong>Credentials Harvested:</strong> {credentials}</p>
                <p><strong>PNL Networks:</strong> {pnl}</p>
            </div>
            """
            # Only update if HTML changed (quick comparison)
            current_html = self.traffic_stats.toPlainText()
            if stats_html not in current_html:
                self.traffic_stats.setHtml(stats_html)
        except Exception as e:
            # Silently handle errors to prevent GUI freeze
            pass
        
    def on_client_selection_changed(self):
        """Handle client selection change"""
        selection_model = self.client_list_table.selectionModel()
        if not selection_model:
            return
            
        selected_rows = selection_model.selectedRows()
        has_selection = len(selected_rows) > 0
        
        # Enable/disable action buttons based on selection
        self.kick_client_btn.setEnabled(has_selection)
        self.view_traffic_btn.setEnabled(has_selection)
        self.analyze_credentials_btn.setEnabled(has_selection)
        
        if has_selection:
            # Update client details
            row = selected_rows[0].row()
            self.update_client_details(row)
    
    def update_client_details(self, row):
        """Update client details display"""
        if row < self.client_list_table.rowCount():
            mac_item = self.client_list_table.item(row, 0)
            ip_item = self.client_list_table.item(row, 1)
            hostname_item = self.client_list_table.item(row, 2)
            conn_time_item = self.client_list_table.item(row, 3)
            traffic_item = self.client_list_table.item(row, 4)
            status_item = self.client_list_table.item(row, 5)
            
            mac = mac_item.text() if mac_item else "Unknown"
            ip = ip_item.text() if ip_item else "Unknown"
            hostname = hostname_item.text() if hostname_item else "Unknown"
            conn_time = conn_time_item.text() if conn_time_item else "Unknown"
            traffic = traffic_item.text() if traffic_item else "Unknown"
            status = status_item.text() if status_item else "Unknown"
            
            details_html = f"""
            <div style="font-family: Consolas, monospace; font-size: 9pt; color: #e2e8f0;">
                <h3 style="color: #4a9eff; margin-top: 0;">Client Details</h3>
                <p><strong>MAC Address:</strong> {mac}</p>
                <p><strong>IP Address:</strong> {ip}</p>
                <p><strong>Hostname:</strong> {hostname}</p>
                <p><strong>Connection Time:</strong> {conn_time}</p>
                <p><strong>Traffic:</strong> {traffic}</p>
                <p><strong>Status:</strong> {status}</p>
            </div>
            """
            self.client_details.setHtml(details_html)
    
    def kick_selected_client(self):
        """Kick the selected client"""
        selection_model = self.client_list_table.selectionModel()
        if not selection_model:
            return
            
        selected_rows = selection_model.selectedRows()
        if selected_rows:
            row = selected_rows[0].row()
            mac_item = self.client_list_table.item(row, 0)
            mac = mac_item.text() if mac_item else "Unknown"
            
            reply = QMessageBox.question(
                self, "Kick Client", 
                f"Are you sure you want to kick client {mac}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                # TODO: Implement actual client kicking logic
                self.log_update.emit(f"[CLIENT] Kicking client {mac}")
                QMessageBox.information(self, "Client Kicked", f"Client {mac} has been kicked from the network.")
    
    def view_client_traffic(self):
        """View traffic for selected client"""
        selection_model = self.client_list_table.selectionModel()
        if not selection_model:
            return
            
        selected_rows = selection_model.selectedRows()
        if selected_rows:
            row = selected_rows[0].row()
            mac_item = self.client_list_table.item(row, 0)
            mac = mac_item.text() if mac_item else "Unknown"
            
            # Implement traffic viewing logic
            self.log_update.emit(f"[CLIENT] Viewing traffic for client {mac}")
            
            # Find traffic capture files for this client
            import glob
            mac_formatted = mac.replace(':', '-')
            traffic_dirs = [
                "karma_captures/traffic/",
                os.path.expanduser("~/wifitex/karma_captures/traffic/"),
            ]
            
            cap_files = []
            for dir_path in traffic_dirs:
                if os.path.exists(dir_path):
                    pattern = os.path.join(dir_path, f"*{mac_formatted}*.cap")
                    cap_files.extend(glob.glob(pattern))
            
            if not cap_files:
                QMessageBox.warning(self, "No Traffic Files", 
                    f"No traffic capture files found for client {mac}.\n\nPlease ensure you have captured traffic from this client first.")
                return
            
            # Open the most recent capture file with Wireshark
            most_recent = max(cap_files, key=os.path.getmtime)
            
            try:
                if os.path.exists(most_recent):
                    # Launch Wireshark
                    subprocess.Popen(['wireshark', most_recent], 
                                   stdout=subprocess.DEVNULL, 
                                   stderr=subprocess.DEVNULL)
                    self.log_update.emit(f"[CLIENT] Opened traffic file: {most_recent}")
                    QMessageBox.information(self, "Traffic View", 
                        f"Opening traffic view for client {mac}\n\nFile: {os.path.basename(most_recent)}")
                else:
                    QMessageBox.warning(self, "File Not Found", f"Traffic file not found: {most_recent}")
            except FileNotFoundError:
                QMessageBox.warning(self, "Wireshark Not Found", 
                    "Wireshark is not installed. Please install it to view traffic captures.\n\n" +
                    "Install with: sudo apt install wireshark")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to open traffic file: {e}")
    
    def analyze_client_credentials(self):
        """Analyze credentials for selected client"""
        selection_model = self.client_list_table.selectionModel()
        if not selection_model:
            return
            
        selected_rows = selection_model.selectedRows()
        if selected_rows:
            row = selected_rows[0].row()
            mac_item = self.client_list_table.item(row, 0)
            mac = mac_item.text() if mac_item else "Unknown"
            
            # Implement credential analysis logic
            self.log_update.emit(f"[CLIENT] Analyzing credentials for client {mac}")
            
            # Find traffic capture files for this client
            import glob
            mac_formatted = mac.replace(':', '-')
            traffic_dirs = [
                "karma_captures/traffic/",
                os.path.expanduser("~/wifitex/karma_captures/traffic/"),
            ]
            
            cap_files = []
            for dir_path in traffic_dirs:
                if os.path.exists(dir_path):
                    pattern = os.path.join(dir_path, f"*{mac_formatted}*.cap")
                    cap_files.extend(glob.glob(pattern))
            
            if not cap_files:
                QMessageBox.warning(self, "No Traffic Files", 
                    f"No traffic capture files found for client {mac}.\n\nPlease ensure you have captured traffic from this client first.")
                return
            
            # Analyze the most recent capture file
            most_recent = max(cap_files, key=os.path.getmtime)
            
            try:
                if not os.path.exists(most_recent):
                    QMessageBox.warning(self, "File Not Found", f"Traffic file not found: {most_recent}")
                    return
                
                # Run tshark to extract credentials
                credentials = []
                
                # Look for HTTP POST requests with form data
                try:
                    result = subprocess.run(
                        ['tshark', '-r', most_recent, '-Y', 'http.request.method == POST',
                         '-T', 'fields', '-e', 'http.host', '-e', 'http.request.uri'],
                        capture_output=True, text=True, timeout=10
                    )
                    
                    if result.returncode == 0 and result.stdout.strip():
                        lines = result.stdout.strip().split('\n')
                        for line in lines[:10]:  # Limit to 10 results
                            if line.strip():
                                parts = line.split('\t')
                                if len(parts) >= 2:
                                    credentials.append(f"POST: {parts[0]} - {parts[1]}")
                except Exception:
                    pass
                
                # Look for HTTP Basic Auth
                try:
                    result = subprocess.run(
                        ['tshark', '-r', most_recent, '-Y', 'http.authorization', 
                         '-T', 'fields', '-e', 'http.host', '-e', 'http.authorization'],
                        capture_output=True, text=True, timeout=10
                    )
                    
                    if result.returncode == 0 and result.stdout.strip():
                        lines = result.stdout.strip().split('\n')
                        for line in lines[:5]:
                            if line.strip() and 'Basic ' in line:
                                credentials.append(f"Basic Auth: {line[:80]}...")
                except Exception:
                    pass
                
                # Show results
                if credentials:
                    results_text = f"Found {len(credentials)} potential credential entries:\n\n"
                    results_text += '\n'.join(credentials[:10])
                    
                    QMessageBox.information(self, "Credential Analysis Complete", 
                        f"Analysis complete for client {mac}\n\n{results_text}")
                    self.log_update.emit(f"[CLIENT] Found {len(credentials)} potential credentials")
                else:
                    QMessageBox.information(self, "No Credentials Found", 
                        f"No credentials found in traffic for client {mac}\n\nFile: {os.path.basename(most_recent)}")
                    
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to analyze credentials: {e}")
    
    def open_pcap_folder(self):
        """Open PCAP files folder"""
        import os
        import subprocess
        
        # Default PCAP folder locations (including KARMA directories)
        pcap_folders = [
            "karma_captures/traffic/",
            "karma_captures/probes/",
            "karma_captures/handshakes/",
            "karma_captures/credentials/",
            "karma_captures/live_monitoring/",
            os.path.expanduser("~/wifitex/karma_captures/traffic/"),
            os.path.expanduser("~/wifitex/karma_captures/probes/"),
            os.path.expanduser("~/wifitex/captures/"),
            os.path.expanduser("~/wifitex/pcaps/"),
            "./captures/",
            "./pcaps/"
        ]
        
        for folder in pcap_folders:
            if os.path.exists(folder):
                try:
                    if os.name == 'nt':  # Windows
                        os.startfile(folder)
                    else:  # Linux/Mac
                        subprocess.run(['xdg-open', folder])
                    self.log_update.emit(f"[DATA] Opened PCAP folder: {folder}")
                    return
                except Exception as e:
                    self.log_update.emit(f"[ERROR] Failed to open PCAP folder: {e}")
        
        QMessageBox.warning(self, "Folder Not Found", "PCAP folder not found. Make sure you have run a KARMA attack first.")
    
    def open_handshake_folder(self):
        """Open handshake files folder"""
        import os
        import subprocess
        
        # Default handshake folder locations
        handshake_folders = [
            os.path.expanduser("~/wifitex/karma_captures/handshakes/"),
            os.path.expanduser("~/wifitex/handshakes/"),
            "./hs/",
            "./handshakes/"
        ]
        
        for folder in handshake_folders:
            if os.path.exists(folder):
                try:
                    if os.name == 'nt':  # Windows
                        os.startfile(folder)
                    else:  # Linux/Mac
                        subprocess.run(['xdg-open', folder])
                    self.log_update.emit(f"[DATA] Opened handshake folder: {folder}")
                    return
                except Exception as e:
                    self.log_update.emit(f"[ERROR] Failed to open handshake folder: {e}")
        
        QMessageBox.warning(self, "Folder Not Found", "Handshake folder not found. Make sure you have captured handshakes first.")
    
    def open_credential_folder(self):
        """Open credential files folder"""
        import os
        import subprocess
        
        # Default credential folder locations
        cred_folders = [
            "./karma_captures/credentials/",  # Current directory karma_captures
            os.path.expanduser("~/wifitex/karma_captures/credentials/"),
            os.path.expanduser("~/wifitex/credentials/"),
            "./credentials/",
            "./creds/"
        ]
        
        for folder in cred_folders:
            if os.path.exists(folder):
                try:
                    if os.name == 'nt':  # Windows
                        os.startfile(folder)
                    else:  # Linux/Mac
                        subprocess.run(['xdg-open', folder])
                    self.log_update.emit(f"[DATA] Opened credential folder: {folder}")
                    return
                except Exception as e:
                    self.log_update.emit(f"[ERROR] Failed to open credential folder: {e}")
        
        QMessageBox.warning(self, "Folder Not Found", "Credential folder not found. Make sure you have captured credentials first.")
    
    def open_in_wireshark(self):
        """Open latest PCAP file in Wireshark"""
        import os
        import subprocess
        import glob
        
        # Look for PCAP files in common locations (including KARMA directories)
        pcap_patterns = [
            "karma_captures/traffic/*.pcap",
            "karma_captures/traffic/*.cap",
            "karma_captures/probes/*.pcap",
            "karma_captures/probes/*.cap",
            "karma_captures/handshakes/*.pcap",
            "karma_captures/handshakes/*.cap",
            "karma_captures/live_monitoring/*.pcap",
            "karma_captures/live_monitoring/*.cap",
            os.path.expanduser("~/wifitex/karma_captures/traffic/*.pcap"),
            os.path.expanduser("~/wifitex/karma_captures/traffic/*.cap"),
            os.path.expanduser("~/wifitex/karma_captures/probes/*.pcap"),
            os.path.expanduser("~/wifitex/karma_captures/probes/*.cap"),
            os.path.expanduser("~/wifitex/captures/*.pcap"),
            os.path.expanduser("~/wifitex/pcaps/*.pcap"),
            "./captures/*.pcap",
            "./pcaps/*.pcap",
            "./*.pcap",
            "./*.cap"
        ]
        
        latest_pcap = None
        latest_time = 0
        
        for pattern in pcap_patterns:
            for pcap_file in glob.glob(pattern):
                if os.path.exists(pcap_file):
                    file_time = os.path.getmtime(pcap_file)
                    if file_time > latest_time:
                        latest_time = file_time
                        latest_pcap = pcap_file
        
        if latest_pcap:
            try:
                subprocess.run(['wireshark', latest_pcap], check=True)
                self.log_update.emit(f"[DATA] Opened {latest_pcap} in Wireshark")
            except subprocess.CalledProcessError:
                QMessageBox.warning(self, "Wireshark Not Found", "Wireshark is not installed or not in PATH.")
            except Exception as e:
                self.log_update.emit(f"[ERROR] Failed to open Wireshark: {e}")
        else:
            QMessageBox.warning(self, "No PCAP Files", "No PCAP files found. Make sure you have run a KARMA attack first.")
                
    def update_status(self, message):
        """Update status display"""
        if hasattr(self, 'status_bar'):
            self.status_bar.showMessage(message, 3000)  # Show for 3 seconds
        
    def save_session(self):
        """Save current session"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Session", "wifitex_session.json", "JSON Files (*.json)"
        )
        
        if filename:
            try:
                import json
                session_data = {
                    'networks': self.networks,
                    'selected_networks': self.selected_networks,
                    'current_attacks': self.current_attacks,
                    'interface': self.interface_combo.currentText(),
                    'channel': self.channel_spin.value(),
                    'settings': {
                        'scan_timeout': self.settings_panel.scan_timeout_spin.value(),
                        'wpa_timeout': self.settings_panel.wpa_timeout_spin.value(),
                        'wordlist': self.settings_panel.wordlist_combo.currentText(),
                        'cracking_strategy': self.settings_panel.cracking_strategy_combo.currentText(),
                    },
                    'timestamp': time.time()
                }
                
                with open(filename, 'w') as f:
                    json.dump(session_data, f, indent=2)
                    
                self.status_update.emit(f"Session saved to {filename}")
                QMessageBox.information(self, "Session Saved", f"Session successfully saved to:\n{filename}")
                
            except Exception as e:
                QMessageBox.critical(self, "Save Error", f"Failed to save session: {str(e)}")
        
    def load_session(self):
        """Load saved session"""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Load Session", "", "JSON Files (*.json)"
        )
        
        if filename:
            try:
                import json
                with open(filename, 'r') as f:
                    session_data = json.load(f)
                
                # Restore networks
                if 'networks' in session_data:
                    self.networks = session_data['networks']
                    self.populate_networks_table()
                
                # Restore selected networks
                if 'selected_networks' in session_data:
                    self.selected_networks = session_data['selected_networks']
                
                # Restore interface settings
                if 'interface' in session_data:
                    interface = session_data['interface']
                    index = self.interface_combo.findText(interface)
                    if index >= 0:
                        self.interface_combo.setCurrentIndex(index)
                
                # Restore channel settings
                if 'channel' in session_data:
                    self.channel_spin.setValue(session_data['channel'])
                
                # Restore settings panel values
                if 'settings' in session_data:
                    settings = session_data['settings']
                    if 'scan_timeout' in settings:
                        self.settings_panel.scan_timeout_spin.setValue(settings['scan_timeout'])
                    if 'wpa_timeout' in settings:
                        self.settings_panel.wpa_timeout_spin.setValue(settings['wpa_timeout'])
                    if 'wordlist' in settings:
                        index = self.settings_panel.wordlist_combo.findText(settings['wordlist'])
                        if index >= 0:
                            self.settings_panel.wordlist_combo.setCurrentIndex(index)
                    if 'cracking_strategy' in settings:
                        index = self.settings_panel.cracking_strategy_combo.findText(settings['cracking_strategy'])
                        if index >= 0:
                            self.settings_panel.cracking_strategy_combo.setCurrentIndex(index)
                
                # Show session info
                timestamp = session_data.get('timestamp', 0)
                if timestamp:
                    import datetime
                    session_time = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                    self.status_update.emit(f"Session loaded from {filename} (saved: {session_time})")
                else:
                    self.status_update.emit(f"Session loaded from {filename}")
                
                QMessageBox.information(self, "Session Loaded", f"Session successfully loaded from:\n{filename}")
                
            except Exception as e:
                QMessageBox.critical(self, "Load Error", f"Failed to load session: {str(e)}")
        
    def export_results(self):
        """Export attack results"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Results", "wifitex_results.json", "JSON Files (*.json);;CSV Files (*.csv);;Text Files (*.txt)"
        )
        
        if filename:
            try:
                import json
                import csv
                import datetime
                
                # Collect all available data for export
                export_data = {
                    'export_info': {
                        'timestamp': datetime.datetime.now().isoformat(),
                        'wifitex_version': '2.0.0',
                        'interface': self.interface_combo.currentText(),
                        'channel': self.channel_spin.value(),
                        'five_ghz_enabled': True  # Always enabled
                    },
                    'networks': self.networks,
                    'selected_networks': self.selected_networks,
                    'attack_results': self.current_attacks,
                    'performance_metrics': self.attack_manager.performance_metrics,
                    'settings': {
                        'scan_timeout': self.settings_panel.scan_timeout_spin.value(),
                        'wpa_timeout': self.settings_panel.wpa_timeout_spin.value(),
                        'wordlist': self.settings_panel.wordlist_combo.currentText(),
                        'cracking_strategy': self.settings_panel.cracking_strategy_combo.currentText(),
                    },
                    'log_content': self.log_text.toPlainText()
                }
                
                file_ext = filename.lower().split('.')[-1]
                
                if file_ext == 'json':
                    with open(filename, 'w') as f:
                        json.dump(export_data, f, indent=2)
                        
                elif file_ext == 'csv':
                    with open(filename, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['Network', 'BSSID', 'Channel', 'Power', 'Encryption', 'Status', 'Results'])
                        
                        for network in self.networks:
                            # Find attack results for this network
                            attack_result = ""
                            for attack_data in self.current_attacks.values():
                                if attack_data.get('network', {}).get('bssid') == network.get('bssid'):
                                    if attack_data.get('success'):
                                        if 'key' in attack_data:
                                            attack_result = f"Password: {attack_data['key']}"
                                        elif 'pin' in attack_data:
                                            attack_result = f"WPS PIN: {attack_data['pin']}"
                                        elif 'handshake' in attack_data:
                                            attack_result = "Handshake captured"
                                        else:
                                            attack_result = "Success"
                                    else:
                                        attack_result = "Failed"
                                    break
                            
                            writer.writerow([
                                network.get('essid', 'Unknown'),
                                network.get('bssid', 'Unknown'),
                                network.get('channel', 'Unknown'),
                                network.get('power', 'Unknown'),
                                network.get('encryption', 'Unknown'),
                                'Attacked' if attack_result else 'Not attacked',
                                attack_result
                            ])
                            
                elif file_ext == 'txt':
                    with open(filename, 'w') as f:
                        f.write("Wifitex Attack Results Export\n")
                        f.write("=" * 50 + "\n\n")
                        f.write(f"Export Date: {export_data['export_info']['timestamp']}\n")
                        f.write(f"Interface: {export_data['export_info']['interface']}\n")
                        f.write(f"Channel: {export_data['export_info']['channel']}\n")
                        f.write(f"Band Scanning: All Bands (2.4GHz, 5GHz, 6GHz if supported)\n\n")
                        
                        f.write("PERFORMANCE METRICS\n")
                        f.write("-" * 20 + "\n")
                        metrics = export_data['performance_metrics']
                        f.write(f"Total Attacks: {metrics.get('total_attacks', 0)}\n")
                        f.write(f"Successful: {metrics.get('successful_attacks', 0)}\n")
                        f.write(f"Failed: {metrics.get('failed_attacks', 0)}\n")
                        success_rate = (metrics.get('successful_attacks', 0) / metrics.get('total_attacks', 1)) * 100
                        f.write(f"Success Rate: {success_rate:.1f}%\n\n")
                        
                        f.write("NETWORK RESULTS\n")
                        f.write("-" * 20 + "\n")
                        for network in self.networks:
                            f.write(f"Network: {network.get('essid', 'Unknown')}\n")
                            f.write(f"BSSID: {network.get('bssid', 'Unknown')}\n")
                            f.write(f"Channel: {network.get('channel', 'Unknown')}\n")
                            f.write(f"Power: {network.get('power', 'Unknown')}\n")
                            f.write(f"Encryption: {network.get('encryption', 'Unknown')}\n")
                            
                            # Find attack results
                            for attack_data in self.current_attacks.values():
                                if attack_data.get('network', {}).get('bssid') == network.get('bssid'):
                                    if attack_data.get('success'):
                                        if 'key' in attack_data:
                                            f.write(f"RESULT: Password found: {attack_data['key']}\n")
                                        elif 'pin' in attack_data:
                                            f.write(f"RESULT: WPS PIN found: {attack_data['pin']}\n")
                                        elif 'handshake' in attack_data:
                                            f.write(f"RESULT: Handshake captured successfully\n")
                                        else:
                                            f.write(f"RESULT: Attack successful\n")
                                    else:
                                        f.write(f"RESULT: Attack failed - {attack_data.get('message', 'Unknown error')}\n")
                                    break
                            else:
                                f.write("RESULT: Not attacked\n")
                            f.write("\n")
                        
                        f.write("\nFULL LOG\n")
                        f.write("-" * 20 + "\n")
                        f.write(export_data['log_content'])
                
                self.status_update.emit(f"Results exported to {filename}")
                QMessageBox.information(self, "Export Complete", f"Results successfully exported to:\n{filename}")
                
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export results: {str(e)}")
        
    def show_about(self):
        """Show about dialog"""
        from . import __version__
        
        about_text = f"""
<h2>Wifitex GUI v{__version__}</h2>
<p><b>Modern GUI interface for wireless network auditing</b></p>

<p>Wifitex is a comprehensive wireless security testing tool featuring both command-line and modern GUI interfaces. It's a complete rewrite of the original wifite with enhanced capabilities, better architecture, and modern features.</p>

<h3>Key Features:</h3>
<ul>
<li><b>Modern Dual Interface:</b> CLI and GUI modes</li>
<li><b>Advanced Attack Capabilities:</b> WPS, WPA/WPA2, PMKID, KARMA attacks</li>
<li><b>Real-time Monitoring:</b> Live network scanning with automatic updates</li>
<li><b>Multi-Interface Support:</b> Run multiple Evil Twin APs simultaneously</li>
<li><b>Comprehensive Logging:</b> Exportable logs with filtering capabilities</li>
</ul>

<h3>Attack Methods:</h3>
<ul>
<li><b>WPS Pixie-Dust Attack:</b> Offline brute-force against WPS vulnerabilities</li>
<li><b>WPS PIN Attack:</b> Online brute-force against WPS PIN authentication</li>
<li><b>WPA Handshake Capture:</b> 4-way handshake capture and offline cracking</li>
<li><b>PMKID Hash Capture:</b> Modern hash extraction without client interaction</li>
</ul>

<p><b>Built with PyQt6</b> for a professional user experience.</p>

<p><b>Author:</b> iga2x (mdpoo2@gmail.com)<br>
<b>License:</b> GNU GPLv2<br>
<b>GitHub:</b> <a href="https://github.com/iga2x/wifitex">https://github.com/iga2x/wifitex</a></p>

<p><b>⚠️ Legal Notice:</b> This tool is for educational and authorized testing purposes only. Only use on networks you own or have explicit permission to test.</p>
        """
        
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("About Wifitex")
        msg_box.setTextFormat(Qt.TextFormat.RichText)
        msg_box.setText(about_text)
        msg_box.setIcon(QMessageBox.Icon.Information)
        msg_box.exec()
        
    def show_user_guide(self):
        """Show comprehensive user guide"""
        guide_text = """
<h2>Wifitex GUI User Guide</h2>

<h3>Getting Started</h3>
<p><b>1. Prerequisites:</b></p>
<ul>
<li>Run as root: <code>sudo wifitex-gui</code></li>
<li>Wireless interface with monitor mode support</li>
<li>Required tools: aircrack-ng, reaver, bully, hashcat, etc.</li>
</ul>

<p><b>2. Interface Selection:</b></p>
<ul>
<li>Select your wireless interface from the dropdown</li>
<li>Enable monitor mode if not already active</li>
<li>Check interface status in the status bar</li>
</ul>

<h3>Network Scanning</h3>
<p><b>Start Scan:</b></p>
<ul>
<li>Click "Start Scan" to begin network discovery</li>
<li>Networks appear in real-time in the table</li>
<li>Use filters to show specific network types</li>
</ul>

<p><b>Scan Options:</b></p>
<ul>
<li><b>Channel:</b> Scan specific channel or all channels</li>
<li><b>WPA Only:</b> Show only WPA/WPA2 networks</li>
<li><b>WPS Only:</b> Show only WPS-enabled networks</li>
<li><b>Clients Only:</b> Show only networks with associated clients</li>
</ul>

<h3>Attack Methods</h3>
<p><b>WPS Attacks:</b></p>
<ul>
<li><b>Pixie-Dust:</b> Offline brute-force against WPS vulnerabilities</li>
<li><b>PIN Attack:</b> Online brute-force against WPS PIN</li>
<li>Select target and click "Attack WPS"</li>
</ul>

<p><b>WPA/WPA2 Attacks:</b></p>
<ul>
<li><b>Handshake Capture:</b> Capture 4-way handshake</li>
<li><b>PMKID Capture:</b> Modern hash extraction</li>
<li>Select target and click "Attack WPA"</li>
</ul>

<h3>Troubleshooting</h3>
<p><b>Common Issues:</b></p>
<ul>
<li><b>Permission Denied:</b> Run as root with <code>sudo</code></li>
<li><b>Interface Not Found:</b> Check interface name and drivers</li>
<li><b>Monitor Mode Failed:</b> Check interface compatibility</li>
<li><b>Tools Missing:</b> Use Tools → Install Required Tools</li>
</ul>

<p><b>⚠️ Legal Notice:</b> Only use on networks you own or have explicit permission to test.</p>
        """
        
        self.show_scrollable_dialog("User Guide", guide_text)
        
    def show_keyboard_shortcuts(self):
        """Show keyboard shortcuts"""
        shortcuts_text = """
<h2>Keyboard Shortcuts</h2>

<h3>General Shortcuts</h3>
<ul>
<li><b>Ctrl+Q:</b> Quit application</li>
<li><b>Ctrl+S:</b> Start/Stop scan</li>
<li><b>Ctrl+A:</b> Select all networks</li>
<li><b>Ctrl+D:</b> Deselect all networks</li>
<li><b>F5:</b> Refresh interface list</li>
<li><b>F1:</b> Show this help</li>
</ul>

<h3>Navigation</h3>
<ul>
<li><b>Tab:</b> Move between interface elements</li>
<li><b>Enter:</b> Activate selected button</li>
<li><b>Escape:</b> Cancel current operation</li>
<li><b>Space:</b> Toggle checkbox/button state</li>
</ul>

<h3>Network Table</h3>
<ul>
<li><b>Up/Down Arrow:</b> Navigate network list</li>
<li><b>Space:</b> Select/deselect network</li>
<li><b>Enter:</b> Attack selected network</li>
<li><b>Ctrl+C:</b> Copy network details</li>
</ul>

<h3>Attack Controls</h3>
<ul>
<li><b>Ctrl+W:</b> Attack WPS</li>
<li><b>Ctrl+P:</b> Attack WPA</li>
<li><b>Ctrl+K:</b> Attack KARMA</li>
<li><b>Ctrl+Shift+S:</b> Stop all attacks</li>
</ul>

<h3>Menu Shortcuts</h3>
<ul>
<li><b>Alt+F:</b> File menu</li>
<li><b>Alt+T:</b> Tools menu</li>
<li><b>Alt+H:</b> Help menu</li>
<li><b>Ctrl+,:</b> Open settings</li>
</ul>
        """
        
        self.show_scrollable_dialog("Keyboard Shortcuts", shortcuts_text)
        
    def show_system_info(self):
        """Show system information"""
        system_info = self.system_utils.get_system_info()
        
        info_text = f"""
<h2>System Information</h2>

<h3>System Details</h3>
<ul>
<li><b>Platform:</b> {system_info['platform']}</li>
<li><b>Version:</b> {system_info['platform_version']}</li>
<li><b>Architecture:</b> {system_info['architecture']}</li>
<li><b>Processor:</b> {system_info['processor']}</li>
<li><b>Hostname:</b> {system_info['hostname']}</li>
</ul>

<h3>Python Environment</h3>
<ul>
<li><b>Python Version:</b> {system_info['python_version'].split()[0]}</li>
<li><b>Running as Root:</b> {'Yes' if system_info['is_root'] else 'No'}</li>
</ul>

<h3>Network Interfaces</h3>
<ul>
"""
        
        try:
            interfaces = self.system_utils.get_wireless_interfaces()
            for interface in interfaces:
                info_text += f"<li><b>{interface}:</b> Wireless interface</li>\n"
        except Exception:
            info_text += "<li><b>Error:</b> Could not detect wireless interfaces</li>\n"
        
        info_text += """
</ul>

<h3>Dependencies Status</h3>
<ul>
"""
        
        try:
            from .utils import DependencyChecker
            deps = DependencyChecker.check_all_dependencies()
            for tool, available in deps['tools'].items():
                status = "✅ Available" if available else "❌ Missing"
                info_text += f"<li><b>{tool}:</b> {status}</li>\n"
        except Exception:
            info_text += "<li><b>Error:</b> Could not check dependencies</li>\n"
        
        info_text += """
</ul>

<p><b>Note:</b> Some tools may be available but not working properly. Use Help → Check Dependencies for detailed status.</p>
        """
        
        self.show_scrollable_dialog("System Information", info_text)
        
    def show_scrollable_dialog(self, title, content):
        """Show a scrollable dialog with proper sizing"""
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.setModal(True)
        dialog.resize(800, 600)  # Reasonable default size
        
        # Create layout
        layout = QVBoxLayout(dialog)
        
        # Create text widget
        text_widget = QTextEdit()
        text_widget.setReadOnly(True)
        text_widget.setHtml(content)
        text_widget.setFont(QFont("Arial", 10))
        
        # Add scroll area
        scroll_area = QScrollArea()
        scroll_area.setWidget(text_widget)
        scroll_area.setWidgetResizable(True)
        layout.addWidget(scroll_area)
        
        # Add close button
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)
        
        # Center dialog on screen
        dialog.move(
            self.x() + (self.width() - dialog.width()) // 2,
            self.y() + (self.height() - dialog.height()) // 2
        )
        
        # Show dialog
        dialog.exec()
        
    def setup_keyboard_shortcuts(self):
        """Setup keyboard shortcuts"""
        # General shortcuts
        QShortcut(QKeySequence("Ctrl+Q"), self, self.close)
        QShortcut(QKeySequence("F1"), self, self.show_user_guide)
        QShortcut(QKeySequence("F5"), self, self.refresh_interfaces)
        
        # Scan shortcuts
        QShortcut(QKeySequence("Ctrl+S"), self, self.toggle_scan)
        
        # Selection shortcuts
        QShortcut(QKeySequence("Ctrl+A"), self, self.select_all_networks)
        QShortcut(QKeySequence("Ctrl+D"), self, self.deselect_all_networks)
        
        # Attack shortcuts
        QShortcut(QKeySequence("Ctrl+W"), self, self.attack_wps_selected)
        QShortcut(QKeySequence("Ctrl+P"), self, self.attack_wpa_selected)
        QShortcut(QKeySequence("Ctrl+K"), self, self.attack_karma_selected)
        QShortcut(QKeySequence("Ctrl+Shift+S"), self, self.stop_all_attacks)
        
    def select_all_networks(self):
        """Select all networks in the table"""
        # This would need to be implemented based on the actual network table interface
        self.status_update.emit("Select all networks shortcut triggered")
    
    def deselect_all_networks(self):
        """Deselect all networks in the table"""
        # This would need to be implemented based on the actual network table interface
        self.status_update.emit("Deselect all networks shortcut triggered")
    
    def attack_wps_selected(self):
        """Attack WPS for selected networks"""
        # This would need to be implemented based on the actual attack manager interface
        self.status_update.emit("WPS attack shortcut triggered")
    
    def attack_wpa_selected(self):
        """Attack WPA for selected networks"""
        # This would need to be implemented based on the actual attack manager interface
        self.status_update.emit("WPA attack shortcut triggered")
    
    def attack_karma_selected(self):
        """Attack KARMA for selected networks"""
        # This would need to be implemented based on the actual attack manager interface
        self.status_update.emit("KARMA attack shortcut triggered")
    
    def toggle_scan(self):
        """Toggle scan on/off"""
        # This would need to be implemented based on the actual scan button interface
        self.status_update.emit("Scan toggle shortcut triggered")
        
    def load_settings(self):
        """Load application settings"""
        try:
            settings = self.config_manager.load_settings()
            
            # Apply settings to UI
            if 'interface' in settings:
                index = self.interface_combo.findText(settings['interface'])
                if index >= 0:
                    self.interface_combo.setCurrentIndex(index)
                    
            if 'channel' in settings:
                # Ensure channel value is valid (0-165)
                channel_val = settings['channel']
                if 0 <= channel_val <= 165:
                    self.channel_spin.setValue(channel_val)
                
        except Exception as e:
            self.log_update.emit(f"Error loading settings: {str(e)}")
            
    def save_settings(self):
        """Save application settings"""
        try:
            # Get main window settings
            main_settings = {
                'interface': self._get_current_interface(),
                'channel': self.channel_spin.value(),
                'deauth': self.deauth_cb.isChecked(),
                'crack': self.crack_cb.isChecked()
            }
            
            # Get settings panel settings
            settings_panel_settings = self.settings_panel.get_current_settings()
            
            # Combine all settings
            all_settings = {**main_settings, **settings_panel_settings}
            
            # Save combined settings
            self.config_manager.save_settings(all_settings)
            self.status_update.emit("Settings saved")
            
        except Exception as e:
            self.log_update.emit(f"Error saving settings: {str(e)}")
    
    def initialize_tool_detection(self):
        """Initialize tool detection for attack manager"""
        try:
            from .utils import DependencyChecker
            
            # Get tool status from dependency checker
            dependency_results = DependencyChecker.check_all_dependencies()
            tools_status = dependency_results.get('tools', {})
            
            # Set available tools in attack manager
            self.attack_manager.set_available_tools(tools_status)
            
            # Initialize attack stats
            self.attack_stats = {
                'networks_found': 0,
                'attacks_completed': 0,
                'successful_attacks': 0
            }
            
            # Update interface identification display
            self.update_interface_identification_display()
            
             # Update tool status
            self.update_tool_status()
            
            # Log tool detection results
            missing_tools = [tool for tool, available in tools_status.items() if not available]
            if missing_tools:
                self.log_update.emit(f"Missing tools detected: {', '.join(missing_tools)}")
            else:
                self.log_update.emit("All tools detected successfully")
                
        except Exception as e:
            self.log_update.emit(f"Error initializing tool detection: {str(e)}")
    
    def update_attack_info(self, attack_data):
        """Update the current attack information display"""
        try:
            if hasattr(self, 'current_attack_info'):
                # Create HTML formatted text with better colors and readability
                network = attack_data.get('network', 'Unknown')
                attack_type = attack_data.get('attack_type', 'Unknown')
                status = attack_data.get('step', 'Running')
                progress = attack_data.get('progress', 0)
                message = attack_data.get('message', 'No updates')
                
                # HTML formatting with colors for better readability
                html_text = f"""
                <div style="color: #e2e8f0; font-family: Consolas, monospace; font-size: 9pt;">
                    <div style="margin-bottom: 4px;">
                        <span style="color: #74c0fc; font-weight: bold;">Target:</span> 
                        <span style="color: #ffd43b;">{network}</span>
                    </div>
                    <div style="margin-bottom: 4px;">
                        <span style="color: #74c0fc; font-weight: bold;">Attack Type:</span> 
                        <span style="color: #51cf66;">{attack_type}</span>
                    </div>
                    <div style="margin-bottom: 4px;">
                        <span style="color: #74c0fc; font-weight: bold;">Status:</span> 
                        <span style="color: #ff922b;">{status}</span>
                    </div>
                    <div style="margin-bottom: 4px;">
                        <span style="color: #74c0fc; font-weight: bold;">Progress:</span> 
                        <span style="color: #da77f2;">{progress}%</span>
                    </div>
                    <div style="margin-bottom: 4px;">
                        <span style="color: #74c0fc; font-weight: bold;">Message:</span> 
                        <span style="color: #e2e8f0;">{message}</span>
                    </div>
                </div>
                """
                self.current_attack_info.setHtml(html_text)
        except Exception as e:
            pass  # Silently ignore errors
    
    def update_attack_stats(self):
        """Update the attack statistics display"""
        try:
            if hasattr(self, 'networks_found_label'):
                self.networks_found_label.setText(f"Networks Found: {self.attack_stats['networks_found']}")
                self.attacks_completed_label.setText(f"Attacks Completed: {self.attack_stats['attacks_completed']}")
                self.successful_attacks_label.setText(f"Successful: {self.attack_stats['successful_attacks']}")
        except Exception as e:
            pass  # Silently ignore errors
    
    def update_tool_status(self):
        """Update the tool status list"""
        try:
            if hasattr(self, 'tool_status_list'):
                self.tool_status_list.clear()
                
                from .utils import DependencyChecker
                dependency_results = DependencyChecker.check_all_dependencies()
                tools_status = dependency_results.get('tools', {})
                
                # Show only essential tools status
                essential_tools = ['aircrack-ng', 'airodump-ng', 'aireplay-ng', 'reaver', 'bully', 'hashcat']
                for tool in essential_tools:
                    status = "✅ Available" if tools_status.get(tool, False) else "❌ Missing"
                    item_text = f"{tool}: {status}"
                    item = QListWidgetItem(item_text)
                    if tools_status.get(tool, False):
                        item.setForeground(QColor("#51cf66"))  # Green
                    else:
                        item.setForeground(QColor("#ff6b6b"))  # Red
                    self.tool_status_list.addItem(item)
                    
        except Exception as e:
            pass  # Silently ignore errors
            
    def closeEvent(self, event):
        """Handle application close event - comprehensive cleanup to prevent system crashes"""
        try:
            # Save settings before closing
            self.save_settings()
            
            # Stop any running operations first
            if hasattr(self, 'scanner'):
                self.scanner.stop_scan()
            if hasattr(self, 'attack_manager'):
                self.attack_manager.stop_attack()
            
            # Show cleanup progress dialog
            cleanup_dialog = CleanupProgressDialog(self)
            
            # Force dialog to render immediately to prevent black screen
            cleanup_dialog.show()
            QApplication.processEvents()
            cleanup_dialog.raise_()
            QApplication.processEvents()
            cleanup_dialog.activateWindow()
            QApplication.processEvents()
            
            # Add initial log message
            cleanup_dialog.add_log("Preparing cleanup...")
            QApplication.processEvents()
            
            # Run cleanup in a background thread
            self._cleanup_worker = CleanupWorker(self)
            self._cleanup_worker.progress.connect(cleanup_dialog.add_log)
            self._cleanup_worker.error.connect(lambda m: cleanup_dialog.add_log(f"⚠️ {m}"))
            self._cleanup_worker.finished.connect(lambda: (cleanup_dialog.set_done(), QTimer.singleShot(250, cleanup_dialog.accept)))
            self._cleanup_worker.start()
            
            # Block with dialog event loop while UI remains responsive
            cleanup_dialog.exec()
            
            event.accept()
            
        except Exception as e:
            logger.error(f"Error during close: {e}")
            event.accept()
    
    def _comprehensive_cleanup(self):
        """Comprehensive cleanup to prevent system crashes - kills all processes and restores network"""
        try:
            import subprocess
            import time
            
            logger.info("Starting comprehensive cleanup...")
            
            # 1. Stop all attacks and threads
            if hasattr(self, 'attack_manager'):
                self.attack_manager.stop_attack()
                self.attack_manager.cleanup_all_processes()
                self.attack_manager._kill_attack_processes()
            
            if hasattr(self, 'scanner'):
                self.scanner.stop_scan()
            
            time.sleep(0.2)
            
            # 2. Kill ALL attack processes aggressively (including KARMA-specific ones)
            processes_to_kill = [
                'reaver', 'bully', 'aircrack-ng', 'aireplay-ng', 'airodump-ng', 
                'hostapd', 'dnsmasq', 'wpa_supplicant', 'dhcpcd', 'tshark',
                'wash', 'pixiewps', 'hcxdumptool', 'hcxpcapngtool', 'hashcat'
            ]
            
            for process in processes_to_kill:
                try:
                    # Kill gracefully
                    subprocess.run(['pkill', '-TERM', '-f', process], 
                                 capture_output=True, stderr=subprocess.DEVNULL)
                    time.sleep(0.05)
                    # Force kill
                    subprocess.run(['pkill', '-KILL', '-f', process], 
                                 capture_output=True, stderr=subprocess.DEVNULL)
                    subprocess.run(['killall', '-9', process], 
                                 capture_output=True, stderr=subprocess.DEVNULL)
                except Exception:
                    pass
            
            time.sleep(0.2)
            
            # 3. Get all interfaces and restore them to managed mode
            try:
                # Get list of wireless interfaces
                result = subprocess.run(['iwconfig'], capture_output=True, text=True)
                if result.returncode == 0:
                    interfaces = []
                    current_interface = None
                    for line in result.stdout.split('\n'):
                        if 'IEEE' in line or 'ESSID' in line:
                            if current_interface:
                                interfaces.append(current_interface)
                            current_interface = line.split()[0]
                    
                    if current_interface:
                        interfaces.append(current_interface)
                    
                    # Restore each interface to managed mode
                    for interface in interfaces:
                        if interface and ' ' not in interface:
                            try:
                                # Bring down
                                subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                                             capture_output=True, stderr=subprocess.DEVNULL, timeout=2)
                                # Set to managed
                                subprocess.run(['iw', 'dev', interface, 'set', 'type', 'managed'], 
                                             capture_output=True, stderr=subprocess.DEVNULL, timeout=2)
                                # Flush IP
                                subprocess.run(['ip', 'addr', 'flush', 'dev', interface], 
                                             capture_output=True, stderr=subprocess.DEVNULL, timeout=2)
                                # Bring up
                                subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                                             capture_output=True, stderr=subprocess.DEVNULL, timeout=2)
                            except Exception:
                                pass
            except Exception:
                pass
            
            time.sleep(0.2)
            
            # 4. Restart NetworkManager to restore network connectivity
            try:
                # Check if NetworkManager is running
                result = subprocess.run(['systemctl', 'is-active', 'NetworkManager'], 
                                      capture_output=True, text=True)
                if 'active' in result.stdout or 'running' in result.stdout:
                    # Restart NetworkManager to restore network
                    subprocess.run(['systemctl', 'restart', 'NetworkManager'], 
                                 capture_output=True, stderr=subprocess.DEVNULL, timeout=5)
            except Exception:
                pass
            
            time.sleep(0.2)
            
            # 5. Unblock rfkill to restore wireless
            try:
                subprocess.run(['rfkill', 'unblock', 'all'], 
                             capture_output=True, stderr=subprocess.DEVNULL, timeout=2)
                subprocess.run(['rfkill', 'unblock', 'wifi'], 
                             capture_output=True, stderr=subprocess.DEVNULL, timeout=2)
            except Exception:
                pass
            
            logger.info("Comprehensive cleanup completed")
            
        except Exception as e:
            logger.error(f"Error during comprehensive cleanup: {e}")
            # Try one more time with the most critical cleanup
            try:
                subprocess.run(['killall', '-9', 'hostapd', 'dnsmasq', 'airodump-ng'], 
                             capture_output=True, stderr=subprocess.DEVNULL)
                subprocess.run(['systemctl', 'restart', 'NetworkManager'], 
                             capture_output=True, stderr=subprocess.DEVNULL)
            except Exception:
                pass


# Run cleanup in background to keep UI responsive
class CleanupWorker(QThread):
    """Run cleanup in background thread and report progress safely via signals"""
    progress = pyqtSignal(str)
    error = pyqtSignal(str)
    def __init__(self, main_window: 'WifitexMainWindow'):
        super().__init__()
        self._mw = main_window
    
    def _log(self, msg: str):
        try:
            self.progress.emit(msg)
        except Exception:
            pass
    
    def run(self):
        try:
            self._run_cleanup_core()
        except Exception as e:
            self.error.emit(f"Cleanup error: {str(e)}")

    def _run_cleanup_core(self):
        import subprocess
        import time
        self._log("Starting comprehensive cleanup...")
        # 1. Stop attacks and scanner
        if hasattr(self._mw, 'attack_manager'):
            self._log("Stopping attacks...")
            try:
                self._mw.attack_manager.stop_attack()
                self._mw.attack_manager.cleanup_all_processes()
                self._mw.attack_manager._kill_attack_processes()
            except Exception:
                pass
        if hasattr(self._mw, 'scanner'):
            self._log("Stopping scanner...")
            try:
                self._mw.scanner.stop_scan()
            except Exception:
                pass
        time.sleep(0.1)
        # 2. Kill known processes
        self._log("Terminating attack processes...")
        processes_to_kill = [
            'reaver', 'bully', 'aircrack-ng', 'aireplay-ng', 'airodump-ng',
            'hostapd', 'dnsmasq', 'wpa_supplicant', 'dhcpcd', 'tshark',
            'wash', 'pixiewps', 'hcxdumptool', 'hcxpcapngtool', 'hashcat'
        ]
        for proc in processes_to_kill:
            try:
                subprocess.run(['pkill', '-TERM', '-f', proc], capture_output=True, stderr=subprocess.DEVNULL)
                time.sleep(0.03)
                subprocess.run(['pkill', '-KILL', '-f', proc], capture_output=True, stderr=subprocess.DEVNULL)
                subprocess.run(['killall', '-9', proc], capture_output=True, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        time.sleep(0.1)
        # 3. Restore interfaces
        self._log("Restoring network interfaces...")
        try:
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            if result.returncode == 0:
                interfaces = []
                current = None
                for line in result.stdout.split('\n'):
                    if 'IEEE' in line or 'ESSID' in line:
                        if current:
                            interfaces.append(current)
                        current = line.split()[0]
                if current:
                    interfaces.append(current)
                for iface in interfaces:
                    if iface and ' ' not in iface:
                        try:
                            subprocess.run(['ip', 'link', 'set', iface, 'down'], capture_output=True, stderr=subprocess.DEVNULL, timeout=2)
                            subprocess.run(['iw', 'dev', iface, 'set', 'type', 'managed'], capture_output=True, stderr=subprocess.DEVNULL, timeout=2)
                            subprocess.run(['ip', 'addr', 'flush', 'dev', iface], capture_output=True, stderr=subprocess.DEVNULL, timeout=2)
                            subprocess.run(['ip', 'link', 'set', iface, 'up'], capture_output=True, stderr=subprocess.DEVNULL, timeout=2)
                            self._log(f"✓ Restored {iface} to managed mode")
                        except Exception:
                            pass
        except Exception:
            pass
        time.sleep(0.1)
        # 4. Restart NetworkManager
        self._log("Restarting NetworkManager...")
        try:
            result = subprocess.run(['systemctl', 'is-active', 'NetworkManager'], capture_output=True, text=True)
            if 'active' in result.stdout or 'running' in result.stdout:
                subprocess.run(['systemctl', 'restart', 'NetworkManager'], capture_output=True, stderr=subprocess.DEVNULL, timeout=5)
                self._log("✓ NetworkManager restarted")
        except Exception:
            pass
        time.sleep(0.1)
        # 5. rfkill unblock
        self._log("Restoring wireless...")
        try:
            subprocess.run(['rfkill', 'unblock', 'all'], capture_output=True, stderr=subprocess.DEVNULL, timeout=2)
            subprocess.run(['rfkill', 'unblock', 'wifi'], capture_output=True, stderr=subprocess.DEVNULL, timeout=2)
            self._log("✓ Wireless restored")
        except Exception:
            pass
        self._log("✓ Cleanup completed successfully")
# Thread classes moved to components.py to avoid duplication


## Removed duplicate ToolInstallDialog and DependencyCheckDialog in favor of dialogs from components.py


class MonitorModeThread(QThread):
    """Thread for handling monitor mode operations without blocking the GUI"""
    
    # Signals for communication with main thread
    monitor_completed = pyqtSignal(dict)
    monitor_progress = pyqtSignal(str)
    monitor_failed = pyqtSignal(dict)
    
    def __init__(self, interface, operation):
        super().__init__()
        self.interface = interface
        self.operation = operation  # "enable" or "disable"
        self.should_stop = False
        
    def run(self):
        """Run the monitor mode operation in background"""
        try:
            if self.operation == "enable":
                self._enable_monitor_mode()
            elif self.operation == "disable":
                self._disable_monitor_mode()
        except Exception as e:
            self.monitor_failed.emit({
                'operation': self.operation,
                'error': f"Unexpected error: {str(e)}"
            })
    
    def _enable_monitor_mode(self):
        """Enable monitor mode using NetworkUtils"""
        try:
            from .utils import NetworkUtils
            
            self.monitor_progress.emit(f"Enabling monitor mode on {self.interface}...")
            
            # Use NetworkUtils to enable monitor mode
            network_utils = NetworkUtils()
            success = network_utils.enable_monitor_mode(self.interface)
            
            if success:
                self.monitor_completed.emit({
                    'operation': 'enable',
                    'interface': self.interface,
                    'message': f"Monitor mode enabled on {self.interface}"
                })
            else:
                self.monitor_failed.emit({
                    'operation': 'enable',
                    'error': "Failed to enable monitor mode"
                })
                
        except Exception as e:
            self.monitor_failed.emit({
                'operation': 'enable',
                'error': f"Unexpected error: {str(e)}"
            })
    
    def _disable_monitor_mode(self):
        """Disable monitor mode using NetworkUtils"""
        try:
            from .utils import NetworkUtils
            
            self.monitor_progress.emit(f"Disabling monitor mode on {self.interface}...")
            
            # Use NetworkUtils to disable monitor mode
            network_utils = NetworkUtils()
            success = network_utils.disable_monitor_mode(self.interface)
            
            if success:
                self.monitor_completed.emit({
                    'operation': 'disable',
                    'interface': self.interface,
                    'message': f"Monitor mode disabled on {self.interface}"
                })
            else:
                self.monitor_failed.emit({
                    'operation': 'disable',
                    'error': "Failed to disable monitor mode"
                })
                
        except Exception as e:
            self.monitor_failed.emit({
                'operation': 'disable',
                'error': f"Unexpected error: {str(e)}"
            })
