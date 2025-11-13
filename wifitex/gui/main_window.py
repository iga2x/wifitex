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
import traceback
import re
import base64
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem,
    QTextEdit, QComboBox, QLineEdit, QSpinBox, QCheckBox, QGroupBox,
    QTabWidget, QProgressBar, QStatusBar, QMenuBar, QMessageBox,
    QFileDialog, QSplitter, QFrame, QScrollArea, QListWidget,
    QListWidgetItem, QDialog, QDialogButtonBox, QFormLayout,
    QAbstractItemView, QSizePolicy
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QPropertyAnimation, QEasingCurve,
    QRect, QSize, QPoint, QSettings, QStandardPaths
)
from PyQt6.QtGui import (
    QFont, QIcon, QPalette, QColor, QPixmap, QAction, QKeySequence,
    QTextCursor, QFontMetrics, QShortcut, QBrush
)

from .styles import DarkTheme
from .components import (
    NetworkScanner, AttackManager, SettingsPanel, LogViewer,
    ProgressIndicator, StatusDisplay, ToolManager,
    DependencyWarningDialog, ToolInstallationDialog, HandshakeCrackerTab
)
from . import components as gui_components
from typing import Any, cast
# Make linter aware of dynamically added dialog in components
CleanupProgressDialog = cast(Any, gui_components).CleanupProgressDialog
from .utils import SystemUtils, NetworkUtils, ConfigManager
from ..config import Configuration
from .error_handler import handle_errors, ConfigurationError
from .logger import get_logger
from .path_utils import get_project_root

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
        
        # Caches for non-blocking status updates
        self._interface_status_cache: Dict[str, str] = {}
        self._monitor_interfaces_cache: List[str] = []
        self._preferred_interface: Optional[str] = None
        
        # Initialize UI components
        self.scanner = NetworkScanner()
        self.attack_manager = AttackManager()
        self.settings_panel = SettingsPanel()
        self.settings_panel.set_config_manager(self.config_manager)  # Connect settings persistence
        self.log_viewer = LogViewer()
        self.progress_indicator = ProgressIndicator()
        self.status_display = StatusDisplay()
        self.tool_manager = ToolManager()
        self.handshake_tab = HandshakeCrackerTab(
            get_default_wordlists=lambda: self.settings_panel.get_all_wordlist_paths(),
            get_bruteforce_options=self.settings_panel.get_bruteforce_options
        )
        self.handshake_tab.log_message.connect(self.add_log)
        self.handshake_tab.status_message.connect(self.status_update.emit)
        self.handshake_tab.crack_saved.connect(self._on_handshake_cracked)

        # Responsive layout state
        self._current_layout_mode: Optional[str] = None
        self._log_expanded: bool = True
        app = QApplication.instance()
        default_font = app.font() if isinstance(app, QApplication) else self.font()
        self._default_font_point_size: float = default_font.pointSizeF() if default_font.pointSizeF() > 0 else float(default_font.pointSize() if default_font.pointSize() > 0 else 10)
        self._default_font_pixel_size: Optional[int] = default_font.pixelSize() if default_font.pixelSize() > 0 else None
        
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
        self._configure_handshake_directory()

        # Monitor orientation changes for responsive layout
        screen = QApplication.primaryScreen()
        if screen is not None:
            screen.orientationChanged.connect(self._on_screen_orientation_changed)
        self.update_responsive_layout()
        
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
        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.main_splitter.setChildrenCollapsible(False)
        self.main_splitter.setOpaqueResize(False)
        main_layout.addWidget(self.main_splitter)
        
        # Left panel (main controls) as a tab set
        left_panel = self.create_left_panel()
        left_panel.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)

        self.main_tab_widget = QTabWidget()
        self.main_tab_widget.addTab(left_panel, "Main Interface")
        self.main_tab_widget.addTab(self.handshake_tab, "Handshake Cracker")

        self.right_panel = self.create_right_panel()
        self.right_panel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.main_splitter.addWidget(self.main_tab_widget)
        self.main_splitter.addWidget(self.right_panel)
        
        # Set splitter proportions
        self.main_splitter.setSizes([800, 600])
        self.main_splitter.setStretchFactor(0, 3)
        self.main_splitter.setStretchFactor(1, 2)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create status bar
        self.create_status_bar()

    def layout_mode_for_width(self, width: int, dpi: float) -> str:
        """Determine the appropriate layout mode based on width and DPI."""
        scale = dpi / 96.0 if dpi > 0 else 1.0
        normalized_width = width / scale if scale > 0 else width
        if normalized_width >= 1150:
            return "desktop"
        if normalized_width >= 820:
            return "tablet"
        return "compact"

    def set_base_font_scale(self, factor: float) -> None:
        """Scale the base application font to improve readability on small displays."""
        app = QApplication.instance()
        if not isinstance(app, QApplication):
            return
        font = app.font()
        if self._default_font_pixel_size is not None:
            font.setPixelSize(int(self._default_font_pixel_size * factor))
        else:
            font.setPointSizeF(self._default_font_point_size * factor)
        app.setFont(font)
        # Adjust specific widgets that benefit from scaling
        self.log_text.setFont(QFont(self.log_text.font().family(), max(8, int(self._default_font_point_size * factor))))
        self.current_attack_info.setFont(QFont(self.current_attack_info.font().family(), max(8, int(self._default_font_point_size * factor))))
        metrics = QFontMetrics(self.log_text.font())
        header = self.networks_table.horizontalHeader()
        if header is not None:
            header.setDefaultSectionSize(max(60, metrics.horizontalAdvance("W" * 12)))
            self.networks_table.resizeColumnsToContents()

    def update_responsive_layout(self) -> None:
        """Adjust layout and component visibility based on current window size."""
        screen = QApplication.primaryScreen()
        dpi = screen.logicalDotsPerInchX() if screen is not None else self.logicalDpiX()
        mode = self.layout_mode_for_width(self.width(), dpi if dpi > 0 else 96.0)
        if mode == self._current_layout_mode:
            return
        self._current_layout_mode = mode

        if mode == "desktop":
            self.main_splitter.setOrientation(Qt.Orientation.Horizontal)
            self.main_splitter.setSizes([max(700, int(self.width() * 0.6)), max(400, int(self.width() * 0.4))])
            self.right_panel.setVisible(True)
            self.toggle_log_button.setVisible(False)
            self._log_expanded = True
            self.toggle_log_button.setText("Hide Details")
            self.set_base_font_scale(1.0)
        elif mode == "tablet":
            self.main_splitter.setOrientation(Qt.Orientation.Vertical)
            if self._log_expanded:
                self.main_splitter.setSizes([max(500, int(self.height() * 0.55)), max(250, int(self.height() * 0.45))])
            else:
                self.main_splitter.setSizes([self.height(), 0])
            self.right_panel.setVisible(self._log_expanded)
            self.toggle_log_button.setVisible(True)
            self.toggle_log_button.setText("Hide Details" if self._log_expanded else "Show Details")
            self.set_base_font_scale(1.1)
        else:
            self.main_splitter.setOrientation(Qt.Orientation.Vertical)
            if self._log_expanded:
                self.main_splitter.setSizes([max(400, int(self.height() * 0.65)), max(180, int(self.height() * 0.35))])
            else:
                self.main_splitter.setSizes([self.height(), 0])
            self.right_panel.setVisible(self._log_expanded)
            self.toggle_log_button.setVisible(True)
            self.toggle_log_button.setText("Hide Details" if self._log_expanded else "Show Details")
            self.set_base_font_scale(1.22)

    def _toggle_log_panel(self) -> None:
        """Toggle visibility of the right-side detail panel."""
        self._log_expanded = not self._log_expanded
        if self._current_layout_mode in ("tablet", "compact"):
            self.right_panel.setVisible(self._log_expanded)
            if self._log_expanded:
                self.toggle_log_button.setText("Hide Details")
                top_size = max(300, int(self.height() * (0.6 if self._current_layout_mode == "compact" else 0.55)))
                bottom_size = max(150, int(self.height() * (0.4 if self._current_layout_mode == "compact" else 0.45)))
                self.main_splitter.setSizes([top_size, bottom_size])
            else:
                self.toggle_log_button.setText("Show Details")
                self.main_splitter.setSizes([self.height(), 0])
        else:
            self.right_panel.setVisible(True)
            self.toggle_log_button.setText("Hide Details")

    def _on_screen_orientation_changed(self, _orientation) -> None:
        """Handle screen orientation changes by re-evaluating the layout."""
        self.update_responsive_layout()

    def resizeEvent(self, event):
        """Respond to window resize events by adjusting layout."""
        super().resizeEvent(event)
        self.update_responsive_layout()
        
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

        self.toggle_log_button = QPushButton("Hide Details")
        self.toggle_log_button.setVisible(False)
        self.toggle_log_button.setCheckable(False)
        self.toggle_log_button.clicked.connect(self._toggle_log_panel)
        layout.addWidget(self.toggle_log_button)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Logs tab
        logs_tab = QWidget()
        logs_layout = QVBoxLayout(logs_tab)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 9))
        self.log_text.setAcceptRichText(True)  # Enable HTML formatting
        self.log_text.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        log_document = self.log_text.document()
        if log_document is not None:
            log_document.setMaximumBlockCount(2000)
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
        
        self.tab_widget.addTab(logs_tab, "Logs")
        
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
        
        self.tab_widget.addTab(attack_info_tab, "Attack Info")
        
        # Settings tab
        self.settings_scroll = QScrollArea()
        self.settings_scroll.setWidget(self.settings_panel)
        self.settings_scroll.setWidgetResizable(True)
        self.settings_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.settings_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.tab_widget.addTab(self.settings_scroll, "Settings")
        self.settings_tab_index = self.tab_widget.indexOf(self.settings_scroll)
        
        layout.addWidget(self.tab_widget)
        
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
        """Update the status bar with current state - Non-blocking version"""
        try:
            # Use the currently selected interface instead of first interface
            if hasattr(self, 'interface_combo') and self.interface_combo.currentText():
                interface = self.interface_combo.currentText().strip()
                # Show cached status immediately (non-blocking)
                if interface and interface in self._interface_status_cache:
                    status = self._interface_status_cache[interface]
                    self.interface_status.setText(f"Interface: {interface} ({status})")
                else:
                    self.interface_status.setText(f"Interface: {interface}")
                
                # Update cache asynchronously (non-blocking, delayed)
                QTimer.singleShot(100, lambda: self._update_interface_status_cache(interface))
            else:
                # Fallback to cached interfaces if no selection
                interfaces = self._last_interfaces
                if interfaces:
                    interface = interfaces[0]
                    if interface in self._interface_status_cache:
                        status = self._interface_status_cache[interface]
                        self.interface_status.setText(f"Interface: {interface} ({status})")
                    else:
                        self.interface_status.setText(f"Interface: {interface}")
                        # Update cache asynchronously
                        QTimer.singleShot(100, lambda: self._update_interface_status_cache(interface))
                else:
                    self.interface_status.setText("Interface: None")
                
            # Update scan status (non-blocking)
            if hasattr(self, 'scanner') and self.scanner.scanning:
                self.scan_status.setText("Scan: Running")
            else:
                self.scan_status.setText("Scan: Stopped")
                
            # Update attack status (non-blocking)
            if hasattr(self, 'attack_manager') and self.attack_manager.attacking:
                self.attack_status.setText("Attack: Running")
            else:
                self.attack_status.setText("Attack: None")
                
        except Exception as e:
            logger.error(f"Error updating status bar: {e}")
    
    def _update_interface_status_cache(self, interface):
        """Update interface status cache asynchronously - Non-blocking"""
        if not interface:
            return
        try:
            result = subprocess.run(['iwconfig', interface], 
                                  capture_output=True, text=True, timeout=0.3)
            if result.returncode == 0:
                if 'Mode:Monitor' in result.stdout:
                    self._interface_status_cache[interface] = "Monitor"
                else:
                    self._interface_status_cache[interface] = "Managed"
        except Exception:
            # Don't block on failures - silently continue
            pass
        
    def setup_connections(self):
        """Setup signal connections"""
        self.scan_completed.connect(self.on_scan_completed)
        self.attack_completed.connect(self.on_attack_completed)
        self.status_update.connect(self.update_status)
        self.log_update.connect(self.add_log)
        
        # Throttle status bar updates to prevent GUI freezing
        # Update every 2 seconds instead of continuously
        self.status_bar_timer = QTimer()
        self.status_bar_timer.timeout.connect(self.update_status_bar)
        self.status_bar_timer.start(2000)  # 2 second interval
        
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
        """Get the current monitor interface - Non-blocking version"""
        try:
            from .utils import SystemUtils
            
            # Use cached monitor interfaces if available (fast, non-blocking)
            selected = self.interface_combo.currentText().strip() if hasattr(self, 'interface_combo') else ''
            
            if selected and selected in self._monitor_interfaces_cache:
                return selected
            
            if self._monitor_interfaces_cache:
                return self._monitor_interfaces_cache[0]
            
            # Quick check for selected interface only (with short timeout)
            if selected:
                try:
                    result = subprocess.run(['iwconfig', selected], 
                                          capture_output=True, text=True, timeout=0.3)
                    if result.returncode == 0 and 'Mode:Monitor' in result.stdout:
                        # Cache result for future use
                        if selected not in self._monitor_interfaces_cache:
                            self._monitor_interfaces_cache.append(selected)
                        return selected
                except Exception:
                    pass
            
            # Fallback: use fast interface detection (doesn't check mode to avoid blocking)
            interfaces = SystemUtils.get_wireless_interfaces(fast=True)
            
            # Return selected interface or first available (without checking mode)
            return selected or (interfaces[0] if interfaces else None)
            
        except Exception as e:
            logger.error(f"Error getting current monitor interface: {e}")
            return None
    
    def refresh_interfaces(self):
        """Refresh available network interfaces"""
        try:
            current_text = self.interface_combo.currentText().strip()
            if current_text:
                self._preferred_interface = current_text

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
        previous_selection = self._preferred_interface or self.interface_combo.currentText().strip()

        self.interface_combo.blockSignals(True)
        self.interface_combo.clear()
        self.interface_combo.addItems(interfaces)

        selected_interface: Optional[str] = None

        if previous_selection:
            index = self.interface_combo.findText(previous_selection, Qt.MatchFlag.MatchExactly)
            if index >= 0:
                self.interface_combo.setCurrentIndex(index)
                selected_interface = previous_selection

        if selected_interface is None and interfaces:
            self.interface_combo.setCurrentIndex(0)
            selected_interface = interfaces[0]

        self.interface_combo.blockSignals(False)

        if selected_interface:
            self._preferred_interface = selected_interface
            self.status_update.emit(f"Found {len(interfaces)} network interfaces")
            self.check_monitor_mode_status(selected_interface)
        else:
            self.status_update.emit("No network interfaces found")
        # Update status bar with cached data
        self.update_status_bar()
            
    def on_interface_changed(self, interface):
        """Handle interface selection change"""
        if interface:
            self._preferred_interface = interface
            self.check_monitor_mode_status(interface)
            self.status_update.emit(f"Selected interface: {interface}")
            self.update_status_bar()
        else:
            self._preferred_interface = None
            
    def check_monitor_mode_status(self, interface):
        """Check if interface is in monitor mode - Non-blocking version"""
        if not interface:
            return
        try:
            # Use cached status if available (immediate response)
            if interface in self._interface_status_cache:
                status = self._interface_status_cache[interface]
                if status == "Monitor":
                    self.monitor_status.setText(f"Status: {interface} in Monitor Mode ✅")
                    self.enable_monitor_btn.setEnabled(False)
                    self.disable_monitor_btn.setEnabled(True)
                else:
                    self.monitor_status.setText(f"Status: {interface} in Managed Mode ⚠️")
                    self.enable_monitor_btn.setEnabled(True)
                    self.disable_monitor_btn.setEnabled(False)
            
            # Update cache asynchronously (non-blocking)
            QTimer.singleShot(100, lambda: self._update_monitor_status_async(interface))
            
        except Exception as e:
            self.monitor_status.setText(f"Status: Error checking {interface} ❌")
            self.enable_monitor_btn.setEnabled(False)
    
    def _update_monitor_status_async(self, interface):
        """Update monitor mode status asynchronously - Non-blocking"""
        if not interface:
            return
        try:
            result = subprocess.run(['iwconfig', interface], 
                                  capture_output=True, text=True, timeout=0.3)
            if result.returncode == 0:
                if 'Mode:Monitor' in result.stdout:
                    status = "Monitor"
                    self.monitor_status.setText(f"Status: {interface} in Monitor Mode ✅")
                    self.enable_monitor_btn.setEnabled(False)
                    self.disable_monitor_btn.setEnabled(True)
                else:
                    status = "Managed"
                    self.monitor_status.setText(f"Status: {interface} in Managed Mode ⚠️")
                    self.enable_monitor_btn.setEnabled(True)
                    self.disable_monitor_btn.setEnabled(False)
                
                # Update cache
                self._interface_status_cache[interface] = status
            else:
                self.monitor_status.setText(f"Status: {interface} not found ❌")
                self.enable_monitor_btn.setEnabled(False)
                self.disable_monitor_btn.setEnabled(False)
        except Exception:
            # Silently continue - don't block on failures
            pass
    
    def _configure_handshake_directory(self):
        """Ensure handshakes are stored in a predictable, dedicated directory."""
        try:
            from .path_utils import get_handshake_dir
            handshake_dir_setting = self.config_manager.get_setting('handshake_dir')

            handshake_dir: Optional[Path] = None

            if handshake_dir_setting:
                handshake_dir = Path(str(handshake_dir_setting)).expanduser()
            else:
                detected = get_handshake_dir()
                if detected:
                    handshake_dir = Path(detected).expanduser()
                else:
                    handshake_dir = (self.config_manager.config_dir / "hs").expanduser()
                self.config_manager.set_setting('handshake_dir', str(handshake_dir))

            handshake_dir.mkdir(parents=True, exist_ok=True)
            Configuration.wpa_handshake_dir = str(handshake_dir)
        except Exception as exc:
            logger.warning(f"[GUI] Failed to configure handshake directory: {exc}")
            
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
            # Determine band preferences from settings
            band_prefs = {
                'scan_24ghz': True,
                'scan_5ghz': True,
                'scan_6ghz': False,
            }
            if hasattr(self, "settings_panel") and self.settings_panel:
                band_prefs = self.settings_panel.get_scan_band_settings()

            if not any(band_prefs.values()):
                QMessageBox.warning(
                    self,
                    "Invalid Scan Configuration",
                    "At least one band (2.4 GHz, 5 GHz, or 6 GHz) must be enabled before scanning."
                )
                return

            # Start scanning using the scanner component
            # Pass None for channel if value is 0 (All channels)
            channel_value = self.channel_spin.value()
            # Scan runs continuously until manually stopped (matches CLI behavior)
            
            self.scanner.start_scan(
                interface,
                channel_value if channel_value > 0 else None,
                scan_24=band_prefs.get('scan_24ghz', True),
                scan_5=band_prefs.get('scan_5ghz', True),
                scan_6=band_prefs.get('scan_6ghz', False)
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
        """Handle scan progress updates with colored messages"""
        message = progress_data.get('message', '{C}Scanning...{W}')
        # Ensure message has color codes for better visibility
        if not any(code in message for code in ['{C}', '{G}', '{B}', '{Y}', '{W}']):
            message = f'{{C}}Scanning...{{W}} {message}'
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
        """Add a single network to the table with colored formatting"""
        # Validate network data before adding
        if not network.get('bssid') or not network.get('bssid').strip():
            return  # Skip invalid networks
        
        # Filter out unassociated clients/networks to match CLI behavior
        bssid = network.get('bssid', '').upper()
        essid = network.get('essid', '').lower()
        if bssid == 'UNASSOCIATED' or 'unassociated' in essid:
            return  # Skip unassociated networks
        
        row = self.networks_table.rowCount()
        self.networks_table.insertRow(row)
        
        # Use update_network_in_table which handles colors
        self.update_network_in_table(row, network)
        
        # Don't auto-resize to maintain fixed column widths
        
    def _create_colored_table_item(self, text, color):
        """Create a QTableWidgetItem with colored text"""
        item = QTableWidgetItem(text)
        item.setForeground(QColor(color))
        return item
    
    def _get_encryption_color(self, encryption):
        """Get color for encryption type"""
        enc_lower = encryption.lower()
        if 'wep' in enc_lower:
            return '#ffd43b'  # Yellow - Legacy
        elif 'wpa2' in enc_lower or 'wpa' in enc_lower:
            return '#51cf66'  # Green - Secure
        elif 'open' in enc_lower:
            return '#ff6b6b'  # Red - Insecure
        else:
            return '#e2e8f0'  # White - Unknown
    
    def _get_wps_color(self, wps):
        """Get color for WPS status"""
        wps_lower = str(wps).lower()
        if 'yes' in wps_lower or 'on' in wps_lower or 'unlocked' in wps_lower:
            return '#51cf66'  # Green - WPS available/enabled
        elif 'locked' in wps_lower:
            return '#ff922b'  # Orange - WPS locked
        elif 'no' in wps_lower:
            return '#868e96'  # Gray - No WPS
        else:
            return '#e2e8f0'  # White - Unknown
    
    def _get_power_color(self, power_str):
        """Get color for signal power"""
        try:
            power = int(power_str)
            if power >= -50:
                return '#51cf66'  # Green - Excellent signal
            elif power >= -70:
                return '#ffd43b'  # Yellow - Good signal
            elif power >= -85:
                return '#ff922b'  # Orange - Fair signal
            else:
                return '#ff6b6b'  # Red - Poor signal
        except (ValueError, TypeError):
            return '#868e96'  # Gray - Unknown
    
    def update_network_in_table(self, row, network):
        """Update an existing network row in the table with colored text"""
        if row < self.networks_table.rowCount():
            # Ensure all fields have valid values
            essid = network.get('essid', '').strip() or '<Hidden>'
            bssid = network.get('bssid', '').strip()
            channel = str(network.get('channel', '')).strip() or '?'
            power = str(network.get('power', '')).strip() or '?'
            encryption = network.get('encryption', 'Unknown').strip() or 'Unknown'
            wps_raw = network.get('wps', 'Unknown')
            # Handle both string and other types
            if isinstance(wps_raw, str):
                wps = wps_raw.strip() or 'Unknown'
            else:
                wps = str(wps_raw).strip() or 'Unknown'
            clients = str(network.get('clients', 0))
            
            # Check if WPS is enabled (Yes or On) for row highlighting - be more explicit
            wps_lower = str(wps).lower().strip()
            wps_enabled = (wps_lower == 'yes' or wps_lower == 'on' or 'unlocked' in wps_lower or wps_lower.startswith('yes') or wps_lower.startswith('on'))
            
            # Debug: log when WPS is detected (can be removed later)
            if wps_enabled:
                logger.debug(f"[GUI] WPS enabled detected for network {essid}: wps={wps}, wps_lower={wps_lower}")
            
            # Prepare green background brush if WPS is enabled
            green_brush = None
            if wps_enabled:
                green_color = QColor('#16a34a')  # Bright green background (#16a34a) for better visibility
                green_brush = QBrush(green_color)
            
            # ESSID - Cyan for visibility
            item_essid = self._create_colored_table_item(essid, '#3bc9db')
            if green_brush:
                item_essid.setBackground(green_brush)
            self.networks_table.setItem(row, 0, item_essid)
            
            # BSSID - White/Gray
            item_bssid = self._create_colored_table_item(bssid, '#868e96')
            if green_brush:
                item_bssid.setBackground(green_brush)
            self.networks_table.setItem(row, 1, item_bssid)
            
            # Channel - Blue
            item_channel = self._create_colored_table_item(channel, '#74c0fc')
            if green_brush:
                item_channel.setBackground(green_brush)
            self.networks_table.setItem(row, 2, item_channel)
            
            # Power - Color based on signal strength
            power_color = self._get_power_color(power)
            item_power = self._create_colored_table_item(power, power_color)
            if green_brush:
                item_power.setBackground(green_brush)
            self.networks_table.setItem(row, 3, item_power)
            
            # Encryption - Color based on type
            enc_color = self._get_encryption_color(encryption)
            item_enc = self._create_colored_table_item(encryption, enc_color)
            if green_brush:
                item_enc.setBackground(green_brush)
            self.networks_table.setItem(row, 4, item_enc)
            
            # WPS - Color based on status (green for Yes/On)
            wps_color = self._get_wps_color(wps)
            item_wps = self._create_colored_table_item(wps, wps_color)
            if green_brush:
                item_wps.setBackground(green_brush)
            self.networks_table.setItem(row, 5, item_wps)
            
            # Clients - White
            item_clients = self._create_colored_table_item(clients, '#e2e8f0')
            if green_brush:
                item_clients.setBackground(green_brush)
            self.networks_table.setItem(row, 6, item_clients)
            
            # Force update background for WPS-enabled rows by applying to all items again
            # This ensures the background is applied even if Qt tries to override it
            if wps_enabled and green_brush:
                # Force apply background one more time to ensure it sticks
                for col in range(self.networks_table.columnCount()):
                    item = self.networks_table.item(row, col)
                    if item:
                        # Use setData with BackgroundRole to ensure it's set  
                        item.setData(Qt.ItemDataRole.BackgroundRole, green_brush)
                        item.setBackground(green_brush)
                        # Also ensure the item is not editable so styling sticks
                        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        
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
            # Use update_network_in_table which handles colors
            self.update_network_in_table(row, network)
        
        # Force repaint to ensure all styling is applied
        viewport = self.networks_table.viewport()
        if viewport:
            viewport.update()
        
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
            'verbose': self.settings_panel.verbose_cb.isChecked(),
            'kill_processes': self.settings_panel.kill_processes_cb.isChecked(),
            'random_mac': self.settings_panel.random_mac_cb.isChecked(),
            'scan_band_24ghz': self.settings_panel.scan_24_cb.isChecked(),
            'scan_band_5ghz': self.settings_panel.scan_5_cb.isChecked(),
            'scan_band_6ghz': self.settings_panel.scan_6_cb.isChecked(),
            # Enhanced cracking options
            'cracking_strategy': self._get_cracking_strategy(),
            'primary_wordlist': self.settings_panel.wordlist_combo.currentData(),
            'multi_wordlist': self.settings_panel.multi_wordlist_cb.isChecked(),
            'custom_wordlist_paths': getattr(self.settings_panel, 'custom_wordlist_paths', []),
            'use_aircrack': self.settings_panel.aircrack_cb.isChecked(),
            'use_hashcat': self.settings_panel.hashcat_cb.isChecked(),
            # Brute force options (from GPU-Accelerated section)
            'use_brute_force': self.settings_panel.brute_force_cb.isChecked(),
            'brute_force_mode': self.settings_panel.brute_mode_combo.currentIndex(),
            'brute_force_mask': self.settings_panel.mask_combo.currentText() == "Custom Pattern" and self.settings_panel.custom_mask_edit.text() or self.settings_panel.mask_patterns.get(self.settings_panel.mask_combo.currentText(), "?d?d?d?d?d?d"),
            'brute_force_timeout': self.settings_panel.brute_timeout_spin.value() * 60,  # Convert minutes to seconds
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
                'hcxpcapngtool': 'Convert PMKID packet captures (aka hcxpcaptool)'
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
        
    def _on_handshake_cracked(self, data: Dict[str, Any]):
        """Handle notification when the handshake cracker finds a key."""
        essid = data.get('essid', 'Unknown')
        key = data.get('key', '')
        self.add_log(f"Handshake cracked for {essid}: {key}")
        self.status_update.emit(f"Handshake cracked for {essid}")
        
    def add_log(self, message):
        """Add message to log with colored formatting and performance optimization"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Convert color codes to HTML formatting
        formatted_message = self._format_log_message(message)
        
        # Only add if message is not empty after formatting
        if formatted_message and formatted_message.strip():
            html_message = f'<span style="color: #868e96;">[{timestamp}]</span> {formatted_message}'
            cursor = self.log_text.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            cursor.insertHtml(html_message + '<br>')
            self.log_text.setTextCursor(cursor)
            self.log_text.ensureCursorVisible()
    
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
                
    def analyze_client_credentials(self):
        """Credential analysis is not available."""
        self.status_update.emit("Credential analysis is unavailable.")
    
    def open_pcap_folder(self):
        """No-op placeholder; PCAP folder browsing removed."""
        self.status_update.emit("PCAP browsing is unavailable.")
    
    def open_handshake_folder(self):
        """No-op placeholder; handshake browsing removed."""
        self.status_update.emit("Handshake browsing is unavailable.")
    
    def open_credential_folder(self):
        """No-op placeholder; credential browsing removed."""
        self.status_update.emit("Credential browsing is unavailable.")
    
    def _open_folder_non_blocking(self, folder_path, folder_type="Folder"):
        """Open a folder using non-blocking method to prevent GUI freezing"""
        import subprocess
        import os
        
        folder_path_abs = os.path.abspath(os.path.expanduser(folder_path))
        
        if not os.path.exists(folder_path_abs):
            QMessageBox.warning(self, "Folder Not Found", 
                               f"{folder_type} folder not found:\n{folder_path_abs}\n\nPlease check the path.")
            return
        
        if not os.path.isdir(folder_path_abs):
            QMessageBox.warning(self, "Invalid Path", 
                               f"Path is not a directory:\n{folder_path_abs}")
            return
        
        # Use QTimer to run subprocess in a way that doesn't block GUI
        from PyQt6.QtCore import QTimer
        def try_open():
            try:
                if os.name == 'nt':  # Windows
                    os.startfile(folder_path_abs)
                    self.log_update.emit(f"[DATA] Opened {folder_type} folder: {folder_path_abs}")
                else:  # Linux/Mac
                    # Try xdg-open first (most common on Linux) - use Popen to avoid blocking
                    try:
                        import subprocess
                        subprocess.Popen(['xdg-open', folder_path_abs], 
                                        stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL)
                        self.log_update.emit(f"[DATA] Opened {folder_type} folder: {folder_path_abs}")
                    except FileNotFoundError:
                        # Fallback: show path with instructions
                        self._show_folder_path(folder_path_abs, folder_type)
                    except Exception:
                        # Fallback: show path with instructions
                        self._show_folder_path(folder_path_abs, folder_type)
            except Exception as e:
                self.log_update.emit(f"[ERROR] Failed to open {folder_type} folder: {e}")
                self._show_folder_path(folder_path_abs, folder_type)
        
        # Schedule to run immediately (non-blocking)
        QTimer.singleShot(0, try_open)
    
    def _show_folder_path(self, folder_path, folder_type="Folder"):
        """Show folder path in message box with copy to clipboard option"""
        folder_path_abs = os.path.abspath(os.path.expanduser(folder_path))
        
        try:
            clipboard = QApplication.clipboard()
            if clipboard:
                clipboard.setText(folder_path_abs)
                QMessageBox.information(self, f"{folder_type} Folder Location", 
                                       f"{folder_type} folder location:\n{folder_path_abs}\n\n"
                                       f"Path copied to clipboard.\n"
                                       f"Paste it in your file manager to open.")
            else:
                QMessageBox.information(self, f"{folder_type} Folder Location", 
                                       f"{folder_type} folder location:\n{folder_path_abs}\n\n"
                                       f"Copy this path to your file manager to open.")
        except Exception:
            QMessageBox.information(self, f"{folder_type} Folder Location", 
                                   f"{folder_type} folder location:\n{folder_path_abs}\n\n"
                                   f"Copy this path to your file manager to open.")
    
    def open_in_wireshark(self):
        """No-op placeholder; Wireshark integration removed."""
        self.status_update.emit("Wireshark integration is unavailable.")
    
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

<p>Wifitex is a comprehensive wireless security testing tool featuring both command-line and modern GUI interfaces. It's a complete rewrite of the original Wifitex codebase with enhanced capabilities, better architecture, and modern features.</p>

<h3>Key Features:</h3>
<ul>
<li><b>Modern Dual Interface:</b> CLI and GUI modes</li>
<li><b>Advanced Attack Capabilities:</b> WPS, WPA/WPA2, PMKID attacks</li>
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
    
    def open_settings_shortcut(self):
        """Open the settings tab via keyboard shortcut"""
        try:
            if hasattr(self, "tab_widget"):
                settings_index = getattr(self, "settings_tab_index", None)
                if settings_index is not None and settings_index >= 0:
                    self.tab_widget.setCurrentIndex(settings_index)
                    if hasattr(self.settings_panel, "setFocus"):
                        self.settings_panel.setFocus(Qt.FocusReason.ShortcutFocusReason)
                    self.status_update.emit("Opened Settings tab")
                    return
        except Exception as exc:
            logger.error(f"Error opening settings via shortcut: {exc}")
        self.status_update.emit("Settings panel unavailable")
        
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
        QShortcut(QKeySequence("Ctrl+Shift+S"), self, self.stop_all_attacks)
        
        # Settings and copy shortcuts
        QShortcut(QKeySequence("Ctrl+,"), self, self.open_settings_shortcut)
        QShortcut(QKeySequence.StandardKey.Copy, self.networks_table, self.copy_selected_network_details)
        
    def select_all_networks(self):
        """Select all networks in the table"""
        if not hasattr(self, "networks_table"):
            return
        total_rows = self.networks_table.rowCount()
        if total_rows == 0:
            self.status_update.emit("No networks available to select")
            return
        self.networks_table.selectAll()
        self.on_network_selection_changed()
        self.status_update.emit(f"Selected {total_rows} network(s)")
    
    def deselect_all_networks(self):
        """Deselect all networks in the table"""
        if not hasattr(self, "networks_table"):
            return
        if not self.networks_table.selectedIndexes():
            self.status_update.emit("No networks selected")
            return
        self.networks_table.clearSelection()
        self.on_network_selection_changed()
        self.status_update.emit("Cleared network selection")
    
    def attack_wps_selected(self):
        """Attack WPS for selected networks"""
        if not self._ensure_network_selection():
            QMessageBox.information(self, "No Selection", "Select at least one network before starting a WPS attack.")
            return
        if not self._set_attack_type(["WPS Pixie-Dust", "WPS PIN", "Auto (Recommended)"]):
            self.status_update.emit("No WPS attack profile available")
            return
        self.status_update.emit("Starting WPS attack")
        self.start_attack()
    
    def attack_wpa_selected(self):
        """Attack WPA for selected networks"""
        if not self._ensure_network_selection():
            QMessageBox.information(self, "No Selection", "Select at least one network before starting a WPA attack.")
            return
        if not self._set_attack_type(["WPA/WPA2 Handshake", "PMKID", "Auto (Recommended)"]):
            self.status_update.emit("No WPA attack profile available")
            return
        self.status_update.emit("Starting WPA attack")
        self.start_attack()
    
    def toggle_scan(self):
        """Toggle scan on/off"""
        try:
            if getattr(self.scanner, "scanning", False):
                self.status_update.emit("Stopping scan...")
                self.stop_scan()
            else:
                self.status_update.emit("Starting scan...")
                self.start_scan()
        except Exception as exc:
            logger.error(f"Error toggling scan: {exc}")
            self.status_update.emit(f"Unable to toggle scan: {exc}")

    def copy_selected_network_details(self):
        """Copy selected network details to the clipboard"""
        if not hasattr(self, "networks_table"):
            return
        selected_indexes = self.networks_table.selectedIndexes()
        if not selected_indexes:
            self.status_update.emit("No networks selected to copy")
            return

        selected_rows = sorted({index.row() for index in selected_indexes})
        if not selected_rows:
            self.status_update.emit("No networks selected to copy")
            return

        headers = []
        for col in range(self.networks_table.columnCount()):
            header_item = self.networks_table.horizontalHeaderItem(col)
            headers.append(header_item.text() if header_item else f"Column {col + 1}")

        lines = ["\t".join(headers)]
        for row in selected_rows:
            column_values = []
            for col in range(self.networks_table.columnCount()):
                item = self.networks_table.item(row, col)
                column_values.append(item.text().strip() if item and item.text() else "")
            lines.append("\t".join(column_values))

        clipboard = QApplication.clipboard()
        if clipboard is None:
            self.status_update.emit("Clipboard unavailable")
            return
        clipboard.setText("\n".join(lines))
        self.status_update.emit(f"Copied details for {len(selected_rows)} network(s)")

    def _ensure_network_selection(self) -> bool:
        """Ensure there is at least one network selected"""
        if self.selected_networks:
            return True
        if hasattr(self, "networks_table") and self.networks_table.selectedIndexes():
            self.on_network_selection_changed()
            return bool(self.selected_networks)
        return False

    def _set_attack_type(self, preferred_labels: List[str]) -> bool:
        """Select the first available attack type matching preferred labels"""
        for label in preferred_labels:
            index = self.attack_type_combo.findText(label, Qt.MatchFlag.MatchExactly)
            if index >= 0:
                self.attack_type_combo.setCurrentIndex(index)
                return True
        return False
        
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
            if hasattr(self, 'handshake_tab'):
                self.handshake_tab.cleanup()

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
            
            # Watchdog: hard-exit if cleanup does not finish in time
            def _force_exit():
                try:
                    os._exit(1)  # last-resort hard exit
                except Exception:
                    pass

            watchdog = QTimer(self)
            watchdog.setSingleShot(True)
            watchdog.timeout.connect(_force_exit)
            watchdog.start(5000)  # 5 seconds

            # Add initial log message
            cleanup_dialog.add_log("Preparing cleanup...")
            QApplication.processEvents()
            
            # Run cleanup in a background thread
            self._cleanup_worker = CleanupWorker(self)
            self._cleanup_worker.progress.connect(cleanup_dialog.add_log)
            self._cleanup_worker.error.connect(lambda m: cleanup_dialog.add_log(f"⚠️ {m}"))
            self._cleanup_worker.finished.connect(lambda: watchdog.stop())
            self._cleanup_worker.finished.connect(lambda: (cleanup_dialog.set_done(), QTimer.singleShot(250, cleanup_dialog.accept)))
            self._cleanup_worker.start()
            
            # Block with dialog event loop while UI remains responsive
            cleanup_dialog.exec()
            
            event.accept()
            
        except Exception as e:
            logger.error(f"Error during close: {e}")
            event.accept()
    
    def _comprehensive_cleanup(self):
        """Cleanup GUI-managed attack resources without aggressive process kills."""
        try:
            logger.info("Starting GUI cleanup...")

            if hasattr(self, 'attack_manager'):
                try:
                    self.attack_manager.stop_attack()
                except Exception:
                    pass
                try:
                    self.attack_manager.cleanup_all_processes()
                except Exception:
                    pass

            if hasattr(self, 'scanner'):
                try:
                    self.scanner.stop_scan()
                except Exception:
                    pass

            try:
                from ..util.process import Process  # Lazy import to avoid cycles
            except Exception:
                Process = None

            if Process is not None:
                try:
                    Process.cleanup_all_processes()
                except Exception:
                    logger.debug("Process cleanup failed", exc_info=True)

            logger.info("GUI cleanup finished")

        except Exception as e:
            logger.error(f"Error during GUI cleanup: {e}")


# Optional: Emergency force reboot method (requires root)
    def force_reboot_system(self):
        """Emergency reboot. Use with caution; requires root."""
        try:
            subprocess.run(['sync'])
            result = subprocess.run(['systemctl', 'reboot', '-i'], capture_output=True)
            if result.returncode != 0:
                subprocess.run(['reboot', '-f'])
        except Exception:
            try:
                # Last resort; may not work on all systems
                subprocess.run(['reboot', '-f'])
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
        self._log("Starting GUI cleanup...")

        try:
            if hasattr(self._mw, 'attack_manager'):
                self._log("Stopping attacks...")
                try:
                    self._mw.attack_manager.stop_attack()
                except Exception:
                    pass
                try:
                    self._mw.attack_manager.cleanup_all_processes()
                except Exception:
                    pass

            if hasattr(self._mw, 'scanner'):
                self._log("Stopping scanner...")
                try:
                    self._mw.scanner.stop_scan()
                except Exception:
                    pass

            try:
                from ..util.process import Process  # Lazy import to avoid circular deps
            except Exception:
                Process = None

            if Process is not None:
                try:
                    self._log("Cleaning tracked processes...")
                    Process.cleanup_all_processes()
                except Exception:
                    self._log("Process cleanup failed; continuing")

            self._log("Cleanup complete.")

        except Exception as exc:
            self._log(f"Cleanup encountered an error: {exc}")
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
            actual_iface = network_utils.interface or self.interface
            
            if success:
                self.interface = actual_iface
                self.monitor_completed.emit({
                    'operation': 'enable',
                    'interface': actual_iface,
                    'message': f"Monitor mode enabled on {actual_iface}"
                })
            else:
                error_msg = network_utils.last_error or "Failed to enable monitor mode"
                self.monitor_failed.emit({
                    'operation': 'enable',
                    'error': error_msg
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
            actual_iface = network_utils.interface or self.interface
            
            if success:
                self.interface = actual_iface
                self.monitor_completed.emit({
                    'operation': 'disable',
                    'interface': actual_iface,
                    'message': f"Monitor mode disabled on {actual_iface}"
                })
            else:
                error_msg = network_utils.last_error or "Failed to disable monitor mode"
                self.monitor_failed.emit({
                    'operation': 'disable',
                    'error': error_msg
                })
                
        except Exception as e:
            self.monitor_failed.emit({
                'operation': 'disable',
                'error': f"Unexpected error: {str(e)}"
            })
