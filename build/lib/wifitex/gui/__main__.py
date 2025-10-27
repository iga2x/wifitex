#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Main entry point for Wifitex GUI

This module provides the main application entry point and handles
application initialization and startup.
"""

import sys
import os
import signal
from PyQt6.QtWidgets import QApplication, QMessageBox, QSplashScreen, QDialog
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QPixmap, QFont

from .main_window import WifitexMainWindow
from .utils import SystemUtils, DependencyChecker, ConfigManager
from .components import DependencyWarningDialog


class WifitexGUIApplication(QApplication):
    """Main application class for Wifitex GUI"""
    
    def __init__(self, argv):
        super().__init__(argv)
        
        # Disable problematic Qt themes
        os.environ['QT_QPA_PLATFORMTHEME'] = ''
        os.environ['QT_QPA_PLATFORM'] = 'xcb'
        os.environ['QT_STYLE_OVERRIDE'] = ''
        
        # Set application properties
        self.setApplicationName("Wifitex GUI")
        self.setApplicationVersion("1.0.0")
        self.setOrganizationName("Wifitex")
        self.setOrganizationDomain("github.com/iga2x/wifitex")
        
        # Set application style - use Fusion which is most compatible
        self.setStyle('Fusion')
        
        # Initialize components
        self.config_manager = ConfigManager()
        self.main_window = None
        
        # Setup signal handlers
        self.setup_signal_handlers()
        
    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
    def signal_handler(self, signum, frame):
        """Handle system signals"""
        print(f"\nReceived signal {signum}, shutting down gracefully...")
        self.quit()
        
    def show_splash_screen(self):
        """Show splash screen during startup"""
        # Create a simple splash screen
        pixmap = QPixmap(400, 300)
        pixmap.fill(Qt.GlobalColor.darkGray)
        
        splash = QSplashScreen(pixmap)
        splash.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.FramelessWindowHint)
        splash.show()
        
        # Center the splash screen
        screen = self.primaryScreen()
        if screen:
            screen_geometry = screen.geometry()
            splash.move(
                (screen_geometry.width() - splash.width()) // 2,
                (screen_geometry.height() - splash.height()) // 2
            )
        
        # Show splash message
        splash.showMessage(
            "Loading Wifitex GUI...",
            Qt.AlignmentFlag.AlignCenter,
            Qt.GlobalColor.white
        )
        
        self.processEvents()
        return splash
        
    def check_requirements(self):
        """Check system requirements before starting"""
        issues = []
        
        # Check if running as root
        if not SystemUtils.is_root():
            issues.append("Root privileges required. Please run with sudo.")
            
        # Check dependencies
        dependency_results = DependencyChecker.check_all_dependencies()
        
        if not dependency_results['system']['is_linux']:
            issues.append("Linux operating system required.")
            
        if not dependency_results['system']['has_wireless']:
            issues.append("No wireless network interfaces found.")
            
        # Check critical tools
        critical_tools = ['aircrack-ng', 'airodump-ng', 'airmon-ng']
        missing_tools = []
        
        for tool in critical_tools:
            if not dependency_results['tools'].get(tool, False):
                missing_tools.append(tool)
                
        if missing_tools:
            issues.append(f"Missing critical tools: {', '.join(missing_tools)}")
            
        return issues
        
    def show_requirements_dialog(self, issues):
        """Show dialog for system requirements issues"""
        message = "System requirements not met:\n\n" + "\n".join(f"• {issue}" for issue in issues)
        message += "\n\nPlease install missing dependencies and try again."
        
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Icon.Warning)
        msg_box.setWindowTitle("System Requirements")
        msg_box.setText(message)
        msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg_box.exec()
        
    def run(self):
        """Run the application"""
        # Show splash screen
        splash = self.show_splash_screen()
        
        # Check requirements
        splash.showMessage("Checking system requirements...", Qt.AlignmentFlag.AlignCenter, Qt.GlobalColor.white)
        self.processEvents()
        
        issues = self.check_requirements()
        if issues:
            splash.close()
            self.show_requirements_dialog(issues)
            return 1
            
        # Check for missing recommended tools and show warning dialog
        splash.showMessage("Checking recommended tools...", Qt.AlignmentFlag.AlignCenter, Qt.GlobalColor.white)
        self.processEvents()
        
        dependency_results = DependencyChecker.check_all_dependencies()
        tool_details = DependencyChecker.get_tool_status_details()
        
        # Check for tools that exist but don't work properly
        problematic_tools = []
        missing_tools = []
        
        for tool, available in dependency_results['tools'].items():
            if tool in ['hcxpcapngtool', 'tshark', 'reaver', 'bully', 'cowpatty', 'hashcat', 'hostapd', 'dnsmasq']:
                if not available:
                    missing_tools.append(tool)
                elif tool in tool_details and tool_details[tool].get('exists') and not tool_details[tool].get('works'):
                    problematic_tools.append({
                        'tool': tool,
                        'error': tool_details[tool].get('error', 'Unknown error')
                    })
        
        if missing_tools or problematic_tools:
            splash.close()
            warning_dialog = DependencyWarningDialog(dependency_results, tool_details, problematic_tools)
            result = warning_dialog.exec()
            if result == QDialog.DialogCode.Rejected:
                return 1
            
        # Create main window
        splash.showMessage("Initializing GUI...", Qt.AlignmentFlag.AlignCenter, Qt.GlobalColor.white)
        self.processEvents()
        
        try:
            self.main_window = WifitexMainWindow()
            
            # Close splash screen
            splash.close()
            
            # Show main window
            self.main_window.show()
            
            # Run application
            return self.exec()
            
        except Exception as e:
            splash.close()
            QMessageBox.critical(
                None,
                "Application Error",
                f"Failed to start application:\n{str(e)}"
            )
            return 1


def main():
    """Main entry point"""
    # Check if we're in the right environment
    if len(sys.argv) > 1 and sys.argv[1] == '--gui':
        # Remove the --gui argument
        sys.argv.pop(1)
        
    # Create and run application
    app = WifitexGUIApplication(sys.argv)
    return app.run()


if __name__ == '__main__':
    sys.exit(main())
