#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
GUI Styles and Themes for Wifitex

This module contains the styling definitions for the GUI interface,
including dark theme and custom styles.
"""

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPalette, QColor


class DarkTheme:
    """Dark theme for the Wifitex GUI"""
    
    # Color palette
    PRIMARY_COLOR = "#2d5a87"
    SECONDARY_COLOR = "#3a6ea5"
    SUCCESS_COLOR = "#28a745"
    WARNING_COLOR = "#ffc107"
    ERROR_COLOR = "#dc3545"
    INFO_COLOR = "#17a2b8"
    
    # Background colors
    BG_PRIMARY = "#1e1e1e"
    BG_SECONDARY = "#2d2d2d"
    BG_TERTIARY = "#3e3e3e"
    
    # Text colors
    TEXT_PRIMARY = "#e2e8f0"  # Changed from white to light gray for better readability
    TEXT_SECONDARY = "#cccccc"
    TEXT_MUTED = "#888888"
    
    # Border colors
    BORDER_PRIMARY = "#555555"
    BORDER_SECONDARY = "#777777"
    
    @classmethod
    def get_stylesheet(cls):
        """Get the complete stylesheet for the dark theme"""
        return f"""
        /* Main Window */
        QMainWindow {{
            background-color: {cls.BG_PRIMARY};
            color: {cls.TEXT_PRIMARY};
        }}
        
        /* Central Widget */
        QWidget {{
            background-color: {cls.BG_PRIMARY};
            color: {cls.TEXT_PRIMARY};
        }}
        
        /* Group Boxes */
        QGroupBox {{
            font-weight: bold;
            border: 2px solid {cls.BORDER_PRIMARY};
            border-radius: 5px;
            margin-top: 1ex;
            padding-top: 10px;
        }}
        
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
            color: {cls.TEXT_PRIMARY};
        }}
        
        /* Buttons */
        QPushButton {{
            background-color: {cls.BG_SECONDARY};
            border: 1px solid {cls.BORDER_PRIMARY};
            border-radius: 4px;
            color: {cls.TEXT_PRIMARY};
            padding: 6px 12px;
            font-weight: bold;
        }}
        
        QPushButton:hover {{
            background-color: {cls.BG_TERTIARY};
            border-color: {cls.BORDER_SECONDARY};
        }}
        
        QPushButton:pressed {{
            background-color: {cls.PRIMARY_COLOR};
            border-color: {cls.SECONDARY_COLOR};
        }}
        
        QPushButton:disabled {{
            background-color: {cls.BG_SECONDARY};
            color: {cls.TEXT_MUTED};
            border-color: {cls.BORDER_PRIMARY};
        }}
        
        /* Combo Boxes */
        QComboBox {{
            background-color: {cls.BG_SECONDARY};
            border: 1px solid {cls.BORDER_PRIMARY};
            border-radius: 4px;
            color: {cls.TEXT_PRIMARY};
            padding: 4px 8px;
            min-width: 100px;
        }}
        
        QComboBox:hover {{
            border-color: {cls.BORDER_SECONDARY};
        }}
        
        QComboBox::drop-down {{
            subcontrol-origin: padding;
            subcontrol-position: top right;
            width: 20px;
            border-left-width: 1px;
            border-left-color: {cls.BORDER_PRIMARY};
            border-left-style: solid;
        }}
        
        QComboBox::down-arrow {{
            image: none;
            border: 2px solid {cls.TEXT_PRIMARY};
            width: 6px;
            height: 6px;
            border-top: none;
            border-right: none;
        }}
        
        QComboBox QAbstractItemView {{
            background-color: {cls.BG_SECONDARY};
            border: 1px solid {cls.BORDER_PRIMARY};
            color: {cls.TEXT_PRIMARY};
            selection-background-color: {cls.PRIMARY_COLOR};
            selection-color: white;
        }}
        
        QComboBox QAbstractItemView::item {{
            background-color: transparent;
            color: {cls.TEXT_PRIMARY};
            padding: 4px 8px;
        }}
        
        QComboBox QAbstractItemView::item:selected {{
            background-color: {cls.PRIMARY_COLOR};
            color: white;
        }}
        
        QComboBox QAbstractItemView::item:hover {{
            background-color: {cls.BG_TERTIARY};
            color: {cls.TEXT_PRIMARY};
        }}
        
        /* Line Edits */
        QLineEdit {{
            background-color: {cls.BG_SECONDARY};
            border: 1px solid {cls.BORDER_PRIMARY};
            border-radius: 4px;
            color: {cls.TEXT_PRIMARY};
            padding: 4px 8px;
        }}
        
        QLineEdit:focus {{
            border-color: {cls.PRIMARY_COLOR};
        }}
        
        /* Spin Boxes */
        QSpinBox {{
            background-color: {cls.BG_SECONDARY};
            border: 1px solid {cls.BORDER_PRIMARY};
            border-radius: 4px;
            color: {cls.TEXT_PRIMARY};
            padding: 4px 8px;
        }}
        
        QSpinBox:focus {{
            border-color: {cls.PRIMARY_COLOR};
        }}
        
        QSpinBox::up-button, QSpinBox::down-button {{
            background-color: {cls.BG_TERTIARY};
            border: 1px solid {cls.BORDER_PRIMARY};
            width: 16px;
        }}
        
        QSpinBox::up-button:hover, QSpinBox::down-button:hover {{
            background-color: {cls.PRIMARY_COLOR};
        }}
        
        /* Check Boxes */
        QCheckBox {{
            color: {cls.TEXT_PRIMARY};
            spacing: 8px;
        }}
        
        QCheckBox::indicator {{
            width: 16px;
            height: 16px;
            border: 1px solid {cls.BORDER_PRIMARY};
            border-radius: 3px;
            background-color: {cls.BG_SECONDARY};
        }}
        
        QCheckBox::indicator:hover {{
            border-color: {cls.BORDER_SECONDARY};
        }}
        
        QCheckBox::indicator:checked {{
            background-color: {cls.PRIMARY_COLOR};
            border-color: {cls.SECONDARY_COLOR};
            image: url(data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIiIGhlaWdodD0iMTIiIHZpZXdCb3g9IjAgMCAxMiAxMiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTEwIDNMNC41IDguNUwyIDYiIHN0cm9rZT0id2hpdGUiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIi8+Cjwvc3ZnPgo=);
        }}
        
        /* Tables */
        QTableWidget {{
            background-color: {cls.BG_SECONDARY};
            border: 1px solid {cls.BORDER_PRIMARY};
            border-radius: 4px;
            color: {cls.TEXT_PRIMARY};
            gridline-color: {cls.BORDER_PRIMARY};
            selection-background-color: {cls.PRIMARY_COLOR};
            alternate-background-color: {cls.BG_TERTIARY};
        }}
        
        QTableWidget::item {{
            padding: 4px;
            border: none;
            background-color: transparent;
            color: {cls.TEXT_PRIMARY};
        }}
        
        QTableWidget::item:selected {{
            background-color: {cls.PRIMARY_COLOR};
            color: white;
        }}
        
        QTableWidget::item:hover {{
            background-color: {cls.BG_TERTIARY};
            color: {cls.TEXT_PRIMARY};
        }}
        
        QTableWidget::item:focus {{
            background-color: {cls.PRIMARY_COLOR};
            color: white;
            outline: none;
        }}
        
        QHeaderView::section {{
            background-color: {cls.BG_TERTIARY};
            color: {cls.TEXT_PRIMARY};
            border: 1px solid {cls.BORDER_PRIMARY};
            padding: 4px;
            font-weight: bold;
        }}
        
        QHeaderView::section:hover {{
            background-color: {cls.PRIMARY_COLOR};
        }}
        
        /* Text Edit */
        QTextEdit {{
            background-color: {cls.BG_SECONDARY};
            border: 1px solid {cls.BORDER_PRIMARY};
            border-radius: 4px;
            color: {cls.TEXT_PRIMARY};
            selection-background-color: {cls.PRIMARY_COLOR};
        }}
        
        /* Progress Bars */
        QProgressBar {{
            background-color: {cls.BG_SECONDARY};
            border: 1px solid {cls.BORDER_PRIMARY};
            border-radius: 4px;
            text-align: center;
            color: {cls.TEXT_PRIMARY};
        }}
        
        QProgressBar::chunk {{
            background-color: {cls.PRIMARY_COLOR};
            border-radius: 3px;
        }}
        
        /* Tab Widget */
        QTabWidget::pane {{
            background-color: {cls.BG_SECONDARY};
            border: 1px solid {cls.BORDER_PRIMARY};
            border-radius: 4px;
        }}
        
        QTabBar::tab {{
            background-color: {cls.BG_SECONDARY};
            border: 1px solid {cls.BORDER_PRIMARY};
            border-bottom: none;
            color: {cls.TEXT_PRIMARY};
            padding: 6px 12px;
            margin-right: 2px;
        }}
        
        QTabBar::tab:selected {{
            background-color: {cls.BG_TERTIARY};
            color: {cls.TEXT_PRIMARY};
        }}
        
        QTabBar::tab:hover {{
            background-color: {cls.PRIMARY_COLOR};
        }}
        
        /* List Widget */
        QListWidget {{
            background-color: {cls.BG_SECONDARY};
            border: 1px solid {cls.BORDER_PRIMARY};
            border-radius: 4px;
            color: {cls.TEXT_PRIMARY};
            selection-background-color: {cls.PRIMARY_COLOR};
        }}
        
        QListWidget::item {{
            padding: 4px;
            border: none;
        }}
        
        QListWidget::item:selected {{
            background-color: {cls.PRIMARY_COLOR};
            color: {cls.TEXT_PRIMARY};
        }}
        
        QListWidget::item:hover {{
            background-color: {cls.BG_TERTIARY};
        }}
        
        /* Menu Bar */
        QMenuBar {{
            background-color: {cls.BG_SECONDARY};
            color: {cls.TEXT_PRIMARY};
            border-bottom: 1px solid {cls.BORDER_PRIMARY};
        }}
        
        QMenuBar::item {{
            background-color: transparent;
            padding: 4px 8px;
        }}
        
        QMenuBar::item:selected {{
            background-color: {cls.PRIMARY_COLOR};
        }}
        
        QMenu {{
            background-color: {cls.BG_SECONDARY};
            border: 1px solid {cls.BORDER_PRIMARY};
            color: {cls.TEXT_PRIMARY};
        }}
        
        QMenu::item {{
            padding: 4px 20px;
        }}
        
        QMenu::item:selected {{
            background-color: {cls.PRIMARY_COLOR};
        }}
        
        /* Status Bar */
        QStatusBar {{
            background-color: {cls.BG_SECONDARY};
            color: {cls.TEXT_PRIMARY};
            border-top: 1px solid {cls.BORDER_PRIMARY};
        }}
        
        /* Labels */
        QLabel {{
            color: {cls.TEXT_PRIMARY};
        }}
        
        /* Scroll Bars */
        QScrollBar:vertical {{
            background-color: {cls.BG_SECONDARY};
            width: 12px;
            border: none;
        }}
        
        QScrollBar::handle:vertical {{
            background-color: {cls.BORDER_SECONDARY};
            border-radius: 6px;
            min-height: 20px;
        }}
        
        QScrollBar::handle:vertical:hover {{
            background-color: {cls.PRIMARY_COLOR};
        }}
        
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
            height: 0px;
        }}
        
        QScrollBar:horizontal {{
            background-color: {cls.BG_SECONDARY};
            height: 12px;
            border: none;
        }}
        
        QScrollBar::handle:horizontal {{
            background-color: {cls.BORDER_SECONDARY};
            border-radius: 6px;
            min-width: 20px;
        }}
        
        QScrollBar::handle:horizontal:hover {{
            background-color: {cls.PRIMARY_COLOR};
        }}
        
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
            width: 0px;
        }}
        
        /* Splitter */
        QSplitter::handle {{
            background-color: {cls.BORDER_PRIMARY};
        }}
        
        QSplitter::handle:horizontal {{
            width: 2px;
        }}
        
        QSplitter::handle:vertical {{
            height: 2px;
        }}
        
        /* Dialog */
        QDialog {{
            background-color: {cls.BG_PRIMARY};
            color: {cls.TEXT_PRIMARY};
        }}
        
        /* Message Box */
        QMessageBox {{
            background-color: {cls.BG_PRIMARY};
            color: {cls.TEXT_PRIMARY};
        }}
        
        /* Global selection fixes - prevent white highlighting */
        * {{
            selection-background-color: {cls.PRIMARY_COLOR};
            selection-color: white;
        }}
        
        /* Override any system default white backgrounds */
        QAbstractItemView {{
            background-color: {cls.BG_SECONDARY};
            color: {cls.TEXT_PRIMARY};
            selection-background-color: {cls.PRIMARY_COLOR};
            selection-color: white;
        }}
        
        QAbstractItemView::item {{
            background-color: transparent;
            color: {cls.TEXT_PRIMARY};
        }}
        
        QAbstractItemView::item:selected {{
            background-color: {cls.PRIMARY_COLOR};
            color: white;
        }}
        
        QAbstractItemView::item:hover {{
            background-color: {cls.BG_TERTIARY};
            color: {cls.TEXT_PRIMARY};
        }}
        
        /* Special button styles */
        QPushButton[class="primary"] {{
            background-color: {cls.PRIMARY_COLOR};
            color: white;
        }}
        
        QPushButton[class="success"] {{
            background-color: {cls.SUCCESS_COLOR};
            color: white;
        }}
        
        QPushButton[class="warning"] {{
            background-color: {cls.WARNING_COLOR};
            color: black;
        }}
        
        QPushButton[class="error"] {{
            background-color: {cls.ERROR_COLOR};
            color: white;
        }}
        """
    
    @classmethod
    def get_palette(cls):
        """Get the color palette for the dark theme"""
        palette = QPalette()
        
        # Set colors for different states
        palette.setColor(QPalette.ColorRole.Window, QColor(cls.BG_PRIMARY))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(cls.TEXT_PRIMARY))
        palette.setColor(QPalette.ColorRole.Base, QColor(cls.BG_SECONDARY))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(cls.BG_TERTIARY))
        palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(cls.BG_SECONDARY))
        palette.setColor(QPalette.ColorRole.ToolTipText, QColor(cls.TEXT_PRIMARY))
        palette.setColor(QPalette.ColorRole.Text, QColor(cls.TEXT_PRIMARY))
        palette.setColor(QPalette.ColorRole.Button, QColor(cls.BG_SECONDARY))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor(cls.TEXT_PRIMARY))
        palette.setColor(QPalette.ColorRole.BrightText, QColor(cls.ERROR_COLOR))
        palette.setColor(QPalette.ColorRole.Link, QColor(cls.PRIMARY_COLOR))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(cls.PRIMARY_COLOR))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor(cls.TEXT_PRIMARY))
        
        return palette


class LightTheme:
    """Light theme for the Wifitex GUI (alternative)"""
    
    # Color palette
    PRIMARY_COLOR = "#007bff"
    SECONDARY_COLOR = "#6c757d"
    SUCCESS_COLOR = "#28a745"
    WARNING_COLOR = "#ffc107"
    ERROR_COLOR = "#dc3545"
    INFO_COLOR = "#17a2b8"
    
    # Background colors
    BG_PRIMARY = "#ffffff"
    BG_SECONDARY = "#f8f9fa"
    BG_TERTIARY = "#e9ecef"
    
    # Text colors
    TEXT_PRIMARY = "#212529"
    TEXT_SECONDARY = "#6c757d"
    TEXT_MUTED = "#868e96"
    
    # Border colors
    BORDER_PRIMARY = "#dee2e6"
    BORDER_SECONDARY = "#adb5bd"
    
    @classmethod
    def get_stylesheet(cls):
        """Get the complete stylesheet for the light theme"""
        # Similar structure to DarkTheme but with light colors
        return f"""
        /* Main Window */
        QMainWindow {{
            background-color: {cls.BG_PRIMARY};
            color: {cls.TEXT_PRIMARY};
        }}
        
        /* Central Widget */
        QWidget {{
            background-color: {cls.BG_PRIMARY};
            color: {cls.TEXT_PRIMARY};
        }}
        
        /* Group Boxes */
        QGroupBox {{
            font-weight: bold;
            border: 2px solid {cls.BORDER_PRIMARY};
            border-radius: 5px;
            margin-top: 1ex;
            padding-top: 10px;
        }}
        
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
            color: {cls.TEXT_PRIMARY};
        }}
        
        /* Buttons */
        QPushButton {{
            background-color: {cls.BG_SECONDARY};
            border: 1px solid {cls.BORDER_PRIMARY};
            border-radius: 4px;
            color: {cls.TEXT_PRIMARY};
            padding: 6px 12px;
            font-weight: bold;
        }}
        
        QPushButton:hover {{
            background-color: {cls.BG_TERTIARY};
            border-color: {cls.BORDER_SECONDARY};
        }}
        
        QPushButton:pressed {{
            background-color: {cls.PRIMARY_COLOR};
            border-color: {cls.SECONDARY_COLOR};
            color: white;
        }}
        
        QPushButton:disabled {{
            background-color: {cls.BG_SECONDARY};
            color: {cls.TEXT_MUTED};
            border-color: {cls.BORDER_PRIMARY};
        }}
        
        /* Additional light theme styles... */
        /* (Implementation similar to dark theme but with light colors) */
        """
