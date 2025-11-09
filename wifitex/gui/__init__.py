#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Wifitex GUI Module

Modern GUI interface for Wifitex using PyQt6.
Provides a user-friendly interface for wireless network auditing.
"""

# Centralized dependency check to provide clear ImportError guidance
try:
    import PyQt6  # noqa: F401 - presence check only
except ImportError as e:
    raise ImportError(
        "PyQt6 is required for Wifitex GUI but was not found.\n"
        "Install it with one of the following commands:\n\n"
        "- pip:    pip install PyQt6\n"
        "- Debian/Ubuntu/Kali: sudo apt install python3-pyqt6\n\n"
        "If you are using a virtual environment, ensure it is activated before installing."
    ) from e

__version__ = '2.7.0'
__author__ = 'Wifitex GUI Team'

from .main_window import WifitexMainWindow

__all__ = [
    'WifitexMainWindow',
    '__version__',
]
