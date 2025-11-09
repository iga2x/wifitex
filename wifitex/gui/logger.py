#!/usr/bin/env python3
"""
Centralized logging configuration for Wifitex GUI
"""

import logging
import os
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime

class ColoredConsoleFormatter(logging.Formatter):
    """Console formatter that preserves colors and converts custom codes to ANSI."""

    LEVEL_COLOR = {
        logging.DEBUG: "\033[36m",   # Cyan
        logging.INFO: "\033[32m",    # Green
        logging.WARNING: "\033[33m", # Yellow
        logging.ERROR: "\033[31m",   # Red
        logging.CRITICAL: "\033[91m"  # Bright Red
    }

    CUSTOM_COLOR_MAP = {
        '{W}': '\033[0m',   # Reset/white
        '{R}': '\033[31m',  # Red
        '{G}': '\033[32m',  # Green
        '{B}': '\033[34m',  # Blue
        '{Y}': '\033[33m',  # Yellow
        '{C}': '\033[36m',  # Cyan
        '{M}': '\033[35m',  # Magenta
        '{O}': '\033[33m',  # Orange -> use Yellow
        '{P}': '\033[35m',  # Purple -> Magenta
        '{T}': '\033[92m',  # Bright Green
        '{K}': '\033[90m',  # Dark Gray
        '{D}': '\033[35m',  # Dark Purple -> Magenta
    }

    RESET = "\033[0m"

    def __init__(self, fmt: str, datefmt: Optional[str] = None, enable_color: bool = True):
        super().__init__(fmt=fmt, datefmt=datefmt)
        self.enable_color = enable_color and self._stream_supports_color()

    def _stream_supports_color(self) -> bool:
        try:
            return sys.stdout.isatty()
        except Exception:
            return False

    def _apply_custom_colors(self, message: str) -> str:
        if not self.enable_color or not message:
            # Strip custom markers if color disabled
            for code in self.CUSTOM_COLOR_MAP.keys():
                message = message.replace(code, '')
            return message
        for code, ansi in self.CUSTOM_COLOR_MAP.items():
            message = message.replace(code, ansi)
        # Ensure reset at end if any ANSI was used
        if '\u001b[' in message or '\033[' in message:
            if not message.endswith(self.RESET):
                message += self.RESET
        return message

    def format(self, record: logging.LogRecord) -> str:
        # Base formatting (timestamp/name/level)
        base = super().format(record)
        if not self.enable_color:
            # Remove custom markers when color disabled
            return self._apply_custom_colors(base)

        # Colorize level/name prefix lightly if no custom colors present
        level_color = self.LEVEL_COLOR.get(record.levelno, '')
        reset = self.RESET if level_color else ''
        colored = f"{level_color}{base}{reset}" if level_color else base
        # Now translate any custom color markers in the message part as well
        return self._apply_custom_colors(colored)

class WifitexLogger:
    """Centralized logger for Wifitex GUI"""
    
    _instance: Optional['WifitexLogger'] = None
    _logger: Optional[logging.Logger] = None
    
    def __new__(cls) -> 'WifitexLogger':
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._logger is None:
            self._setup_logger()
    
    def _setup_logger(self):
        """Setup the main logger"""
        self._logger = logging.getLogger('wifitex_gui')
        self._logger.setLevel(logging.DEBUG)
        
        # Prevent duplicate handlers
        if self._logger.handlers:
            return
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        
        # File handler (gracefully handle permission errors)
        file_handler = None
        try:
            log_file = self._get_log_file_path()
            file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
        except Exception as e:
            # Fall back to console-only logging if we cannot open the log file
            # Avoid crashing modules that import the logger in restricted environments
            try:
                self._logger.warning(f"File logging disabled: {e}")
            except Exception:
                pass
        
        # Formatters
        plain_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        colored_formatter = ColoredConsoleFormatter('%(message)s')
        
        console_handler.setFormatter(colored_formatter)
        if file_handler is not None:
            file_handler.setFormatter(plain_formatter)
        
        self._logger.addHandler(console_handler)
        if file_handler is not None:
            self._logger.addHandler(file_handler)
    
    def _get_log_file_path(self) -> str:
        """Get the log file path"""
        # Try to get project root
        try:
            from .path_utils import get_project_root
            project_root = get_project_root()
            if project_root:
                log_dir = os.path.join(project_root, 'logs')
                os.makedirs(log_dir, exist_ok=True)
                return os.path.join(log_dir, f'wifitex_gui_{datetime.now().strftime("%Y%m%d")}.log')
        except Exception:
            pass
        
        # Fallback to temp directory
        import tempfile
        temp_dir = tempfile.gettempdir()
        log_dir = os.path.join(temp_dir, 'wifitex_logs')
        os.makedirs(log_dir, exist_ok=True)
        return os.path.join(log_dir, f'wifitex_gui_{datetime.now().strftime("%Y%m%d")}.log')
    
    def get_logger(self, name: Optional[str] = None) -> logging.Logger:
        """Get a logger instance"""
        if name:
            return logging.getLogger(f'wifitex_gui.{name}')
        return self._logger or logging.getLogger('wifitex_gui')
    
    def clear_log_file(self):
        """Clear the current log file"""
        try:
            log_file = self._get_log_file_path()
            if os.path.exists(log_file):
                with open(log_file, 'w', encoding='utf-8') as f:
                    f.write('')
                if self._logger:
                    self._logger.info("Log file cleared")
        except Exception as e:
            if self._logger:
                self._logger.warning(f"Could not clear log file: {e}")

# Global logger instance
wifitex_logger = WifitexLogger()

def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Get a logger instance"""
    return wifitex_logger.get_logger(name)

def log_error(message: str, exception: Optional[Exception] = None, logger_name: Optional[str] = None):
    """Log an error message with optional exception details"""
    logger = get_logger(logger_name)
    if exception:
        logger.error(f"{message}: {str(exception)}", exc_info=True)
    else:
        logger.error(message)

def log_warning(message: str, logger_name: Optional[str] = None):
    """Log a warning message"""
    logger = get_logger(logger_name)
    logger.warning(message)

def log_info(message: str, logger_name: Optional[str] = None):
    """Log an info message"""
    logger = get_logger(logger_name)
    logger.info(message)

def log_debug(message: str, logger_name: Optional[str] = None):
    """Log a debug message"""
    logger = get_logger(logger_name)
    logger.debug(message)
