#!/usr/bin/env python3
"""
Shared utility class for log formatting and ANSI color conversion
"""

class LogFormatter:
    """Shared utility class for formatting log messages with ANSI color codes"""
    
    @staticmethod
    def format_message_for_html(message: str) -> str:
        """Convert ANSI color codes and custom color codes to HTML spans"""
        if not message:
            return ""
        
        # Custom color codes mapping (Wifitex style)
        custom_color_map = {
            '{W}': '</span>',  # White (reset)
            '{R}': '<span style="color: #ff6b6b; font-weight: bold;">',  # Red - Error/Critical
            '{G}': '<span style="color: #51cf66; font-weight: bold;">',  # Green - Success
            '{B}': '<span style="color: #74c0fc; font-weight: bold;">',  # Blue - Info
            '{Y}': '<span style="color: #ffd43b; font-weight: bold;">',  # Yellow - Warning
            '{C}': '<span style="color: #3bc9db; font-weight: bold;">',  # Cyan - Debug/Scan
            '{M}': '<span style="color: #da77f2; font-weight: bold;">',  # Magenta - Special
            '{O}': '<span style="color: #ff922b; font-weight: bold;">',  # Orange - Action
            '{P}': '<span style="color: #9775fa; font-weight: bold;">',  # Purple - Network
            '{T}': '<span style="color: #69db7c; font-weight: bold;">',  # Bright Green - Success
            '{K}': '<span style="color: #868e96; font-weight: normal;">',  # Gray - Timestamp/Info
            '{D}': '<span style="color: #5f3dc4; font-weight: bold;">',  # Dark Purple - Important
        }
        
        # Replace custom color codes with HTML spans
        for color_code, html_span in custom_color_map.items():
            message = message.replace(color_code, html_span)
        
        # ANSI color codes mapping
        ansi_colors = {
            '\033[0m': '</span>',  # Reset
            '\033[31m': '<span style="color: #ff6b6b; font-weight: bold;">',  # Red - Error
            '\033[32m': '<span style="color: #51cf66; font-weight: bold;">',  # Green - Success
            '\033[33m': '<span style="color: #ffd43b; font-weight: bold;">',  # Yellow - Warning
            '\033[34m': '<span style="color: #74c0fc; font-weight: bold;">',  # Blue - Info
            '\033[35m': '<span style="color: #da77f2; font-weight: bold;">',  # Magenta/Purple
            '\033[36m': '<span style="color: #3bc9db; font-weight: bold;">',  # Cyan - Debug
            '\033[37m': '<span style="color: #f8f9fa; font-weight: normal;">',  # White/Light
            '\033[90m': '<span style="color: #868e96; font-weight: normal;">',  # Dark Gray
            '\033[91m': '<span style="color: #ff8787; font-weight: bold;">',  # Bright Red
            '\033[92m': '<span style="color: #69db7c; font-weight: bold;">',  # Bright Green
            '\033[93m': '<span style="color: #ffd43b; font-weight: bold;">',  # Bright Yellow
            '\033[94m': '<span style="color: #74c0fc; font-weight: bold;">',  # Bright Blue
            '\033[95m': '<span style="color: #da77f2; font-weight: bold;">',  # Bright Magenta
            '\033[96m': '<span style="color: #3bc9db; font-weight: bold;">',  # Bright Cyan
            '\033[97m': '<span style="color: #f8f9fa; font-weight: bold;">',  # Bright White
            '\033[2m': '<span style="opacity: 0.6; font-weight: normal;">',     # Dim
            '\033[1m': '<span style="font-weight: bold;">',  # Bold
        }
        
        # Replace ANSI codes with HTML
        for ansi_code, html_span in ansi_colors.items():
            message = message.replace(ansi_code, html_span)
        
        # Ensure proper span closure
        if '<span' in message and not message.endswith('</span>'):
            message += '</span>'
        
        return message
    
    @staticmethod
    def format_message_for_console(message: str) -> str:
        """Remove ANSI color codes for console output"""
        if not message:
            return ""
        
        import re
        
        # Remove ANSI escape sequences
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        message = ansi_escape.sub('', message)
        
        # Remove custom color codes
        custom_codes = ['{W}', '{R}', '{G}', '{B}', '{Y}', '{C}', '{M}', '{O}', '{P}', '{T}', '{K}', '{D}']
        for code in custom_codes:
            message = message.replace(code, '')
        
        return message
    
    @staticmethod
    def clean_message(message: str) -> str:
        """Clean message by removing color codes and formatting"""
        if not message:
            return ""
        
        # First remove ANSI codes
        message = LogFormatter.format_message_for_console(message)
        
        # Remove HTML tags if any
        import re
        message = re.sub(r'<[^>]+>', '', message)
        
        # Clean up extra whitespace
        message = ' '.join(message.split())
        
        return message
    
    @staticmethod
    def format_timestamp() -> str:
        """Get formatted timestamp for log messages"""
        from datetime import datetime
        return datetime.now().strftime("%H:%M:%S")
    
    @staticmethod
    def format_log_entry(message: str, level: str = "INFO") -> str:
        """Format a complete log entry with timestamp and level"""
        timestamp = LogFormatter.format_timestamp()
        clean_msg = LogFormatter.clean_message(message)
        return f"[{timestamp}] [{level}] {clean_msg}"
