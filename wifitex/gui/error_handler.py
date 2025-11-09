#!/usr/bin/env python3
"""
Centralized error handling for Wifitex GUI
"""

from typing import Optional, Any, Callable, TypeVar, Union
from functools import wraps
import traceback

T = TypeVar('T')

class WifitexError(Exception):
    """Base exception for Wifitex GUI errors"""
    pass

class NetworkError(WifitexError):
    """Network-related errors"""
    pass

class InterfaceError(WifitexError):
    """Interface-related errors"""
    pass

class ConfigurationError(WifitexError):
    """Configuration-related errors"""
    pass

class ToolError(WifitexError):
    """External tool execution errors"""
    pass

class FileError(WifitexError):
    """File operation errors"""
    pass

class AttackError(WifitexError):
    """Attack execution errors"""
    pass

class TargetError(WifitexError):
    """Target-related errors"""
    pass

class ProcessError(WifitexError):
    """Process execution errors"""
    pass

class TimeoutError(WifitexError):
    """Timeout-related errors"""
    pass

class ValidationError(WifitexError):
    """Data validation errors"""
    pass

class UnimplementedMethodError(WifitexError):
    """Unimplemented method errors"""
    pass

def safe_execute(
    func: Callable[..., T], 
    *args, 
    default: Optional[T] = None,
    raise_on_error: bool = False,
    error_class: type = WifitexError,
    **kwargs
) -> Optional[T]:
    """
    Safely execute a function with consistent error handling
    
    Args:
        func: Function to execute
        *args: Positional arguments for the function
        default: Default value to return on error
        raise_on_error: Whether to raise exception on error
        error_class: Exception class to raise if raise_on_error is True
        **kwargs: Keyword arguments for the function
    
    Returns:
        Function result or default value
    """
    try:
        return func(*args, **kwargs)
    except Exception as e:
        if raise_on_error:
            if isinstance(e, error_class):
                raise
            else:
                raise error_class(f"Error in {func.__name__}: {str(e)}") from e
        return default

def handle_errors(
    default: Optional[Any] = None,
    raise_on_error: bool = False,
    error_class: type = WifitexError,
    log_errors: bool = True
):
    """
    Decorator for consistent error handling
    
    Args:
        default: Default value to return on error
        raise_on_error: Whether to raise exception on error
        error_class: Exception class to raise if raise_on_error is True
        log_errors: Whether to log errors
    """
    def decorator(func: Callable[..., T]) -> Callable[..., Optional[T]]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Optional[T]:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if log_errors:
                    try:
                        from .logger import log_error
                        log_error(f"Error in {func.__name__}", e)
                    except ImportError:
                        print(f"Error in {func.__name__}: {e}")
                
                if raise_on_error:
                    if isinstance(e, error_class):
                        raise
                    else:
                        raise error_class(f"Error in {func.__name__}: {str(e)}") from e
                
                return default
        return wrapper
    return decorator

def validate_interface(interface: str) -> bool:
    """Validate network interface name"""
    if not interface or not isinstance(interface, str):
        return False
    
    # Basic validation - interface names should be alphanumeric with underscores
    return interface.replace('_', '').replace('-', '').isalnum()

def validate_file_path(file_path: str) -> bool:
    """Validate file path"""
    if not file_path or not isinstance(file_path, str):
        return False
    
    # Check if path exists and is accessible
    try:
        import os
        return os.path.exists(file_path) and os.access(file_path, os.R_OK)
    except Exception:
        return False

def validate_channel(channel: int) -> bool:
    """Validate WiFi channel number"""
    if not isinstance(channel, int):
        return False
    
    # Valid WiFi channels (2.4GHz: 1-14, 5GHz: 36-165)
    return 1 <= channel <= 165

def get_error_context() -> str:
    """Get current error context for debugging"""
    return traceback.format_exc()

def format_error_message(error: Exception, context: Optional[str] = None) -> str:
    """Format error message with context"""
    message = f"{type(error).__name__}: {str(error)}"
    if context:
        message += f"\nContext: {context}"
    return message
