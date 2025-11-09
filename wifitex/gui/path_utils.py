#!/usr/bin/env python3
"""
Path utilities for dynamic path detection in Wifitex GUI
"""

import os
import sys
from pathlib import Path
from typing import Optional, List
from .error_handler import handle_errors, FileError
from .logger import get_logger

logger = get_logger('path_utils')

@handle_errors(default=None, log_errors=True)
def get_project_root() -> Optional[str]:
    """
    Dynamically detect the Wifitex project root directory.
    
    This function looks for the project root by:
    1. Walking up from current file location (prioritizes development version)
    2. Looking for key project files (setup.py, pyproject.toml, etc.)
    3. Finding the directory containing the wifitex package
    
    Returns:
        str: Path to the project root directory, or None if not found
    """
    try:
        # Method 1: Walk up from current file location (prioritizes development version)
        current_file = os.path.abspath(__file__)
        current_dir = os.path.dirname(current_file)
        
        # Walk up the directory tree
        for _ in range(10):  # Limit to 10 levels up
            # Check for project indicators
            project_indicators = [
                'setup.py',
                'pyproject.toml',
                'wifitex',
                'wordlist-top4800-probable.txt',
                'README.md'
            ]
            
            if any(os.path.exists(os.path.join(current_dir, indicator)) for indicator in project_indicators):
                return current_dir
            
            parent_dir = os.path.dirname(current_dir)
            if parent_dir == current_dir:  # Reached root
                break
            current_dir = parent_dir
        
        # Method 2: Look for wifitex package in Python path (but avoid installed packages)
        for path in sys.path:
            if path and os.path.exists(path) and not path.startswith('/usr'):
                wifitex_path = os.path.join(path, 'wifitex')
                if os.path.exists(wifitex_path):
                    # Found wifitex package, get its parent directory
                    project_root = os.path.dirname(wifitex_path)
                    # Verify it's a development version by checking for setup.py
                    if os.path.exists(os.path.join(project_root, 'setup.py')):
                        return project_root
        
        # Method 3: Try to find from wifitex package location (fallback)
        try:
            import wifitex
            wifitex_path = os.path.dirname(wifitex.__file__)
            project_root = os.path.dirname(wifitex_path)
            # Only use this if it looks like a development version
            if os.path.exists(os.path.join(project_root, 'setup.py')):
                return project_root
        except ImportError as e:
            # wifitex module not available - this is expected in some environments
            logger.debug(f"Could not import wifitex module: {e}")
            pass
        
        return None
        
    except Exception as e:
        logger.error(f"Error detecting project root: {e}")
        return None

@handle_errors(default=None, log_errors=True)
def get_wordlist_path(filename: str = 'wordlist-top4800-probable.txt') -> Optional[str]:
    """
    Get the full path to a wordlist file in the wifitex/wordlists folder.
    
    Args:
        filename: Name of the wordlist file
        
    Returns:
        str: Full path to the wordlist file, or None if not found
    """
    try:
        # Get the path to wifitex/wordlists folder
        # The wordlists are in: wifitex/gui -> wifitex -> wifitex/wordlists
        wifitex_package_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        wifitex_wordlists_dir = os.path.join(wifitex_package_dir, 'wordlists')
        
        wordlist_path = os.path.join(wifitex_wordlists_dir, filename)
        if os.path.exists(wordlist_path):
            return wordlist_path
        
        # Fallback: Try project root (for development/legacy)
        project_root = get_project_root()
        if project_root:
            fallback_path = os.path.join(project_root, filename)
            if os.path.exists(fallback_path):
                return fallback_path
    except Exception as e:
        logger.debug(f"Error in get_wordlist_path: {e}")
    
    return None

@handle_errors(default=None, log_errors=True)
def get_handshake_dir() -> Optional[str]:
    """
    Get the handshake directory path.
    
    Returns:
        str: Path to the handshake directory, or None if not found
    """
    project_root = get_project_root()
    if project_root:
        hs_dir = os.path.join(project_root, 'hs')
        if os.path.exists(hs_dir):
            return hs_dir
        else:
            # Create the directory if it doesn't exist
            try:
                os.makedirs(hs_dir, exist_ok=True)
                return hs_dir
            except (OSError, IOError) as e:
                # Directory creation failed - return None
                logger.warning(f"Could not create handshake directory {hs_dir}: {e}")
                pass
    
    return None

def get_temp_dir() -> str:
    """
    Get a temporary directory for the application.
    
    Returns:
        str: Path to temporary directory
    """
    import tempfile
    return tempfile.gettempdir()

@handle_errors(default=None, log_errors=True)
def find_system_wordlists() -> List[str]:
    """
    Find common system wordlist locations.
    
    Returns:
        list: List of potential wordlist paths
    """
    common_paths = [
        # Kali Linux / Debian paths
        '/usr/share/wordlists',
        '/usr/share/dict',
        '/usr/share/john',
        '/usr/share/nmap/nselib/data',
        '/usr/share/dirb/wordlists',
        '/usr/share/wfuzz/wordlist',
        '/usr/share/legion/wordlists',
        '/usr/share/metasploit-framework/data/wordlists',
        '/usr/share/commix/src/txt',
        
        # Common alternative locations
        '/opt/wordlists',
        '/var/lib/wordlists',
        '/usr/local/share/wordlists',
        
        # User home directory
        os.path.expanduser('~/wordlists'),
        os.path.expanduser('~/.wordlists'),
    ]
    
    wordlist_paths = []
    for base_path in common_paths:
        if os.path.exists(base_path):
            # Look for common wordlist files
            for root, dirs, files in os.walk(base_path):
                for file in files:
                    if any(ext in file.lower() for ext in ['.txt', '.lst', '.gz']):
                        wordlist_paths.append(os.path.join(root, file))
    
    return wordlist_paths

@handle_errors(default=[], log_errors=True)
def get_dynamic_wordlist_paths() -> List[str]:
    """
    Get all available wordlist paths from system locations (excluding wifitex/wordlists).
    
    Returns:
        list: List of system wordlist paths
    """
    wordlist_paths = []
    
    # Add system wordlists only (wifitex/wordlists handled separately in wordlist_manager)
    system_wordlists = find_system_wordlists()
    if system_wordlists:
        wordlist_paths.extend(system_wordlists)
    
    return wordlist_paths

@handle_errors(default=None, log_errors=True)
def get_user_home_directory() -> Optional[str]:
    """
    Get the current user's home directory dynamically.
    
    Returns:
        str: Path to user's home directory, or None if not found
    """
    try:
        import os
        import pwd
        
        # Method 1: Use os.path.expanduser
        home_dir = os.path.expanduser("~")
        if os.path.exists(home_dir):
            return home_dir
        
        # Method 2: Use pwd module
        try:
            user_info = pwd.getpwuid(os.getuid())
            if user_info and os.path.exists(user_info.pw_dir):
                return user_info.pw_dir
        except (KeyError, AttributeError):
            pass
        
        # Method 3: Use environment variables
        home_env = os.environ.get('HOME')
        if home_env and os.path.exists(home_env):
            return home_env
            
    except Exception as e:
        logger.warning(f"Could not determine user home directory: {e}")
    
    return None

@handle_errors(default=None, log_errors=True)
def get_desktop_directory() -> Optional[str]:
    """
    Get the user's desktop directory dynamically.
    
    Returns:
        str: Path to desktop directory, or None if not found
    """
    try:
        home_dir = get_user_home_directory()
        if not home_dir:
            return None
        
        # Common desktop directory names
        desktop_names = ['Desktop', 'desktop', 'DESKTOP']
        
        for desktop_name in desktop_names:
            desktop_path = os.path.join(home_dir, desktop_name)
            if os.path.exists(desktop_path) and os.path.isdir(desktop_path):
                return desktop_path
        
        # If no desktop directory exists, return the home directory
        return home_dir
        
    except Exception as e:
        logger.warning(f"Could not determine desktop directory: {e}")
    
    return None

@handle_errors(default=None, log_errors=True)
def get_system_bin_directory() -> Optional[str]:
    """
    Get the system binary directory dynamically.
    
    Returns:
        str: Path to system binary directory, or None if not found
    """
    try:
        import shutil
        
        # Common system binary directories
        bin_dirs = [
            '/usr/local/bin',
            '/usr/bin',
            '/bin',
            '/sbin',
            '/usr/sbin'
        ]
        
        for bin_dir in bin_dirs:
            if os.path.exists(bin_dir) and os.path.isdir(bin_dir):
                return bin_dir
        
        # Fallback: use which command to find a common binary
        try:
            result = shutil.which('python3')
            if result:
                return os.path.dirname(result)
        except:
            pass
            
    except Exception as e:
        logger.warning(f"Could not determine system binary directory: {e}")
    
    return None

@handle_errors(default=None, log_errors=True)
def get_system_share_directory() -> Optional[str]:
    """
    Get the system share directory dynamically.
    
    Returns:
        str: Path to system share directory, or None if not found
    """
    try:
        # Common system share directories
        share_dirs = [
            '/usr/share',
            '/usr/local/share',
            '/var/lib',
            '/opt'
        ]
        
        for share_dir in share_dirs:
            if os.path.exists(share_dir) and os.path.isdir(share_dir):
                return share_dir
                
    except Exception as e:
        logger.warning(f"Could not determine system share directory: {e}")
    
    return None

@handle_errors(default=None, log_errors=True)
def get_sysfs_net_path() -> Optional[str]:
    """
    Get the sysfs network interface path dynamically.
    
    Returns:
        str: Path to sysfs network interfaces, or None if not found
    """
    try:
        sysfs_paths = [
            '/sys/class/net',
            '/sys/devices/virtual/net',
            '/proc/sys/net'
        ]
        
        for path in sysfs_paths:
            if os.path.exists(path):
                return path
                
    except Exception as e:
        logger.warning(f"Could not determine sysfs network path: {e}")
    
    return None

@handle_errors(default=None, log_errors=True)
def get_proc_sys_path() -> Optional[str]:
    """
    Get the proc sys path dynamically.
    
    Returns:
        str: Path to proc sys, or None if not found
    """
    try:
        proc_paths = [
            '/proc/sys',
            '/sys/kernel'
        ]
        
        for path in proc_paths:
            if os.path.exists(path):
                return path
                
    except Exception as e:
        logger.warning(f"Could not determine proc sys path: {e}")
    
    return None

@handle_errors(default=None, log_errors=True)
def get_dev_path() -> Optional[str]:
    """
    Get the device directory path dynamically.
    
    Returns:
        str: Path to device directory, or None if not found
    """
    try:
        dev_paths = [
            '/dev',
            '/devices'
        ]
        
        for path in dev_paths:
            if os.path.exists(path):
                return path
                
    except Exception as e:
        logger.warning(f"Could not determine device path: {e}")
    
    return None

@handle_errors(default=None, log_errors=True)
def get_test_files_path() -> Optional[str]:
    """
    Get the test files directory path dynamically.
    
    Returns:
        str: Path to test files directory, or None if not found
    """
    try:
        project_root = get_project_root()
        if project_root:
            test_files_path = os.path.join(project_root, 'tests', 'files')
            if os.path.exists(test_files_path):
                return test_files_path
                
    except Exception as e:
        logger.warning(f"Could not determine test files path: {e}")
    
    return None

if __name__ == "__main__":
    # Test the path detection
    logger.info("🔍 Dynamic Path Detection Test")
    logger.info("=" * 40)
    
    project_root = get_project_root()
    logger.info(f"Project root: {project_root}")
    
    wordlist_path = get_wordlist_path()
    logger.info(f"Project wordlist: {wordlist_path}")
    
    handshake_dir = get_handshake_dir()
    logger.info(f"Handshake directory: {handshake_dir}")
    
    temp_dir = get_temp_dir()
    logger.info(f"Temp directory: {temp_dir}")
    
    system_wordlists = find_system_wordlists()
    logger.info(f"\nSystem wordlists found: {len(system_wordlists) if system_wordlists else 0}")
    if system_wordlists:
        for path in system_wordlists[:10]:  # Show first 10
            logger.info(f"  • {path}")
        
        if len(system_wordlists) > 10:
            logger.info(f"  ... and {len(system_wordlists) - 10} more")
    
    # Test new dynamic path functions
    user_home = get_user_home_directory()
    logger.info(f"\nUser home directory: {user_home}")
    
    desktop_dir = get_desktop_directory()
    logger.info(f"Desktop directory: {desktop_dir}")
    
    system_bin = get_system_bin_directory()
    logger.info(f"System binary directory: {system_bin}")
    
    system_share = get_system_share_directory()
    logger.info(f"System share directory: {system_share}")
    
    # Test new system path functions
    sysfs_net = get_sysfs_net_path()
    logger.info(f"\nSysfs network path: {sysfs_net}")
    
    proc_sys = get_proc_sys_path()
    logger.info(f"Proc sys path: {proc_sys}")
    
    dev_path = get_dev_path()
    logger.info(f"Device path: {dev_path}")
    
    test_files = get_test_files_path()
    logger.info(f"Test files path: {test_files}")
