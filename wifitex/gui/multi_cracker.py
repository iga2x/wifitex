#!/usr/bin/env python3
"""
Enhanced Multi-Wordlist Cracker for Wifitex GUI
Supports multiple wordlists, different cracking tools, and smart cracking strategies
"""

import os
import tempfile
import subprocess
import time
from typing import List, Dict, Optional, Tuple, Any
from pathlib import Path

from .wordlist_manager import wordlist_manager
from .error_handler import handle_errors, ToolError, FileError
from .logger import get_logger

logger = get_logger('multi_cracker')

class MultiWordlistCracker:
    """Enhanced cracker that supports multiple wordlists and tools"""
    
    def __init__(self):
        self.wordlist_manager = wordlist_manager
        self.available_tools = self._detect_cracking_tools()
        self.cracking_strategies = self._get_cracking_strategies()
    
    def _detect_cracking_tools(self) -> Dict[str, bool]:
        """Detect available cracking tools"""
        tools = {
            'aircrack-ng': False,
            'hashcat': False,
            'john': False,
            'cowpatty': False
        }
        
        for tool in tools:
            try:
                result = subprocess.run(['which', tool], 
                                      capture_output=True, text=True, timeout=5)
                tools[tool] = result.returncode == 0
            except:
                tools[tool] = False
        
        return tools
    
    def _get_cracking_strategies(self) -> Dict[str, Dict]:
        """Get available cracking strategies - auto-detect all wordlists"""
        # Get all detected wordlists from system and wifitex/wordlists folder
        all_wordlists = self.wordlist_manager.get_all_wordlists()
        wordlist_paths = list(all_wordlists.keys())
        
        return {
            'fast': {
                'name': 'Fast Attack',
                'description': 'Use small, fast wordlists first',
                'wordlists': wordlist_paths[:3] if len(wordlist_paths) >= 3 else wordlist_paths,  # Top 3
                'max_time_per_wordlist': 300,  # 5 minutes
                'tools': ['aircrack-ng']
            },
            'comprehensive': {
                'name': 'Comprehensive Attack',
                'description': f'Use ALL {len(wordlist_paths)} detected wordlists',
                'wordlists': wordlist_paths,  # ALL detected wordlists
                'max_time_per_wordlist': 1800,  # 30 minutes
                'tools': ['aircrack-ng', 'hashcat']
            },
            'router_focused': {
                'name': 'Router-Focused Attack',
                'description': 'Focus on router default credentials and common passwords',
                'wordlists': wordlist_paths[:5] if len(wordlist_paths) >= 5 else wordlist_paths,  # Top 5
                'max_time_per_wordlist': 600,  # 10 minutes
                'tools': ['aircrack-ng']
            },
            'custom': {
                'name': 'Custom Strategy',
                'description': 'User-defined wordlist selection',
                'wordlists': [],
                'max_time_per_wordlist': 3600,  # 60 minutes
                'tools': ['aircrack-ng', 'hashcat', 'john']
            }
        }
    
    def crack_handshake(self, handshake_file: str, strategy: str = 'fast', 
                       custom_wordlists: Optional[List[str]] = None, 
                       progress_callback=None) -> Dict[str, Any]:
        """
        Crack a handshake file using multiple wordlists
        
        Args:
            handshake_file: Path to the handshake .cap file
            strategy: Cracking strategy to use
            custom_wordlists: Custom wordlists to use (overrides strategy)
            progress_callback: Callback function for progress updates
            
        Returns:
            Dict with cracking results
        """
        if not os.path.exists(handshake_file):
            return {
                'success': False,
                'error': f'Handshake file not found: {handshake_file}',
                'cracked_password': None,
                'wordlist_used': None,
                'time_taken': 0
            }
        
        # Get wordlists to use
        if custom_wordlists:
            wordlists_to_use = custom_wordlists
            # Custom wordlists are already paths, use them directly
            wordlist_paths = custom_wordlists
        else:
            strategy_config = self.cracking_strategies.get(strategy, self.cracking_strategies['fast'])
            wordlists_to_use = strategy_config['wordlists']
            
            # If strategy provides paths directly (auto-detected), use them
            if isinstance(wordlists_to_use, list) and wordlists_to_use and os.path.exists(str(wordlists_to_use[0])):
                wordlist_paths = wordlists_to_use  # Already resolved paths
            else:
                # Otherwise resolve wordlist names to paths
                wordlist_paths = self._resolve_wordlist_paths(wordlists_to_use)
        
        if not wordlist_paths:
            return {
                'success': False,
                'error': 'No valid wordlists found',
                'cracked_password': None,
                'wordlist_used': None,
                'time_taken': 0
            }
        
        start_time = time.time()
        total_wordlists = len(wordlist_paths)
        
        # Try each wordlist
        for i, wordlist_path in enumerate(wordlist_paths):
            if progress_callback:
                progress_callback({
                    'current_wordlist': i + 1,
                    'total_wordlists': total_wordlists,
                    'wordlist_name': os.path.basename(wordlist_path),
                    'progress_percent': (i / total_wordlists) * 100,
                    'status': f'Trying wordlist {i + 1}/{total_wordlists}: {os.path.basename(wordlist_path)}'
                })
            
            # Extract gzipped wordlist if needed
            actual_wordlist_path = self.wordlist_manager.extract_gzipped_wordlist(wordlist_path)
            if not actual_wordlist_path:
                continue
            
            # Try cracking with available tools
            for tool in ['aircrack-ng', 'hashcat']:
                if not self.available_tools.get(tool, False):
                    continue
                
                result = self._crack_with_tool(handshake_file, actual_wordlist_path, tool)
                
                if result['success']:
                    # Cleanup temporary file if created
                    if actual_wordlist_path != wordlist_path:
                        try:
                            os.unlink(actual_wordlist_path)
                        except (OSError, IOError) as e:
                            # Cleanup failed - not critical
                            logger.debug(f"Could not remove temporary wordlist {actual_wordlist_path}: {e}")
                            pass
                    
                    time_taken = time.time() - start_time
                    return {
                        'success': True,
                        'cracked_password': result['password'],
                        'wordlist_used': os.path.basename(wordlist_path),
                        'tool_used': tool,
                        'time_taken': time_taken,
                        'wordlist_index': i + 1,
                        'total_wordlists': total_wordlists
                    }
            
            # Cleanup temporary file if created
            if actual_wordlist_path != wordlist_path:
                try:
                    os.unlink(actual_wordlist_path)
                except (OSError, IOError) as e:
                    # Cleanup failed - not critical
                    logger.debug(f"Could not remove temporary wordlist {actual_wordlist_path}: {e}")
                    pass
        
        time_taken = time.time() - start_time
        return {
            'success': False,
            'error': 'Password not found in any wordlist',
            'cracked_password': None,
            'wordlist_used': None,
            'time_taken': time_taken,
            'wordlists_tried': total_wordlists
        }
    
    def _resolve_wordlist_paths(self, wordlist_names: List[str]) -> List[str]:
        """Resolve wordlist names to actual file paths"""
        resolved_paths = []
        all_wordlists = self.wordlist_manager.get_all_wordlists()
        
        for name in wordlist_names:
            # Find matching wordlist
            for path, info in all_wordlists.items():
                if name.lower() in info['name'].lower():
                    resolved_paths.append(path)
                    break
        
        return resolved_paths
    
    def _crack_with_tool(self, handshake_file: str, wordlist_file: str, tool: str) -> Dict[str, Any]:
        """Crack handshake with a specific tool"""
        try:
            if tool == 'aircrack-ng':
                return self._crack_with_aircrack(handshake_file, wordlist_file)
            elif tool == 'hashcat':
                return self._crack_with_hashcat(handshake_file, wordlist_file)
            else:
                return {'success': False, 'error': f'Unknown tool: {tool}'}
        except Exception as e:
            return {'success': False, 'error': f'Error with {tool}: {str(e)}'}
    
    def _crack_with_aircrack(self, handshake_file: str, wordlist_file: str) -> Dict[str, Any]:
        """Crack using aircrack-ng"""
        try:
            # Run aircrack-ng
            cmd = [
                'aircrack-ng',
                '-w', wordlist_file,
                '-b', self._extract_bssid_from_cap(handshake_file),
                handshake_file
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Parse output for password
            if result.returncode == 0 and 'KEY FOUND!' in result.stdout:
                # Extract password from output
                password = self._extract_password_from_aircrack_output(result.stdout)
                if password:
                    return {
                        'success': True,
                        'password': password,
                        'tool': 'aircrack-ng'
                    }
            
            return {'success': False, 'error': 'Password not found'}
            
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _crack_with_hashcat(self, handshake_file: str, wordlist_file: str) -> Dict[str, Any]:
        """Crack using hashcat"""
        try:
            # Convert handshake to hashcat format
            hash_file = self._convert_to_hashcat_format(handshake_file)
            if not hash_file:
                return {'success': False, 'error': 'Failed to convert handshake'}
            
            # Run hashcat
            cmd = [
                'hashcat',
                '-m', '2500',  # WPA/WPA2 mode
                '-a', '0',     # Dictionary attack
                '--quiet',
                hash_file,
                wordlist_file
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Parse output for password
            if result.returncode == 0:
                password = self._extract_password_from_hashcat_output(result.stdout)
                if password:
                    return {
                        'success': True,
                        'password': password,
                        'tool': 'hashcat'
                    }
            
            return {'success': False, 'error': 'Password not found'}
            
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
        finally:
            # Cleanup hash file
            if 'hash_file' in locals() and hash_file is not None and os.path.exists(hash_file):
                try:
                    os.unlink(hash_file)
                except (OSError, IOError) as e:
                    # Cleanup failed - not critical
                    logger.debug(f"Could not remove hash file {hash_file}: {e}")
                    pass
    
    def _extract_bssid_from_cap(self, cap_file: str) -> str:
        """Extract BSSID from cap file using tshark"""
        try:
            cmd = ['tshark', '-r', cap_file, '-T', 'fields', '-e', 'wlan.bssid', '-c', '1']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip().split('\n')[0]
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError) as e:
            # tshark command failed - use fallback
            logger.error(f"Could not extract BSSID from {cap_file}: {e}")
            pass
        return '00:00:00:00:00:00'  # Fallback
    
    def _extract_password_from_aircrack_output(self, output: str) -> Optional[str]:
        """Extract password from aircrack-ng output"""
        lines = output.split('\n')
        for line in lines:
            if 'KEY FOUND!' in line:
                # Look for password in brackets or quotes
                import re
                # Try to find password in various formats
                patterns = [
                    r'KEY FOUND!\s*\[([^\]]+)\]',
                    r'KEY FOUND!\s*"([^"]+)"',
                    r'KEY FOUND!\s*([^\s]+)',
                ]
                for pattern in patterns:
                    match = re.search(pattern, line)
                    if match:
                        return match.group(1)
        return None
    
    def _extract_password_from_hashcat_output(self, output: str) -> Optional[str]:
        """Extract password from hashcat output"""
        lines = output.split('\n')
        for line in lines:
            if ':' in line and not line.startswith('#'):
                parts = line.split(':')
                if len(parts) >= 2:
                    return parts[-1].strip()
        return None
    
    def _convert_to_hashcat_format(self, cap_file: str) -> Optional[str]:
        """Convert cap file to hashcat format"""
        try:
            # Use cap2hccapx or similar tool
            temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hccapx')
            temp_path = temp_file.name
            temp_file.close()
            
            # Try cap2hccapx first
            cmd = ['cap2hccapx', cap_file, temp_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and os.path.exists(temp_path) and os.path.getsize(temp_path) > 0:
                return temp_path
            
            # If cap2hccapx failed, try hashcat's built-in conversion
            os.unlink(temp_path)
            return None
            
        except Exception as e:
            logger.error(f"Error converting to hashcat format: {e}")
            return None
    
    def get_available_strategies(self) -> Dict[str, Dict]:
        """Get available cracking strategies"""
        return self.cracking_strategies.copy()
    
    def get_available_tools(self) -> Dict[str, bool]:
        """Get available cracking tools"""
        return self.available_tools.copy()
    
    def create_custom_strategy(self, name: str, wordlists: List[str], 
                             max_time_per_wordlist: int = 1800) -> bool:
        """Create a custom cracking strategy"""
        try:
            self.cracking_strategies[name] = {
                'name': name,
                'description': f'Custom strategy with {len(wordlists)} wordlists',
                'wordlists': wordlists,
                'max_time_per_wordlist': max_time_per_wordlist,
                'tools': ['aircrack-ng', 'hashcat']
            }
            return True
        except Exception as e:
            logger.error(f"Error creating custom strategy: {e}")
            return False

# Global instance
multi_cracker = MultiWordlistCracker()

if __name__ == "__main__":
    # Test the multi-wordlist cracker
    cracker = MultiWordlistCracker()
    
    logger.info("Available Cracking Tools:")
    logger.info("=" * 40)
    for tool, available in cracker.get_available_tools().items():
        status = "✓" if available else "✗"
        logger.info(f"{status} {tool}")
    
    logger.info("\nAvailable Strategies:")
    logger.info("=" * 40)
    for name, strategy in cracker.get_available_strategies().items():
        logger.info(f"• {strategy['name']}: {strategy['description']}")
        logger.info(f"  Wordlists: {', '.join(strategy['wordlists'])}")
        logger.info(f"  Max time per wordlist: {strategy['max_time_per_wordlist']}s")
        logger.info("")
