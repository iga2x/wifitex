#!/usr/bin/env python3
"""
Wordlist Manager for Wifitex GUI
Provides comprehensive wordlist management and multi-wordlist cracking support
"""

import os
import gzip
import tempfile
from typing import List, Dict, Optional, Tuple, cast
from pathlib import Path

from .path_utils import get_dynamic_wordlist_paths, get_project_root, get_wordlist_path
from .error_handler import handle_errors, FileError
from .logger import get_logger

logger = get_logger('wordlist_manager')

class WordlistManager:
    """Manages wordlists for password cracking"""
    
    def __init__(self):
        self.available_wordlists = {}
        self._scanned = False
    
    def scan_system_wordlists(self):
        """Scan system for available wordlists"""
        if self._scanned:
            return
        self.available_wordlists.clear()
        # Initialize with empty list
        wordlist_paths = []
        
        # FIRST: Scan wifitex/wordlists folder (default wordlists)
        try:
            # Get the path to wifitex/wordlists folder
            # The wordlists are in the same directory as this file (wifitex/gui/wordlist_manager.py)
            # So we need to go: wifitex/gui -> wifitex -> wifitex/wordlists
            wifitex_package_dir = os.path.dirname(os.path.dirname(__file__))
            wifitex_wordlists_dir = os.path.join(wifitex_package_dir, 'wordlists')
            
            if os.path.exists(wifitex_wordlists_dir) and os.path.isdir(wifitex_wordlists_dir):
                # Scan all .txt, .lst, .gz files in wifitex/wordlists folder
                for root, dirs, files in os.walk(wifitex_wordlists_dir):
                    for file in files:
                        if any(ext in file.lower() for ext in ['.txt', '.lst', '.gz']):
                            wifitex_wordlist_path = os.path.join(root, file)
                            wordlist_paths.append(wifitex_wordlist_path)  # Add to front for priority
                            logger.info(f"Detected wifitex wordlist (default): {file}")
        except Exception as e:
            logger.debug(f"Could not scan wifitex/wordlists folder: {e}")
        
        # SECOND: Add system wordlists (extra wordlists)
        system_wordlists = cast(List[str], get_dynamic_wordlist_paths() or [])
        if system_wordlists:
            wordlist_paths.extend(system_wordlists)
        
        # Add some specific common paths that might not be found by the dynamic search
        # Use dynamic system share directory detection
        from .path_utils import get_system_share_directory
        system_share = get_system_share_directory() or '/usr/share'
        
        additional_paths = [
            os.path.join(system_share, 'wordlists', 'rockyou.txt.gz'),
            os.path.join(system_share, 'wordlists', 'rockyou.txt'),
            os.path.join(system_share, 'wordlists', 'john.lst'),
            os.path.join(system_share, 'wordlists', 'nmap.lst'),
            os.path.join(system_share, 'wordlists', 'sqlmap.txt'),
            os.path.join(system_share, 'wordlists', 'wifitex.txt'),
            os.path.join(system_share, 'dirb', 'wordlists', 'common.txt'),
            os.path.join(system_share, 'wfuzz', 'wordlist', 'general', 'common.txt'),
            os.path.join(system_share, 'wfuzz', 'wordlist', 'others', 'common_pass.txt'),
            os.path.join(system_share, 'john', 'password.lst'),
            os.path.join(system_share, 'nmap', 'nselib', 'data', 'passwords.lst'),
            os.path.join(system_share, 'legion', 'wordlists', 'routers-userpass.txt'),
            os.path.join(system_share, 'legion', 'wordlists', 'ssh-password.txt'),
            os.path.join(system_share, 'metasploit-framework', 'data', 'wordlists', 'tomcat_mgr_default_pass.txt'),
            os.path.join(system_share, 'commix', 'src', 'txt', 'default_passwords.txt'),
        ]
        
        # Combine and deduplicate paths
        all_paths = list(set(wordlist_paths + additional_paths))
        
        for path in all_paths:
            if os.path.exists(path):
                wordlist_info = self._analyze_wordlist(path)
                if wordlist_info:
                    self.available_wordlists[path] = wordlist_info
        self._scanned = True

    def _ensure_scanned(self) -> None:
        if not self._scanned:
            self.scan_system_wordlists()
    
    @handle_errors(default=None, log_errors=True)
    def _analyze_wordlist(self, path: str) -> Optional[Dict]:
        """Analyze a wordlist file and return metadata"""
        try:
            # Check if it's a gzipped file
            is_gzipped = path.endswith('.gz')
            
            if is_gzipped:
                # For gzipped files, we need to decompress to count lines
                with gzip.open(path, 'rt', encoding='utf-8', errors='ignore') as f:
                    # Read first few lines to get sample
                    sample_lines = []
                    for i, line in enumerate(f):
                        if i >= 10:  # Sample first 10 lines
                            break
                        sample_lines.append(line.strip())
                    
                    # Get file size
                    file_size = os.path.getsize(path)
                    
                    # Estimate line count (rough approximation)
                    estimated_lines = file_size // 8  # Rough estimate
                    
                    return {
                        'path': path,
                        'name': os.path.basename(path).replace('.gz', ''),
                        'size': file_size,
                        'estimated_lines': estimated_lines,
                        'is_gzipped': True,
                        'sample': sample_lines[:5],
                        'description': self._get_wordlist_description(path)
                    }
            else:
                # For regular files, count actual lines
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    line_count = len(lines)
                    sample_lines = [line.strip() for line in lines[:10]]
                
                file_size = os.path.getsize(path)
                
                return {
                    'path': path,
                    'name': os.path.basename(path),
                    'size': file_size,
                    'line_count': line_count,
                    'is_gzipped': False,
                    'sample': sample_lines[:5],
                    'description': self._get_wordlist_description(path)
                }
                
        except Exception as e:
            logger.error(f"Error analyzing wordlist {path}: {e}")
            return None
    
    def _get_wordlist_description(self, path: str) -> str:
        """Get description for wordlist based on path"""
        basename = os.path.basename(path).lower()
        
        descriptions = {
            'rockyou': 'Comprehensive password list (14M+ passwords)',
            'john.lst': 'John the Ripper password list',
            'nmap.lst': 'Nmap password list',
            'sqlmap.txt': 'SQLMap wordlist',
            'wifitex.txt': 'Wifitex default wordlist',
            'common.txt': 'Common passwords list',
            'common_pass.txt': 'Common passwords',
            'password.lst': 'Password list',
            'passwords.lst': 'Passwords list',
            'routers-userpass.txt': 'Router default credentials',
            'ssh-password.txt': 'SSH passwords',
            'wordlist-top4800-probable.txt': 'Top 4800 probable passwords'
        }
        
        for key, desc in descriptions.items():
            if key in basename:
                return desc
        
        return 'Custom wordlist'
    
    def get_wordlist_info(self, path: str) -> Optional[Dict]:
        """Get information about a specific wordlist"""
        self._ensure_scanned()
        return self.available_wordlists.get(path)
    
    def get_all_wordlists(self) -> Dict[str, Dict]:
        """Get all available wordlists"""
        self._ensure_scanned()
        return self.available_wordlists.copy()
    
    def get_recommended_wordlists(self) -> List[Tuple[str, Dict]]:
        """Get recommended wordlists in order of effectiveness"""
        self._ensure_scanned()
        recommended = []
        
        # Priority order for wordlists
        priority_order = [
            'rockyou',
            'wordlist-top4800-probable',
            'common',
            'routers-userpass',
            'ssh-password',
            'john.lst',
            'nmap.lst'
        ]
        
        for priority in priority_order:
            for path, info in self.available_wordlists.items():
                if priority in info['name'].lower():
                    recommended.append((path, info))
                    break
        
        return recommended
    
    def extract_gzipped_wordlist(self, gzipped_path: str) -> Optional[str]:
        """Extract a gzipped wordlist to a temporary file"""
        try:
            if not gzipped_path.endswith('.gz'):
                return gzipped_path
            
            # Create temporary file
            temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
            temp_path = temp_file.name
            temp_file.close()
            
            # Extract gzipped content
            with gzip.open(gzipped_path, 'rt', encoding='utf-8', errors='ignore') as gz_file:
                with open(temp_path, 'w', encoding='utf-8') as out_file:
                    # Copy in chunks to handle large files
                    while True:
                        chunk = gz_file.read(8192)
                        if not chunk:
                            break
                        out_file.write(chunk)
            
            return temp_path
            
        except Exception as e:
            logger.error(f"Error extracting wordlist {gzipped_path}: {e}")
            return None
    
    def create_custom_wordlist(self, passwords: List[str], filename: Optional[str] = None) -> Optional[str]:
        """Create a custom wordlist from a list of passwords"""
        self._ensure_scanned()
        if filename is None:
            temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
            filename = temp_file.name
            temp_file.close()
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                for password in passwords:
                    f.write(f"{password}\n")
            
            # Update available wordlists
            self.available_wordlists[filename] = self._analyze_wordlist(filename)
            
            return filename
            
        except Exception as e:
            logger.error(f"Error creating custom wordlist: {e}")
            return None
    
    
    def get_wordlist_stats(self) -> Dict:
        """Get statistics about available wordlists"""
        self._ensure_scanned()
        total_wordlists = len(self.available_wordlists)
        total_size = sum(info['size'] for info in self.available_wordlists.values())
        
        # Count by type
        gzipped_count = sum(1 for info in self.available_wordlists.values() if info.get('is_gzipped', False))
        regular_count = total_wordlists - gzipped_count
        
        return {
            'total_wordlists': total_wordlists,
            'total_size_mb': total_size / (1024 * 1024),
            'gzipped_count': gzipped_count,
            'regular_count': regular_count,
            'largest_wordlist': max(self.available_wordlists.values(), key=lambda x: x['size'])['name'] if self.available_wordlists else None
        }

# Global instance
wordlist_manager = WordlistManager()

if __name__ == "__main__":
    # Test the wordlist manager
    manager = WordlistManager()
    
    logger.info("Available Wordlists:")
    logger.info("=" * 50)
    
    for path, info in manager.get_all_wordlists().items():
        logger.info(f"Name: {info['name']}")
        logger.info(f"Path: {path}")
        logger.info(f"Size: {info['size'] / (1024*1024):.1f} MB")
        if 'line_count' in info:
            logger.info(f"Lines: {info['line_count']:,}")
        else:
            logger.info(f"Estimated Lines: {info['estimated_lines']:,}")
        logger.info(f"Description: {info['description']}")
        logger.info(f"Sample: {', '.join(info['sample'][:3])}")
        logger.info("-" * 30)
    
    logger.info("\nRecommended Wordlists:")
    logger.info("=" * 50)
    
    for path, info in manager.get_recommended_wordlists():
        logger.info(f"• {info['name']} - {info['description']}")
    
    logger.info(f"\nStats: {manager.get_wordlist_stats()}")
