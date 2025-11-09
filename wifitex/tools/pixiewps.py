#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dependency import Dependency
from ..util.process import Process
from ..util.color import Color
from ..config import Configuration
import re

class Pixiewps(Dependency):
    ''' Wrapper for standalone Pixiewps tool '''
    dependency_required = False
    dependency_name = 'pixiewps'
    dependency_url = 'https://github.com/wiire/pixiewps'

    @staticmethod
    def crack_pin(pke, e_hash1, e_hash2, authkey=None, e_nonce=None, r_nonce=None, e_bssid=None):
        '''
        Attempts to crack WPS PIN using standalone pixiewps tool
        Args:
            pke: Enrollee's DH public key (from M1)
            e_hash1: Enrollee hash-1 (from M3)
            e_hash2: Enrollee hash-2 (from M3)
            authkey: Authentication session key (optional)
            e_nonce: Enrollee's nonce (optional)
            r_nonce: Registrar's nonce (optional)
            e_bssid: Enrollee's BSSID (optional)
        Returns:
            PIN if found, None otherwise
        '''
        if not Pixiewps.exists():
            return None

        cmd = ['pixiewps', '-e', pke, '-s', e_hash1, '-z', e_hash2]
        
        # Add optional parameters if available
        if authkey:
            cmd.extend(['-a', authkey])
        if e_nonce:
            cmd.extend(['-n', e_nonce])
        if r_nonce:
            cmd.extend(['-m', r_nonce])
        if e_bssid:
            cmd.extend(['-b', e_bssid])

        try:
            proc = Process(cmd)
            output = proc.stdout() or ''
            
            if Configuration.verbose > 1:
                Color.pe('\n{P} [pixiewps] %s{W}' % output)
            
            # Parse output for PIN
            pin_match = re.search(r'WPS pin:\s*(\d+)', output, re.IGNORECASE)
            if pin_match:
                return pin_match.group(1)
                
        except Exception as e:
            if Configuration.verbose > 0:
                Color.pe('\n{P} [pixiewps] Error: %s{W}' % str(e))
        
        return None

    @staticmethod
    def extract_parameters_from_reaver_output(output):
        '''
        Extracts Pixie-Dust parameters from Reaver output
        Supports multiple reaver output formats including pixiewps command lines
        Returns dict with extracted parameters or None
        '''
        params = {}
        
        # Try to extract from pixiewps command line (most reliable)
        # Example: executing pixiewps -e <pke> -s <e_hash1> -z <e_hash2> -a <authkey> -n <e_nonce> -r <r_nonce>
        # Improved pattern to handle various formats and whitespace
        pixiewps_cmd_match = re.search(r'pixiewps\s+-e\s+([a-fA-F0-9]+)\s+-s\s+([a-fA-F0-9]+)\s+-z\s+([a-fA-F0-9]+)', output, re.IGNORECASE | re.MULTILINE)
        if not pixiewps_cmd_match:
            # Try alternative format with different spacing
            pixiewps_cmd_match = re.search(r'pixiewps.*?-e\s+([a-fA-F0-9]+).*?-s\s+([a-fA-F0-9]+).*?-z\s+([a-fA-F0-9]+)', output, re.IGNORECASE | re.DOTALL)
        
        if pixiewps_cmd_match:
            params['pke'] = pixiewps_cmd_match.group(1)
            params['e_hash1'] = pixiewps_cmd_match.group(2)
            params['e_hash2'] = pixiewps_cmd_match.group(3)
            
            # Extract optional parameters from command line (improved patterns)
            authkey_match = re.search(r'-a\s+([a-fA-F0-9]+)', output, re.IGNORECASE)
            if not authkey_match:
                authkey_match = re.search(r'--authkey\s+([a-fA-F0-9]+)', output, re.IGNORECASE)
            if authkey_match:
                params['authkey'] = authkey_match.group(1)
            
            e_nonce_match = re.search(r'-n\s+([a-fA-F0-9]+)', output, re.IGNORECASE)
            if not e_nonce_match:
                e_nonce_match = re.search(r'--e-nonce\s+([a-fA-F0-9]+)', output, re.IGNORECASE)
            if e_nonce_match:
                params['e_nonce'] = e_nonce_match.group(1)
            
            r_nonce_match = re.search(r'-r\s+([a-fA-F0-9]+)', output, re.IGNORECASE)
            if not r_nonce_match:
                r_nonce_match = re.search(r'--r-nonce\s+([a-fA-F0-9]+)', output, re.IGNORECASE)
            if not r_nonce_match:
                r_nonce_match = re.search(r'-m\s+([a-fA-F0-9]+)', output, re.IGNORECASE)  # Some versions use -m
            if r_nonce_match:
                params['r_nonce'] = r_nonce_match.group(1)
        
        # If command line extraction failed, try direct pattern matching
        if 'pke' not in params:
            # Extract PKE (Enrollee's DH public key) - try multiple formats
            pke_match = re.search(r'PKE:\s*([a-fA-F0-9]+)', output, re.IGNORECASE)
            if not pke_match:
                # Try without colon (some formats)
                pke_match = re.search(r'\[.*?\]\s*PKE\s*:\s*([a-fA-F0-9]+)', output, re.IGNORECASE)
            if not pke_match:
                # Try ES1/ES2 format (some reaver versions)
                pke_match = re.search(r'ES1:\s*([a-fA-F0-9]+)', output, re.IGNORECASE)
            if not pke_match:
                # Try [*] ES1 format
                pke_match = re.search(r'\[\*\]\s*ES1:\s*([a-fA-F0-9]+)', output, re.IGNORECASE)
            if pke_match:
                params['pke'] = pke_match.group(1)
        
        if 'e_hash1' not in params:
            # Extract E-Hash1 - try multiple formats
            e_hash1_match = re.search(r'E-?Hash1:\s*([a-fA-F0-9]+)', output, re.IGNORECASE)
            if not e_hash1_match:
                e_hash1_match = re.search(r'\[.*?\]\s*E-?Hash1\s*:\s*([a-fA-F0-9]+)', output, re.IGNORECASE)
            if not e_hash1_match:
                # Try PSK1 format (some reaver versions)
                e_hash1_match = re.search(r'PSK1:\s*([a-fA-F0-9]+)', output, re.IGNORECASE)
            if not e_hash1_match:
                # Try [*] PSK1 format
                e_hash1_match = re.search(r'\[\*\]\s*PSK1:\s*([a-fA-F0-9]+)', output, re.IGNORECASE)
            if e_hash1_match:
                params['e_hash1'] = e_hash1_match.group(1)
        
        if 'e_hash2' not in params:
            # Extract E-Hash2 - try multiple formats
            e_hash2_match = re.search(r'E-?Hash2:\s*([a-fA-F0-9]+)', output, re.IGNORECASE)
            if not e_hash2_match:
                e_hash2_match = re.search(r'\[.*?\]\s*E-?Hash2\s*:\s*([a-fA-F0-9]+)', output, re.IGNORECASE)
            if not e_hash2_match:
                # Try PSK2 format (some reaver versions)
                e_hash2_match = re.search(r'PSK2:\s*([a-fA-F0-9]+)', output, re.IGNORECASE)
            if not e_hash2_match:
                # Try [*] PSK2 format
                e_hash2_match = re.search(r'\[\*\]\s*PSK2:\s*([a-fA-F0-9]+)', output, re.IGNORECASE)
            if e_hash2_match:
                params['e_hash2'] = e_hash2_match.group(1)
        
        # Extract optional parameters if not already found
        if 'authkey' not in params:
            authkey_match = re.search(r'AuthKey:\s*([a-fA-F0-9]+)', output, re.IGNORECASE)
            if authkey_match:
                params['authkey'] = authkey_match.group(1)
        
        if 'e_nonce' not in params:
            e_nonce_match = re.search(r'E-?Nonce:\s*([a-fA-F0-9]+)', output, re.IGNORECASE)
            if e_nonce_match:
                params['e_nonce'] = e_nonce_match.group(1)
        
        if 'r_nonce' not in params:
            r_nonce_match = re.search(r'R-?Nonce:\s*([a-fA-F0-9]+)', output, re.IGNORECASE)
            if r_nonce_match:
                params['r_nonce'] = r_nonce_match.group(1)
        
        # Extract BSSID (useful for pixiewps)
        if 'e_bssid' not in params:
            bssid_match = re.search(r'BSSID:\s*([a-fA-F0-9:]{17})', output, re.IGNORECASE)
            if not bssid_match:
                # Try extracting from --bssid flag
                bssid_match = re.search(r'--bssid\s+([a-fA-F0-9:]{17})', output, re.IGNORECASE)
            if bssid_match:
                params['e_bssid'] = bssid_match.group(1)
        
        # Return params if we have the minimum required parameters
        if 'pke' in params and 'e_hash1' in params and 'e_hash2' in params:
            return params
        
        return None

    @staticmethod
    def extract_parameters_from_bully_output(output):
        '''
        Extracts Pixie-Dust parameters from Bully output
        Returns dict with extracted parameters or None
        '''
        params = {}
        
        # Bully output format may differ, implement specific parsing
        # This is a placeholder for Bully-specific parameter extraction
        
        return None


if __name__ == '__main__':
    # Test the Pixiewps integration
    from ..config import Configuration
    Configuration.initialize(False)
    
    # Test with sample parameters
    test_params = {
        'pke': 'test_pke',
        'e_hash1': 'test_hash1', 
        'e_hash2': 'test_hash2'
    }
    
    result = Pixiewps.crack_pin(**test_params)
    print('Test result:', result)
