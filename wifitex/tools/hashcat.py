#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dependency import Dependency
from ..config import Configuration
from ..util.process import Process
from ..util.color import Color

import os
import subprocess
from subprocess import PIPE, DEVNULL
import sys


class Hashcat(Dependency):
    dependency_required = False
    dependency_name = 'hashcat'
    dependency_url = 'https://hashcat.net/hashcat/'

    @staticmethod
    def should_use_force():
        command = ['hashcat', '-I']
        stderr = Process(command).stderr()
        # stderr is guaranteed to be a string from Process.stderr()
        return 'No devices found/left' in str(stderr)
    
    @staticmethod
    def has_gpu():
        """Check if GPU is available for hashcat"""
        try:
            command = ['hashcat', '-I']
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                output = result.stdout
                return 'CUDA Info:' in output or 'OpenCL Info:' in output
            return False
        except Exception:
            return False
    
    @staticmethod
    def get_gpu_info():
        """Get GPU information (fast version)"""
        try:
            command = ['hashcat', '-I']
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)  # Reduced timeout
            if result.returncode == 0:
                output = result.stdout
                gpu_info = {}
                
                # Quick extraction - just check for basic info
                if 'CUDA Info:' in output:
                    # Look for GPU name in first few lines
                    lines = output.split('\n')[:20]  # Only check first 20 lines
                    for line in lines:
                        if 'Name...........:' in line and ('RTX' in line or 'GTX' in line or 'Tesla' in line):
                            gpu_info['cuda_gpu'] = line.split(':')[1].strip()
                        elif 'CUDA.Version.:' in line:
                            gpu_info['cuda_version'] = line.split(':')[1].strip()
                
                # Quick OpenCL check
                if 'OpenCL Info:' in output:
                    gpu_info['opencl_available'] = True
                    
                return gpu_info
            return {}
        except Exception:
            return {}
    
    @staticmethod
    def get_performance_info():
        """Get GPU performance information"""
        try:
            # Test WPA performance (mode 22000 - modern format)
            command = ['hashcat', '--benchmark', '-m', '22000', '--quiet']
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                output = result.stdout
                for line in output.split('\n'):
                    if 'Speed.#01' in line:
                        speed = line.split(':')[1].split('(')[0].strip()
                        return {'wpa_speed': speed}
            return {}
        except Exception:
            return {}

    @staticmethod
    def get_wordlists():
        """Get list of wordlists to try in order - auto-detect from all sources"""
        wordlists = []
        
        # Add primary wordlist first
        if Configuration.wordlist and os.path.exists(Configuration.wordlist):
            wordlists.append(Configuration.wordlist)
        
        # Auto-detect wordlists from wifitex/wordlists folder (HIGHEST PRIORITY)
        try:
            # Get wifitex package directory
            import wifitex
            wifitex_dir = os.path.dirname(os.path.abspath(wifitex.__file__))
            wifitex_wordlists = os.path.join(wifitex_dir, 'wordlists')
            
            if os.path.exists(wifitex_wordlists):
                # Scan all wordlist files
                for root, dirs, files in os.walk(wifitex_wordlists):
                    for file in files:
                        if any(ext in file.lower() for ext in ['.txt', '.lst', '.gz']):
                            wordlist_path = os.path.join(root, file)
                            if wordlist_path not in wordlists:
                                wordlists.append(wordlist_path)
        except Exception:
            pass
        
        # Add rockyou.txt if it exists
        rockyou_paths = [
            '/usr/share/wordlists/rockyou.txt',
            '/usr/share/wordlists/rockyou.txt.gz',
            './wordlists/rockyou.txt',
            'rockyou.txt'
        ]
        for path in rockyou_paths:
            if os.path.exists(path) and path not in wordlists:
                wordlists.append(path)
                break
        
        # Add other common wordlists
        additional_wordlists = [
            './wordlist-top4800-probable.txt',
            '/usr/share/dict/wordlist-top4800-probable.txt',
            '/usr/share/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/passwds/phpbb.txt',
            '/usr/share/wordlists/fern-wifi/common.txt'
        ]
        for wlist in additional_wordlists:
            if os.path.exists(wlist) and wlist not in wordlists:
                wordlists.append(wlist)
        
        return wordlists

    @staticmethod
    def crack_handshake(handshake, show_command=False):
        """Try to crack handshake using multiple wordlists"""
        # Generate hccapx (modern format)
        hccapx_file = HcxPcapTool.generate_hccapx_file(
                handshake, show_command=show_command)

        # Get list of wordlists to try
        wordlists = Hashcat.get_wordlists()
        
        key = None
        for wordlist in wordlists:
            if not os.path.exists(wordlist):
                continue
                
            if show_command:
                Color.pl('{+} {C}Trying wordlist: {G}%s{W}' % os.path.basename(wordlist))
            
            # Try cracking with this wordlist
            for additional_arg in ([], ['--show']):
                command = [
                    'hashcat',
                    '--quiet',
                    '-m', '22000',  # Modern WPA-PBKDF2-PMKID+EAPOL format
                    hccapx_file,
                    wordlist
                ]
                if Hashcat.should_use_force():
                    command.append('--force')
                command.extend(additional_arg)
                if show_command:
                    Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
                process = Process(command)
                stdout, stderr = process.get_output()
                # stdout is guaranteed to be a string from Process.get_output()
                if ':' not in str(stdout):
                    continue
                else:
                    # stdout is guaranteed to be a string from Process.get_output()
                    key = str(stdout).split(':', 5)[-1].strip()
                    break
            
            # If we found the key, stop trying other wordlists
            if key:
                if show_command:
                    Color.pl('{+} {G}Password found using %s!{W}' % os.path.basename(wordlist))
                break

        if os.path.exists(hccapx_file):
            os.remove(hccapx_file)

        return key


    @staticmethod
    def crack_pmkid(pmkid_file, verbose=False):
        '''
        Cracks a given pmkid_file using the PMKID/WPA2 attack (-m 16800)
        Returns:
            Key (str) if found; `None` if not found.
        '''

        # Run hashcat once normally, then with --show if it failed
        # To catch cases where the password is already in the pot file.
        for additional_arg in ([], ['--show']):
            command = [
                'hashcat',
                '--quiet',      # Only output the password if found.
                '-m', '16800',  # WPA-PMKID-PBKDF2
                '-a', '0',      # Wordlist attack-mode
                pmkid_file,
                Configuration.wordlist
            ]
            if Hashcat.should_use_force():
                command.append('--force')
            command.extend(additional_arg)
            if verbose and additional_arg == []:
                Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))

            # TODO: Check status of hashcat (%); it's impossible with --quiet

            hashcat_proc = Process(command)
            hashcat_proc.wait()
            stdout = hashcat_proc.stdout()

            # stdout is guaranteed to be a string from Process.stdout()
            if ':' not in str(stdout):
                # Failed
                continue
            else:
                # Cracked
                # stdout is guaranteed to be a string from Process.get_output()
                key = str(stdout).strip().split(':', 1)[1]
                return key

    @staticmethod
    def crack_handshake_brute_force(handshake, mask=None, attack_mode='3', show_command=False):
        '''
        Brute force attack using hashcat mask (-a 3).
        Modes:
            -a 3: Pure brute force with mask
            -a 6: Hybrid wordlist + mask
            -a 7: Hybrid mask + wordlist
        
        Mask patterns:
            ?l = lowercase letters (a-z)
            ?u = uppercase letters (A-Z)
            ?d = digits (0-9)
            ?s = special chars (!"#$%%&'()*+,-./:;<=>?@[\\]^_`{|}~)
            ?a = all printable ASCII (?l?u?d?s)
            ?b = all bytes (0x00-0xff)
        
        Returns: Key (str) if found; `None` if not found.
        '''
        if not Hashcat.exists():
            return None
            
        if mask is None:
            mask = Configuration.brute_force_mask
            
        # Generate hccapx (modern format)
        hccapx_file = HcxPcapTool.generate_hccapx_file(
                handshake, show_command=show_command)

        # Build command
        command = [
            'hashcat',
            '--status',           # Enable status updates
            '--status-timer=10',  # Update every 10 seconds
            '-m', '22000',  # Modern WPA-PBKDF2-PMKID+EAPOL format
            '-a', attack_mode,  # Brute force attack mode
            hccapx_file
        ]
        
        # Add mask or wordlist based on attack mode
        if attack_mode == '3':
            # Pure brute force: add mask directly
            command.append(mask)
        elif attack_mode == '6':
            # Hybrid wordlist + mask
            if not Configuration.wordlist or not os.path.exists(Configuration.wordlist):
                if show_command:
                    Color.pl('{!} {R}Error: Wordlist required for hybrid attack mode 6{W}')
                return None
            command.append(Configuration.wordlist)
            command.append(mask)
        elif attack_mode == '7':
            # Hybrid mask + wordlist
            if not Configuration.wordlist or not os.path.exists(Configuration.wordlist):
                if show_command:
                    Color.pl('{!} {R}Error: Wordlist required for hybrid attack mode 7{W}')
                return None
            command.append(mask)
            command.append(Configuration.wordlist)
        
        if Hashcat.should_use_force():
            command.append('--force')
            
        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
            
        # Create process with stderr=sys.stderr to show real-time progress
        process = Process(command, stdout=PIPE, stderr=sys.stderr)  # type: ignore[arg-type]
        stdout, stderr = process.get_output()
        
        key = None
        if ':' in str(stdout):
            key = str(stdout).split(':', 5)[-1].strip()
            
        if os.path.exists(hccapx_file):
            os.remove(hccapx_file)
            
        return key

    @staticmethod
    def crack_pmkid_brute_force(pmkid_file, mask=None, attack_mode='3', verbose=False):
        '''
        Brute force attack on PMKID using hashcat mask (-a 3, 6, or 7).
        Returns: Key (str) if found; `None` if not found.
        '''
        if mask is None:
            mask = Configuration.brute_force_mask
            
        # Build command
        command = [
            'hashcat',
            '--status',           # Enable status updates
            '--status-timer=10',  # Update every 10 seconds
            '-m', '16800',  # WPA-PMKID-PBKDF2
            '-a', attack_mode,
            pmkid_file
        ]
        
        # Add mask or wordlist based on attack mode
        if attack_mode == '3':
            command.append(mask)
        elif attack_mode == '6':
            if not Configuration.wordlist or not os.path.exists(Configuration.wordlist):
                if verbose:
                    Color.pl('{!} {R}Error: Wordlist required for hybrid attack mode 6{W}')
                return None
            command.append(Configuration.wordlist)
            command.append(mask)
        elif attack_mode == '7':
            if not Configuration.wordlist or not os.path.exists(Configuration.wordlist):
                if verbose:
                    Color.pl('{!} {R}Error: Wordlist required for hybrid attack mode 7{W}')
                return None
            command.append(mask)
            command.append(Configuration.wordlist)
        
        if Hashcat.should_use_force():
            command.append('--force')
            
        if verbose:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
            
        # Create process with stderr=sys.stderr to show real-time progress  
        hashcat_proc = Process(command, stdout=PIPE, stderr=sys.stderr)  # type: ignore[arg-type]
        hashcat_proc.wait()
        stdout = hashcat_proc.stdout()
        
        # stdout is guaranteed to be a string from Process.stdout()
        if ':' not in str(stdout):
            return None
        else:
            key = str(stdout).strip().split(':', 1)[1]
            return key

    @staticmethod
    def generate_mask_from_length(length, charset='?a'):
        '''
        Generate a hashcat mask pattern from length.
        Args:
            length: Password length
            charset: Charset to use (default ?a = all printable ASCII)
        Returns:
            Mask pattern string (e.g., ?a?a?a?a?a for length 5)
        '''
        return ''.join([charset] * length)


class HcxDumpTool(Dependency):
    dependency_required = False
    dependency_name = 'hcxdumptool'
    dependency_url = 'https://github.com/ZerBea/hcxdumptool'

    def __init__(self, target, pcapng_file):
        # Create filterlist
        filterlist = Configuration.temp('pmkid.filterlist')
        with open(filterlist, 'w') as filter_handle:
            filter_handle.write(target.bssid.replace(':', ''))

        if os.path.exists(pcapng_file):
            os.remove(pcapng_file)

        command = [
            'hcxdumptool',
            '-i', Configuration.interface,
            '--filterlist', filterlist,
            '--filtermode', '2',
            '-c', str(target.channel),
            '-o', pcapng_file
        ]

        self.proc = Process(command)

    def poll(self):
        return self.proc.poll()

    def interrupt(self):
        self.proc.interrupt()


class HcxPcapTool(Dependency):
    dependency_required = False
    dependency_name = 'hcxpcapngtool'
    dependency_url = 'https://github.com/ZerBea/hcxtools'

    def __init__(self, target):
        self.target = target
        self.bssid = self.target.bssid.lower().replace(':', '')
        self.pmkid_file = Configuration.temp('pmkid-%s.16800' % self.bssid)

    @staticmethod
    def generate_hccapx_file(handshake, show_command=False):
        hccapx_file = Configuration.temp('generated.hccapx')
        if os.path.exists(hccapx_file):
            os.remove(hccapx_file)

        command = [
            'hcxpcapngtool',
            '-o', hccapx_file,
            handshake.capfile
        ]

        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))

        process = Process(command)
        stdout, stderr = process.get_output()
        if not os.path.exists(hccapx_file):
            raise ValueError('Failed to generate .hccapx file, output: \n%s\n%s' % (
                stdout, stderr))

        return hccapx_file

    @staticmethod
    def generate_john_file(handshake, show_command=False):
        john_file = Configuration.temp('generated.john')
        if os.path.exists(john_file):
            os.remove(john_file)

        command = [
            'hcxpcapngtool',
            '-j', john_file,
            handshake.capfile
        ]

        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))

        process = Process(command)
        stdout, stderr = process.get_output()
        if not os.path.exists(john_file):
            raise ValueError('Failed to generate .john file, output: \n%s\n%s' % (
                stdout, stderr))

        return john_file

    def get_pmkid_hash(self, pcapng_file):
        if os.path.exists(self.pmkid_file):
            os.remove(self.pmkid_file)

        command = [
            'hcxpcapngtool',
            '--pmkid', self.pmkid_file,
            pcapng_file
        ]
        hcxpcap_proc = Process(command)
        hcxpcap_proc.wait()

        if not os.path.exists(self.pmkid_file):
            return None

        with open(self.pmkid_file, 'r') as f:
            output = f.read()
            # Each line looks like:
            # hash*bssid*station*essid

        # Note: The dumptool will record *anything* it finds, ignoring the filterlist.
        # Check that we got the right target (filter by BSSID)
        matching_pmkid_hash = None
        for line in output.split('\n'):
            fields = line.split('*')
            if len(fields) >= 3 and fields[1].lower() == self.bssid:
                # Found it
                matching_pmkid_hash = line
                break

        os.remove(self.pmkid_file)
        return matching_pmkid_hash
