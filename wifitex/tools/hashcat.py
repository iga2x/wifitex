#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dependency import Dependency
from ..config import Configuration
from ..util.process import Process
from ..util.color import Color

import os
import subprocess


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
    def crack_handshake(handshake, show_command=False):
        # Generate hccapx (modern format)
        hccapx_file = HcxPcapTool.generate_hccapx_file(
                handshake, show_command=show_command)

        key = None
        # Crack hccapx using modern hashcat format (22000)
        for additional_arg in ([], ['--show']):
            command = [
                'hashcat',
                '--quiet',
                '-m', '22000',  # Modern WPA-PBKDF2-PMKID+EAPOL format
                hccapx_file,
                Configuration.wordlist
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
            '-w', pcapng_file
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
            '-z', self.pmkid_file,
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
