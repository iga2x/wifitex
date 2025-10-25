#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dependency import Dependency
from ..config import Configuration
from ..util.process import Process
from ..util.timer import Timer

import os, time, re, subprocess
from threading import Thread

# Local exception types for this module (avoid cross-module type aliasing issues)
class AttackError(Exception):
    pass

class InterfaceError(Exception):
    pass

class Aireplay(Thread, Dependency):
    dependency_required = True
    dependency_name = 'aireplay-ng'
    dependency_url = 'https://www.aircrack-ng.org/install.html'

    def __init__(self, target, attack_type, client_mac=None, replay_file=None):
        '''
            Starts aireplay process for deauth attacks.
            Args:
                target - Instance of Target object, AP to attack.
                attack_type - str, e.g. 'deauth'
                client_mac - MAC address of an associated client.
        '''
        super(Aireplay, self).__init__() # Init the parent Thread

        self.target = target
        self.output_file = Configuration.temp('aireplay_%s.output' % attack_type)
        self.attack_type = attack_type
        self.error = None
        self.status = None
        
        # Only support deauth attacks now
        if attack_type != 'deauth':
            raise AttackError('Only deauth attacks are supported')
            
        self.cmd = Aireplay.get_deauth_command(self.target, client_mac)
        self.pid = Process(self.cmd,
                stdout=open(self.output_file, 'a'),  # type: ignore
                stderr=subprocess.DEVNULL,
                cwd=Configuration.temp())
        self.start()

    def is_running(self):
        return self.pid.poll() is None

    def stop(self):
        ''' Stops aireplay process '''
        if hasattr(self, 'pid') and self.pid and self.pid.poll() is None:
            self.pid.interrupt()

    def get_output(self):
        ''' Returns stdout from aireplay process '''
        return self.stdout

    def run(self):
        self.stdout = ''
        while self.pid.poll() is None:
            time.sleep(0.1)
            if not os.path.exists(self.output_file): continue
            # Read output file & clear output file
            with open(self.output_file, 'r+') as fid:
                lines = fid.read()
                self.stdout += lines
                fid.seek(0)
                fid.truncate()

            if Configuration.verbose > 1 and lines.strip() != '':
                from ..util.color import Color
                Color.pl('\n{P} [?] aireplay output:\n     %s{W}' % lines.strip().replace('\n', '\n     '))

            for line in lines.split('\n'):
                line = line.replace('\r', '').strip()
                if line == '': continue
                if 'Notice: got a deauth/disassoc packet' in line:
                    self.error = 'Not associated (needs fakeauth)'

    def __del__(self):
        self.stop()

    @staticmethod
    def get_deauth_command(target, client_mac=None):
        '''
            Generates aireplay deauth command based on target
            Args:
                target      - Instance of Target object, AP to attack.
                client_mac  - MAC address of an associated client.
        '''
        # Interface is required at this point
        Configuration.initialize()
        if Configuration.interface is None:
            raise InterfaceError('Wireless interface must be defined (-i)')

        cmd = ['aireplay-ng']
        cmd.append('--ignore-negative-one')
        cmd.extend([
            '-0', '1',  # Deauthentication, 1 packet
            '-a', target.bssid
        ])
        
        if client_mac:
            cmd.extend(['-c', client_mac])
            
        cmd.append(Configuration.interface)
        return cmd

    @staticmethod
    def deauth(target_bssid, essid=None, client_mac=None, num_deauths=None, timeout=2):
        num_deauths = num_deauths or Configuration.num_deauths
        deauth_cmd = [
            'aireplay-ng',
            '-0', # Deauthentication
            str(num_deauths),
            '--ignore-negative-one',
            '-a', target_bssid, # Target AP
            '-D' # Skip AP detection
        ]
        if client_mac is not None:
            # Station-specific deauth
            deauth_cmd.extend(['-c', client_mac])
        if essid:
            deauth_cmd.extend(['-e', essid])
        deauth_cmd.append(Configuration.interface)
        proc = Process(deauth_cmd)  # type: Process
        while proc.poll() is None:
            if proc.running_time() >= timeout:
                proc.interrupt()
            time.sleep(0.2)

if __name__ == '__main__':
    # Test deauth functionality
    print("Aireplay deauth test")

