#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dependency import Dependency
from ..config import Configuration
from ..util.color import Color
from ..util.process import Process
from ..tools.hashcat import HcxPcapTool

import os


class John(Dependency):
    ''' Wrapper for John program. '''
    dependency_required = False
    dependency_name = 'john'
    dependency_url = 'http://www.openwall.com/john/'


    @staticmethod
    def crack_handshake(handshake, show_command=False, wordlist=None):
        john_file = HcxPcapTool.generate_john_file(handshake, show_command=show_command)

        wordlist_path = wordlist or Configuration.wordlist
        if not wordlist_path:
            raise ValueError('No wordlist specified for john WPA attack')

        # Use `john --list=formats` to find if OpenCL or CUDA is supported.
        formats_raw = Process(['john', '--list=formats']).stdout()
        if isinstance(formats_raw, bytes):
            formats_stdout = formats_raw.decode('utf-8', errors='ignore')
        else:
            formats_stdout = formats_raw or ''
        if 'wpapsk-opencl' in formats_stdout:
            john_format = 'wpapsk-opencl'
        elif 'wpapsk-cuda' in formats_stdout:
            john_format = 'wpapsk-cuda'
        else:
            john_format = 'wpapsk'

        # Crack john file
        command = [
            'john',
            '--format=%s' % john_format,
            '--wordlist', wordlist_path,
            john_file
        ]

        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
        process = Process(command)
        process.wait()

        # Run again with --show to consistently get the password
        command = ['john', '--show', john_file]
        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
        process = Process(command)
        stdout, stderr = process.get_output()
        stdout = stdout or ''

        # Parse password (regex doesn't work for some reason)
        key = None
        if '0 password hashes cracked' not in stdout:
            for line in stdout.split('\n'):
                if handshake.capfile in line:
                    key = line.split(':')[1]
                    break

        if os.path.exists(john_file):
            os.remove(john_file)

        return key
