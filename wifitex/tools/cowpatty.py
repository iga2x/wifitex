#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dependency import Dependency
from ..config import Configuration
from ..util.color import Color
from ..util.process import Process
from ..tools.hashcat import HcxPcapTool

import os
import re


class Cowpatty(Dependency):
    ''' Wrapper for Cowpatty program. '''
    dependency_required = False
    dependency_name = 'cowpatty'
    dependency_url = 'https://tools.kali.org/wireless-attacks/cowpatty'


    @staticmethod
    def crack_handshake(handshake, show_command=False, wordlist=None):
        # Crack john file
        wordlist_path = wordlist or Configuration.wordlist
        if not wordlist_path:
            raise ValueError('No wordlist specified for cowpatty WPA attack')

        command = [
            'cowpatty',
            '-f', wordlist_path,
            '-r', handshake.capfile,
            '-s', handshake.essid
        ]
        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
        process = Process(command)
        stdout, stderr = process.get_output()
        if not stdout:
            return None

        key = None
        for line in stdout.split('\n'):
            if 'The PSK is "' in line:
                key = line.split('"', 1)[1][:-2]
                break

        return key
