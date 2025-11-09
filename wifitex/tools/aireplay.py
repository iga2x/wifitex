#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dependency import Dependency
from ..config import Configuration
from ..util.process import Process

import time


class Aireplay(Dependency):
    """Minimal aireplay-ng wrapper used for WPA/WPS deauthentication."""

    dependency_required = True
    dependency_name = 'aireplay-ng'
    dependency_url = 'https://www.aircrack-ng.org/install.html'

    @staticmethod
    def deauth(target_bssid, essid=None, client_mac=None, num_deauths=None, timeout=2):
        """
        Send deauthentication frames via aireplay-ng.

        Args:
            target_bssid (str): Access point BSSID.
            essid (str, optional): ESSID to include in the request.
            client_mac (str, optional): Specific client MAC to target.
            num_deauths (int, optional): Number of deauth frames to send.
            timeout (int, optional): Seconds to wait before forcibly stopping the process.
        """
        num_deauths = num_deauths or Configuration.num_deauths
        command = [
            'aireplay-ng',
            '-0',
            str(num_deauths),
            '--ignore-negative-one',
            '-a', target_bssid,
            '-D'
        ]
        if client_mac:
            command.extend(['-c', client_mac])
        if essid:
            command.extend(['-e', essid])
        command.append(Configuration.interface)

        proc = Process(command)
        while proc.poll() is None:
            if proc.running_time() >= timeout:
                proc.interrupt()
            time.sleep(0.2)

