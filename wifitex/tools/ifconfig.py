#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
from typing import TYPE_CHECKING

from .dependency import Dependency

# Provide a stable type for checkers and a runtime binding
if TYPE_CHECKING:
    class InterfaceError(Exception):
        ...
else:
    try:
        from ..gui.error_handler import InterfaceError
    except ImportError:
        class InterfaceError(Exception):
            pass

class Ifconfig(Dependency):
    dependency_required = True
    dependency_name = 'ifconfig'
    dependency_url = 'apt-get install net-tools'

    @classmethod
    def up(cls, interface, args=[]):
        '''Put interface up'''
        from ..util.process import Process

        command = ['ifconfig', interface]
        if isinstance(args, list):
            command.extend(args)
        elif isinstance(args, str):
            command.append(args)
        command.append('up')

        pid = Process(command)
        pid.wait()
        if pid.poll() != 0:
            raise InterfaceError('Error putting interface %s up:\n%s\n%s' % (interface, pid.stdout(), pid.stderr()))


    @classmethod
    def down(cls, interface):
        '''Put interface down'''
        from ..util.process import Process

        pid = Process(['ifconfig', interface, 'down'])
        pid.wait()
        if pid.poll() != 0:
            raise InterfaceError('Error putting interface %s down:\n%s\n%s' % (interface, pid.stdout(), pid.stderr()))


    @classmethod
    def get_mac(cls, interface):
        from ..util.process import Process

        output = Process(['ifconfig', interface]).stdout()

        # Mac address separated by dashes
        mac_dash_regex = ('[a-zA-Z0-9]{2}-' * 6)[:-1]
        match = re.search(' ({})'.format(mac_dash_regex), output)
        if match:
            return match.group(1).replace('-', ':')

        # Mac address separated by colons
        mac_colon_regex = ('[a-zA-Z0-9]{2}:' * 6)[:-1]
        match = re.search(' ({})'.format(mac_colon_regex), output)
        if match:
            return match.group(1)

        raise InterfaceError('Could not find the mac address for %s' % interface)

