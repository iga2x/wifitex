#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ..util.color import Color

import re
from typing import TYPE_CHECKING

# Import custom exceptions with consistent typing for static analyzers
if TYPE_CHECKING:
    from ..gui.error_handler import ValidationError as GUIValidationError
else:
    try:
        from ..gui.error_handler import ValidationError as GUIValidationError
    except ImportError:
        # Fallback for when GUI module is not available
        class GUIValidationError(Exception):
            pass

# Always expose a module-local ValidationError with a consistent type
class ValidationError(GUIValidationError):
    pass


class WPSState:
    NONE, UNLOCKED, LOCKED, UNKNOWN = range(0, 4)


class Target(object):
    '''
        Holds details for a 'Target' aka Access Point (e.g. router).
    '''

    def __init__(self, fields):
        '''
            Initializes & stores target info based on fields.
            Args:
                Fields - List of strings
                INDEX KEY             EXAMPLE
                    0 BSSID           (00:1D:D5:9B:11:00)
                    1 First time seen (2015-05-27 19:28:43)
                    2 Last time seen  (2015-05-27 19:28:46)
                    3 channel         (6)
                    4 Speed           (54)
                    5 Privacy         (WPA2)
                    6 Cipher          (CCMP TKIP)
                    7 Authentication  (PSK)
                    8 Power           (-62)
                    9 beacons         (2)
                    10 # IV           (0)
                    11 LAN IP         (0.  0.  0.  0)
                    12 ID-length      (9)
                    13 ESSID          (HOME-ABCD)
                    14 Key            ()
        '''
        self.bssid      =     fields[0].strip()
        self.channel    =     fields[3].strip()

        self.encryption =     fields[5].strip()
        if 'WPA' in self.encryption:
            self.encryption = 'WPA'
        if len(self.encryption) > 4:
            self.encryption = self.encryption[0:4].strip()

        self.power      = int(fields[8].strip())
        if self.power < 0:
            self.power += 100

        self.beacons    = int(fields[9].strip())
        self.ivs        = int(fields[10].strip())

        self.essid_known = True
        self.essid_len   = int(fields[12].strip())
        self.essid       =     fields[13]
        if self.essid == '\\x00' * self.essid_len or \
                self.essid == 'x00' * self.essid_len or \
                self.essid.strip() == '':
            # Don't display '\x00...' for hidden ESSIDs
            self.essid = None # '(%s)' % self.bssid
            self.essid_known = False

        self.wps = WPSState.UNKNOWN

        self.decloaked = False # If ESSID was hidden but we decloaked it.

        self.clients = []

        self.validate()

    def validate(self):
        ''' Checks that the target is valid. '''
        if self.channel == '-1':
            raise ValidationError('Ignoring target with Negative-One (-1) channel')

        # Skip validation for unassociated clients target
        if self.bssid == 'UNASSOCIATED':
            return

        # Filter broadcast/multicast BSSIDs, see https://github.com/iga2x/wifitex/issues/32
        bssid_broadcast = re.compile(r'^(ff:ff:ff:ff:ff:ff|00:00:00:00:00:00)$', re.IGNORECASE)
        if bssid_broadcast.match(self.bssid):
            raise ValidationError('Ignoring target with Broadcast BSSID (%s)' % self.bssid)

        bssid_multicast = re.compile(r'^(01:00:5e|01:80:c2|33:33)', re.IGNORECASE)
        if bssid_multicast.match(self.bssid):
            raise ValidationError('Ignoring target with Multicast BSSID (%s)' % self.bssid)

    def to_str(self, show_bssid=False):
        '''
            *Colored* string representation of this Target.
            Specifically formatted for the 'scanning' table view.
        '''

        max_essid_len = 24
        essid = self.essid if self.essid_known else '(%s)' % self.bssid
        # Trim ESSID (router name) if needed
        if essid and len(essid) > max_essid_len:
            essid = essid[0:max_essid_len-3] + '...'
        else:
            essid = essid.rjust(max_essid_len) if essid else '(%s)' % self.bssid

        if self.essid_known:
            # Known ESSID
            essid = Color.s('{C}%s' % essid)
        else:
            # Unknown ESSID
            essid = Color.s('{O}%s' % essid)

        # Add a '*' if we decloaked the ESSID
        decloaked_char = '*' if self.decloaked else ' '
        essid += Color.s('{P}%s' % decloaked_char)

        if show_bssid:
            bssid = Color.s('{O}%s  ' % self.bssid)
        else:
            bssid = ''

        channel_color = '{G}'
        if int(self.channel) > 14:
            channel_color = '{C}'
        channel = Color.s('%s%s' % (channel_color, str(self.channel).rjust(3)))

        encryption = self.encryption.rjust(4)
        if 'WPA' in encryption:
            encryption = Color.s('{O}%s' % encryption)

        power = '%sdb' % str(self.power).rjust(3)
        if self.power > 50:
            color ='G'
        elif self.power > 35:
            color = 'O'
        else:
            color = 'R'
        power = Color.s('{%s}%s' % (color, power))

        if self.wps == WPSState.UNLOCKED:
            wps = Color.s('{G} yes')
        elif self.wps == WPSState.NONE:
            wps = Color.s('{O}  no')
        elif self.wps == WPSState.LOCKED:
            wps = Color.s('{R}lock')
        elif self.wps == WPSState.UNKNOWN:
            wps = Color.s('{O} n/a')

        clients = '       '
        if len(self.clients) > 0:
            clients = Color.s('{G}  ' + str(len(self.clients)))

        result = '%s  %s%s  %s  %s  %s  %s' % (
                essid, bssid, channel, encryption, power, wps, clients)
        result += Color.s('{W}')
        return result


if __name__ == '__main__':
    fields = 'AA:BB:CC:DD:EE:FF,2015-05-27 19:28:44,2015-05-27 19:28:46,1,54,WPA2,CCMP TKIP,PSK,-58,2,0,0.0.0.0,9,HOME-ABCD,'.split(',')
    t = Target(fields)
    t.clients.append('asdf')
    t.clients.append('asdf')
    print(t.to_str())

