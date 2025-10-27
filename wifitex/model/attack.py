#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import builtins

# Import custom exceptions
try:
    from ..gui.error_handler import TargetError as GuiTargetError
    TargetError = GuiTargetError  # type: ignore
except ImportError:
    # Fallback for when GUI module is not available
    class TargetError(Exception):
        """Target-related errors"""
        pass

class Attack(object):
    '''Contains functionality common to all attacks.'''

    target_wait = 60

    def __init__(self, target):
        self.target = target

    def run(self):
        raise NotImplementedError('Subclasses must implement run() method')

    def validate_target(self, required_attrs=None):
        '''Validates that target has required attributes'''
        if required_attrs is None:
            required_attrs = ['bssid', 'channel']
        
        for attr in required_attrs:
            if not hasattr(self.target, attr) or not getattr(self.target, attr):
                raise ValueError('Target must have a valid %s' % attr.upper())
        
        return True

    def wait_for_target(self, airodump):
        start_time = time.time()
        targets = airodump.get_targets(apply_filter=False)
        while len(targets) == 0:
            # Wait for target to appear in airodump.
            if int(time.time() - start_time) > Attack.target_wait:
                raise builtins.TimeoutError('Target did not appear after %d seconds, stopping' % Attack.target_wait)
            time.sleep(1)
            targets = airodump.get_targets(apply_filter=False)
            continue

        # Ensure this target was seen by airodump
        airodump_target = None
        for t in targets:
            if t.bssid == self.target.bssid:
                airodump_target = t
                break

        if airodump_target is None:
            raise TargetError(
                'Could not find target (%s) in airodump' % self.target.bssid)

        return airodump_target

