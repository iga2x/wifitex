#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time


class AttackAborted(Exception):
    '''Raised when an attack is cancelled by the user or GUI'''
    pass

class Attack(object):
    '''Contains functionality common to all attacks.'''

    target_wait = 60

    def __init__(self, target):
        self.target = target
        # Default runtime control flags so downstream attacks can safely
        # inspect or override them when invoked from the GUI.
        self.running: bool = True
        self.skip_current_attack: bool = False

    def should_abort(self) -> bool:
        return (not getattr(self, 'running', True)) or getattr(self, 'skip_current_attack', False)

    def run(self):
        raise Exception('Unimplemented method: run')

    def wait_for_target(self, airodump):
        '''Waits for target to appear in airodump.'''
        start_time = time.time()
        targets = airodump.get_targets(apply_filter=False)
        while len(targets) == 0:
            if self.should_abort():
                raise AttackAborted('Attack aborted while waiting for target')
            # Wait for target to appear in airodump.
            if int(time.time() - start_time) > Attack.target_wait:
                raise Exception('Target did not appear after %d seconds, stopping' % Attack.target_wait)
            time.sleep(1)
            targets = airodump.get_targets()
            continue

        # Ensure this target was seen by airodump
        airodump_target = None
        for t in targets:
            if t.bssid == self.target.bssid:
                airodump_target = t
                break

        if airodump_target is None:
            raise Exception(
                'Could not find target (%s) in airodump' % self.target.bssid)

        return airodump_target

