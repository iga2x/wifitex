#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .wpa import AttackWPA
from .wps import AttackWPS
from .pmkid import AttackPMKID
from .karma import AttackKARMA
from ..config import Configuration
from ..util.color import Color
from ..model.target import WPSState

class AttackAll(object):

    @classmethod
    def attack_multiple(cls, targets):
        '''
        Attacks all given `targets` (list[wifitex.model.target]) until user interruption.
        Returns: Number of targets that were attacked (int)
        '''
        if any(t.wps for t in targets) and not AttackWPS.can_attack_wps():
            # Warn that WPS attacks are not available.
            Color.pl('{!} {O}Note: WPS attacks are not possible because you do not have {C}reaver{O} nor {C}bully{W}')

        attacked_targets = 0
        targets_remaining = len(targets)
        for index, target in enumerate(targets, start=1):
            attacked_targets += 1
            targets_remaining -= 1

            bssid = target.bssid
            essid = target.essid if target.essid_known else '{O}ESSID unknown{W}'

            Color.pl('\n{+} ({G}%d{W}/{G}%d{W})' % (index, len(targets)) +
                     ' Starting attacks against {C}%s{W} ({C}%s{W})' % (bssid, essid))

            should_continue = cls.attack_single(target, targets_remaining)
            if not should_continue:
                break

        return attacked_targets

    @classmethod
    def attack_single(cls, target, targets_remaining):
        '''
        Attacks a single `target` (wifitex.model.target).
        Returns: True if attacks should continue, False otherwise.
        '''

        attacks = []

        if Configuration.use_karma:
            # KARMA attack - enhanced Evil Twin with PNL capture
            if AttackKARMA.can_attack_karma():
                attacks.append(AttackKARMA())
            else:
                Color.pl('{!} {R}Error: KARMA attack not available - missing required tools{W}')
                Color.pl('{!} {O}Required: hostapd, dnsmasq, tshark{W}')

        elif Configuration.use_eviltwin:
            # INACTIVE: EvilTwin attack is kept as reference but not implemented
            # KARMA attack provides enhanced Evil Twin functionality with PNL capture
            # TODO: EvilTwin attack
            pass

        elif 'WPA' in target.encryption or 'WPA3' in target.encryption:
            # WPA/WPA2/WPA3 can have multiple attack vectors:

            # WPS - Only attack if target actually supports WPS (not available on WPA3)
            if not Configuration.use_pmkid_only and 'WPA3' not in target.encryption:
                # Check if target supports WPS before attempting WPS attacks
                if target.wps in [WPSState.UNLOCKED, WPSState.LOCKED] and AttackWPS.can_attack_wps():
                    Color.pl('{+} {C}Target supports WPS - attempting WPS attacks{W}')
                    
                    # Pixie-Dust
                    if Configuration.wps_pixie:
                        attacks.append(AttackWPS(target, pixie_dust=True))

                    # PIN attack
                    if Configuration.wps_pin:
                        attacks.append(AttackWPS(target, pixie_dust=False))
                elif target.wps == WPSState.NONE:
                    Color.pl('{!} {O}Target does not support WPS - skipping WPS attacks{W}')
                elif target.wps == WPSState.UNKNOWN:
                    Color.pl('{!} {O}WPS status unknown - attempting WPS attacks anyway{W}')
                    # For unknown WPS status, try WPS attacks but with lower priority
                    if AttackWPS.can_attack_wps():
                        if Configuration.wps_pixie:
                            attacks.append(AttackWPS(target, pixie_dust=True))
                        if Configuration.wps_pin:
                            attacks.append(AttackWPS(target, pixie_dust=False))
                else:
                    Color.pl('{!} {O}WPS attacks not available - missing reaver/bully tools{W}')
            elif 'WPA3' in target.encryption:
                Color.pl('{!} {O}WPA3 networks do not support WPS - skipping WPS attacks{W}')

            if not Configuration.wps_only:
                # PMKID - Works on WPA2 and WPA3
                attacks.append(AttackPMKID(target))

                # Handshake capture - Works on WPA, WPA2, and WPA3
                if not Configuration.use_pmkid_only:
                    attacks.append(AttackWPA(target))

        if len(attacks) == 0:
            Color.pl('{!} {R}Error: {O}Unable to attack: no attacks available')
            return True  # Keep attacking other targets (skip)

        max_attempts = len(attacks) * 2  # Allow each attack to fail once
        attempt_count = 0
        
        while len(attacks) > 0 and attempt_count < max_attempts:
            attack = attacks.pop(0)
            attempt_count += 1
            try:
                result = attack.run()
                if result:
                    break  # Attack was successful, stop other attacks.
            except Exception as e:
                Color.pexception(e)
                continue
            except KeyboardInterrupt:
                Color.pl('\n{!} {O}Interrupted{W}\n')
                answer = cls.user_wants_to_continue(targets_remaining, len(attacks))
                if answer is True:
                    continue  # Keep attacking the same target (continue)
                elif answer is None:
                    return True  # Keep attacking other targets (skip)
                else:
                    return False  # Stop all attacks (exit)

        if attack.success:
            attack.crack_result.save()

        return True  # Keep attacking other targets


    @classmethod
    def user_wants_to_continue(cls, targets_remaining, attacks_remaining=0):
        '''
        Asks user if attacks should continue onto other targets
        Returns:
            True if user wants to continue, False otherwise.
        '''
        if attacks_remaining == 0 and targets_remaining == 0:
            return  # No targets or attacksleft, drop out

        prompt_list = []
        if attacks_remaining > 0:
            prompt_list.append(Color.s('{C}%d{W} attack(s)' % attacks_remaining))
        if targets_remaining > 0:
            prompt_list.append(Color.s('{C}%d{W} target(s)' % targets_remaining))
        prompt = ' and '.join(prompt_list) + ' remain'
        Color.pl('{+} %s' % prompt)

        prompt = '{+} Do you want to'
        options = '('

        if attacks_remaining > 0:
            prompt += ' {G}continue{W} attacking,'
            options += '{G}C{W}{D}, {W}'

        if targets_remaining > 0:
            prompt += ' {O}skip{W} to the next target,'
            options += '{O}s{W}{D}, {W}'

        options += '{R}e{W})'
        prompt += ' or {R}exit{W} %s? {C}' % options

        from ..util.input import raw_input
        answer = raw_input(Color.s(prompt)).lower()

        if answer.startswith('s'):
            return None  # Skip
        elif answer.startswith('e'):
            return False  # Exit
        else:
            return True  # Continue

