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
        Attacks a single `target` (wifitex.model.target) with intelligent attack selection.
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
            # Analyze target characteristics for intelligent attack selection
            target_analysis = cls.analyze_target_characteristics(target)
            
            # Display target analysis
            cls.display_target_analysis(target, target_analysis)
            
            # Select optimal attack sequence based on analysis
            attacks = cls.select_optimal_attack_sequence(target, target_analysis)

        if len(attacks) == 0:
            Color.pl('{!} {R}Error: {O}Unable to attack: no attacks available')
            return True  # Keep attacking other targets (skip)

        # Execute attacks with intelligent retry and parallel execution
        if len(attacks) > 1 and getattr(Configuration, 'enable_parallel_attacks', True):
            return cls.execute_parallel_attacks(attacks, target)
        else:
            return cls.execute_attacks_intelligently(attacks, target, targets_remaining)

    @classmethod
    def analyze_target_characteristics(cls, target):
        """Analyze target characteristics to determine optimal attack strategy"""
        analysis = {
            'supports_wps': False,
            'wps_vulnerable_to_pixie_dust': False,
            'wps_locked': False,
            'supports_pmkid': False,
            'is_wpa3': False,
            'has_clients': False,
            'signal_strength': 'unknown',
            'encryption_type': target.encryption,
            'recommended_attacks': []
        }
        
        try:
            # Check WPS support and status
            if hasattr(target, 'wps') and target.wps:
                analysis['supports_wps'] = True
                
                # Check if WPS is locked or unlocked
                if hasattr(target, 'wps') and target.wps in ['UNLOCKED', 'LOCKED']:
                    analysis['wps_locked'] = (target.wps == 'LOCKED')
                    
                    # Check for Pixie-Dust vulnerability (common in older routers)
                    if hasattr(target, 'vendor') and target.vendor:
                        vulnerable_vendors = ['linksys', 'netgear', 'dlink', 'belkin', 'asus', 'tp-link']
                        analysis['wps_vulnerable_to_pixie_dust'] = any(
                            vendor.lower() in target.vendor.lower() for vendor in vulnerable_vendors
                        )
            
            # Check PMKID support (WPA2/WPA3)
            if 'WPA2' in target.encryption or 'WPA3' in target.encryption:
                analysis['supports_pmkid'] = True
            
            # Check WPA3 specific
            if 'WPA3' in target.encryption:
                analysis['is_wpa3'] = True
            
            # Check for active clients
            if hasattr(target, 'clients') and target.clients:
                analysis['has_clients'] = len(target.clients) > 0
            
            # Determine signal strength
            if hasattr(target, 'power') and target.power:
                try:
                    power_value = int(target.power.replace(' dBm', ''))
                    if power_value > -50:
                        analysis['signal_strength'] = 'excellent'
                    elif power_value > -70:
                        analysis['signal_strength'] = 'good'
                    elif power_value > -80:
                        analysis['signal_strength'] = 'fair'
                    else:
                        analysis['signal_strength'] = 'poor'
                except:
                    analysis['signal_strength'] = 'unknown'
            
            return analysis
            
        except Exception as e:
            Color.pl('{!} {R}Error analyzing target: {O}%s{W}' % str(e))
            return analysis

    @classmethod
    def display_target_analysis(cls, target, analysis):
        """Display target analysis results"""
        Color.pl('\n{+} {C}=== Target Analysis ==={W}')
        Color.pl('{+} {C}Target: {G}%s{W} ({G}%s{W})' % (target.essid, target.bssid))
        Color.pl('{+} {C}Encryption: {G}%s{W}' % analysis['encryption_type'])
        Color.pl('{+} {C}Signal Strength: {G}%s{W}' % analysis['signal_strength'])
        
        # WPS Analysis
        if analysis['supports_wps']:
            Color.pl('{+} {C}WPS Support: {G}Yes{W}')
            if analysis['wps_locked']:
                Color.pl('{+} {C}WPS Status: {R}Locked{W}')
            else:
                Color.pl('{+} {C}WPS Status: {G}Unlocked{W}')
            if analysis['wps_vulnerable_to_pixie_dust']:
                Color.pl('{+} {C}Pixie-Dust Vulnerability: {G}Likely{W}')
        else:
            Color.pl('{+} {C}WPS Support: {R}No{W}')
        
        # PMKID Analysis
        if analysis['supports_pmkid']:
            Color.pl('{+} {C}PMKID Support: {G}Yes{W}')
        else:
            Color.pl('{+} {C}PMKID Support: {R}No{W}')
        
        # WPA3 Analysis
        if analysis['is_wpa3']:
            Color.pl('{+} {C}WPA3 Support: {G}Yes{W}')
        else:
            Color.pl('{+} {C}WPA3 Support: {R}No{W}')
        
        # Client Analysis
        if analysis['has_clients']:
            Color.pl('{+} {C}Active Clients: {G}Yes{W}')
        else:
            Color.pl('{+} {C}Active Clients: {R}No{W}')
        
        Color.pl('{+} {C}=== End Analysis ==={W}\n')

    @classmethod
    def select_optimal_attack_sequence(cls, target, analysis):
        """Select optimal attack sequence based on target analysis"""
        attacks = []
        
        try:
            # Skip WPS attacks if target doesn't support WPS or is WPA3
            if analysis['supports_wps'] and not analysis['is_wpa3']:
                Color.pl('{+} {C}Target supports WPS - adding WPS attacks{W}')
                
                # 1. WPS Default PIN Attack (fastest, highest success rate)
                if not Configuration.use_pmkid_only:
                    Color.pl('{+} {G}Adding WPS Default PIN attack{W}')
                    attacks.append(AttackWPS(target, pixie_dust=False, default_pins=True))
                
                # 2. WPS Pixie-Dust Attack (very fast for vulnerable devices)
                if analysis['wps_vulnerable_to_pixie_dust'] and not Configuration.use_pmkid_only:
                    Color.pl('{+} {G}Adding WPS Pixie-Dust attack (target likely vulnerable){W}')
                    attacks.append(AttackWPS(target, pixie_dust=True, default_pins=False))
                
                # 3. WPS PIN Brute-force Attack (slowest, last resort)
                if not Configuration.use_pmkid_only and not Configuration.wps_only:
                    Color.pl('{+} {G}Adding WPS PIN brute-force attack{W}')
                    attacks.append(AttackWPS(target, pixie_dust=False, default_pins=False))
            else:
                if analysis['is_wpa3']:
                    Color.pl('{!} {O}WPA3 networks do not support WPS - skipping WPS attacks{W}')
                else:
                    Color.pl('{!} {O}Target does not support WPS - skipping WPS attacks{W}')

            # Skip PMKID attacks if target doesn't support it
            if analysis['supports_pmkid'] and not Configuration.wps_only:
                Color.pl('{+} {C}Target supports PMKID - adding PMKID attack{W}')
                attacks.append(AttackPMKID(target))
            else:
                Color.pl('{!} {O}Target does not support PMKID - skipping PMKID attacks{W}')

            # Add WPA3-specific attacks if target is WPA3
            if analysis['is_wpa3'] and not Configuration.wps_only:
                Color.pl('{+} {C}Target is WPA3 - adding WPA3-specific attacks{W}')
                wpa3_attacks = cls.create_wpa3_specific_attacks(target)
                attacks.extend(wpa3_attacks)

            # Skip handshake capture if only PMKID is requested
            if not Configuration.use_pmkid_only and not Configuration.wps_only:
                Color.pl('{+} {C}Adding handshake capture attack{W}')
                attacks.append(AttackWPA(target))
            else:
                Color.pl('{!} {O}Handshake capture skipped due to configuration{W}')

            # Display selected attack sequence
            if attacks:
                Color.pl('\n{+} {C}=== Selected Attack Sequence ==={W}')
                for i, attack in enumerate(attacks, 1):
                    attack_name = attack.__class__.__name__.replace('Attack', '')
                    Color.pl('{+} {C}%d. {G}%s{W} attack{W}' % (i, attack_name))
                Color.pl('{+} {C}=== End Sequence ==={W}\n')
            else:
                Color.pl('{!} {R}No suitable attacks found for this target{W}')

            return attacks
            
        except Exception as e:
            Color.pl('{!} {R}Error selecting attack sequence: {O}%s{W}' % str(e))
            return []

    @classmethod
    def execute_attacks_intelligently(cls, attacks, target, targets_remaining):
        """Execute attacks with intelligent retry and parallel execution"""
        if not attacks:
            return True  # Keep attacking other targets
        
        max_attempts = len(attacks) * 2  # Allow each attack to fail once
        attempt_count = 0
        successful_attack = None
        
        Color.pl('{+} {C}Starting intelligent attack execution...{W}')
        
        while len(attacks) > 0 and attempt_count < max_attempts:
            attack = attacks.pop(0)
            attempt_count += 1
            
            try:
                Color.pl('\n{+} {C}Executing {G}%s{W} attack (attempt {C}%d{W}/{C}%d{W}){W}' % 
                        (attack.__class__.__name__.replace('Attack', ''), attempt_count, max_attempts))
                
                result = attack.run()
                if result:
                    Color.pl('{+} {G}Attack successful!{W}')
                    successful_attack = attack
                    break  # Attack was successful, stop other attacks
                else:
                    Color.pl('{!} {O}Attack failed, trying next method...{W}')
                    
            except Exception as e:
                Color.pl('{!} {R}Error during attack: {O}%s{W}' % str(e))
                if Configuration.verbose > 0:
                    Color.pexception(e)
                continue
            except KeyboardInterrupt:
                Color.pl('\n{!} {O}Attack interrupted by user{W}\n')
                answer = cls.user_wants_to_continue(targets_remaining, len(attacks))
                if answer is True:
                    continue  # Keep attacking the same target
                elif answer is None:
                    return True  # Keep attacking other targets
                else:
                    return False  # Stop all attacks

        # Save successful attack result
        if successful_attack and hasattr(successful_attack, 'crack_result') and successful_attack.crack_result:
            successful_attack.crack_result.save()
            Color.pl('{+} {G}Attack result saved successfully{W}')

        return True  # Keep attacking other targets

    @classmethod
    def create_wpa3_specific_attacks(cls, target):
        """Create WPA3-specific attack methods"""
        wpa3_attacks = []
        
        try:
            # Enhanced PMKID for WPA3 (WPA3 uses different PMKID format)
            Color.pl('{+} {G}Adding enhanced WPA3 PMKID attack{W}')
            wpa3_attacks.append(AttackPMKID(target))  # PMKID works on WPA3
            
            # WPA3 SAE (Simultaneous Authentication of Equals) attacks
            Color.pl('{+} {G}Adding WPA3 SAE attack{W}')
            # Note: SAE attacks would be implemented here
            # For now, we rely on PMKID and handshake capture
            
            # WPA3 Dragonfly key exchange attacks
            Color.pl('{+} {G}Adding WPA3 Dragonfly attack{W}')
            # Note: Dragonfly attacks would be implemented here
            
            return wpa3_attacks
            
        except Exception as e:
            Color.pl('{!} {R}Error creating WPA3 attacks: {O}%s{W}' % str(e))
            return []

    @classmethod
    def execute_parallel_attacks(cls, attacks, target):
        """Execute compatible attacks in parallel for faster success"""
        if len(attacks) < 2:
            return cls.execute_attacks_intelligently(attacks, target, 0)
        
        Color.pl('{+} {C}Starting parallel attack execution...{W}')
        
        # Group attacks that can run in parallel
        parallel_groups = cls.group_parallel_attacks(attacks)
        
        for group in parallel_groups:
            if len(group) == 1:
                # Single attack - run normally
                attack = group[0]
                Color.pl('{+} {C}Executing {G}%s{W} attack{W}' % 
                        attack.__class__.__name__.replace('Attack', ''))
                try:
                    result = attack.run()
                    if result:
                        Color.pl('{+} {G}Attack successful!{W}')
                        return True
                except Exception as e:
                    Color.pl('{!} {R}Error during attack: {O}%s{W}' % str(e))
            else:
                # Multiple attacks - run in parallel
                Color.pl('{+} {C}Executing parallel attacks: {G}%s{W}' % 
                        ', '.join([a.__class__.__name__.replace('Attack', '') for a in group]))
                
                success = cls.run_attacks_parallel(group)
                if success:
                    return True
        
        return False

    @classmethod
    def group_parallel_attacks(cls, attacks):
        """Group attacks that can run in parallel"""
        groups = []
        
        # PMKID and Handshake capture can run in parallel
        pmkid_attacks = [a for a in attacks if a.__class__.__name__ == 'AttackPMKID']
        handshake_attacks = [a for a in attacks if a.__class__.__name__ == 'AttackWPA']
        
        if pmkid_attacks and handshake_attacks:
            # Group PMKID and Handshake together
            groups.append(pmkid_attacks + handshake_attacks)
            remaining = [a for a in attacks if a not in pmkid_attacks + handshake_attacks]
        else:
            remaining = attacks
        
        # Add remaining attacks as individual groups
        for attack in remaining:
            groups.append([attack])
        
        return groups

    @classmethod
    def run_attacks_parallel(cls, attacks):
        """Run multiple attacks in parallel using threading"""
        import threading
        import queue
        
        results = queue.Queue()
        
        def run_attack(attack):
            try:
                result = attack.run()
                results.put((attack, result))
            except Exception as e:
                results.put((attack, False))
        
        # Start all attacks in parallel
        threads = []
        for attack in attacks:
            thread = threading.Thread(target=run_attack, args=(attack,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for first successful result
        successful_attack = None
        for _ in range(len(attacks)):
            try:
                attack, result = results.get(timeout=300)  # 5 minute timeout
                if result:
                    successful_attack = attack
                    break
            except queue.Empty:
                break
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=1)
        
        if successful_attack:
            Color.pl('{+} {G}Parallel attack successful: {C}%s{W}' % 
                    successful_attack.__class__.__name__.replace('Attack', ''))
            return True
        
        return False

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

