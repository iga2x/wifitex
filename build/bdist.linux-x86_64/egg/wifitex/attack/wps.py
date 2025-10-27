#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ..model.attack import Attack
from ..util.color import Color
from ..util.process import Process
from ..config import Configuration
from ..tools.bully import Bully
from ..tools.reaver import Reaver

class AttackWPS(Attack):

    @staticmethod
    def can_attack_wps():
        '''Check if WPS attack tools are available'''
        try:
            return Reaver.exists() or Bully.exists()
        except Exception:
            return False

    def __init__(self, target, pixie_dust=False):
        super(AttackWPS, self).__init__(target)
        self.success = False
        self.crack_result = None
        self.pixie_dust = pixie_dust
        
        # Validate target has required attributes
        self.validate_target(['bssid', 'channel', 'wps'])

    def run(self):
        ''' Run all WPS-related attacks '''
        
        try:
            # Use pattack for GUI logging integration
            attack_type = "WPS Pixie-Dust" if self.pixie_dust else "WPS PIN"
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

            if not Configuration.wps_pixie and self.pixie_dust:
                Color.pl('\r{!} {O}--no-pixie{R} was given, ignoring WPS PIN Attack on ' +
                        '{O}%s{W}' % self.target.essid)
                Color.pattack(attack_type, self.target, 'WPS Attack', 'Skipped - Pixie-dust disabled')
                self.success = False
                return self.success

            if not Configuration.wps_pin and not self.pixie_dust:
                Color.pl('\r{!} {O}--no-pin{R} was given, ignoring WPS Pixie-Dust Attack ' +
                        'on {O}%s{W}' % self.target.essid)
                Color.pattack(attack_type, self.target, 'WPS Attack', 'Skipped - PIN disabled')
                self.success = False
                return self.success

            # Check if any WPS tools are available
            if not AttackWPS.can_attack_wps():
                Color.pl('\r{!} {R}No WPS attack tools available (reaver/bully not found){W}')
                Color.pattack(attack_type, self.target, 'WPS Attack', 'Failed - No tools available')
                self.success = False
                return self.success

            # Select appropriate tool and run attack
            Color.pattack(attack_type, self.target, 'WPS Attack', 'Starting attack')
            
            if not Reaver.exists() and Bully.exists():
                # Use bully if reaver isn't available
                Color.pattack(attack_type, self.target, 'WPS Attack', 'Using Bully (Reaver not available)')
                return self.run_bully()
            elif self.pixie_dust and not Reaver.is_pixiedust_supported() and Bully.exists():
                # Use bully if reaver can't do pixie-dust
                Color.pattack(attack_type, self.target, 'WPS Attack', 'Using Bully (Reaver no pixie-dust support)')
                return self.run_bully()
            elif Configuration.use_bully:
                # Use bully if asked by user
                Color.pattack(attack_type, self.target, 'WPS Attack', 'Using Bully (user preference)')
                return self.run_bully()
            elif not Reaver.exists():
                # Print error if reaver isn't found (bully not available)
                if self.pixie_dust:
                    Color.pl('\r{!} {R}Skipping WPS Pixie-Dust attack: {O}reaver{R} not found.{W}')
                    Color.pattack(attack_type, self.target, 'WPS Attack', 'Failed - Reaver not found')
                else:
                    Color.pl('\r{!} {R}Skipping WPS PIN attack: {O}reaver{R} not found.{W}')
                    Color.pattack(attack_type, self.target, 'WPS Attack', 'Failed - Reaver not found')
                self.success = False
                return self.success
            elif self.pixie_dust and not Reaver.is_pixiedust_supported():
                # Print error if reaver can't support pixie-dust (bully not available)
                Color.pl('\r{!} {R}Skipping WPS attack: {O}reaver{R} does not support {O}--pixie-dust{W}')
                self.success = False
                return self.success
            else:
                return self.run_reaver()
                
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
        if self.pixie_dust:
            return 'Pixie-Dust'
        else:
            return 'PIN'
            
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

    def stop(self):
        """Stop the WPS attack - interface method for GUI compatibility"""
        self.success = False
        # Clean up any running processes
        Process.cleanup_all_processes()

