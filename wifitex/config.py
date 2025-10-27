#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging

from .util.color import Color
from .tools.macchanger import Macchanger

class Configuration(object):
    ''' Stores configuration variables and functions for Wifitex. '''
    version = '2.7.0'

    initialized = False # Flag indicating config has been initialized
    temp_dir = None     # Temporary directory
    interface = None
    verbose = 0
    logger = None       # Logger instance

    @classmethod
    def initialize(cls, load_interface=True):
        '''
            Sets up default initial configuration values.
            Also sets config values based on command-line arguments.
        '''
        # TODO: categorize configuration into separate classes (under config/*.py)
        # E.g. Configuration.wps.enabled, Configuration.wps.timeout, etc

        # Only initialize this class once
        if cls.initialized:
            return
        cls.initialized = True
        
        # Setup logging
        cls.logger = logging.getLogger('wifitex.config')
        cls.logger.debug("Initializing Wifitex configuration")

        cls.verbose = 0 # Verbosity of output. Higher number means more debug info about running processes.
        cls.print_stack_traces = True

        cls.kill_conflicting_processes = False

        cls.scan_time = 0 # Time to wait before attacking all targets

        cls.tx_power = 0 # Wifi transmit power (0 is default)
        cls.interface = None
        cls.target_channel = None # User-defined channel to scan
        cls.target_essid = None # User-defined AP name
        cls.target_bssid = None # User-defined AP BSSID
        cls.ignore_essid = None # ESSIDs to ignore
        cls.clients_only = False # Only show targets that have associated clients
        cls.five_ghz = True # Scan 5Ghz channels by default
        cls.six_ghz = True # Scan 6Ghz channels (WiFi 6E) by default
        cls.seven_ghz = True # Scan 7Ghz channels (future WiFi 7) by default
        cls.show_bssids = False # Show BSSIDs in targets list
        cls.random_mac = False # Should generate a random Mac address at startup.
        cls.no_deauth = False # Deauth hidden networks & WPA handshake targets
        cls.num_deauths = 1 # Number of deauth packets to send to each target.

        # Monitor mode commands
        cls.enable_monitor = False
        cls.disable_monitor = False

        cls.encryption_filter = ['WPA', 'WPS']

        # EvilTwin variables
        cls.use_eviltwin = False
        cls.eviltwin_port = 80
        cls.eviltwin_deauth_iface = None
        cls.eviltwin_fakeap_iface = None

        # KARMA Attack variables
        cls.use_karma = False
        cls.karma_probe_timeout = 50  # Time to capture probe requests (seconds)
        cls.karma_rogue_interface = None  # Interface for rogue AP
        cls.karma_probe_interface = None  # Interface for capturing probe requests
        cls.karma_auto_connect = True  # Enable automatic victim connection
        cls.karma_capture_all_channels = False  # Capture probes from all channels
        cls.karma_min_probes = 1  # Minimum number of probe requests to capture before starting attack
        cls.karma_dns_spoofing = True  # Enable DNS spoofing for Layer 7 attacks (enabled for credential harvesting)
        cls.karma_handshake_capture = True  # Enable handshake capture (enabled by default)
        cls.karma_handshake_cracking = False  # Enable handshake cracking (disabled by default - enable only if needed)
        cls.karma_encryption = 'mixed'  # AP encryption: 'wpa', 'wpa2', 'wpa3', 'mixed', 'none' (default: 'mixed')
        
        # KARMA Client Monitoring & Data Access Settings
        cls.karma_client_monitoring = True  # Enable real-time client monitoring
        cls.karma_traffic_capture = True  # Capture all client traffic to PCAP files
        cls.karma_credential_harvesting = True  # Enable credential harvesting from traffic
        cls.karma_internet_access = True  # Allow clients internet access for realistic traffic and HTTP data capture
        cls.karma_analyze_http = True  # Analyze HTTP/HTTPS traffic for credentials
        cls.karma_analyze_dns = True  # Monitor DNS queries
        cls.karma_analyze_smb = True  # Capture SMB credentials
        
        # KARMA Attack Save Directories
        cls.karma_captures_dir = 'karma_captures'  # Main KARMA captures directory
        cls.karma_probes_dir = 'karma_captures/probes'  # Probe request captures
        cls.karma_handshakes_dir = 'karma_captures/handshakes'  # KARMA handshakes
        cls.karma_credentials_dir = 'karma_captures/credentials'  # Credential harvests
        cls.karma_traffic_dir = 'karma_captures/traffic'  # Client traffic
        cls.karma_live_monitoring_dir = 'karma_captures/live_monitoring'  # Live monitoring captures

        # WPA/WPA2/WPA3 variables

        # WPA variables
        cls.wpa_filter = False # Only attack WPA networks
        cls.wpa_deauth_timeout = 10 # Wait time between deauths
        cls.wpa_attack_timeout = 500 # Wait time before failing
        cls.wpa_handshake_dir = 'hs' # Dir to store handshakes
        cls.wpa_strip_handshake = False # Strip non-handshake packets
        cls.ignore_old_handshakes = False # Always fetch a new handshake

        # PMKID variables
        cls.use_pmkid_only = False  # Only use PMKID Capture+Crack attack
        cls.pmkid_timeout = 60  # Time to wait for PMKID capture (increased from 30)

        # Brute force attack variables
        cls.use_brute_force = False  # Enable brute force attack mode
        cls.brute_force_mode = '3'  # Attack mode: 0=dict, 3=brute, 6=hybrid dict+mask, 7=hybrid mask+dict
        cls.brute_force_mask = '?a?a?a?a?a?a?a?a'  # Default mask: 8 chars all charset
        cls.brute_force_increment = False  # Increment mask length automatically
        cls.brute_force_min_length = 8  # Minimum password length for brute force
        cls.brute_force_max_length = 12  # Maximum password length for brute force
        cls.brute_force_timeout = 3600  # Max time per brute force attempt (1 hour)
        
        # Default dictionary for cracking
        cls.cracked_file = 'cracked.txt'
        cls.wordlist = None
        # Use dynamic wordlist detection from GUI path_utils
        try:
            from .gui.path_utils import get_wordlist_path, find_system_wordlists
            cls.wordlist = get_wordlist_path()
            if not cls.wordlist:
                # Fallback to system wordlists
                system_wordlists = find_system_wordlists()
                if system_wordlists:
                    for wlist in system_wordlists:
                        if os.path.exists(wlist):
                            cls.wordlist = wlist
                            break
        except ImportError:
            # Fallback to original hardcoded paths if GUI module not available
            wordlists = [
                './wordlist-top4800-probable.txt',  # Local file (ran from cloned repo)
                '/usr/share/dict/wordlist-top4800-probable.txt',  # setup.py with prefix=/usr
                '/usr/local/share/dict/wordlist-top4800-probable.txt',  # setup.py with prefix=/usr/local
                # Other passwords found on Kali
                '/usr/share/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/passwds/phpbb.txt',
                '/usr/share/fuzzdb/wordlists-user-passwd/passwds/phpbb.txt',
                '/usr/share/wordlists/fern-wifi/common.txt'
            ]
            for wlist in wordlists:
                if os.path.exists(wlist):
                    cls.wordlist = wlist
                    break

        # Cracking tool preferences (used by GUI and CLI)
        # Auto-detect GPU and set preferences accordingly
        cls._detect_and_set_cracking_preferences()

        # WPS variables
        cls.wps_filter  = False  # Only attack WPS networks
        cls.no_wps      = False  # Do not use WPS attacks (Pixie-Dust & PIN attacks)
        cls.wps_only    = False  # ONLY use WPS attacks
        cls.use_bully   = False  # Use bully instead of reaver
        cls.wps_pixie   = True
        cls.wps_pin     = True
        cls.wps_ignore_lock = False  # Skip WPS PIN attack if AP is locked.
        cls.wps_pixie_timeout = 300      # Seconds to wait for PIN before WPS Pixie attack fails
        cls.wps_pin_timeout = 600        # Seconds to wait for PIN attack (10 minutes)
        cls.wps_fail_threshold = 100     # Max number of failures
        cls.wps_timeout_threshold = 100  # Max number of timeouts
        cls.wps_use_standalone_pixiewps = True  # Use standalone pixiewps as fallback

        # Commands
        cls.show_cracked = False
        cls.check_handshake = None
        cls.crack_handshake = False

        # Overwrite config values with arguments (if defined)
        cls.load_from_arguments()

        if load_interface:
            cls.get_monitor_mode_interface()


    @classmethod
    def get_monitor_mode_interface(cls):
        if cls.interface is None:
            # Use the same robust monitor mode handling as GUI
            cls.interface = cls._get_monitor_mode_interface_cli()
            
            if cls.random_mac and cls.interface:
                Macchanger.random()
    
    @classmethod
    def _get_monitor_mode_interface_cli(cls):
        """Get monitor mode interface using the same robust method as GUI"""
        import subprocess
        from .gui.utils import NetworkUtils, SystemUtils
        
        Color.pl('{+} {C}Detecting wireless interfaces...{W}')
        
        # Get available wireless interfaces
        interfaces = SystemUtils.get_wireless_interfaces()
        if not interfaces:
            Color.pl('{!} {R}No wireless interfaces found{W}')
            return None
        
        # Check for existing monitor mode interfaces
        monitor_interfaces = []
        for interface in interfaces:
            try:
                result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and 'Mode:Monitor' in result.stdout:
                    monitor_interfaces.append(interface)
            except:
                pass
        
        # If we have monitor interfaces, use the first one
        if monitor_interfaces:
            Color.pl('{+} {G}Found monitor interface: %s{W}' % monitor_interfaces[0])
            return monitor_interfaces[0]
        
        # No monitor interfaces found, need to enable monitor mode
        if len(interfaces) == 1:
            # Only one interface, use it
            target_interface = interfaces[0]
            Color.pl('{+} {C}Using interface: %s{W}' % target_interface)
        else:
            # Multiple interfaces, let user choose
            Color.pl('{+} {C}Multiple interfaces found:{W}')
            for i, interface in enumerate(interfaces, 1):
                Color.pl('  {G}%d{W}. {C}%s{W}' % (i, interface))
            
            while True:
                try:
                    choice = input('{+} {C}Select interface (1-%d): {W}' % len(interfaces)).strip()
                    if not choice:
                        Color.pl('{!} {R}Please enter a number{W}')
                        continue
                    choice_idx = int(choice) - 1
                    if 0 <= choice_idx < len(interfaces):
                        target_interface = interfaces[choice_idx]
                        break
                    else:
                        Color.pl('{!} {R}Invalid choice. Please select a number between 1-%d{W}' % len(interfaces))
                except ValueError:
                    Color.pl('{!} {R}Invalid input. Please enter a number{W}')
                except KeyboardInterrupt:
                    Color.pl('\n{!} {O}Interface selection cancelled{W}')
                    return None
        
        # Enable monitor mode using NetworkUtils (same as GUI)
        Color.pl('{+} {C}Enabling monitor mode on %s...{W}' % target_interface)
        
        network_utils = NetworkUtils()
        success = network_utils.enable_monitor_mode(target_interface)
        
        if success:
            Color.pl('{+} {G}Monitor mode enabled on %s{W}' % target_interface)
            return target_interface
        else:
            Color.pl('{!} {R}Failed to enable monitor mode on %s{W}' % target_interface)
            Color.pl('{!} {O}Please try manually:{W}')
            Color.pl('{!} {O}  sudo airmon-ng start %s{W}' % target_interface)
            Color.pl('{!} {O}  sudo ifconfig %s down{W}' % target_interface)
            Color.pl('{!} {O}  sudo iwconfig %s mode monitor{W}' % target_interface)
            Color.pl('{!} {O}  sudo ifconfig %s up{W}' % target_interface)
            return None

    @classmethod
    def load_from_arguments(cls):
        ''' Sets configuration values based on Argument.args object '''
        from .args import Arguments

        args = Arguments(cls).args
        cls.parse_settings_args(args)
        cls.parse_wpa_args(args)
        cls.parse_wps_args(args)
        cls.parse_pmkid_args(args)
        cls.parse_karma_args(args)
        cls.parse_encryption()

        # Note: EvilTwin functionality has been replaced by KARMA attack
        # which provides enhanced Evil Twin functionality with PNL capture

        cls.validate()

        # Commands
        if args.cracked:         cls.show_cracked = True
        if args.check_handshake: cls.check_handshake = args.check_handshake
        if args.crack_handshake: cls.crack_handshake = True


    @classmethod
    def validate(cls):
        if cls.use_pmkid_only and cls.wps_only:
            Color.pl('{!} {R}Bad Configuration:{O} --pmkid and --wps-only are not compatible')
            raise RuntimeError('Unable to attack networks: --pmkid and --wps-only are not compatible together')


    @classmethod
    def parse_settings_args(cls, args):
        '''Parses basic settings/configurations from arguments.'''
        if args.random_mac:
            cls.random_mac = True
            Color.pl('{+} {C}option:{W} using {G}random mac address{W} ' +
                    'when scanning & attacking')

        if args.channel:
            cls.target_channel = args.channel
            Color.pl('{+} {C}option:{W} scanning for targets on channel ' +
                    '{G}%s{W}' % args.channel)

        if args.interface:
            cls.interface = args.interface
            Color.pl('{+} {C}option:{W} using wireless interface ' +
                    '{G}%s{W}' % args.interface)

        if args.target_bssid:
            cls.target_bssid = args.target_bssid
            Color.pl('{+} {C}option:{W} targeting BSSID ' +
                    '{G}%s{W}' % args.target_bssid)

        if args.five_ghz == True:
            cls.five_ghz = True
            Color.pl('{+} {C}option:{W} including {G}5Ghz networks{W} in scans')

        if args.show_bssids == True:
            cls.show_bssids = True
            Color.pl('{+} {C}option:{W} showing {G}bssids{W} of targets during scan')

        if args.no_deauth == True:
            cls.no_deauth = True
            Color.pl('{+} {C}option:{W} will {R}not{W} {O}deauth{W} clients ' +
                    'during scans or captures')

        if args.num_deauths and args.num_deauths > 0:
            cls.num_deauths = args.num_deauths
            Color.pl('{+} {C}option:{W} send {G}%d{W} deauth packets when deauthing' % (
                cls.num_deauths))

        if args.target_essid:
            cls.target_essid = args.target_essid
            Color.pl('{+} {C}option:{W} targeting ESSID {G}%s{W}' % args.target_essid)

        if args.ignore_essid is not None:
            cls.ignore_essid = args.ignore_essid
            Color.pl('{+} {C}option:{W} {O}ignoring ESSIDs that include {R}%s{W}' % (
                args.ignore_essid))

        if args.clients_only == True:
            cls.clients_only = True
            Color.pl('{+} {C}option:{W} {O}ignoring targets that do not have ' +
                'associated clients')

        if args.scan_time:
            cls.scan_time = args.scan_time
            Color.pl('{+} {C}option:{W} ({G}pillage{W}) attack all targets ' +
                'after {G}%d{W}s' % args.scan_time)

        if args.verbose:
            cls.verbose = args.verbose
            Color.pl('{+} {C}option:{W} verbosity level {G}%d{W}' % args.verbose)

        if args.kill_conflicting_processes:
            cls.kill_conflicting_processes = True
            Color.pl('{+} {C}option:{W} kill conflicting processes {G}enabled{W}')

        # Monitor mode commands
        if hasattr(args, 'enable_monitor') and args.enable_monitor:
            cls.enable_monitor = True
            
        if hasattr(args, 'disable_monitor') and args.disable_monitor:
            cls.disable_monitor = True


    @classmethod
    def parse_wpa_args(cls, args):
        '''Parses WPA-specific arguments'''
        if args.wpa_filter:
            cls.wpa_filter = args.wpa_filter

        if args.wordlist:
            if not os.path.exists(args.wordlist):
                cls.wordlist = None
                Color.pl('{+} {C}option:{O} wordlist {R}%s{O} was not found, wifitex will NOT attempt to crack handshakes' % args.wordlist)
            elif os.path.isfile(args.wordlist):
                cls.wordlist = args.wordlist
                Color.pl('{+} {C}option:{W} using wordlist {G}%s{W} to crack WPA handshakes' % args.wordlist)
            elif os.path.isdir(args.wordlist):
                cls.wordlist = None
                Color.pl('{+} {C}option:{O} wordlist {R}%s{O} is a directory, not a file. Wifitex will NOT attempt to crack handshakes' % args.wordlist)

        if args.wpa_deauth_timeout:
            cls.wpa_deauth_timeout = args.wpa_deauth_timeout
            Color.pl('{+} {C}option:{W} will deauth WPA clients every ' +
                    '{G}%d seconds{W}' % args.wpa_deauth_timeout)

        if args.wpa_attack_timeout:
            cls.wpa_attack_timeout = args.wpa_attack_timeout
            Color.pl('{+} {C}option:{W} will stop WPA handshake capture after ' +
                    '{G}%d seconds{W}' % args.wpa_attack_timeout)

        if args.ignore_old_handshakes:
            cls.ignore_old_handshakes = True
            Color.pl('{+} {C}option:{W} will {O}ignore{W} existing handshakes ' +
                    '(force capture)')

        if args.wpa_handshake_dir:
            cls.wpa_handshake_dir = args.wpa_handshake_dir
            Color.pl('{+} {C}option:{W} will store handshakes to ' +
                    '{G}%s{W}' % args.wpa_handshake_dir)

        if args.wpa_strip_handshake:
            cls.wpa_strip_handshake = True
            Color.pl('{+} {C}option:{W} will {G}strip{W} non-handshake packets')

        # Brute force attack arguments
        if hasattr(args, 'use_brute_force') and args.use_brute_force:
            cls.use_brute_force = True
            Color.pl('{+} {C}option:{W} using {O}brute force{W} attack mode')
        
        if hasattr(args, 'brute_force_mode') and args.brute_force_mode:
            cls.brute_force_mode = args.brute_force_mode
            Color.pl('{+} {C}option:{W} brute force mode {G}%s{W}' % args.brute_force_mode)
        
        if hasattr(args, 'brute_force_mask') and args.brute_force_mask:
            cls.brute_force_mask = args.brute_force_mask
            Color.pl('{+} {C}option:{W} brute force mask {G}%s{W}' % args.brute_force_mask)
        
        if hasattr(args, 'brute_force_timeout') and args.brute_force_timeout:
            cls.brute_force_timeout = args.brute_force_timeout
            Color.pl('{+} {C}option:{W} brute force timeout {G}%d seconds{W}' % args.brute_force_timeout)

    @classmethod
    def parse_wps_args(cls, args):
        '''Parses WPS-specific arguments'''
        if args.wps_filter:
            cls.wps_filter = args.wps_filter

        if args.wps_only:
            cls.wps_only = True
            cls.wps_filter = True  # Also only show WPS networks
            Color.pl('{+} {C}option:{W} will *only* attack WPS networks with ' +
                    '{G}WPS attacks{W} (avoids handshake and PMKID)')

        if args.no_wps:
            # No WPS attacks at all
            cls.no_wps = args.no_wps
            cls.wps_pixie = False
            cls.wps_pin = False
            Color.pl('{+} {C}option:{W} will {O}never{W} use {C}WPS attacks{W} ' +
                    '(Pixie-Dust/PIN) on targets')

        elif args.wps_pixie:
            # WPS Pixie-Dust only
            cls.wps_pixie = True
            cls.wps_pin = False
            Color.pl('{+} {C}option:{W} will {G}only{W} use {C}WPS Pixie-Dust ' +
                    'attack{W} (no {O}PIN{W}) on targets')

        elif args.wps_no_pixie:
            # WPS PIN only
            cls.wps_pixie = False
            cls.wps_pin = True
            Color.pl('{+} {C}option:{W} will {G}only{W} use {C}WPS PIN attack{W} ' +
                    '(no {O}Pixie-Dust{W}) on targets')

        if args.use_bully:
            from .tools.bully import Bully
            if not Bully.exists():
                Color.pl('{!} {R}Bully not found. Defaulting to {O}reaver{W}')
                cls.use_bully = False
            else:
                cls.use_bully = args.use_bully
                Color.pl('{+} {C}option:{W} use {C}bully{W} instead of {C}reaver{W} ' +
                        'for WPS Attacks')

        if args.wps_pixie_timeout:
            cls.wps_pixie_timeout = args.wps_pixie_timeout
            Color.pl('{+} {C}option:{W} WPS pixie-dust attack will fail after ' +
                    '{O}%d seconds{W}' % args.wps_pixie_timeout)

        if args.wps_fail_threshold:
            cls.wps_fail_threshold = args.wps_fail_threshold
            Color.pl('{+} {C}option:{W} will stop WPS attack after ' +
                    '{O}%d failures{W}' % args.wps_fail_threshold)

        if args.wps_timeout_threshold:
            cls.wps_timeout_threshold = args.wps_timeout_threshold
            Color.pl('{+} {C}option:{W} will stop WPS attack after ' +
                    '{O}%d timeouts{W}' % args.wps_timeout_threshold)

        if args.wps_ignore_lock:
            cls.wps_ignore_lock = True
            Color.pl('{+} {C}option:{W} will {O}ignore{W} WPS lock-outs')

    @classmethod
    def parse_pmkid_args(cls, args):
        if args.use_pmkid_only:
            cls.use_pmkid_only = True
            Color.pl('{+} {C}option:{W} will ONLY use {C}PMKID{W} attack on WPA networks')

        if args.pmkid_timeout:
            cls.pmkid_timeout = args.pmkid_timeout
            Color.pl('{+} {C}option:{W} will wait {G}%d seconds{W} during {C}PMKID{W} capture' % args.pmkid_timeout)

    @classmethod
    def parse_karma_args(cls, args):
        '''Parses KARMA attack-specific arguments'''
        if hasattr(args, 'use_karma') and args.use_karma:
            cls.use_karma = True
            Color.pl('{+} {C}option:{W} using {G}KARMA attack{W} (enhanced Evil Twin with PNL capture)')

        if hasattr(args, 'karma_probe_timeout') and args.karma_probe_timeout:
            cls.karma_probe_timeout = args.karma_probe_timeout
            Color.pl('{+} {C}option:{W} will capture probe requests for {G}%d seconds{W} before starting KARMA attack' % args.karma_probe_timeout)

        if hasattr(args, 'karma_rogue_interface') and args.karma_rogue_interface:
            cls.karma_rogue_interface = args.karma_rogue_interface
            Color.pl('{+} {C}option:{W} using {G}%s{W} as rogue AP interface' % args.karma_rogue_interface)

        if hasattr(args, 'karma_probe_interface') and args.karma_probe_interface:
            cls.karma_probe_interface = args.karma_probe_interface
            Color.pl('{+} {C}option:{W} using {G}%s{W} as probe capture interface' % args.karma_probe_interface)

        if hasattr(args, 'karma_min_probes') and args.karma_min_probes:
            cls.karma_min_probes = args.karma_min_probes
            Color.pl('{+} {C}option:{W} will capture minimum {G}%d probe requests{W} before starting attack' % args.karma_min_probes)

    @classmethod
    def parse_encryption(cls):
        '''Adjusts encryption filter (WPA and/or WPS)'''
        cls.encryption_filter = []
        if cls.wpa_filter: cls.encryption_filter.append('WPA')
        if cls.wps_filter: cls.encryption_filter.append('WPS')

        if len(cls.encryption_filter) == 2:
            Color.pl('{+} {C}option:{W} targeting {G}all encrypted networks{W}')
        elif len(cls.encryption_filter) == 0:
            # Default to scan all types
            cls.encryption_filter = ['WPA', 'WPS']
        else:
            Color.pl('{+} {C}option:{W} ' +
                     'targeting {G}%s-encrypted{W} networks'
                        % '/'.join(cls.encryption_filter))

    @classmethod
    def temp(cls, subfile=''):
        ''' Creates and/or returns the temporary directory '''
        if cls.temp_dir is None:
            cls.temp_dir = cls.create_temp()
        return cls.temp_dir + subfile

    @staticmethod
    def create_temp():
        ''' Creates and returns a temporary directory '''
        from tempfile import mkdtemp
        tmp = mkdtemp(prefix='wifitex')
        if not tmp.endswith(os.sep):
            tmp += os.sep
        return tmp

    @classmethod
    def _detect_and_set_cracking_preferences(cls):
        '''Auto-detect GPU availability and set cracking tool preferences'''
        try:
            from .tools.hashcat import Hashcat
            from .tools.aircrack import Aircrack
            
            # Check if hashcat is available
            hashcat_available = Hashcat.exists()
            aircrack_available = Aircrack.exists()
            
            if hashcat_available:
                # Check for GPU support
                has_gpu = Hashcat.has_gpu()
                
                if has_gpu:
                    # GPU available - prefer hashcat for speed
                    cls.prefer_hashcat = True
                    cls.prefer_aircrack = False
                    if hasattr(cls, 'logger') and cls.logger:
                        cls.logger.debug("GPU detected - preferring hashcat for faster cracking")
                else:
                    # No GPU - prefer aircrack-ng (more reliable)
                    cls.prefer_hashcat = False
                    cls.prefer_aircrack = True
                    if hasattr(cls, 'logger') and cls.logger:
                        cls.logger.debug("No GPU detected - preferring aircrack-ng")
            else:
                # Hashcat not available - use aircrack-ng
                cls.prefer_hashcat = False
                cls.prefer_aircrack = True
                if hasattr(cls, 'logger') and cls.logger:
                    cls.logger.debug("Hashcat not available - using aircrack-ng")
                
        except ImportError:
            # Fallback if tools not available
            cls.prefer_hashcat = False
            cls.prefer_aircrack = True
            if hasattr(cls, 'logger') and cls.logger:
                cls.logger.debug("Tools not available - defaulting to aircrack-ng")

    @classmethod
    def delete_temp(cls):
        ''' Remove temp files and folder '''
        if cls.temp_dir is None: return
        if os.path.exists(cls.temp_dir):
            for f in os.listdir(cls.temp_dir):
                os.remove(cls.temp_dir + f)
            os.rmdir(cls.temp_dir)


    @classmethod
    def exit_gracefully(cls, code=0):
        ''' Deletes temp and exist with the given code '''
        cls.delete_temp()
        Macchanger.reset_if_changed()
        from .tools.airmon import Airmon
        if cls.interface is not None and Airmon.base_interface is not None:
            Color.pl('{!} {O}Note:{W} Leaving interface in Monitor Mode!')
            Color.pl('{!} To disable Monitor Mode when finished: ' +
                    '{C}airmon-ng stop %s{W}' % cls.interface)

            # Stop monitor mode
            #Airmon.stop(cls.interface)
            # Bring original interface back up
            #Airmon.put_interface_up(Airmon.base_interface)

        if Airmon.killed_network_manager:
            Color.pl('{!} You can restart NetworkManager when finished ({C}service network-manager start{W})')
            #Airmon.start_network_manager()

        exit(code)

    @classmethod
    def dump(cls):
        ''' (Colorful) string representation of the configuration '''
        from .util.color import Color

        max_len = 20
        for key in cls.__dict__.keys():
            max_len = max(max_len, len(key))

        result  = Color.s('{W}%s  Value{W}\n' % 'cls Key'.ljust(max_len))
        result += Color.s('{W}%s------------------{W}\n' % ('-' * max_len))

        for (key,val) in sorted(cls.__dict__.items()):
            if key.startswith('__') or type(val) in [classmethod, staticmethod] or val is None:
                continue
            result += Color.s('{G}%s {W} {C}%s{W}\n' % (key.ljust(max_len),val))
        return result

if __name__ == '__main__':
    Configuration.initialize(False)
    print(Configuration.dump())
