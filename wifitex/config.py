#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

from .util.color import Color
from .tools.macchanger import Macchanger

class Configuration(object):
    ''' Stores configuration variables and functions for Wifitex. '''
    version = '2.2.5'

    initialized = False # Flag indicating config has been initialized
    temp_dir = None     # Temporary directory
    cracked_file = os.path.join('cracked', 'cracked.txt')
    interface = None
    verbose = 0
    abort_requested = False  # Global flag for aborting long-running operations

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
        cls.five_ghz = False # Scan 5Ghz channels
        cls.six_ghz = False  # Scan 6Ghz channels
        cls.scan_band_24 = True  # Include 2.4GHz by default
        cls.scan_band_5 = False  # Include 5GHz when explicitly enabled
        cls.scan_band_6 = False  # Include 6GHz when explicitly enabled
        cls.show_bssids = False # Show BSSIDs in targets list
        cls.random_mac = False # Should generate a random Mac address at startup.
        cls.no_deauth = False # Deauth hidden networks & WPA handshake targets
        cls.num_deauths = 1 # Number of deauth packets to send to each target.

        cls.encryption_filter = ['WPA', 'WPS']

        # EvilTwin variables
        cls.use_eviltwin = False
        cls.eviltwin_port = 80
        cls.eviltwin_deauth_iface = None
        cls.eviltwin_fakeap_iface = None

        # WPA variables
        cls.wpa_filter = False # Only attack WPA networks
        cls.wpa_deauth_timeout = 15 # Wait time between deauths
        cls.wpa_attack_timeout = 500 # Wait time before failing
        cls.wpa_handshake_dir = 'hs' # Dir to store handshakes
        cls.wpa_strip_handshake = False # Strip non-handshake packets
        cls.ignore_old_handshakes = False # Always fetch a new handshake

        # PMKID variables
        cls.use_pmkid_only = False  # Only use PMKID Capture+Crack attack
        cls.pmkid_timeout = 300  # Time to wait for PMKID capture

        # Cracking tool preferences
        cls.prefer_aircrack = True   # Prefer aircrack-ng for cracking by default
        cls.prefer_hashcat = False   # Hashcat is opt-in due to GPU requirement
        cls.preferred_cracker = 'auto'  # Auto-select best cracker unless overridden
        cls.multi_wordlist = False   # Use a single primary wordlist by default
        cls.custom_wordlist_paths = []  # Additional wordlists provided by the user
        cls.use_brute_force = False  # Brute force is disabled by default
        cls.brute_force_mode = '0'   # Default to dictionary attack mode for hashcat
        cls.brute_force_mask = '?d?d?d?d?d?d?d?d'  # Default mask when brute force is enabled
        cls.brute_force_timeout = 3600  # Maximum time (seconds) to spend on brute force

        # Default dictionary for cracking
        cls.cracked_file = os.path.join('cracked', 'cracked.txt')
        cracked_dir = os.path.dirname(cls.cracked_file)
        if cracked_dir and not os.path.exists(cracked_dir):
            os.makedirs(cracked_dir, exist_ok=True)
        cls.wordlist = None
        package_wordlist_dir = os.path.join(os.path.dirname(__file__), 'wordlists')
        package_wordlist = os.path.join(package_wordlist_dir, 'wordlist-top4800-probable.txt')
        wordlists = [
            package_wordlist,  # Project packaged wordlist
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

        # WPS variables
        cls.wps_filter  = False  # Only attack WPS networks
        cls.no_wps      = False  # Do not use WPS attacks (Pixie-Dust & PIN attacks)
        cls.wps_only    = False  # ONLY use WPS attacks on non-WEP networks
        cls.use_bully   = False  # Use bully instead of reaver
        cls.wps_pixie   = True
        cls.wps_pin     = True
        cls.wps_ignore_lock = False  # Skip WPS PIN attack if AP is locked.
        cls.wps_pin_timeout = 1800       # Seconds to wait for overall WPS PIN brute force attempts
        cls.wps_pixie_timeout = 300      # Seconds to wait for PIN before WPS Pixie attack fails
        cls.wps_fail_threshold = 100     # Max number of failures
        cls.wps_timeout_threshold = 100  # Max number of timeouts
        cls.wps_pin_precheck_timeout = 45  # Seconds to wait for each suggested PIN attempt

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
            # Interface wasn't defined, select it!
            from .tools.airmon import Airmon
            cls.interface = Airmon.ask()
            if cls.random_mac:
                Macchanger.random()

    @classmethod
    def load_from_arguments(cls):
        ''' Sets configuration values based on Argument.args object '''
        from .args import Arguments

        args = Arguments(cls).args
        cls.parse_settings_args(args)
        cls.parse_wpa_args(args)
        cls.parse_wps_args(args)
        cls.parse_pmkid_args(args)
        cls.parse_encryption()

        # EvilTwin
        '''
        if args.use_eviltwin:
            cls.use_eviltwin = True
            Color.pl('{+} {C}option:{W} using {G}eviltwin attacks{W} against all targets')
        '''

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
            if hasattr(cls, 'scan_band_5'):
                cls.scan_band_5 = True
            Color.pl('{+} {C}option:{W} including {G}5Ghz networks{W} in scans')

        if getattr(args, 'six_ghz', False):
            cls.six_ghz = True
            if hasattr(cls, 'scan_band_6'):
                cls.scan_band_6 = True
            Color.pl('{+} {C}option:{W} including {G}6Ghz networks{W} in scans')

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

        preferred_cracker = getattr(args, 'cracker', None)
        if preferred_cracker is not None:
            normalized_cracker = preferred_cracker
            if preferred_cracker == 'aircrack-ng':
                normalized_cracker = 'aircrack'
            cls.preferred_cracker = normalized_cracker
            if preferred_cracker != 'auto':
                Color.pl('{+} {C}option:{W} preferring {G}%s{W} for WPA cracking' % preferred_cracker)

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

        wps_pin_timeout = getattr(args, 'wps_pin_timeout', None)
        if wps_pin_timeout is not None:
            cls.wps_pin_timeout = wps_pin_timeout
            Color.pl('{+} {C}option:{W} WPS PIN attack timeout set to ' +
                     '{O}%d seconds{W}' % wps_pin_timeout)

        wps_pixie_timeout = getattr(args, 'wps_pixie_timeout', None)
        if wps_pixie_timeout is not None:
            cls.wps_pixie_timeout = wps_pixie_timeout
            Color.pl('{+} {C}option:{W} WPS pixie-dust attack will fail after ' +
                    '{O}%d seconds{W}' % wps_pixie_timeout)

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

        precheck_timeout = getattr(args, 'wps_pin_precheck_timeout', None)
        if precheck_timeout is not None:
            cls.wps_pin_precheck_timeout = max(0, precheck_timeout)
            if cls.wps_pin_precheck_timeout == 0:
                Color.pl('{+} {C}option:{W} will {O}disable{W} suggested PIN timeout (wait indefinitely)')
            else:
                Color.pl('{+} {C}option:{W} suggested PIN attempts limited to ' +
                         '{O}%d seconds{W}' % cls.wps_pin_precheck_timeout)

    @classmethod
    def parse_pmkid_args(cls, args):
        if args.use_pmkid_only:
            cls.use_pmkid_only = True
            Color.pl('{+} {C}option:{W} will ONLY use {C}PMKID{W} attack on WPA networks')

        if args.pmkid_timeout:
            cls.pmkid_timeout = args.pmkid_timeout
            Color.pl('{+} {C}option:{W} will wait {G}%d seconds{W} during {C}PMKID{W} capture' % args.pmkid_timeout)

    @classmethod
    def parse_encryption(cls):
        '''Adjusts encryption filter (WPA and/or WPS)'''
        cls.encryption_filter = []
        if cls.wpa_filter: cls.encryption_filter.append('WPA')
        if cls.wps_filter: cls.encryption_filter.append('WPS')

        if len(cls.encryption_filter) == 0:
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
