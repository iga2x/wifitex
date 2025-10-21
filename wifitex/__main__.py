#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from .config import Configuration
except (ValueError, ImportError) as e:
    # Import custom exceptions
    try:
        from .gui.error_handler import ConfigurationError as _ConfigurationError
    except ImportError:
        # Fallback for when GUI module is not available
        _ConfigurationError = Exception
    raise _ConfigurationError('You may need to run wifitex from the root directory (which includes README.md)', e)

from .util.color import Color

import os
import sys
import logging


class Wifitex(object):

    def __init__(self):
        '''
        Initializes Wifitex. Checks for root permissions and ensures dependencies are installed.
        '''
        
        # Setup logging
        self.logger = logging.getLogger('wifitex.main')
        self.logger.info("Starting Wifitex initialization")

        self.print_banner()

        Configuration.initialize(load_interface=False)

        if os.getuid() != 0:
            self.logger.error("Wifitex must be run as root")
            Color.pl('{!} {R}error: {O}wifitex{R} must be run as {O}root{W}')
            Color.pl('{!} {R}re-run with {O}sudo{W}')
            Configuration.exit_gracefully(0)

        from .tools.dependency import Dependency
        self.logger.info("Running dependency check")
        Dependency.run_dependency_check()


    def start(self):
        '''
        Starts target-scan + attack loop, or launches utilities dpeending on user input.
        '''
        from .model.result import CrackResult
        from .model.handshake import Handshake
        from .util.crack import CrackHelper

        if Configuration.show_cracked:
            CrackResult.display()

        elif Configuration.check_handshake:
            Handshake.check()

        elif Configuration.crack_handshake:
            CrackHelper.run()

        else:
            Configuration.get_monitor_mode_interface()
            self.scan_and_attack()


    def print_banner(self):
        '''Displays ASCII art of the highest caliber.'''
        Color.pl(r' {G}  .     {GR}{D}     {W}{G}     .    {W}')
        Color.pl(r' {G}.´  ·  .{GR}{D}     {W}{G}.  ·  `.  {G}wifitex {D}%s{W}' % Configuration.version)
        Color.pl(r' {G}:  :  : {GR}{D} (¯) {W}{G} :  :  :  {W}{D}automated wireless auditor{W}')
        Color.pl(r' {G}`.  ·  `{GR}{D} /¯\ {W}{G}´  ·  .´  {C}{D}https://github.com/iga2x/wifitex{W}')
        Color.pl(r' {G}  `     {GR}{D}/¯¯¯\{W}{G}     ´    {W}')
        Color.pl('')
        
        # Show cracking tool preference
        self._show_cracking_tool_info()


    def _show_cracking_tool_info(self):
        '''Show which cracking tool is being used and why'''
        try:
            from .tools.hashcat import Hashcat
            from .tools.aircrack import Aircrack
            
            # Ensure Configuration is initialized
            Configuration.initialize(load_interface=False)
            
            if Configuration.prefer_hashcat and Hashcat.exists():
                if Hashcat.has_gpu():
                    # Get GPU info for display
                    gpu_info = Hashcat.get_gpu_info()
                    gpu_name = gpu_info.get('cuda_gpu', 'GPU')
                    Color.pl('{+} {G}Using hashcat with GPU acceleration{W} ({C}%s{W})' % gpu_name)
                else:
                    Color.pl('{+} {G}Using hashcat{W} ({O}CPU mode{W})')
            elif Configuration.prefer_aircrack and Aircrack.exists():
                Color.pl('{+} {G}Using aircrack-ng{W} ({O}CPU mode{W})')
            else:
                Color.pl('{!} {O}Warning: No preferred cracking tools available{W}')
                
        except ImportError:
            Color.pl('{!} {O}Warning: Unable to detect cracking tools{W}')
        Color.pl('')


    def scan_and_attack(self):
        '''
        1) Scans for targets, asks user to select targets
        2) Attacks each target
        '''
        from .util.scanner import Scanner
        from .attack.all import AttackAll

        Color.pl('')

        # Scan
        s = Scanner()
        targets = s.select_targets()

        # Attack
        attacked_targets = AttackAll.attack_multiple(targets)

        Color.pl('{+} Finished attacking {C}%d{W} target(s), exiting' % attacked_targets)


##############################################################


def entry_point():
    # Check if help was requested (argparse will handle it and exit)
    if len(sys.argv) > 1 and ('-h' in sys.argv or '--help' in sys.argv):
        # Let argparse handle the help and exit
        try:
            Configuration.initialize(load_interface=False)
            from .args import Arguments
            Arguments(Configuration)  # This will show help and exit
        except SystemExit:
            return  # Help was shown, exit normally
        except Exception:
            # Fallback if argparse fails
            Color.pl('{G}wifitex{W} - automated wireless auditor')
            Color.pl('Usage: wifitex [options]')
            Color.pl('Run: wifitex --help for full options')
        return
    
    # Check if GUI mode is requested
    if len(sys.argv) > 1 and '--gui' in sys.argv:
        try:
            # Import and run GUI
            from .gui.__main__ import main as gui_main
            sys.exit(gui_main())
        except ImportError as e:
            Color.pl('{!} {R}Error: GUI module not available{W}')
            Color.pl('{!} {O}Please install GUI dependencies: pip install -r requirements-gui.txt{W}')
            Color.pl('{!} {O}Or run without --gui flag for command line mode{W}')
            sys.exit(1)
        except Exception as e:
            Color.pl('{!} {R}Error starting GUI: %s{W}' % str(e))
            sys.exit(1)
    
    # Default command line mode
    try:
        wifitex = Wifitex()
        wifitex.start()
    except KeyboardInterrupt:
        Color.pl('\n{!} {O}Interrupted, Shutting down...{W}')
    except Exception as e:
        Color.pexception(e)
        Color.pl('\n{!} {R}Exiting{W}\n')

    Configuration.exit_gracefully(0)


if __name__ == '__main__':
    entry_point()
