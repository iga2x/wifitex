#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dependency import Dependency
from ..util.process import Process
from ..config import Configuration

import os
import re
from typing import Type

# Import custom exceptions with a consistent type for static checkers
try:
    from ..gui.error_handler import FileError as _FileError
except ImportError:
    _FileError = Exception  # Fallback when GUI module is not available

# Expose a name that is always a subclass of Exception for type checkers
FileError: Type[Exception] = _FileError

class Aircrack(Dependency):
    dependency_required = True
    dependency_name = 'aircrack-ng'
    dependency_url = 'https://www.aircrack-ng.org/install.html'

    def __init__(self, ivs_file=None):

        self.cracked_file = os.path.abspath(
            os.path.join(Configuration.temp(), 'wepkey.txt')
        )

        # Delete previous cracked files
        if os.path.exists(self.cracked_file):
            try:
                os.remove(self.cracked_file)
            except OSError:
                pass

        command = [
            'aircrack-ng',
            '-a', '1',
            '-l', self.cracked_file,
        ]

        # Normalize ivs_file into an iterable list (handle None, str, list, tuple)
        if ivs_file is None:
            ivs_files = []
        elif isinstance(ivs_file, (str, bytes)):
            ivs_files = [ivs_file]
        else:
            # assume iterable of paths
            ivs_files = list(ivs_file)

        if ivs_files:
            # Convert all paths to strings to ensure type consistency
            command.extend(str(path) for path in ivs_files)

        self.pid = Process(command, devnull=True)


    def is_running(self):
        return self.pid.poll() is None

    def is_cracked(self):
        return os.path.exists(self.cracked_file)

    def stop(self):
        ''' Stops aircrack process '''
        if self.pid.poll() is None:
            try:
                self.pid.interrupt()
            except Exception:
                pass

    def get_key_hex_ascii(self):
        if not self.is_cracked():
            raise FileError('Cracked file not found')

        with open(self.cracked_file, 'r') as fid:
            hex_raw = fid.read()

        return self._hex_and_ascii_key(hex_raw)

    @staticmethod
    def _hex_and_ascii_key(hex_raw):
        """
        Convert a raw hex string (possibly containing newlines or whitespace)
        into a colon-separated hex key and an ASCII key (or None if non-printable).
        """
        if hex_raw is None:
            return (None, None)

        # Remove whitespace/newlines and make sure we have even length
        hex_str = re.sub(r'\s+', '', hex_raw).strip()
        if len(hex_str) % 2 != 0:
            # drop the last nibble if odd length
            hex_str = hex_str[:-1]

        hex_chars = []
        ascii_key = ''
        for index in range(0, len(hex_str), 2):
            byt = hex_str[index:index+2]
            hex_chars.append(byt)
            try:
                byt_int = int(byt, 16)
            except ValueError:
                # invalid hex -> treat ASCII as non-printable
                ascii_key = None
                continue

            if ascii_key is not None:  # maintain None once set
                if byt_int < 32 or byt_int > 126:
                    ascii_key = None  # Not printable
                else:
                    ascii_key += chr(byt_int)

        hex_key = ':'.join(hex_chars) if hex_chars else None

        return (hex_key, ascii_key)


    def __del__(self):
        try:
            if os.path.exists(self.cracked_file):
                os.remove(self.cracked_file)
        except Exception:
            pass


    @staticmethod
    def get_wordlists():
        """Get list of wordlists to try in order - auto-detect from all sources"""
        wordlists = []
        
        # Add primary wordlist first
        if Configuration.wordlist and os.path.exists(Configuration.wordlist):
            wordlists.append(Configuration.wordlist)
        
        # Auto-detect wordlists from wifitex/wordlists folder (HIGHEST PRIORITY)
        try:
            # Get wifitex package directory
            import wifitex
            wifitex_dir = os.path.dirname(os.path.abspath(wifitex.__file__))
            wifitex_wordlists = os.path.join(wifitex_dir, 'wordlists')
            
            if os.path.exists(wifitex_wordlists):
                # Scan all wordlist files
                for root, dirs, files in os.walk(wifitex_wordlists):
                    for file in files:
                        if any(ext in file.lower() for ext in ['.txt', '.lst', '.gz']):
                            wordlist_path = os.path.join(root, file)
                            if wordlist_path not in wordlists:
                                wordlists.append(wordlist_path)
        except Exception:
            pass
        
        # Add rockyou.txt if it exists
        rockyou_paths = [
            '/usr/share/wordlists/rockyou.txt',
            '/usr/share/wordlists/rockyou.txt.gz',
            './wordlists/rockyou.txt',
            'rockyou.txt'
        ]
        for path in rockyou_paths:
            if os.path.exists(path) and path not in wordlists:
                wordlists.append(path)
                break
        
        # Add other common wordlists
        additional_wordlists = [
            'wifitex/wordlists/wordlist-top4800-probable.txt',
            '/usr/share/dict/wordlist-top4800-probable.txt',
            '/usr/share/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/passwds/phpbb.txt',
            '/usr/share/wordlists/fern-wifi/common.txt'
        ]
        for wlist in additional_wordlists:
            if os.path.exists(wlist) and wlist not in wordlists:
                wordlists.append(wlist)
        
        return wordlists

    @staticmethod
    def crack_handshake(handshake, show_command=False):
        from ..util.color import Color
        from ..util.timer import Timer
        '''Tries to crack a handshake. Returns WPA key if found, otherwise None.'''

        # Get list of wordlists to try
        wordlists = Aircrack.get_wordlists()
        
        key = None
        for wordlist in wordlists:
            if not os.path.exists(wordlist):
                continue
            
            if show_command:
                Color.pl('{+} {C}Trying wordlist: {G}%s{W}' % os.path.basename(wordlist))
            
            key_file = Configuration.temp('wpakey.txt')
            command = [
                'aircrack-ng',
                '-a', '2',
                '-w', wordlist,
                '--bssid', handshake.bssid,
                '-l', key_file,
                handshake.capfile
            ]
            if show_command:
                Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
            crack_proc = Process(command)

            # Report progress of cracking
            aircrack_nums_re = re.compile(r'(\d+)/(\d+) keys tested.*\(([\d.]+)\s+k/s', re.IGNORECASE)
            aircrack_key_re  = re.compile(r'Current passphrase:\s*([^\s].*[^\s])\s*$', re.IGNORECASE)
            num_tried = num_total = 0
            percent = num_kps = 0.0
            eta_str = 'unknown'
            current_key = ''
            try:
                while crack_proc.poll() is None:
                    # read a line (bytes), decode safely
                    try:
                        raw_line = crack_proc.stdoutln()
                        if not raw_line:
                            # process may have ended or no more output right now
                            continue
                        line = raw_line.decode('utf-8', 'ignore')
                    except Exception:
                        continue

                    match_nums = aircrack_nums_re.search(line)
                    match_keys = aircrack_key_re.search(line)
                    if match_nums:
                        try:
                            num_tried = int(match_nums.group(1))
                            num_total = int(match_nums.group(2))
                            num_kps = float(match_nums.group(3))
                        except (ValueError, ZeroDivisionError):
                            num_kps = 0.0

                        if num_kps > 0.0 and num_total >= num_tried:
                            eta_seconds = (num_total - num_tried) / num_kps
                            eta_str = Timer.secs_to_str(eta_seconds)
                            percent = 100.0 * float(num_tried) / float(num_total) if num_total > 0 else 0.0
                        else:
                            eta_str = 'unknown'
                            percent = 0.0
                    elif match_keys:
                        current_key = match_keys.group(1)
                    else:
                        continue

                    status = '\r{+} {C}Cracking WPA Handshake: %0.2f%%{W}' % percent
                    status += ' ETA: {C}%s{W}' % eta_str
                    status += ' @ {C}%0.1fkps{W}' % num_kps
                    status += ' (current key: {C}%s{W})' % current_key
                    Color.clear_entire_line()
                    Color.p(status)
            finally:
                # ensure we print a newline after progress
                Color.pl('')

            # Check crack result
            if os.path.exists(key_file):
                try:
                    with open(key_file, 'r') as fid:
                        key = fid.read().strip()
                    os.remove(key_file)
                except Exception:
                    key = None
                
                if key:
                    if show_command:
                        Color.pl('{+} {G}Password found using %s!{W}' % os.path.basename(wordlist))
                    return key
        
        return None


if __name__ == '__main__':
    (hexkey, asciikey) = Aircrack._hex_and_ascii_key('A1B1C1D1E1')
    assert hexkey == 'A1:B1:C1:D1:E1', 'hexkey was "%s", expected "A1:B1:C1:D1:E1"' % hexkey
    assert asciikey is None, 'asciikey was "%s", expected None' % asciikey

    (hexkey, asciikey) = Aircrack._hex_and_ascii_key('6162636465')
    assert hexkey == '61:62:63:64:65', 'hexkey was "%s", expected "61:62:63:64:65"' % hexkey
    assert asciikey == 'abcde', 'asciikey was "%s", expected "abcde"' % asciikey

    from time import sleep

    Configuration.initialize(False)

    # Use dynamic test file path detection
    import os
    ivs_file = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'tests', 'files', 'wep-crackable.ivs')
    print('Running aircrack on %s ...' % ivs_file)

    aircrack = Aircrack(ivs_file)
    while aircrack.is_running():
        sleep(1)

    assert aircrack.is_cracked(), 'Aircrack should have cracked %s' % ivs_file
    print('aircrack process completed.')

    (hexkey, asciikey) = aircrack.get_key_hex_ascii()
    print('aircrack found HEX key: (%s) and ASCII key: (%s)' % (hexkey, asciikey))
    assert hexkey == '75:6E:63:6C:65', 'hexkey was "%s", expected "75:6E:63:6C:65"' % hexkey
    assert asciikey == 'uncle', 'asciikey was "%s", expected "uncle"' % asciikey

    Configuration.exit_gracefully(0)
