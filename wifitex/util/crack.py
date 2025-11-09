#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ..config import Configuration
from ..model.handshake import Handshake
from ..model.wpa_result import CrackResultWPA
from ..model.pmkid_result import CrackResultPMKID
from ..util.process import Process
from ..util.color import Color
from ..util.input import raw_input
from ..tools.aircrack import Aircrack
from ..tools.cowpatty import Cowpatty
from ..tools.hashcat import Hashcat, HcxPcapTool
from ..tools.john import John

from json import loads

import os


# TODO: Bring back the 'print' option, for easy copy/pasting. Just one-liners people can paste into terminal.

# TODO: --no-crack option while attacking targets (implies user will run --crack later)

class CrackHelper:
    '''Manages handshake retrieval, selection, and running the cracking commands.'''

    TYPES = {
        '4-WAY': '4-Way Handshake',
        'PMKID': 'PMKID Hash'
    }
    DEFAULT_WORDLIST_FILENAMES = (
        'wordlist-top4800-probable.txt',
    )

    @staticmethod
    def _resolve_default_wordlist_dir():
        return os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'wordlists'))

    @classmethod
    def _ensure_default_wordlist(cls):
        if Configuration.wordlist and os.path.isfile(Configuration.wordlist):
            return

        default_dir = cls._resolve_default_wordlist_dir()
        if not os.path.isdir(default_dir):
            return

        # Prefer known filenames first
        for filename in cls.DEFAULT_WORDLIST_FILENAMES:
            candidate = os.path.abspath(os.path.join(default_dir, filename))
            if os.path.isfile(candidate):
                Configuration.wordlist = candidate
                Color.pl('{+} Using default wordlist from {C}%s{W}' % candidate)
                return

        # Fallback to the first textual wordlist available
        for entry in sorted(os.listdir(default_dir)):
            candidate = os.path.join(default_dir, entry)
            if os.path.isfile(candidate) and entry.lower().endswith(('.txt', '.lst', '.gz')):
                Configuration.wordlist = os.path.abspath(candidate)
                Color.pl('{+} Using default wordlist from {C}%s{W}' % Configuration.wordlist)
                return

    @classmethod
    def _collect_wordlists(cls):
        """Gather all available wordlists, prioritizing configured and project defaults."""
        seen = set()
        wordlists = []

        def add(path):
            if not path:
                return
            abs_path = os.path.abspath(path)
            if abs_path in seen:
                return
            if os.path.isfile(abs_path):
                seen.add(abs_path)
                wordlists.append(abs_path)

        add(getattr(Configuration, 'wordlist', None))

        default_dir = cls._resolve_default_wordlist_dir()
        if os.path.isdir(default_dir):
            for entry in sorted(os.listdir(default_dir)):
                if entry.lower().endswith(('.txt', '.lst', '.gz')):
                    add(os.path.join(default_dir, entry))

        custom_paths = getattr(Configuration, 'custom_wordlist_paths', []) or []
        for path in custom_paths:
            add(path)

        return wordlists

    @classmethod
    def _wordlists_for_attack(cls):
        """Determine which wordlists should be used during cracking."""
        wordlists = cls._collect_wordlists()
        if not wordlists:
            return []

        if getattr(Configuration, 'multi_wordlist', False) or not getattr(Configuration, 'wordlist', None):
            return wordlists

        return [wordlists[0]]

    @classmethod
    def run(cls):
        Configuration.initialize(False)
        cls._ensure_default_wordlist()

        # Get wordlist
        if not Configuration.wordlist or not os.path.isfile(Configuration.wordlist):
            Color.p('\n{+} Enter wordlist file to use for cracking: {G}')
            entered_wordlist = raw_input().strip()
            default_dir = cls._resolve_default_wordlist_dir()
            if os.path.isabs(entered_wordlist):
                candidate_paths = [entered_wordlist]
            else:
                candidate_paths = [
                    os.path.abspath(entered_wordlist),
                    os.path.abspath(os.path.join(default_dir, entered_wordlist))
                ]

            Configuration.wordlist = next((path for path in candidate_paths if os.path.isfile(path)), None)
            if not Configuration.wordlist:
                Color.pl('{!} {R}Wordlist {O}%s{R} not found. Exiting.' % entered_wordlist)
                return
            Color.pl('')

        # Get handshakes
        handshakes = cls.get_handshakes()
        if len(handshakes) == 0:
            Color.pl('{!} {O}No handshakes found{W}')
            return

        hs_to_crack = cls.get_user_selection(handshakes)
        all_pmkid = all([hs['type'] == 'PMKID' for hs in hs_to_crack])

        # Tools for cracking & their dependencies.
        tool_dependencies = {
            'aircrack': [Aircrack],
            'hashcat':  [Hashcat, HcxPcapTool],
            'john':     [John, HcxPcapTool],
            'cowpatty': [Cowpatty]
        }
        # Identify missing tools
        available_tools = {}
        missing_tools = []
        for tool, dependencies in tool_dependencies.items():
            missing = [
                dep for dep in dependencies
                if not Process.exists(dep.dependency_name)
            ]
            if len(missing) > 0:
                missing_tools.append((tool, missing))
            else:
                available_tools[tool] = dependencies

        if len(missing_tools) > 0:
            Color.pl('\n{!} {O}Unavailable tools (install to enable):{W}')
            for tool, deps in missing_tools:
                dep_list = ', '.join([dep.dependency_name for dep in deps])
                Color.pl('     {R}* {R}%s {W}({O}%s{W})' % (tool, dep_list))

        hashcat_available = 'hashcat' in available_tools
        aircrack_available = 'aircrack' in available_tools

        gpu_available = False
        gpu_error = None
        gpu_name = 'Unknown'
        if hashcat_available:
            try:
                gpu_info = Hashcat.get_gpu_info()
                if gpu_info.get('error'):
                    gpu_error = gpu_info['error']
                gpu_available = gpu_info.get('available', False)
                gpu_name = gpu_info.get('gpu_name', gpu_name)
            except Exception as exc:
                gpu_error = str(exc)

        if all_pmkid:
            Color.pl('{!} {O}Note: PMKID hashes can only be cracked using {C}hashcat{W}')
            if not hashcat_available:
                Color.pl('{!} {R}Hashcat is unavailable; cannot crack PMKID hashes.{W}')
                return
            if gpu_error:
                Color.pl('{!} {O}Hashcat GPU detection issue: {R}%s{W}' % gpu_error)
            elif not gpu_available:
                Color.pl('{!} {O}Hashcat did not detect a GPU. Continuing in CPU mode; cracking will be slower.{W}')
            tool_name = 'hashcat'
        else:
            if hashcat_available and gpu_available:
                Color.pl('{+} {C}hashcat{W} selected (GPU detected: {G}%s{W})' % gpu_name)
                tool_name = 'hashcat'
            elif aircrack_available:
                if hashcat_available:
                    if gpu_error:
                        Color.pl('{!} {O}Hashcat GPU detection issue: {R}%s{W}' % gpu_error)
                    else:
                        Color.pl('{!} {O}No GPU detected by hashcat; using {C}aircrack-ng{W} instead.')
                else:
                    Color.pl('{+} {C}aircrack-ng{W} selected (hashcat unavailable or no GPU detected).')
                tool_name = 'aircrack'
            elif hashcat_available:
                if gpu_error:
                    Color.pl('{!} {O}Hashcat GPU detection issue: {R}%s{W}' % gpu_error)
                else:
                    Color.pl('{!} {O}Hashcat did not detect a GPU. Continuing in CPU mode; cracking may be slow.{W}')
                tool_name = 'hashcat'
            else:
                Color.pl('{!} {R}No supported cracking tools are available.{W}')
                return

        try:
            for hs in hs_to_crack:
                if hs['type'] == 'PMKID':
                    if not hashcat_available:
                        Color.pl('{!} {O}Skipping PMKID hash for {C}%s{O}: hashcat is unavailable.{W}' % hs['essid'])
                        continue
                    cls.crack(hs, 'hashcat')
                else:
                    cls.crack(hs, tool_name if hs['type'] != 'PMKID' else 'hashcat')
        except KeyboardInterrupt:
            Color.pl('\n{!} {O}Interrupted{W}')

    @classmethod
    def is_cracked(cls, file):
        if not os.path.exists(Configuration.cracked_file):
            return False
        with open(Configuration.cracked_file) as f:
            json = loads(f.read())
        if json is None:
            return False
        for result in json:
            for k in result.keys():
                v = result[k]
                if 'file' in k and os.path.basename(v) == file:
                    return True
        return False

    @classmethod
    def get_handshakes(cls):
        handshakes = []

        skipped_pmkid_files = skipped_cracked_files = 0

        hs_dir = Configuration.wpa_handshake_dir
        if not os.path.exists(hs_dir) or not os.path.isdir(hs_dir):
            Color.pl('\n{!} {O}directory not found: {R}%s{W}' % hs_dir)
            return []

        Color.pl('\n{+} Listing captured handshakes from {C}%s{W}:\n' % os.path.abspath(hs_dir))
        for hs_file in os.listdir(hs_dir):
            if hs_file.count('_') != 3:
                continue

            if cls.is_cracked(hs_file):
                skipped_cracked_files += 1
                continue

            if hs_file.endswith('.cap'):
                # WPA Handshake
                hs_type = '4-WAY'
            elif hs_file.endswith(('.22000', '.16800')):
                # PMKID hash
                if not Process.exists('hashcat'):
                    skipped_pmkid_files += 1
                    continue
                hs_type = 'PMKID'
            else:
                continue

            name, essid, bssid, date = hs_file.split('_')
            date = date.rsplit('.', 1)[0]
            days,hours = date.split('T')
            hours = hours.replace('-', ':')
            date = '%s %s' % (days, hours)

            handshake = {
                'filename': os.path.join(hs_dir, hs_file),
                'bssid': bssid.replace('-', ':'),
                'essid': essid,
                'date': date,
                'type': hs_type
            }

            if hs_file.endswith('.cap'):
                # WPA Handshake
                handshake['type'] = '4-WAY'
            elif hs_file.endswith(('.22000', '.16800')):
                # PMKID hash
                handshake['type'] = 'PMKID'
            else:
                continue

            handshakes.append(handshake)

        if skipped_pmkid_files > 0:
            Color.pl('{!} {O}Skipping %d {R}*.22000{O} files because {R}hashcat{O} is missing.{W}\n' % skipped_pmkid_files)
        if skipped_cracked_files > 0:
            Color.pl('{!} {O}Skipping %d already cracked files.{W}\n' % skipped_cracked_files)

        # Sort by Date (Descending)
        return sorted(handshakes, key=lambda x: x.get('date'), reverse=True)


    @classmethod
    def print_handshakes(cls, handshakes):
        # Header
        max_essid_len = max([len(hs['essid']) for hs in handshakes] + [len('ESSID (truncated)')])
        Color.p('{W}{D}  NUM')
        Color.p('  ' + 'ESSID (truncated)'.ljust(max_essid_len))
        Color.p('  ' + 'BSSID'.ljust(17))
        Color.p('  ' + 'TYPE'.ljust(5))
        Color.p('  ' + 'DATE CAPTURED\n')
        Color.p('  ---')
        Color.p('  ' + ('-' * max_essid_len))
        Color.p('  ' + ('-' * 17))
        Color.p('  ' + ('-' * 5))
        Color.p('  ' + ('-' * 19) + '{W}\n')
        # Handshakes
        for index, handshake in enumerate(handshakes, start=1):
            Color.p('  {G}%s{W}' % str(index).rjust(3))
            Color.p('  {C}%s{W}' % handshake['essid'].ljust(max_essid_len))
            Color.p('  {O}%s{W}' % handshake['bssid'].ljust(17))
            Color.p('  {C}%s{W}' % handshake['type'].ljust(5))
            Color.p('  {W}%s{W}\n' % handshake['date'])


    @classmethod
    def get_user_selection(cls, handshakes):
        cls.print_handshakes(handshakes)

        Color.p('{+} Select handshake(s) to crack ({G}%d{W}-{G}%d{W}, select multiple with {C},{W} or {C}-{W} or {C}all{W}): {G}' % (1, len(handshakes)))
        choices = raw_input()

        selection = []
        for choice in choices.split(','):
            if '-' in choice:
                first, last = [int(x) for x in choice.split('-')]
                for index in range(first, last + 1):
                    selection.append(handshakes[index-1])
            elif choice.strip().lower() == 'all':
                selection = handshakes[:]
                break
            elif [c.isdigit() for c in choice]:
                index = int(choice)
                selection.append(handshakes[index-1])

        return selection


    @classmethod
    def crack(cls, hs, tool):
        Color.pl('\n{+} Cracking {G}%s {C}%s{W} ({C}%s{W})' % (
            cls.TYPES[hs['type']], hs['essid'], hs['bssid']))

        if hs['type'] == 'PMKID':
            crack_result = cls.crack_pmkid(hs, tool)
        elif hs['type'] == '4-WAY':
            crack_result = cls.crack_4way(hs, tool)
        else:
            raise ValueError('Cannot crack handshake: Type is not PMKID or 4-WAY. Handshake=%s' % hs)

        if crack_result is None:
            # Failed to crack
            Color.pl('{!} {R}Failed to crack {O}%s{R} ({O}%s{R}): Passphrase not in dictionary' % (
                hs['essid'], hs['bssid']))
        else:
            # Cracked, replace existing entry (if any), or add to
            Color.pl('{+} {G}Cracked{W} {C}%s{W} ({C}%s{W}). Key: "{G}%s{W}"' % (
                hs['essid'], hs['bssid'], crack_result.key))
            crack_result.save()


    @classmethod
    def crack_4way(cls, hs, tool):

        handshake = Handshake(hs['filename'],
                bssid=hs['bssid'],
                essid=hs['essid'])
        try:
            handshake.divine_bssid_and_essid()
        except ValueError as e:
            Color.pl('{!} {R}Error: {O}%s{W}' % e)
            return None

        wordlists = cls._wordlists_for_attack()
        if not wordlists:
            Color.pl('{!} {R}No wordlists found. Unable to crack handshake.{W}')
            return None

        original_wordlist = getattr(Configuration, 'wordlist', None)
        try:
            if tool == 'hashcat':
                if wordlists:
                    Configuration.wordlist = wordlists[0]
                else:
                    Configuration.wordlist = None
                if len(wordlists) > 1:
                    Color.pl('{+} Processing {C}%d{W} wordlists with {C}hashcat{W} (includes brute-force plan).' % len(wordlists))
                key = Hashcat.crack_handshake(
                    handshake,
                    show_command=True,
                    wordlists=wordlists
                )
                if key is not None:
                    return CrackResultWPA(hs['bssid'], hs['essid'], hs['filename'], key)
            else:
                for index, wordlist in enumerate(wordlists, start=1):
                    if len(wordlists) > 1:
                        Color.pl('{+} Trying wordlist {C}%d{W}/{C}%d{W}: {G}%s{W}' % (
                            index, len(wordlists), os.path.basename(wordlist)))
                    Configuration.wordlist = wordlist

                    if tool == 'aircrack':
                        key = Aircrack.crack_handshake(handshake, show_command=True, wordlist=wordlist)
                    elif tool == 'john':
                        key = John.crack_handshake(handshake, show_command=True, wordlist=wordlist)
                    elif tool == 'cowpatty':
                        key = Cowpatty.crack_handshake(handshake, show_command=True, wordlist=wordlist)
                    else:
                        key = None

                    if key is not None:
                        return CrackResultWPA(hs['bssid'], hs['essid'], hs['filename'], key)
        finally:
            Configuration.wordlist = original_wordlist

        return None


    @classmethod
    def crack_pmkid(cls, hs, tool):
        if tool != 'hashcat':
            Color.pl('{!} {O}Note: PMKID hashes can only be cracked using {C}hashcat{W}')

        wordlists = cls._wordlists_for_attack()
        if not wordlists:
            Color.pl('{!} {R}No wordlists found. Unable to crack PMKID hash.{W}')
            return None

        original_wordlist = getattr(Configuration, 'wordlist', None)
        try:
            if wordlists:
                Configuration.wordlist = wordlists[0]
            else:
                Configuration.wordlist = None

            if len(wordlists) > 1:
                Color.pl('{+} Processing {C}%d{W} wordlists with {C}hashcat{W} (includes brute-force plan).' % len(wordlists))

            key = Hashcat.crack_pmkid(
                hs['filename'],
                verbose=True,
                wordlists=wordlists
            )
            if key is not None:
                return CrackResultPMKID(hs['bssid'], hs['essid'], hs['filename'], key)
        finally:
            Configuration.wordlist = original_wordlist

        return None


if __name__ == '__main__':
    CrackHelper.run()


