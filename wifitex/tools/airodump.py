#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dependency import Dependency
from .tshark import Tshark
from .wash import Wash
from ..util.process import Process
from ..config import Configuration
from ..model.target import Target, WPSState
from ..model.client import Client

import os, time
import subprocess

# Import custom exceptions
try:
    from ..gui.error_handler import InterfaceError
except ImportError:
    # Fallback for when GUI module is not available
    # Use a different name to avoid type conflicts
    class AirodumpInterfaceError(Exception):
        """Interface-related errors - fallback when GUI module is not available"""
        pass
    # Create an alias for compatibility
    InterfaceError = AirodumpInterfaceError

class Airodump(Dependency):
    ''' Wrapper around airodump-ng program '''
    dependency_required = True
    dependency_name = 'airodump-ng'
    dependency_url = 'https://www.aircrack-ng.org/install.html'

    def __init__(self, interface=None, channel=None, encryption=None,\
                       wps=WPSState.UNKNOWN, target_bssid=None,
                       output_file_prefix='airodump',\
                       ivs_only=False, skip_wps=False, delete_existing_files=True):
        '''Sets up airodump arguments, doesn't start process yet.'''

        Configuration.initialize()

        if interface is None:
            interface = Configuration.interface
        if interface is None:
            raise InterfaceError('Wireless interface must be defined (-i)')
        self.interface = interface

        self.targets = []

        if channel is None:
            channel = Configuration.target_channel
        self.channel = channel
        self.five_ghz = Configuration.five_ghz

        self.encryption = encryption
        self.wps = wps

        self.target_bssid = target_bssid
        self.output_file_prefix = output_file_prefix
        self.ivs_only = ivs_only
        self.skip_wps = skip_wps

        # For tracking decloaked APs (previously were hidden)
        self.decloaking = False
        self.decloaked_bssids = set()
        self.decloaked_times = {} # Map of BSSID(str) -> epoch(int) of last deauth

        self.delete_existing_files = delete_existing_files


    def __enter__(self):
        '''
        Setting things up for this context.
        Called at start of 'with Airodump(...) as x:'
        Actually starts the airodump process.
        '''
        if self.delete_existing_files:
            self.delete_airodump_temp_files(self.output_file_prefix)

        self.csv_file_prefix = Configuration.temp() + self.output_file_prefix

        # Ensure RF-kill is not blocking and interface is up before starting
        self._ensure_rfkill_and_iface_up()

        # Build the command
        command = [
            'airodump-ng',
            self.interface,
            '-w', self.csv_file_prefix, # Output file prefix
            '--write-interval', '1' # Write every second
        ]
        if self.channel:    command.extend(['-c', str(self.channel)])
        elif self.five_ghz: command.extend(['--band', 'a'])

        if self.encryption:   command.extend(['--enc', self.encryption])
        if self.wps:          command.extend(['--wps'])
        if self.target_bssid: command.extend(['--bssid', self.target_bssid])

        if self.ivs_only: command.extend(['--output-format', 'ivs,csv'])
        else:             command.extend(['--output-format', 'pcap,csv'])

        # Start the process
        self.pid = Process(command, devnull=True)
        return self


    def __exit__(self, type, value, traceback):
        '''
        Tearing things down since the context is being exited.
        Called after 'with Airodump(...)' goes out of scope.
        '''
        # Kill the process
        self.pid.interrupt()

        if self.delete_existing_files:
            self.delete_airodump_temp_files(self.output_file_prefix)


    def find_files(self, endswith=None):
        return self.find_files_by_output_prefix(self.output_file_prefix, endswith=endswith)

    def _ensure_rfkill_and_iface_up(self):
        """Best-effort: unblock RF-kill for Wi‑Fi and bring interface up.

        If rfkill is not present or we lack privileges, we do not crash here;
        airodump-ng will still provide its own error which will be surfaced.
        """
        try:
            # Check rfkill status
            rfkill = subprocess.run(['rfkill', 'list'], capture_output=True, text=True, timeout=3)
            if rfkill.returncode == 0:
                out = rfkill.stdout or ''
                # If any Wireless LAN soft blocked, try to unblock wifi
                if ('Wireless LAN' in out and 'Soft blocked: yes' in out) or 'Soft blocked: yes' in out:
                    subprocess.run(['rfkill', 'unblock', 'wifi'], capture_output=True, text=True, timeout=3)
                    # Some systems prefer 'all'
                    subprocess.run(['rfkill', 'unblock', 'all'], capture_output=True, text=True, timeout=3)
        except Exception:
            # Ignore rfkill issues here; we will still try to bring link up
            pass

        # Bring interface up (in case it's down due to rfkill or state)
        try:
            if self.interface:
                subprocess.run(['ip', 'link', 'set', self.interface, 'up'], capture_output=True, text=True, timeout=3)
        except Exception:
            pass

    @classmethod
    def find_files_by_output_prefix(cls, output_file_prefix, endswith=None):
        ''' Finds all files in the temp directory that start with the output_file_prefix '''
        result = []
        temp = Configuration.temp()
        for fil in os.listdir(temp):
            if not fil.startswith(output_file_prefix):
                continue

            if endswith is None or fil.endswith(endswith):
                result.append(os.path.join(temp, fil))

        return result

    @classmethod
    def delete_airodump_temp_files(cls, output_file_prefix):
        '''
        Deletes airodump* files in the temp directory.
        Also deletes replay_*.cap and *.xor files in pwd.
        '''
        # Remove all temp files
        for fil in cls.find_files_by_output_prefix(output_file_prefix):
            os.remove(fil)

        # Remove .cap and .xor files from pwd
        for fil in os.listdir('.'):
            if fil.startswith('replay_') and fil.endswith('.cap') or fil.endswith('.xor'):
                os.remove(fil)

        # Remove replay/cap/xor files from temp
        temp_dir = Configuration.temp()
        for fil in os.listdir(temp_dir):
            if fil.startswith('replay_') and fil.endswith('.cap') or fil.endswith('.xor'):
                os.remove(os.path.join(temp_dir, fil))

    def get_targets(self, old_targets=[], apply_filter=True):
        ''' Parses airodump's CSV file, returns list of Targets '''

        # Find the .CSV file
        csv_filename = None
        for fil in self.find_files(endswith='.csv'):
            csv_filename = fil  # Found the file
            break

        if csv_filename is None or not os.path.exists(csv_filename):
            return self.targets  # No file found

        targets = Airodump.get_targets_from_csv(csv_filename)
        for old_target in old_targets:
            for target in targets:
                if old_target.bssid == target.bssid:
                    target.wps = old_target.wps

        # Check targets for WPS
        if not self.skip_wps:
            capfile = csv_filename[:-3] + 'cap'
            try:
                Tshark.check_for_wps_and_update_targets(capfile, targets)
            except ValueError:
                # No tshark, or it failed. Fall-back to wash
                Wash.check_for_wps_and_update_targets(capfile, targets)
        
        # Parse probe requests to detect unassociated clients
        self.parse_probe_requests_for_clients(targets)

        if apply_filter:
            # Filter targets based on encryption & WPS capability
            targets = Airodump.filter_targets(targets, skip_wps=self.skip_wps)

        # Sort by power
        targets.sort(key=lambda x: x.power, reverse=True)

        # Identify decloaked targets
        for old_target in self.targets:
            for new_target in targets:
                if old_target.bssid != new_target.bssid:
                    continue

                if new_target.essid_known and not old_target.essid_known:
                    # We decloaked a target!
                    new_target.decloaked = True
                    self.decloaked_bssids.add(new_target.bssid)

        self.targets = targets
        self.deauth_hidden_targets()

        return self.targets


    @staticmethod
    def get_targets_from_csv(csv_filename):
        '''Returns list of Target objects parsed from CSV file.'''
        targets = []
        import csv
        from ..model.target import Target
        from ..model.client import Client
        with open(csv_filename, 'r') as csvopen:
            lines = []
            for line in csvopen:
                line = line.replace('\0', '')
                lines.append(line)
            csv_reader = csv.reader(lines,
                    delimiter=',',
                    quoting=csv.QUOTE_ALL,
                    skipinitialspace=True,
                    escapechar='\\')

            hit_clients = False
            target_count = 0
            client_count = 0
            
            for row in csv_reader:
                # Each 'row' is a list of fields for a target/client

                if len(row) == 0: continue

                if row[0].strip() == 'BSSID':
                    # This is the 'header' for the list of Targets
                    hit_clients = False
                    continue

                elif row[0].strip() == 'Station MAC':
                    # This is the 'header' for the list of Clients
                    hit_clients = True
                    continue

                if hit_clients:
                    # The current row corresponds to a 'Client' (computer)
                    try:
                        client = Client(row)
                        client_count += 1
                    except (IndexError, ValueError) as e:
                        # Skip if we can't parse the client row
                        continue

                    # Handle both associated and unassociated clients
                    if 'not associated' in client.bssid:
                        # For unassociated clients, create a virtual target or add to a general list
                        # We'll add them to a special "unassociated" target
                        unassociated_target = None
                        for t in targets:
                            if t.bssid == 'UNASSOCIATED':
                                unassociated_target = t
                                break
                        
                        if unassociated_target is None:
                            # Create a virtual target for unassociated clients
                            unassociated_target = Target(['UNASSOCIATED', '', '', '0', '0', 'Open', '', '', '-100', '0', '0', '0.0.0.0', '0', 'Unassociated Clients'])
                            targets.append(unassociated_target)
                        
                        unassociated_target.clients.append(client)
                    else:
                        # Add this client to the appropriate Target
                        for t in targets:
                            if t.bssid == client.bssid:
                                t.clients.append(client)
                                break

                else:
                    # The current row corresponds to a 'Target' (router)
                    try:
                        target = Target(row)
                        targets.append(target)
                        target_count += 1
                    except Exception as e:
                        # Skip if we can't parse the target row
                        continue

        return targets

    @staticmethod
    def filter_targets(targets, skip_wps=False):
        ''' Filters targets based on Configuration '''
        result = []
        # Filter based on Encryption
        for target in targets:
            if Configuration.clients_only and len(target.clients) == 0:
                continue
            
            # If encryption_filter is empty, show all targets
            if not Configuration.encryption_filter:
                result.append(target)
            elif 'WPA' in Configuration.encryption_filter and 'WPA' in target.encryption:
                result.append(target)
            elif 'WPS' in Configuration.encryption_filter and target.wps in [WPSState.UNLOCKED, WPSState.LOCKED]:
                result.append(target)
            elif skip_wps:
                result.append(target)

        # Filter based on BSSID/ESSID
        bssid = Configuration.target_bssid
        essid = Configuration.target_essid
        i = 0
        while i < len(result):
            if result[i].essid is not None and Configuration.ignore_essid is not None and Configuration.ignore_essid.lower() in result[i].essid.lower():
                result.pop(i)
            elif bssid and result[i].bssid.lower() != bssid.lower():
                result.pop(i)
            elif essid and result[i].essid and result[i].essid.lower() != essid.lower():
                result.pop(i)
            else:
                i += 1
        return result

    def deauth_hidden_targets(self):
        '''
        Sends deauths (to broadcast and to each client) for all
        targets (APs) that have unknown ESSIDs (hidden router names).
        '''
        self.decloaking = False

        if Configuration.no_deauth:
            return  # Do not deauth if requested

        if self.channel is None:
            return  # Do not deauth if channel is not fixed.

        # Reusable deauth command
        deauth_cmd = [
            'aireplay-ng',
            '-0', # Deauthentication
            str(Configuration.num_deauths), # Number of deauth packets to send
            '--ignore-negative-one'
        ]

        for target in self.targets:
            if target.essid_known:
                continue

            now = int(time.time())
            secs_since_decloak = now - self.decloaked_times.get(target.bssid, 0)

            if secs_since_decloak < 30:
                continue  # Decloak every AP once every 30 seconds

            self.decloaking = True
            self.decloaked_times[target.bssid] = now
            if Configuration.verbose > 1:
                from ..util.color import Color
                Color.pe('{C} [?] Deauthing %s (broadcast & %d clients){W}' % (target.bssid, len(target.clients)))

            # Deauth broadcast
            iface = Configuration.interface
            Process(deauth_cmd + ['-a', str(target.bssid), str(iface)])

            # Deauth clients
            for client in target.clients:
                Process(deauth_cmd + ['-a', str(target.bssid), '-c', str(client.bssid), str(iface)])

    def parse_probe_requests_for_clients(self, targets):
        """Parse probe requests from captured packets to detect unassociated clients"""
        try:
            # Find the .cap file
            cap_files = self.find_files(endswith='.cap')
            if not cap_files:
                return
            
            capfile = cap_files[0]
            if not os.path.exists(capfile):
                return
            
            # Check if tshark is available
            if not Tshark.exists():
                return
            
            # Use tshark to extract probe requests
            import subprocess
            command = [
                'tshark',
                '-r', capfile,
                '-n',  # Don't resolve addresses
                '-Y', 'wlan.fc.type_subtype == 0x04 and wlan.ssid != ""',  # Probe request frames with SSID
                '-T', 'fields',
                '-e', 'wlan.sa',  # Source MAC
                '-e', 'wlan.ssid'  # SSID
            ]
            
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                return
            
            # Find or create unassociated target
            unassociated_target = None
            for target in targets:
                if target.bssid == 'UNASSOCIATED':
                    unassociated_target = target
                    break
            
            if unassociated_target is None:
                from ..model.target import Target
                unassociated_target = Target(['UNASSOCIATED', '', '', '0', '0', 'Open', '', '', '-100', '0', '0', '0.0.0.0', '0', 'Unassociated Clients'])
                targets.append(unassociated_target)
            
            # Parse probe requests
            probe_clients = {}  # MAC -> Client object
            for line in stdout.split('\n'):
                line = line.strip()
                if not line or '\t' not in line:
                    continue
                
                parts = line.split('\t')
                if len(parts) >= 2:
                    client_mac = parts[0].strip()
                    ssid = parts[1].strip()
                    
                    # Validate MAC address format
                    if not self.is_valid_mac(client_mac):
                        continue
                    
                    if client_mac and ssid and ssid != '' and ssid != '<MISSING>':
                        # Convert hex-encoded SSIDs to readable text
                        readable_ssid = self.decode_hex_ssid(ssid)
                        
                        # Skip empty or invalid SSIDs
                        if readable_ssid and len(readable_ssid.strip()) > 0:
                            # Create or update client entry
                            if client_mac not in probe_clients:
                                # Create a Client object for probe requests
                                from ..model.client import Client
                                client_fields = [client_mac, '', '', '-50', '1', '(not associated)', readable_ssid]
                                probe_clients[client_mac] = Client(client_fields)
                            else:
                                # Add SSID to probed ESSIDs
                                existing_client = probe_clients[client_mac]
                                if hasattr(existing_client, 'probed_essids'):
                                    existing_client.probed_essids.append(readable_ssid)
                                else:
                                    existing_client.probed_essids = [readable_ssid]
            
            # Add probe clients to unassociated target
            for client in probe_clients.values():
                # Check if client already exists
                client_exists = False
                for existing_client in unassociated_target.clients:
                    if existing_client.station == client.station:
                        client_exists = True
                        break
                
                if not client_exists:
                    unassociated_target.clients.append(client)
                    
        except Exception as e:
            # Silently fail if probe request parsing fails
            pass
    
    def is_valid_mac(self, mac):
        """Check if MAC address is valid"""
        try:
            if not mac or len(mac) != 17:
                return False
            
            # Check format: XX:XX:XX:XX:XX:XX
            parts = mac.split(':')
            if len(parts) != 6:
                return False
            
            for part in parts:
                if len(part) != 2:
                    return False
                try:
                    int(part, 16)
                except ValueError:
                    return False
            
            return True
        except:
            return False
    
    def decode_hex_ssid(self, ssid):
        """Convert hex-encoded SSID to readable text"""
        try:
            # Check if SSID is hex-encoded
            if len(ssid) > 2 and ssid.startswith('\\x'):
                # Remove \x prefix and decode
                hex_part = ssid[2:]
                if len(hex_part) % 2 == 0:
                    try:
                        decoded = bytes.fromhex(hex_part).decode('utf-8', errors='ignore')
                        return decoded
                    except:
                        pass
            
            # Check if SSID contains hex patterns
            import re
            hex_pattern = re.compile(r'\\x([0-9a-fA-F]{2})')
            if hex_pattern.search(ssid):
                def hex_replace(match):
                    return chr(int(match.group(1), 16))
                decoded = hex_pattern.sub(hex_replace, ssid)
                return decoded
            
            return ssid
        except:
            return ssid

if __name__ == '__main__':
    ''' Example usage. wlan0mon should be in Monitor Mode '''
    with Airodump() as airodump:

        from time import sleep
        sleep(7)

        from ..util.color import Color

        targets = airodump.get_targets()
        for idx, target in enumerate(targets, start=1):
            Color.pl('   {G}%s %s' % (str(idx).rjust(3), target.to_str()))

    Configuration.delete_temp()
