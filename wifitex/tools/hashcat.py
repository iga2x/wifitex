#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dependency import Dependency
from ..config import Configuration
from ..util.process import Process
from ..util.color import Color

import os
import re
import uuid
from typing import Any, Dict, List, Optional


class Hashcat(Dependency):
    dependency_required = False
    dependency_name = 'hashcat'
    dependency_url = 'https://hashcat.net/hashcat/'

    @staticmethod
    def _ensure_text(value: Any) -> str:
        if isinstance(value, bytes):
            return value.decode('utf-8', errors='ignore')
        return value or ''

    @staticmethod
    def should_use_force():
        if not Hashcat.exists():
            return False
        command = ['hashcat', '-I']
        proc = Process(command)
        stderr_raw = proc.stderr()
        stderr = Hashcat._ensure_text(stderr_raw)
        return 'No devices found/left' in stderr

    @staticmethod
    def has_gpu() -> bool:
        """
        Return True when a GPU-capable accelerator is detected by hashcat.
        Falls back to False if hashcat is unavailable or the query fails.
        """
        info = Hashcat.get_gpu_info()
        return info.get('available', False)

    @staticmethod
    def _run_hashcat_info() -> str:
        """Execute `hashcat -I` and return combined stdout/stderr output."""
        if not Hashcat.exists():
            return ''

        try:
            proc = Process(['hashcat', '-I'])
            stdout = Hashcat._ensure_text(proc.stdout())
            stderr = Hashcat._ensure_text(proc.stderr())
            return_code = proc.pid.returncode
            if return_code not in (0,):
                combined = f'{stdout}\n{stderr}'.strip()
                raise RuntimeError(f'`hashcat -I` failed with exit code {return_code}: {combined or "no output"}')
            return f'{stdout}\n{stderr}'.strip()
        except Exception as exc:
            raise RuntimeError(f'Failed to query hashcat capabilities: {exc}') from exc

    @classmethod
    def get_gpu_info(cls) -> Dict[str, Any]:
        """
        Return a dictionary describing the first GPU device detected by hashcat.
        Keys: available (bool), gpu_name (str), cuda_version (str),
        opencl_version (str)
        """
        info = {
            'available': False,
            'gpu_name': 'Unknown',
            'cuda_version': 'Unknown',
            'opencl_version': 'Unknown',
            'error': None,
        }

        try:
            output = cls._run_hashcat_info()
        except Exception as exc:
            info['error'] = str(exc)
            return info

        if not output:
            if not cls.exists():
                info['error'] = 'hashcat binary not found in PATH'
            else:
                info['error'] = '`hashcat -I` returned no output'
            return info

        cuda_version = re.search(r'CUDA\.Version\.\s*:\s*([^\n]+)', output)
        if cuda_version:
            info['cuda_version'] = cuda_version.group(1).strip()
        else:
            cuda_api = re.search(r'CUDA API\s*\(([^)]+)\)', output)
            if cuda_api:
                info['cuda_version'] = cuda_api.group(1).strip()

        opencl_version = re.search(r'OpenCL API\s*\(([^)]+)\)', output)
        if opencl_version:
            info['opencl_version'] = opencl_version.group(1).strip()

        current_device = None
        last_name = None
        pending_gpu = False
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if stripped.startswith('Backend Device ID') or stripped.startswith('Device #'):
                current_device = None
                last_name = None
                pending_gpu = False
                continue

            if stripped.startswith('Name'):
                value = stripped.split(':', 1)[1].strip()
                last_name = value
                lowered = value.lower()
                # Skip platform names (e.g. "NVIDIA CUDA", "Portable Computing Language")
                if 'cuda' in lowered and 'geforce' not in lowered and 'rtx' not in lowered and 'tesla' not in lowered:
                    continue
                if 'portable computing language' in lowered:
                    continue
                current_device = value
                if pending_gpu:
                    info['available'] = True
                    info['gpu_name'] = current_device
                    break

            if stripped.startswith('Device Type'):
                type_value = stripped.split(':', 1)[1].strip().upper()
                is_gpu = 'GPU' in type_value
                pending_gpu = is_gpu
                if is_gpu:
                    if current_device:
                        info['available'] = True
                        info['gpu_name'] = current_device
                    elif last_name:
                        info['available'] = True
                        info['gpu_name'] = last_name
                    if info['available']:
                        break

            if stripped.startswith('Type'):
                type_value = stripped.split(':', 1)[1].strip().upper()
                is_gpu = 'GPU' in type_value
                pending_gpu = is_gpu
                if is_gpu:
                    if current_device:
                        info['available'] = True
                        info['gpu_name'] = current_device
                    elif last_name:
                        info['available'] = True
                        info['gpu_name'] = last_name
                    if info['available']:
                        break

        return info

    @staticmethod
    def _resolve_bruteforce_options(overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Normalize brute-force configuration into a dict with consistent keys."""
        options = {
            'enabled': getattr(Configuration, 'use_brute_force', False),
            'modes': [],
            'mask': getattr(Configuration, 'brute_force_mask', None),
            'timeout_seconds': getattr(Configuration, 'brute_force_timeout', 0),
        }

        mode_value = getattr(Configuration, 'brute_force_mode', '0')
        modes: List[str] = []
        if isinstance(mode_value, str):
            modes = [entry.strip() for entry in mode_value.split(',') if entry.strip()]
        elif isinstance(mode_value, (list, tuple, set)):
            modes = [str(entry).strip() for entry in mode_value if str(entry).strip()]
        elif mode_value is not None:
            modes = [str(mode_value).strip()]
        options['modes'] = modes

        if overrides:
            for key, value in overrides.items():
                if value is not None:
                    options[key] = value

        if not options.get('mask'):
            options['mask'] = '?d?d?d?d?d?d?d?d'

        timeout = options.get('timeout_seconds')
        if isinstance(timeout, (int, float)) and timeout < 0:
            options['timeout_seconds'] = 0

        return options

    @staticmethod
    def _build_hashcat_tasks(wordlists: List[str], brute_options: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Construct hashcat attack tasks based on wordlists and brute-force options."""
        tasks: List[Dict[str, Any]] = []
        cleaned_wordlists = [os.path.abspath(path) for path in wordlists if path]

        enabled = bool(brute_options.get('enabled'))
        modes = [mode for mode in brute_options.get('modes', []) if mode]
        mask = brute_options.get('mask') or '?d?d?d?d?d?d?d?d'
        timeout_seconds = brute_options.get('timeout_seconds')
        options = {
            'timeout_seconds': timeout_seconds
        }

        if not enabled:
            if not cleaned_wordlists:
                raise FileNotFoundError("No wordlists provided for dictionary attack.")
            for path in cleaned_wordlists:
                tasks.append({'mode': '0', 'wordlist': path, 'mask': None, 'options': options})
            return tasks

        if not modes:
            if not cleaned_wordlists:
                raise FileNotFoundError("No wordlists provided for dictionary attack.")
            for path in cleaned_wordlists:
                tasks.append({'mode': '0', 'wordlist': path, 'mask': None, 'options': options})
            return tasks

        dictionary_required = any(mode in {'0', '6', '7'} for mode in modes)
        if dictionary_required and not cleaned_wordlists:
            raise FileNotFoundError("Selected brute-force modes require a wordlist, but none were provided.")

        for raw_mode in modes:
            mode = raw_mode.strip()
            if mode == '3':
                tasks.append({'mode': '3', 'wordlist': None, 'mask': mask, 'options': options})
            elif mode in {'6', '7'}:
                for path in cleaned_wordlists:
                    tasks.append({'mode': mode, 'wordlist': path, 'mask': mask, 'options': options})
            else:
                for path in cleaned_wordlists:
                    tasks.append({'mode': '0', 'wordlist': path, 'mask': None, 'options': options})

        return tasks

    @staticmethod
    def _prepare_hash_input(handshake_or_path, show_command: bool = False):
        """
        Convert a capture to hashcat format if needed.

        Returns a tuple of (hash_input_path, hash_mode, temporary_file_path)
        """
        temporary_input: Optional[str] = None

        if hasattr(handshake_or_path, 'capfile'):
            cap_path = handshake_or_path.capfile
            handshake = handshake_or_path
        else:
            cap_path = str(handshake_or_path)
            handshake = None

        lower_path = cap_path.lower()
        if lower_path.endswith('.16800'):
            return cap_path, '16800', temporary_input
        if lower_path.endswith('.22000'):
            return cap_path, '22000', temporary_input

        if handshake is None:
            raise ValueError('Handshake instance required to convert capture to hashcat format.')

        temporary_input = HcxPcapTool.generate_22000_file(handshake, show_command=show_command)
        return temporary_input, '22000', temporary_input

    @staticmethod
    def _run_hashcat_task(
            hash_input: str,
            hash_mode: str,
            task: Dict[str, Any],
            show_command: bool = False):
        """Execute a single hashcat task and return (return_code, key)."""
        attack_mode = task.get('mode', '0')
        wordlist = task.get('wordlist')
        mask = task.get('mask') or '?d?d?d?d?d?d?d?d'
        options = task.get('options') or {}
        runtime_seconds = options.get('timeout_seconds')

        key_file = os.path.join(Configuration.temp(), f'hashcat_cli_{uuid.uuid4().hex}.key')

        command = ['hashcat', '--quiet', '-m', hash_mode, '-a', attack_mode, hash_input]

        session_name = task.get('session') if task else None
        if not session_name:
            session_name = f"wifitex_{uuid.uuid4().hex[:12]}"
            if isinstance(task, dict):
                task['session'] = session_name

        if attack_mode == '3':
            command.append(mask)
        elif attack_mode == '6':
            if not wordlist:
                raise ValueError('Hashcat mode 6 requires a wordlist.')
            command.extend([wordlist, mask])
        elif attack_mode == '7':
            if not wordlist:
                raise ValueError('Hashcat mode 7 requires a wordlist.')
            command.extend([mask, wordlist])
        else:
            if not wordlist:
                raise ValueError('Hashcat dictionary mode requires a wordlist.')
            command.append(wordlist)

        command.extend(['--outfile', key_file, '--outfile-format', '2'])
        command.extend(['--session', session_name])

        if runtime_seconds:
            try:
                runtime_int = int(runtime_seconds)
                if runtime_int > 0:
                    command.extend(['--runtime', str(runtime_int)])
            except (TypeError, ValueError):
                pass

        if Hashcat.should_use_force():
            command.append('--force')

        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))

        process = Process(command)
        stdout = Hashcat._ensure_text(process.stdout())
        stderr = Hashcat._ensure_text(process.stderr())
        return_code = process.pid.returncode

        key_value: Optional[str] = None
        try:
            if os.path.exists(key_file):
                with open(key_file, 'r', encoding='utf-8', errors='ignore') as key_fd:
                    key_value = key_fd.readline().strip()
        finally:
            if os.path.exists(key_file):
                try:
                    os.remove(key_file)
                except Exception:
                    pass

        if return_code not in (0, 1):
            combined = (stdout or '').strip()
            if stderr:
                combined = f'{combined}\n{stderr}'.strip() if combined else stderr.strip()
            raise RuntimeError(f'hashcat exited with code {return_code}: {combined or "no output"}')

        return return_code, key_value

    @staticmethod
    def _run_hashcat_show(hash_input: str, hash_mode: str, show_command: bool = False) -> Optional[str]:
        """Attempt to extract a cracked key from the potfile."""
        command = ['hashcat', '--quiet', '--show', '-m', hash_mode, hash_input]
        if Hashcat.should_use_force():
            command.append('--force')
        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
        process = Process(command)
        stdout = Hashcat._ensure_text(process.stdout()) or ''
        if not stdout:
            return None
        lines = [line.strip() for line in stdout.splitlines() if line.strip()]
        if not lines:
            return None
        last_line = lines[-1]
        if ':' not in last_line:
            return None
        return last_line.rsplit(':', 1)[-1].strip() or None

    @classmethod
    def get_performance_info(cls) -> Dict[str, Any]:
        """
        Run a lightweight benchmark to estimate WPA cracking speed.
        Returns a dictionary with keys: wpa_speed (str), raw_output (str), success (bool)
        """
        result = {
            'wpa_speed': 'Unknown',
            'raw_output': '',
            'success': False,
            'error': None,
        }

        if not cls.exists():
            result['error'] = 'hashcat binary not found in PATH'
            return result

        try:
            # Benchmark the WPA2/PMKID hash-mode (22000) which hashcat uses for WPA cracking.
            benchmark_cmd = ['hashcat', '-b', '-m', '22000']
            proc = Process(benchmark_cmd)
            stdout = Hashcat._ensure_text(proc.stdout())
            stderr = Hashcat._ensure_text(proc.stderr())
            combined = f'{stdout}\n{stderr}'.strip()
            result['raw_output'] = combined

            # Extract the first reported speed line: "Speed.#1.........: 123.4 MH/s"
            speed_match = re.search(r'Speed\.\#\d+\s*:\s*([0-9.]+\s*(?:[kMGT]?H/s))', combined)
            if speed_match:
                result['wpa_speed'] = speed_match.group(1).strip()
                result['success'] = True
            else:
                # If speed not found, still mark success if command executed without errors.
                result['success'] = proc.pid.returncode == 0
                if not result['success']:
                    result['error'] = f'Benchmark exited with code {proc.pid.returncode}'
        except Exception as exc:
            result['raw_output'] = f'Error running hashcat benchmark: {exc}'
            result['error'] = str(exc)

        return result

    @staticmethod
    def crack_handshake(
            handshake,
            show_command: bool = False,
            wordlist: Optional[str] = None,
            wordlists: Optional[List[str]] = None) -> Optional[str]:
        """Crack a captured WPA/WPA2 handshake using hashcat."""
        wordlist_paths: List[str] = []
        if wordlists:
            wordlist_paths.extend([os.path.abspath(path) for path in wordlists if path])
        elif wordlist:
            wordlist_paths.append(os.path.abspath(wordlist))
        elif Configuration.wordlist:
            wordlist_paths.append(os.path.abspath(Configuration.wordlist))

        brute_options = Hashcat._resolve_bruteforce_options()
        try:
            tasks = Hashcat._build_hashcat_tasks(wordlist_paths, brute_options)
        except FileNotFoundError as exc:
            raise ValueError(str(exc)) from exc

        hash_input, hash_mode, temporary_input = Hashcat._prepare_hash_input(handshake, show_command=show_command)
        try:
            for task in tasks:
                _, key_value = Hashcat._run_hashcat_task(hash_input, hash_mode, task, show_command=show_command)
                if key_value:
                    return key_value

            key_value = Hashcat._run_hashcat_show(hash_input, hash_mode, show_command=show_command)
            if key_value:
                return key_value
        finally:
            if temporary_input and os.path.exists(temporary_input):
                try:
                    os.remove(temporary_input)
                except Exception:
                    pass

        return None


    @staticmethod
    def crack_pmkid(
            pmkid_file,
            verbose: bool = False,
            wordlist: Optional[str] = None,
            wordlists: Optional[List[str]] = None) -> Optional[str]:
        '''
        Cracks a given pmkid_file using the PMKID/WPA2 attack.
        Returns:
            Key (str) if found; `None` if not found.
        '''

        wordlist_paths: List[str] = []
        if wordlists:
            wordlist_paths.extend([os.path.abspath(path) for path in wordlists if path])
        elif wordlist:
            wordlist_paths.append(os.path.abspath(wordlist))
        elif Configuration.wordlist:
            wordlist_paths.append(os.path.abspath(Configuration.wordlist))

        brute_options = Hashcat._resolve_bruteforce_options()
        try:
            tasks = Hashcat._build_hashcat_tasks(wordlist_paths, brute_options)
        except FileNotFoundError as exc:
            raise ValueError(str(exc)) from exc

        hash_input = os.path.abspath(pmkid_file)
        lower_input = hash_input.lower()
        if lower_input.endswith('.16800'):
            hash_mode = '16800'
        else:
            hash_mode = '22000'

        for task in tasks:
            _, key_value = Hashcat._run_hashcat_task(hash_input, hash_mode, task, show_command=verbose)
            if key_value:
                return key_value

        return Hashcat._run_hashcat_show(hash_input, hash_mode, show_command=verbose)


class HcxDumpTool(Dependency):
    dependency_required = False
    dependency_name = 'hcxdumptool'
    dependency_url = 'https://github.com/ZerBea/hcxdumptool'

    def __init__(self, target, pcapng_file):
        # Create filterlist
        filterlist = Configuration.temp('pmkid.filterlist')
        with open(filterlist, 'w') as filter_handle:
            filter_handle.write(target.bssid.replace(':', ''))

        if os.path.exists(pcapng_file):
            os.remove(pcapng_file)

        command = [
            'hcxdumptool',
            '-i', Configuration.interface,
            '-c', f'{target.channel}a',
            '-w', pcapng_file
        ]

        self.proc = Process(command)

    def poll(self):
        return self.proc.poll()

    def interrupt(self):
        self.proc.interrupt()


class HcxPcapTool(Dependency):
    dependency_required = False
    dependency_name = 'hcxpcaptool'
    dependency_url = 'https://github.com/ZerBea/hcxtools'

    def __init__(self, target):
        self.target = target
        self.bssid = self.target.bssid.lower().replace(':', '')
        self.pmkid_file = Configuration.temp('pmkid-%s.22000' % self.bssid)

    @staticmethod
    def generate_hccapx_file(handshake, show_command=False):
        hccapx_file = Configuration.temp('generated.hccapx')
        if os.path.exists(hccapx_file):
            os.remove(hccapx_file)

        command = [
            'hcxpcaptool',
            '-o', hccapx_file,
            handshake.capfile
        ]

        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))

        process = Process(command)
        stdout, stderr = process.get_output()
        if not os.path.exists(hccapx_file):
            raise ValueError('Failed to generate .hccapx file, output: \n%s\n%s' % (
                stdout, stderr))

        return hccapx_file

    @staticmethod
    def generate_22000_file(handshake, show_command=False):
        hash_file = Configuration.temp('generated.22000')
        if os.path.exists(hash_file):
            os.remove(hash_file)

        commands = [
            ['hcxpcapngtool', '-o', hash_file, handshake.capfile],
            ['hcxpcapngtool', '--hashcat', hash_file, handshake.capfile],
        ]

        errors = []
        for command in commands:
            if show_command:
                Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))

            process = Process(command)
            stdout, stderr = process.get_output()
            if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
                return hash_file

            errors.append('Command: {0}\nStdout: {1}\nStderr: {2}'.format(
                ' '.join(command),
                Hashcat._ensure_text(stdout),
                Hashcat._ensure_text(stderr),
            ))
            if os.path.exists(hash_file):
                os.remove(hash_file)

        raise ValueError('Failed to generate .22000 file, output:\n%s' % '\n\n'.join(errors))

    @staticmethod
    def generate_john_file(handshake, show_command=False):
        john_file = Configuration.temp('generated.john')
        if os.path.exists(john_file):
            os.remove(john_file)

        command = [
            'hcxpcaptool',
            '-j', john_file,
            handshake.capfile
        ]

        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))

        process = Process(command)
        stdout, stderr = process.get_output()
        if not os.path.exists(john_file):
            raise ValueError('Failed to generate .john file, output: \n%s\n%s' % (
                stdout, stderr))

        return john_file

    def get_pmkid_hash(self, pcapng_file):
        if os.path.exists(self.pmkid_file):
            os.remove(self.pmkid_file)

        command = [
            'hcxpcapngtool',
            '--pmkid', self.pmkid_file,
            pcapng_file
        ]
        hcxpcap_proc = Process(command)
        hcxpcap_proc.wait()

        if not os.path.exists(self.pmkid_file):
            return None

        with open(self.pmkid_file, 'r') as f:
            output = f.read()
            # Each line looks like:
            # hashcat hash format v22000

        # Note: The dumptool will record *anything* it finds, ignoring the filterlist.
        # Check that we got the right target (filter by BSSID)
        matching_pmkid_hash = None
        for line in output.split('\n'):
            fields = line.split('*')
            if len(fields) >= 3 and fields[1].lower() == self.bssid:
                # Found it
                matching_pmkid_hash = line
                break

        os.remove(self.pmkid_file)
        return matching_pmkid_hash
