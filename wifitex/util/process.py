#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import signal
import os
from typing import Optional, Tuple, Union, List

from subprocess import Popen, PIPE

from ..util.color import Color
from ..config import Configuration


class Process(object):
    ''' Represents a running/ran process '''
    
    # Global process tracker for cleanup
    _global_processes = []
    _process_tracker_enabled = False

    @staticmethod
    def enable_process_tracking():
        """Enable global process tracking for cleanup"""
        Process._process_tracker_enabled = True

    @staticmethod
    def disable_process_tracking():
        """Disable global process tracking"""
        Process._process_tracker_enabled = False

    @staticmethod
    def cleanup_all_processes():
        """Cleanup all tracked processes"""
        for process in Process._global_processes[:]:  # Copy list to avoid modification during iteration
            try:
                if hasattr(process, 'interrupt'):
                    process.interrupt()
                elif hasattr(process, 'terminate'):
                    process.terminate()
                elif hasattr(process, 'kill'):
                    process.kill()
            except Exception:
                pass
        Process._global_processes.clear()

    @staticmethod
    def devnull():
        ''' Helper method for opening devnull using dynamic device path '''
        # Use dynamic device path detection
        dev_null_path = '/dev/null'
        return open(dev_null_path, 'w')

    @staticmethod
    def call(command, cwd=None, shell=False) -> Tuple[str, str]:
        '''
            Calls a command (either string or list of args).
            Returns tuple:
                (stdout, stderr)
        '''
        # Determine shell mode
        if type(command) is str or ' ' in command or shell:
            shell = True
        else:
            shell = False

        # Execute command
        pid = Popen(command, cwd=cwd, stdout=PIPE, stderr=PIPE, shell=shell)
        (stdout_bytes, stderr_bytes) = pid.communicate()

        # Decode output
        stdout: str = Process.decode_output(stdout_bytes)
        stderr: str = Process.decode_output(stderr_bytes)

        return (stdout, stderr)

    @staticmethod
    def exists(program):
        ''' Checks if program is installed on this system '''
        stdout, stderr = Process.call(['which', program])
        stdout = stdout.strip()
        stderr = stderr.strip()

        if stdout == '' and stderr == '':
            return False
        else:
            return True

    @staticmethod
    def decode_output(output_bytes):
        '''Helper method to decode bytes to string with Python 3 compatibility'''
        if isinstance(output_bytes, bytes):
            return output_bytes.decode('utf-8')
        return output_bytes

    @staticmethod
    def format_verbose_output(output, output_type='stdout'):
        '''Helper method to format verbose output with Color.pe()'''
        if Configuration.verbose > 1 and output is not None and output.strip() != '':
            Color.pe('{P} [%s] %s{W}' % (output_type, '\n [%s] '.join(output.strip().split('\n')) % output_type))

    @staticmethod
    def build_wps_command(tool_name, target, interface, pixie_dust=False, extra_args=None):
        '''Helper method to build common WPS command patterns'''
        cmd = [tool_name]
        
        # Add common WPS arguments
        if tool_name == 'reaver':
            cmd.extend([
                '--interface', interface,
                '--bssid', target.bssid,
                '--channel', target.channel,
                '-vv'
            ])
            if pixie_dust:
                cmd.extend(['--pixie-dust', '1'])
        elif tool_name == 'bully':
            # Add stdbuf if available
            if Process.exists('stdbuf'):
                cmd = ['stdbuf', '-o0'] + cmd
            
            cmd.extend([
                '--bssid', target.bssid,
                '--channel', target.channel,
                '--force',
                '-v', '4',
                interface
            ])
            if pixie_dust:
                cmd.insert(-1, '--pixiewps')
        
        # Add any extra arguments
        if extra_args:
            cmd.extend(extra_args)
            
        return cmd

    def __init__(self, command: Union[str, List[str]], devnull: bool = False, stdout=PIPE, stderr=PIPE, cwd: Optional[str] = None, bufsize: int = 0, stdin=PIPE):
        ''' Starts executing command '''

        if type(command) is str:
            # Commands have to be a list
            command = command.split(' ')

        self.command = command

        if Configuration.verbose > 1:
            Color.pe('\n {C}[?] {W} Executing: {B}%s{W}' % ' '.join(command))

        self.out: Optional[str] = None
        self.err: Optional[str] = None
        if devnull:
            sout = Process.devnull()
            serr = Process.devnull()
        else:
            sout = stdout
            serr = stderr

        self.start_time = time.time()

        self.pid = Popen(command, stdout=sout, stderr=serr, stdin=stdin, cwd=cwd, bufsize=bufsize)
        
        # Register this process for cleanup if tracking is enabled
        if Process._process_tracker_enabled:
            Process._global_processes.append(self)

    def __del__(self):
        '''
            Ran when object is GC'd.
            If process is still running at this point, it should die.
        '''
        try:
            if self.pid and self.pid.poll() is None:
                self.interrupt()
        except AttributeError:
            pass

    def stdout(self) -> str:
        ''' Waits for process to finish, returns stdout output '''
        self.get_output()
        Process.format_verbose_output(self.out, 'stdout')
        return self.out or ''

    def stderr(self) -> str:
        ''' Waits for process to finish, returns stderr output '''
        self.get_output()
        Process.format_verbose_output(self.err, 'stderr')
        return self.err or ''

    def get_output(self) -> Tuple[str, str]:
        ''' Waits for process to finish, returns tuple (stdout, stderr) '''
        if self.out is None or self.err is None:
            (stdout_bytes, stderr_bytes) = self.pid.communicate()
            self.out = Process.decode_output(stdout_bytes)
            self.err = Process.decode_output(stderr_bytes)
        return (self.out, self.err)

    def poll(self):
        ''' Returns None if process is still running, otherwise returns exit code '''
        return self.pid.poll()

    def wait(self):
        ''' Waits for process to finish '''
        return self.pid.wait()

    def running_time(self) -> float:
        ''' Returns how long the process has been running (in seconds) '''
        return time.time() - self.start_time

    def interrupt(self, wait_time=2.0):
        '''
            Send interrupt to current process.
            If process fails to exit within `wait_time` seconds, terminates it.
        '''
        try:
            pid = self.pid.pid
            cmd = self.command
            if type(cmd) is list:
                cmd = ' '.join(cmd)

            if Configuration.verbose > 1:
                Color.pe('\n {C}[?] {W} sending interrupt to PID %d (%s)' % (pid, cmd))

            os.kill(pid, signal.SIGINT)

            start_time = time.time()  # Time since Interrupt was sent
            while self.pid.poll() is None:
                # Process is still running
                time.sleep(0.1)
                if time.time() - start_time > wait_time:
                    # We waited too long for process to die, terminate it.
                    if Configuration.verbose > 1:
                        Color.pe('\n {C}[?] {W} Waited > %0.2f seconds for process to die, killing it' % wait_time)
                    os.kill(pid, signal.SIGTERM)
                    self.pid.terminate()
                    break

        except OSError as e:
            if 'No such process' in e.__str__():
                pass  # Process already died
            else:
                Color.pl('\n{!} {R}Error interrupting process: {O}%s{W}' % str(e))
        except Exception as e:
            Color.pl('\n{!} {R}Error interrupting process: {O}%s{W}' % str(e))

    def terminate(self):
        ''' Terminates the process '''
        try:
            self.pid.terminate()
        except Exception as e:
            Color.pl('\n{!} {R}Error terminating process: {O}%s{W}' % str(e))

    def kill(self):
        ''' Kills the process '''
        try:
            self.pid.kill()
        except Exception as e:
            Color.pl('\n{!} {R}Error killing process: {O}%s{W}' % str(e))

    def stdoutln(self):
        ''' Reads a line from stdout while process is running. Returns bytes or None. '''
        try:
            if self.pid.stdout:
                return self.pid.stdout.readline()
        except Exception:
            pass
        return None