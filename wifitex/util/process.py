#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import signal
import os
import shlex
import atexit
import shutil
from typing import Any, IO, Optional, Sequence, Union, List

from subprocess import Popen, PIPE

from ..util.color import Color
from ..config import Configuration


class Process(object):
    ''' Represents a running/ran process '''

    _tracking_enabled = False
    _tracked_processes: List["Process"] = []

    @staticmethod
    def devnull():
        ''' Helper method for opening devnull '''
        return open('/dev/null', 'w')

    @staticmethod
    def call(command: Union[str, Sequence[Union[str, os.PathLike]]], cwd: Optional[str] = None, shell: bool = False):
        '''
            Calls a command (either string or list of args).
            Returns tuple:
                (stdout, stderr)
        '''
        run_shell = shell
        if not run_shell and isinstance(command, str) and any(ch.isspace() for ch in command):
            run_shell = True

        log_command = ''
        if run_shell:
            if isinstance(command, str):
                popen_command = command
            else:
                popen_command = ' '.join(shlex.quote(str(arg)) for arg in command)
            log_command = str(popen_command)
        else:
            if isinstance(command, str):
                popen_command_list = shlex.split(command)
            else:
                popen_command_list = [str(arg) for arg in command]
            popen_command = popen_command_list
            log_command = ' '.join(popen_command_list)

        if Configuration.verbose > 1:
            if run_shell:
                Color.pe('\n {C}[?] {W} Executing (Shell): {B}%s{W}' % log_command)
            else:
                Color.pe('\n {C}[?]{W} Executing: {B}%s{W}' % log_command)

        pid = Popen(popen_command, cwd=cwd, stdout=PIPE, stderr=PIPE, shell=run_shell)
        pid.wait()
        (stdout, stderr) = pid.communicate()

        # Python 3 compatibility
        if isinstance(stdout, bytes):
            stdout = stdout.decode('utf-8', errors='ignore')
        if isinstance(stderr, bytes):
            stderr = stderr.decode('utf-8', errors='ignore')


        if Configuration.verbose > 1 and isinstance(stdout, str):
            stdout_text = stdout.strip()
            if stdout_text != '':
                Color.pe('{P} [stdout] %s{W}' % '\n [stdout] '.join(stdout_text.splitlines()))
        if Configuration.verbose > 1 and isinstance(stderr, str):
            stderr_text = stderr.strip()
            if stderr_text != '':
                Color.pe('{P} [stderr] %s{W}' % '\n [stderr] '.join(stderr_text.splitlines()))

        return (stdout, stderr)

    @staticmethod
    def exists(program):
        ''' Checks if program is installed on this system '''
        return Process.which(program) is not None

    @staticmethod
    def which(program: Optional[Union[str, os.PathLike]]):
        ''' Returns absolute path to program, or None if not found '''
        if not program:
            return None
        try:
            return shutil.which(str(program))
        except Exception:
            return None

    @staticmethod
    def get_version(program: Union[str, os.PathLike],
                    version_args: Optional[Union[str, Sequence[str]]] = None) -> Optional[str]:
        '''
            Attempts to fetch a version string for the given program.
            Returns first non-empty line of stdout/stderr, or None if version could not be determined.
        '''
        if not program:
            return None

        if version_args is None:
            args: Sequence[str] = ('--version',)
        elif isinstance(version_args, str):
            args = (version_args,)
        else:
            args = tuple(str(arg) for arg in version_args)

        if len(args) == 0:
            return None

        cmd: List[str] = [str(program)]
        cmd.extend(args)

        try:
            stdout, stderr = Process.call(cmd)
        except Exception:
            return None

        for stream in (stdout, stderr):
            if isinstance(stream, bytes):
                stream = stream.decode('utf-8', errors='ignore')
            if isinstance(stream, str):
                text = stream.strip()
                if text != '':
                    return text.splitlines()[0]

        return None

    def __init__(self,
            command: Union[str, Sequence[Union[str, os.PathLike]]],
            devnull: bool = False,
            stdout: Union[int, IO[Any]] = PIPE,
            stderr: Union[int, IO[Any]] = PIPE,
            cwd: Optional[str] = None,
            bufsize: int = 0,
            stdin: Union[int, IO[Any]] = PIPE):
        ''' Starts executing command '''

        if isinstance(command, str):
            # Commands have to be a list
            command_args = shlex.split(command)
        else:
            command_args = [str(arg) for arg in command]

        self.command = command_args

        if Configuration.verbose > 1:
            Color.pe('\n {C}[?] {W} Executing: {B}%s{W}' % ' '.join(command_args))

        self.out = None
        self.err = None
        if devnull:
            sout = Process.devnull()
            serr = Process.devnull()
        else:
            sout = stdout
            serr = stderr

        self.start_time = time.time()

        self.pid = Popen(command_args, stdout=sout, stderr=serr, stdin=stdin, cwd=cwd, bufsize=bufsize)
        self._track_process()

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

    def stdout(self):
        ''' Waits for process to finish, returns stdout output '''
        self.get_output()
        if Configuration.verbose > 1 and isinstance(self.out, str):
            out_text = self.out.strip()
            if out_text != '':
                Color.pe('{P} [stdout] %s{W}' % '\n [stdout] '.join(out_text.splitlines()))
        return self.out

    def stderr(self):
        ''' Waits for process to finish, returns stderr output '''
        self.get_output()
        if Configuration.verbose > 1 and isinstance(self.err, str):
            err_text = self.err.strip()
            if err_text != '':
                Color.pe('{P} [stderr] %s{W}' % '\n [stderr] '.join(err_text.splitlines()))
        return self.err

    def stdoutln(self):
        if self.pid.stdout:
            line = self.pid.stdout.readline()
            if isinstance(line, bytes):
                return line.decode('utf-8', errors='ignore')
            return line
        return ''

    def stderrln(self):
        if self.pid.stderr:
            line = self.pid.stderr.readline()
            if isinstance(line, bytes):
                return line.decode('utf-8', errors='ignore')
            return line
        return ''

    def stdin(self, text):
        if self.pid.stdin:
            self.pid.stdin.write(text.encode('utf-8'))
            self.pid.stdin.flush()

    def get_output(self):
        ''' Waits for process to finish, sets stdout & stderr '''
        if self.pid.poll() is None:
            self.pid.wait()
        if self.out is None:
            (self.out, self.err) = self.pid.communicate()

        if isinstance(self.out, bytes):
            self.out = self.out.decode('utf-8', errors='ignore')

        if isinstance(self.err, bytes):
            self.err = self.err.decode('utf-8', errors='ignore')

        return (self.out, self.err)

    def poll(self):
        ''' Returns exit code if process is dead, otherwise 'None' '''
        return self.pid.poll()

    def wait(self):
        self.pid.wait()

    def running_time(self):
        ''' Returns number of seconds since process was started '''
        return int(time.time() - self.start_time)

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
                return
            raise e  # process cannot be killed

    @classmethod
    def enable_process_tracking(cls):
        if cls._tracking_enabled:
            return
        cls._tracking_enabled = True
        atexit.register(cls._cleanup_tracked_processes)

    @classmethod
    def disable_process_tracking(cls):
        cls._tracking_enabled = False
        cls._tracked_processes.clear()

    @classmethod
    def _track(cls, proc: "Process"):
        if cls._tracking_enabled:
            cls._tracked_processes.append(proc)

    @classmethod
    def _cleanup_tracked_processes(cls):
        for proc in cls._tracked_processes:
            try:
                if proc.pid and proc.pid.poll() is None:
                    proc.interrupt()
            except Exception:
                pass
        cls._tracked_processes.clear()

    @classmethod
    def cleanup_all_processes(cls):
        """
        Public helper for wiping out any processes being tracked by the helper.
        UI callers rely on this to make sure no lingering subprocesses survive
        when the application exits.

        The tracker is only active when explicitly enabled, so guard against the
        method being called while tracking is disabled.
        """
        if not cls._tracking_enabled:
            return
        cls._cleanup_tracked_processes()

    def _track_process(self):
        self.__class__._track(self)


if __name__ == '__main__':
    Configuration.initialize(False)
    p = Process('ls')
    print(p.stdout())
    print(p.stderr())
    p.interrupt()

    # Calling as list of arguments
    (out, err) = Process.call(['ls', '-lah'])
    print(out)
    print(err)

    print('\n---------------------\n')

    # Calling as string
    (out, err) = Process.call('ls -l | head -2')
    print(out)
    print(err)

    print('"reaver" exists: %s' % Process.exists('reaver'))

    # Test on never-ending process
    p = Process('yes')
    print('Running yes...')
    time.sleep(1)
    print('yes should stop now')
    # After program loses reference to instance in 'p', process dies.

