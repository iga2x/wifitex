#!/usr/bin/env python
# -*- coding: utf-8 -*-

from typing import ClassVar, Optional, Sequence


class Dependency(object):
    dependency_name: ClassVar[str]
    dependency_url: ClassVar[str]
    dependency_required: ClassVar[bool]
    dependency_version_args: ClassVar[Optional[Sequence[str]]] = None
    required_attr_names = ['dependency_name', 'dependency_url', 'dependency_required']

    # https://stackoverflow.com/a/49024227
    def __init_subclass__(cls):
        for attr_name in cls.required_attr_names:
            if not attr_name in cls.__dict__:
                raise NotImplementedError(
                    'Attribute "{}" has not been overridden in class "{}"' \
                    .format(attr_name, cls.__name__)
                )


    @classmethod
    def exists(cls):
        from ..util.process import Process
        return Process.exists(cls.dependency_name)

    @classmethod
    def dependency_path(cls) -> Optional[str]:
        from ..util.process import Process
        return Process.which(cls.dependency_name)

    @classmethod
    def dependency_version(cls) -> Optional[str]:
        from ..util.process import Process
        if cls.dependency_version_args is None:
            return None
        return Process.get_version(cls.dependency_name, cls.dependency_version_args)


    @classmethod
    def run_dependency_check(cls):
        from ..util.color import Color

        from .airmon import Airmon
        from .airodump import Airodump
        from .aircrack import Aircrack
        from .aireplay import Aireplay
        from .ifconfig import Ifconfig
        from .iwconfig import Iwconfig
        from .bully import Bully
        from .reaver import Reaver
        from .wash import Wash
        from .pixiewps import Pixiewps
        from .tshark import Tshark
        from .macchanger import Macchanger
        from .hashcat import Hashcat, HcxDumpTool, HcxPcapTool
        from .john import John
        from .cowpatty import Cowpatty

        apps = [
                # Aircrack
                Aircrack, Airodump, Airmon, Aireplay,
                # wireless/net tools
                Iwconfig, Ifconfig,
                # WPS
                Reaver, Bully, Wash, Pixiewps,
                # Cracking/handshakes
                Tshark, John, Cowpatty,
                # Hashcat
                Hashcat, HcxDumpTool, HcxPcapTool,
                # Misc
                Macchanger
            ]

        missing_required = any([app.fails_dependency_check() for app in apps])

        from ..config import Configuration
        if Configuration.verbose > 0:
            for app in apps:
                if not app.exists():
                    continue
                path = app.dependency_path()
                version = app.dependency_version()
                info_parts = []
                if path:
                    info_parts.append('path={C}%s{W}' % path)
                if version:
                    info_parts.append('version={C}%s{W}' % version)
                if info_parts:
                    Color.pl('{+} {G}%s{W} (%s)' % (
                        app.dependency_name,
                        ', '.join(info_parts)))

        if missing_required:
            Color.pl('{!} {O}At least 1 Required app is missing. Wifitex needs Required apps to run{W}')
            import sys
            sys.exit(-1)


    @classmethod
    def fails_dependency_check(cls):
        from ..util.color import Color
        from ..util.process import Process

        if Process.exists(cls.dependency_name):
            return False

        if cls.dependency_required:
            Color.p('{!} {O}Error: Required app {R}%s{O} was not found' % cls.dependency_name)
            Color.pl('. {W}install @ {C}%s{W}' % cls.dependency_url)
            return True

        else:
            Color.p('{!} {O}Warning: Recommended app {R}%s{O} was not found' % cls.dependency_name)
            Color.pl('. {W}install @ {C}%s{W}' % cls.dependency_url)
            return False
