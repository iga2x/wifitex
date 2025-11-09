#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Setup script for Wifitex
"""

from setuptools import setup, find_packages

# Read version from config file directly
import os
import re

def get_version():
    version_file = os.path.join(os.path.dirname(__file__), 'wifitex', 'config.py')
    with open(version_file, 'r') as f:
        content = f.read()
    match = re.search(r"version = '([^']+)'", content)
    if match:
        return match.group(1)
    return '2.7.0'

# Read the README file for long description
try:
    with open('README.md', 'r', encoding='utf-8') as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = 'Wireless Network Auditor for Linux.'

# Read requirements
try:
    with open('requirements-gui.txt', 'r') as f:
        gui_requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]
except FileNotFoundError:
    gui_requirements = []

setup(
    # Basic information
    name='wifitex',
    version=get_version(),
    author='iga2x',
    author_email='mdpoo2@gmail.com',
    url='https://github.com/iga2x/wifitex',
    description='Wireless Network Auditor for Linux',
    long_description=long_description,
    long_description_content_type='text/markdown',
    
    # License
    license='GNU GPLv2',
    
    # Package information
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    
    # Python version requirements
    python_requires='>=3.6',
    
    # Dependencies
    install_requires=[
        'psutil>=5.9.6',
        'requests>=2.31.0',
    ],
    
    # Optional GUI dependencies
    extras_require={
        'gui': gui_requirements,
        'all': gui_requirements,
    },
    
    # Entry points
    entry_points={
        'console_scripts': [
            'wifitex = wifitex.__main__:entry_point',
            'wifitex-gui = wifitex.gui.__main__:main'
        ],
    },
    
    # Scripts
    # Note: bin/wifitex is kept for development use
    # wifitex-gui and wifitex-gui-desktop are handled by install.sh script
    # which creates wifitex-gui-launcher and wifitex-gui at install time
    scripts=['bin/wifitex'],
    
    # Data files
    data_files=[
        ('share/applications', ['data/wifitex-gui.desktop']),
        ('share/polkit-1/actions', ['data/wifitex-gui.policy']),
        ('share/pixmaps', [
            'icons/wifitex-256x256.png',
            'icons/wifitex-128x128.png', 
            'icons/wifitex-64x64.png',
            'icons/wifitex-48x48.png',
            'icons/wifitex-32x32.png',
            'icons/wifitex-24x24.png',
            'icons/wifitex-22x22.png',
            'icons/wifitex-16x16.png',
            'icons/wifitex.svg',
            'icons/wifitex.ico',
            'icons/wifitex.xpm'
        ]),
        ('share/doc/wifitex', [
            'README.md',
            'LICENSE', 
            'GUI_README.md',
            'PMKID.md',
            'EVILTWIN.md'
        ]),
        ('share/man/man1', [
            'man/wifitex.1',
            'man/wifitex-gui.1'
        ]),
        ('share/wifitex', [
            'wordlist-top4800-probable.txt'
        ]),
    ],
    
    # Classifiers
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
    ],
    
    # Keywords
    keywords='wireless, wifi, security, audit, penetration testing, aircrack-ng, wpa, wep, wps',
    
    # Project URLs
    project_urls={
        'Bug Reports': 'https://github.com/iga2x/wifitex/issues',
        'Source': 'https://github.com/iga2x/wifitex',
        'Documentation': 'https://github.com/iga2x/wifitex/blob/master/README.md',
    },
)