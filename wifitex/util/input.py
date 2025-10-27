#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Compatibility for Python 2 and 3
import sys

if sys.version_info[0] < 3:
    # Python 2: use raw_input
    input = raw_input
    raw_input = raw_input
    range = xrange
else:
    # Python 3: input and range are already correct
    from builtins import input, range
    raw_input = input  # For compatibility with code expecting raw_input
    xrange = range  # For compatibility with code expecting xrange
