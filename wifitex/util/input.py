#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Fix for Python 2/3 compatibility of input/raw_input and range/xrange.
import builtins

raw_input = getattr(builtins, "raw_input", builtins.input)
input = raw_input

xrange = getattr(builtins, "xrange", builtins.range)
range = xrange
