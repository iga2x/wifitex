#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Thin entry-point wrapper for launching the WifiteX GUI."""

from __future__ import annotations

import sys

from PyQt6.QtWidgets import QApplication

from .main_window import WifitexMainWindow


def main() -> int:
    """Launch the WifiteX GUI."""
    app = QApplication(sys.argv)
    main_window = WifitexMainWindow()
    main_window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
