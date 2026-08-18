#!/usr/bin/env python3
"""
ghostwire.py — top-level shim.

Delegates to the ghostwire package CLI so that both
  python ghostwire.py <args>
and
  python -m ghostwire <args>
work identically. All logic lives in the ghostwire/ package.
"""
from ghostwire.cli import main

if __name__ == '__main__':
    main()
