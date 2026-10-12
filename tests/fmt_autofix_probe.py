"""Throwaway file to exercise fmt auto-commit; do not merge."""

import os
import sys


def probe(value: str) -> str:
    return os.path.join(value, sys.prefix)
