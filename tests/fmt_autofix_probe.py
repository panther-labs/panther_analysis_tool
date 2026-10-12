"""Throwaway file to exercise fmt auto-commit; do not merge."""
import sys
import os


def probe( value : str ) -> str:
    return os.path.join( value,sys.prefix )
