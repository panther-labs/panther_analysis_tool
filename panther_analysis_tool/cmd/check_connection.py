import argparse
import logging

from typing import Tuple
from panther_analysis_tool.backend.client import Client as BackendClient


def run(backend: BackendClient, args: argparse.Namespace) -> Tuple[int, str]:
    logging.info(f"checking connection to {args.api_host}...")
    result = backend.check()

    if result.success:
        logging.info(f"connection successful: {result.message}")
        return 0, ""
    else:
        logging.info(f"connection failed")
        return 1, result.message

