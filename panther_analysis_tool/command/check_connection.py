import argparse
import logging
from typing import Tuple

from panther_analysis_tool.backend.client import Client as BackendClient


def run(backend: BackendClient, args: argparse.Namespace) -> Tuple[int, str]:
    logging.info("checking connection to %s...", args.api_host)
    result = backend.check()

    if not result.success:
        logging.info("connection failed")
        return 1, result.message

    logging.info("connection successful: %s", result.message)
    return 0, ""
