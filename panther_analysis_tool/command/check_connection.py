import logging
from typing import Tuple

from panther_analysis_tool.backend.client import Client as BackendClient


def run(backend: BackendClient, api_host: str) -> Tuple[int, str]:
    logging.info("checking connection to %s...", api_host)
    result = backend.check()

    if not result.success:
        logging.info("connection failed")
        return 1, result.message

    logging.info("connection successful: %s", result.message)
    return 0, ""
