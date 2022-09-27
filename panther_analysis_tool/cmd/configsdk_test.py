import argparse
import logging
from typing import Tuple


def run(args: argparse.Namespace) -> Tuple[int, list]:
    """Runs unit tests for config sdk detections.

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A tuple of the return code, and a list of tuples containing invalid specs and their error.
    """
    logging.info("running config detections")

    return 1, []
