import logging
import os
import runpy
import sys
from typing import Dict, List

import jsonlines


def run_sdk_module(panther_sdk_cache_path: str) -> None:
    if not os.path.exists(os.path.join("panther_content", "__main__.py")):
        raise FileNotFoundError("Did not find a Panther SDK based module at ./panther_content")

    try:
        os.remove(panther_sdk_cache_path)
    except FileNotFoundError:
        pass

    path_had_cwd = os.getcwd() in sys.path
    if not path_had_cwd:
        sys.path.append(os.getcwd())
    runpy.run_module("panther_content")
    if not path_had_cwd:
        sys.path.remove(os.getcwd())

    if not os.path.exists(panther_sdk_cache_path):
        logging.error("panther_content did not generate %s", panther_sdk_cache_path)
        raise FileNotFoundError(f"panther_content did not generate {panther_sdk_cache_path}")


def get_sdk_cache_path() -> str:
    return os.path.join(".panther", "panther-sdk-cache")


def load_intermediate_sdk_cache(panther_sdk_cache_path: str) -> List[Dict]:
    """Load intermediate Panther SDK code from the cache.

    Returns:
        A list of the intermediate json as dicts.
    """
    if not os.path.exists(panther_sdk_cache_path):
        raise FileNotFoundError(f"No file exists with path {panther_sdk_cache_path}")

    with jsonlines.open(panther_sdk_cache_path) as reader:
        return [obj for obj in reader]  # pylint: disable=R1721
