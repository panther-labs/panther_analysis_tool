"""
Panther Analysis Tool is a command line interface for writing,
testing, and packaging policies/rules.
Copyright (C) 2020 Panther Labs Inc

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import argparse
import logging
import os
import re
from functools import reduce
from importlib import util as import_util
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TextIO, Tuple

import boto3
import requests
from packaging import version

from panther_analysis_tool.backend.client import Client as BackendClient
from panther_analysis_tool.backend.lambda_client import LambdaClient, LambdaClientOpts
from panther_analysis_tool.backend.public_api_client import (
    PublicAPIClient,
    PublicAPIClientOptions,
)
from panther_analysis_tool.constants import (
    PACKAGE_NAME,
    PANTHER_USER_ID,
    VERSION_STRING,
    AnalysisTypes,
)

UNKNOWN_VERSION = "unknown"


class BackendNotFoundException(Exception):
    pass


def allowed_char(char: str) -> bool:
    """Return true if the character is part of a valid ID."""
    return char.isalnum() or char in {" ", "-", "."}


def id_to_path(directory: str, object_id: str) -> str:
    """Method returns the file path where the module will be stored"""
    safe_id = "".join(x if allowed_char(x) else "_" for x in object_id)
    path = os.path.join(directory, safe_id + ".py")
    return path


def get_latest_version() -> str:
    try:
        response = requests.get(f"https://pypi.org/pypi/{PACKAGE_NAME}/json")
        if response.status_code == 200:
            return response.json().get("info", {}).get("version", UNKNOWN_VERSION)
    except Exception:  # pylint: disable=broad-except
        logging.debug("Unable to determine latest version", exc_info=True)
    return UNKNOWN_VERSION


def is_latest(latest_version: str) -> bool:
    try:
        return version.parse(VERSION_STRING) >= version.parse(latest_version)
    except Exception:  # pylint: disable=broad-except
        logging.debug("Unable to determine latest version", exc_info=True)
    # if we run into any issues connecting or parsing the version,
    # we should just return True
    return True


def import_file_as_module(path: str, object_id: str) -> Any:
    """Dynamically import a Python module from a file.

    See also: https://docs.python.org/3/library/importlib.html#importing-a-source-file-directly
    """

    spec = import_util.spec_from_file_location(object_id, path)
    mod = import_util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


def store_modules(path: str, body: str) -> None:
    """Stores modules to disk."""
    # Create dir if it doesn't exist
    Path(os.path.dirname(path)).mkdir(parents=True, exist_ok=True)
    with open(path, "w") as py_file:
        py_file.write(body)


def get_client(aws_profile: str, service: str) -> boto3.client:
    # optionally set env variable for profile passed as argument
    if aws_profile is not None:
        logging.info("Using AWS profile: %s", aws_profile)
        set_env("AWS_PROFILE", aws_profile)
        sess = boto3.Session(profile_name=aws_profile)
        client = sess.client(service)
    else:
        client = boto3.client(service)
    return client


def func_with_api_backend(
    func: Callable[[BackendClient, argparse.Namespace], Any]
) -> Callable[[argparse.Namespace], Tuple[int, str]]:
    return lambda args: func(get_api_backend(args), args)


def func_with_backend(
    func: Callable[[BackendClient, argparse.Namespace], Any]
) -> Callable[[argparse.Namespace], Tuple[int, str]]:
    return lambda args: func(get_backend(args), args)


def func_with_optional_backend(
    func: Callable[[argparse.Namespace, Optional[BackendClient]], Any]
) -> Callable[[argparse.Namespace], Tuple[int, str]]:
    return lambda args: func(args, get_optional_backend(args))


def get_optional_backend(args: argparse.Namespace) -> Optional[BackendClient]:
    if args.api_token:
        return PublicAPIClient(
            PublicAPIClientOptions(
                token=args.api_token, user_id=PANTHER_USER_ID, host=args.api_host
            )
        )

    return None


def get_api_backend(args: argparse.Namespace) -> BackendClient:
    if not args.api_token:
        raise BackendNotFoundException("This function requires an API token. API token not found.")

    return PublicAPIClient(
        PublicAPIClientOptions(token=args.api_token, user_id=PANTHER_USER_ID, host=args.api_host)
    )


def get_backend(args: argparse.Namespace) -> BackendClient:
    if args.api_token:
        return PublicAPIClient(
            PublicAPIClientOptions(
                token=args.api_token, user_id=PANTHER_USER_ID, host=args.api_host
            )
        )

    datalake_lambda = get_datalake_lambda(args)

    return LambdaClient(
        LambdaClientOpts(
            user_id=PANTHER_USER_ID,
            aws_profile=args.aws_profile,
            datalake_lambda=datalake_lambda,
        )
    )


def get_datalake_lambda(args: argparse.Namespace) -> str:
    if "athena_datalake" not in args:
        return ""

    return "panther-athena-api" if args.athena_datalake else "panther-snowflake-api"


def set_env(key: str, value: str) -> None:
    os.environ[key] = value


def convert_keys_to_lowercase(mapping: Dict[str, Any]) -> Dict[str, Any]:
    """A helper function for converting top-level dictionary keys to lowercase.
    Converting keys to lowercase maintains compatibility with how the backend
    behaves.

    Args:
        mapping: The dictionary.

    Returns:
        A new dictionary with each key converted with str.lower()
    """
    return {k.lower(): v for k, v in mapping.items()}


def deep_get(obj: Dict, path: List[str], default: Any = None) -> Any:
    result = reduce(lambda val, key: val.get(key) if val else None, path, obj)  # type: ignore
    return result if result is not None else default


def to_list(listish: Any) -> List:
    """Make a single instance a list or keep a list a list."""
    return listish if isinstance(listish, list) else [listish]


def convert_unicode(obj: Any) -> str:
    """Swap unicode 4 byte strings with arbitrary numbers of leading slashes with the actual character
    e.g. \\\\u003c => <"""
    string_to_convert = str(obj)
    return re.sub(r"\\*\\u([0-9a-f]{4})", lambda m: chr(int(m.group(1), 16)), string_to_convert)


def is_simple_detection(analysis_item: Dict[str, Any]) -> bool:
    return all(
        [
            analysis_item.get("Detection") is not None,
            is_correlation_rule(analysis_item) is False,
            is_policy(analysis_item) is False,
        ]
    )


def is_correlation_rule(analysis_item: Dict[str, Any]) -> bool:
    return analysis_item.get("AnalysisType") == AnalysisTypes.CORRELATION_RULE


def is_policy(analysis_item: Dict[str, Any]) -> bool:
    return analysis_item.get("AnalysisType") == AnalysisTypes.POLICY


def is_derived_detection(analysis_item: Dict[str, Any]) -> bool:
    return analysis_item.get("BaseDetection") is not None


def add_path_to_filename(output_path: str, filename: str) -> str:
    if output_path:
        if not os.path.isdir(output_path):
            logging.info(
                "Creating directory: %s",
                output_path,
            )
            os.makedirs(output_path)
        filename = f"{output_path.rstrip('/')}/{filename}"

    return filename


def log_and_write_to_file(msgs: List[str], filename: TextIO) -> None:
    for msg in msgs:
        filename.write(msg + "\n")
        logging.info(msg)
