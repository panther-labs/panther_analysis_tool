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
from functools import partial, reduce
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
)


def allowed_char(char: str) -> bool:
    """Is char part of a valid python identifier?"""
    return char.isalnum() or char in " -."


def id_to_path(directory: str, object_id: str) -> str:
    """Convert an object id to a path in the given directory"""
    safe_id = "".join(x if allowed_char(x) else "_" for x in object_id)
    return os.path.join(directory, f"{safe_id}.py")


def get_latest_version() -> str:
    """Get the latest version of the package from pypi"""
    url = f"https://pypi.org/pypi/{PACKAGE_NAME}/json"
    try:
        res = requests.get(url, timeout=30)
        res.raise_for_status()
        info = res.json().get("info", {})
        return info.get("version", "unknown")
    except requests.exceptions.RequestException:
        logging.debug("Unable to retrieve package version from pypi", exc_info=True)
        return "unknown"


def is_latest(latest_version: str) -> bool:
    """Is the current version the latest? Return true if we can't check."""
    try:
        return version.parse(VERSION_STRING) >= version.parse(latest_version)
    except version.InvalidVersion:
        logging.debug("Unable to determine latest version", exc_info=True)
        return True


def import_file_as_module(path: str, object_id: str) -> Any:
    """Import a file as a module by object id"""
    spec = import_util.spec_from_file_location(object_id, path)
    mod = import_util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def store_modules(path: str, body: str) -> None:
    """Store a file at the given path with the given body"""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)


def get_client(service: str, args: argparse.Namespace) -> boto3.client:
    """Get a boto3 client for the given service"""
    aws_profile = getattr(args, "aws_profile", None)
    if aws_profile:
        logging.info("Using AWS profile: %s", aws_profile)
        os.environ["AWS_PROFILE"] = aws_profile
        return boto3.Session(profile_name=aws_profile).client(service)
    return boto3.client(service)


def create_client(client_class, options_class, **kwargs) -> BackendClient:
    """Create a backend client with the given options"""
    return client_class(options_class(**kwargs))


def get_datalake_lambda(athena_datalake: Optional[bool] = None) -> str:
    """Get the name of the datalake lambda"""
    return "panther-athena-api" if athena_datalake else "panther-snowflake-api"


def get_backend(args: argparse.Namespace, athena_datalake: Optional[bool] = None) -> BackendClient:
    api_token = getattr(args, "api_token", None)
    aws_profile = getattr(args, "aws_profile", None)
    if api_token:
        return create_client(
            PublicAPIClient, PublicAPIClientOptions, api_token=api_token, user_id=PANTHER_USER_ID
        )
    if aws_profile:
        lambda_opts = get_datalake_lambda(athena_datalake)
        return create_client(
            LambdaClient,
            LambdaClientOpts,
            aws_profile=aws_profile,
            datalake_lambda=lambda_opts,
            user_id=PANTHER_USER_ID,
        )
    raise ValueError("Neither api_token nor aws_profile provided.")


def func_with_backend_or_optional(
    func: Callable, backend_getter: Callable, args: argparse.Namespace
) -> Tuple[int, str]:
    return func(args, backend_getter(args.api_token, args.aws_profile, args.athena_datalake))


def get_optional_backend(args: argparse.Namespace) -> Optional[BackendClient]:
    """Get a backend client for the given api_token or aws_profile"""
    if args.api_token:
        return PublicAPIClient(
            PublicAPIClientOptions(
                token=args.api_token, user_id=PANTHER_USER_ID, host=args.api_host
            )
        )
    return None


def func_with_backend(
    func: Callable[[BackendClient, argparse.Namespace], Any]
) -> Callable[[argparse.Namespace], Tuple[int, str]]:
    """Wrap a function that takes a backend client and args with a function that takes args and returns a tuple of exit code and output"""
    return partial(func_with_backend_or_optional, func, get_backend)


def func_with_optional_backend(
    func: Callable[[argparse.Namespace, Optional[BackendClient]], Any]
) -> Callable[[argparse.Namespace], Tuple[int, str]]:
    """Wrap a function that takes a backend client and args with a function that takes args and returns a tuple of exit code and output"""
    return partial(func_with_backend_or_optional, func, get_optional_backend)


def set_env(key: str, value: str) -> None:
    """Set an environment variable"""
    os.environ[key] = value


def convert_keys_to_lowercase(mapping: Dict[str, Any]) -> Dict[str, Any]:
    """Convert the keys of a mapping to lowercase"""
    return {key.lower(): value for key, value in mapping.items()}


def deep_get(obj: Dict, path: List[str], default: Any = None) -> Any:
    """Get a value from a nested dictionary by path"""
    result = reduce(lambda val, key: val.get(key) if val else None, path, obj)
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
    """Is the analysis item a simple detection?"""
    return analysis_item.get("Detection") is not None


def is_derived_detection(analysis_item: Dict[str, Any]) -> bool:
    """Is the analysis item a derived detection?"""
    return analysis_item.get("BaseDetection") is not None


def add_path_to_filename(output_path: str, filename: str) -> str:
    """Add the output path to the filename if it exists"""
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
    """Log the messages and write them to the given file"""
    for msg in msgs:
        filename.write(msg + "\n")
        logging.info(msg)
