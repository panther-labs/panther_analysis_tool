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

from importlib import util as import_util
from pathlib import Path
from typing import Any, Callable, Tuple

import boto3

from panther_analysis_tool.backend.client import Client as BackendClient
from panther_analysis_tool.backend.public_api_client import PublicAPIClient, PublicAPIClientOptions
from panther_analysis_tool.backend.lambda_client import LambdaClient, LambdaClientOpts


def allowed_char(char: str) -> bool:
    """Return true if the character is part of a valid ID."""
    return char.isalnum() or char in {" ", "-", "."}


def id_to_path(directory: str, object_id: str) -> str:
    """Method returns the file path where the module will be stored"""
    safe_id = "".join(x if allowed_char(x) else "_" for x in object_id)
    path = os.path.join(directory, safe_id + ".py")
    return path


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


def func_with_backend(func: Callable[[BackendClient, argparse.Namespace], Any]) -> Callable[[argparse.Namespace], Tuple[int, str]]:
    return lambda args: func(get_backend(args), args)


def get_backend(args: argparse.Namespace) -> BackendClient:
    # The UserID is required by Panther for this API call, but we have no way of
    # acquiring it, and it isn't used for anything. This is a valid UUID used by the
    # Panther deployment tool to indicate this action was performed automatically.
    user_id = "00000000-0000-4000-8000-000000000000"

    if args.api_token:
        return PublicAPIClient(PublicAPIClientOptions(token=args.api_token, user_id=user_id, host=args.api_host))

    datalake_lambda = get_datalake_lambda(args)

    return LambdaClient(LambdaClientOpts(
        user_id=user_id,
        aws_profile=args.aws_profile,
        datalake_lambda=datalake_lambda,
    ))


def get_datalake_lambda(args: argparse.Namespace) -> str:
    if "athena_datalake" not in args:
        return ""

    return "panther-athena-api" if args.athena_datalake else "panther-snowflake-api"


def set_env(key: str, value: str) -> None:
    os.environ[key] = value
