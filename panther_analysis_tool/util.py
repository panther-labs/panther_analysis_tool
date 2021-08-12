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

import logging
import os
from importlib import util as import_util
from pathlib import Path
from typing import Any

import boto3


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


def set_env(key: str, value: str) -> None:
    os.environ[key] = value
