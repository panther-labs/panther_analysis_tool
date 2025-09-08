import logging
import os
import re
from functools import reduce
from pathlib import Path
from typing import Any, Dict, List, Optional, TextIO, Union

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


def get_latest_version() -> str:
    try:
        response = requests.get(f"https://pypi.org/pypi/{PACKAGE_NAME}/json", timeout=10)
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


def get_client(aws_profile: Optional[str], service: str) -> boto3.client:
    # optionally set env variable for profile passed as argument
    if aws_profile is not None:
        logging.info("Using AWS profile: %s", aws_profile)
        set_env("AWS_PROFILE", aws_profile)
        sess = boto3.Session(profile_name=aws_profile)
        client = sess.client(service)
    else:
        client = boto3.client(service)
    return client


def get_optional_backend(api_token: Optional[str], api_host: str) -> Optional[BackendClient]:
    if api_token:
        return PublicAPIClient(
            PublicAPIClientOptions(token=api_token, user_id=PANTHER_USER_ID, host=api_host)
        )

    return None


def get_api_backend(api_token: Optional[str], api_host: str) -> BackendClient:
    if not api_token:
        raise BackendNotFoundException("This function requires an API token. API token not found.")

    return PublicAPIClient(
        PublicAPIClientOptions(token=api_token, user_id=PANTHER_USER_ID, host=api_host)
    )


def get_backend(
    api_token: Optional[str], api_host: str, aws_profile: Optional[str]
) -> BackendClient:
    if api_token:
        return PublicAPIClient(
            PublicAPIClientOptions(token=api_token, user_id=PANTHER_USER_ID, host=api_host)
        )

    return LambdaClient(
        LambdaClientOpts(
            user_id=PANTHER_USER_ID,
            aws_profile=aws_profile,
            datalake_lambda="panther-snowflake-api",
        )
    )


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


def deep_get(obj: Dict, path: List[str], default: Optional[Any] = None) -> Any:
    result = reduce(lambda val, key: val.get(key) if val else None, path, obj)  # type: ignore
    return result if result is not None else default


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


def get_spec_id(spec: dict) -> str:
    """Returns the ID of an analysis item."""
    # Two possible cases: item is an analysis item, or a schema
    if analysis_type := spec.get("AnalysisType", ""):
        id_keys = {
            "correlation_rule": "RuleID",
            "datamodel": "DataModelID",
            "global": "GlobalID",
            "lookup_table": "LookupName",
            "pack": "PackID",
            "policy": "PolicyID",
            "saved_query": "QueryName",
            "scheduled_query": "QueryName",
            "scheduled_rule": "RuleID",
            "rule": "RuleID",
        }
        return spec[id_keys[analysis_type]]
    if schema_name := spec.get("schema", ""):
        return schema_name
    # Not an analysis item:
    return ""


def get_imports(spec: dict, path: Union[str, Path, os.PathLike]) -> set[str]:
    """Checks if an analysis item has a Python file, and if so, what Python imports are used.
    'path' is the directory where this item resides."""
    # Define some useful regex expressions
    pattern_import = re.compile(r"(?:from (\w+) import \w+)|(?:import (\w+))")
    pattern_block_comment = re.compile(r'"{3}.*?"{3}', flags=re.DOTALL)
    pattern_line_comment = re.compile(r"#.*?\n")

    imports = set()  # Holds the set of imports
    if spec.get("Filename", "").endswith(".py"):
        pyfile = Path(path) / spec["Filename"]
        with pyfile.open("r") as file_:
            contents = file_.read()
            contents = pattern_block_comment.sub("", contents)
            contents = pattern_line_comment.sub("", contents)
            matches = pattern_import.finditer(contents)
            for match in matches:
                # Extract module name
                for module_name in match.groups():
                    if module_name is not None:
                        # Handle nested imports
                        module_name = module_name.split(".")[0]
                        imports.add(module_name)

    return imports


def get_recursive_mappings(id_: str, mapping: dict[str, set]) -> set:
    """Recursively fetch a set of all dictionary items by trying each referenced item as a key.
    Used in check_packs."""
    mappings = {id_}
    for submapping in mapping.get(id_, []):
        mappings.update(get_recursive_mappings(submapping, mapping))
    return mappings
