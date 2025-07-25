# pylint: disable=wrong-import-order, wrong-import-position, ungrouped-imports
import argparse
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import logging
import mimetypes
import os
import re
import shutil
import subprocess  # nosec
import sys
import time
import typing  # 'from typing import Optional' conflicts with 'from schema import Optional', below
import zipfile
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime

# Comment below disabling pylint checks is due to a bug in the CircleCi image with Pylint
# It seems to be unable to import the distutils module, however the module is present and importable
# in the Python Repl.
from distutils.util import strtobool  # pylint: disable=E0611, E0401
from importlib.abc import Loader
from typing import Any, DefaultDict, Dict, List, Tuple, Type
from unittest.mock import MagicMock, patch
from uuid import uuid4

from panther_analysis_tool.directory import setup_temp

# this is needed at this location so each process can have its own temp directory
setup_temp()

import botocore
import dateutil.parser
import jsonschema
import requests
import schema
from colorama import Fore, Style
from dynaconf import Dynaconf, Validator
from gql.transport.aiohttp import log as aiohttp_logger
from jsonschema.validators import Draft202012Validator
from panther_core.data_model import DataModel
from panther_core.enriched_event import PantherEvent
from panther_core.exceptions import UnknownDestinationError
from panther_core.policy import TYPE_POLICY, Policy
from panther_core.rule import Detection, Rule
from panther_core.testing import (
    TestCaseEvaluator,
    TestExpectations,
    TestResult,
    TestSpecification,
)
from ruamel.yaml import YAML, SafeConstructor, constructor
from ruamel.yaml import parser as YAMLParser
from ruamel.yaml import scanner as YAMLScanner
from schema import (
    Optional,
    SchemaError,
    SchemaForbiddenKeyError,
    SchemaMissingKeyError,
    SchemaUnexpectedTypeError,
    SchemaWrongKeyError,
)

from panther_analysis_tool import cli_output
from panther_analysis_tool import util as pat_utils
from panther_analysis_tool.analysis_utils import (
    ClassifiedAnalysis,
    ClassifiedAnalysisContainer,
    disable_all_base_detections,
    filter_analysis,
    get_simple_detections_as_python,
    load_analysis_specs,
    load_analysis_specs_ex,
    lookup_base_detection,
    test_correlation_rule,
    transpile_inline_filters,
)
from panther_analysis_tool.backend.client import (
    BackendError,
    BulkUploadMultipartError,
    BulkUploadParams,
)
from panther_analysis_tool.backend.client import Client as BackendClient
from panther_analysis_tool.backend.client import (
    FeatureFlagsParams,
    FeatureFlagWithDefault,
)
from panther_analysis_tool.command import (
    benchmark,
    bulk_delete,
    check_connection,
    standard_args,
    validate,
)
from panther_analysis_tool.constants import (
    BACKEND_FILTERS_ANALYSIS_SPEC_KEY,
    CONFIG_FILE,
    DATA_MODEL_LOCATION,
    ENABLE_CORRELATION_RULES_FLAG,
    HELPERS_LOCATION,
    PACKAGE_NAME,
    SCHEMAS,
    TMP_HELPER_MODULE_LOCATION,
    VERSION_STRING,
    AnalysisTypes,
)
from panther_analysis_tool.destination import FakeDestination
from panther_analysis_tool.enriched_event_generator import EnrichedEventGenerator
from panther_analysis_tool.log_schemas import user_defined
from panther_analysis_tool.schemas import (
    ANALYSIS_CONFIG_SCHEMA,
    DERIVED_SCHEMA,
    GLOBAL_SCHEMA,
    LOOKUP_TABLE_SCHEMA,
    POLICY_SCHEMA,
    RULE_SCHEMA,
    TYPE_SCHEMA,
)
from panther_analysis_tool.util import (
    BackendNotFoundException,
    add_path_to_filename,
    convert_unicode,
    get_imports,
    get_recursive_mappings,
    get_spec_id,
    is_correlation_rule,
    is_simple_detection,
)
from panther_analysis_tool.validation import (
    contains_invalid_field_set,
    contains_invalid_table_names,
    validate_packs,
)
from panther_analysis_tool.zip_chunker import ZipArgs, ZipChunk, analysis_chunks

# This file was generated in whole or in part by GitHub Copilot.

# interpret datetime as str, the backend uses the default behavior for json.loads, which
# interprets these as str.  This sets global config for ruamel SafeConstructor
constructor.SafeConstructor.add_constructor(
    "tag:yaml.org,2002:timestamp", SafeConstructor.construct_yaml_str
)


# exception for conflicting ids
class AnalysisIDConflictException(Exception):
    def __init__(self, analysis_id: str):
        self.message = f"Conflicting AnalysisID: [{analysis_id}]"
        super().__init__(self.message)


# exception for conflicting ids
class AnalysisContainsDuplicatesException(Exception):
    def __init__(self, analysis_id: str, invalid_fields: List[str]):
        self.message = f'Specification file for [{analysis_id}] contains fields \
        with duplicate values: [{", ".join(x for x in invalid_fields)}]'
        super().__init__(self.message)


# Exception for invalid Panther Snowflake table names
class AnalysisContainsInvalidTableNamesException(Exception):
    def __init__(self, analysis_id: str, invalid_table_names: List[str]):
        self.message = (
            f'Specification file for [{analysis_id}] contains invalid Panther table names: [{", ".join(x for x in invalid_table_names)}]. '
            'Try using a fully qualified table name such as "panther_logs.public.log_type" '
            "or setting --ignore-table-names for queries using non-Panther or non-Snowflake tables."
        )
        super().__init__(self.message)


@dataclass
class TestResultContainer:
    detection: typing.Optional[Detection]
    result: TestResult
    failed_tests: DefaultDict[str, list]
    output: str


@dataclass
class TestResultsContainer:
    """A container for all test results"""

    passed: Dict[str, List[TestResultContainer]]
    errored: Dict[str, List[TestResultContainer]]


def load_module(filename: str) -> Tuple[Any, Any]:
    """Loads the analysis function module from a file.

    Args:
        filename: The relative path to the file.

    Returns:
        A loaded Python module.
    """
    module_name = filename.split(".")[0]
    spec = importlib.util.spec_from_file_location(module_name, filename)
    module = importlib.util.module_from_spec(spec)  # type: ignore
    try:
        assert isinstance(spec.loader, Loader)  # type: ignore # nosec
        spec.loader.exec_module(module)  # type: ignore
    except FileNotFoundError as err:
        print("\t[ERROR] File not found: " + filename + ", skipping\n")
        return None, err
    except Exception as err:  # pylint: disable=broad-except
        # Catch arbitrary exceptions thrown by user code
        print("\t[ERROR] Error loading module, skipping\n")
        return None, err
    return module, None


def datetime_converted(obj: Any) -> Any:
    """A helper function for dumping spec files to JSON.

    Args:
        obj: Any object to convert.

    Returns:
        A string representation of the datetime.
    """
    if isinstance(obj, datetime):
        return str(obj)
    return obj


def zip_analysis_chunks(args: argparse.Namespace) -> List[str]:
    logging.info("Zipping analysis items in %s to %s", args.path, args.out)

    current_time = datetime.now().isoformat(timespec="seconds").replace(":", "-")
    zip_chunks = [
        # note: all the files we care about have an AnalysisType field in their yml
        # so we can ignore file patterns and leave them empty
        ZipChunk(patterns=[], types=(AnalysisTypes.DATA_MODEL, AnalysisTypes.GLOBAL)),  # type: ignore
        ZipChunk(patterns=[], types=AnalysisTypes.RULE, max_size=200),  # type: ignore
        ZipChunk(patterns=[], types=AnalysisTypes.POLICY, max_size=200),  # type: ignore
        ZipChunk(patterns=[], types=AnalysisTypes.SCHEDULED_QUERY, max_size=100),  # type: ignore
        ZipChunk(patterns=[], types=AnalysisTypes.SCHEDULED_RULE, max_size=200),  # type: ignore
        ZipChunk(patterns=[], types=AnalysisTypes.LOOKUP_TABLE, max_size=100),  # type: ignore
        ZipChunk(patterns=[], types=AnalysisTypes.CORRELATION_RULE, max_size=200),  # type: ignore
    ]

    filenames = []
    chunks = analysis_chunks(ZipArgs.from_args(args), zip_chunks)
    batch_id = uuid4()
    for idx, chunk in enumerate(chunks):
        filename = f"panther-analysis-{current_time}-{batch_id}-batch-{idx + 1}.zip"
        filename = add_path_to_filename(args.out, filename)
        filenames.append(filename)
        with zipfile.ZipFile(filename, "w", zipfile.ZIP_DEFLATED) as zip_out:
            for name in chunk.files:
                zip_out.write(name)

    return filenames


def zip_analysis(
    args: argparse.Namespace, backend: typing.Optional[BackendClient] = None
) -> Tuple[int, str]:
    """Tests, validates, and then archives all policies and rules into a local zip file.

    Returns 1 if the analysis tests or validation fails.

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A tuple of return code and the archive filename.
    """
    if not args.skip_tests:
        return_code, invalid_specs = test_analysis(args, backend)
        if return_code != 0:
            logging.error(invalid_specs)
            return return_code, ""

    logging.info("Zipping analysis items in %s to %s", args.path, args.out)
    # example: 2019-08-05T18-23-25
    # The colon character is not valid in filenames.
    current_time = datetime.now().isoformat(timespec="seconds").replace(":", "-")
    filename = f"panther-analysis-{current_time}-{uuid4()}.zip"
    filename = add_path_to_filename(args.out, filename)

    typed_args = ZipArgs.from_args(args)
    chunks = analysis_chunks(typed_args)
    if len(chunks) != 1:
        logging.error("something went wrong zipping batches.")
        return 1, ""
    with zipfile.ZipFile(filename, "w", zipfile.ZIP_DEFLATED) as zip_out:
        for name in chunks[0].files:
            zip_out.write(name)

    return 0, filename


def upload_analysis(backend: BackendClient, args: argparse.Namespace) -> Tuple[int, str]:
    """Tests, validates, packages, and uploads all policies and rules into a Panther deployment.

    Returns 1 if the analysis tests, validation, packaging, or upload fails.

    Args:
        backend: a backend client
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A tuple of return code and error if applicable.
    """
    if args.auto_disable_base:
        zipargs = ZipArgs.from_args(args)
        disable_all_base_detections([zipargs.path], zipargs.ignore_files)

    use_async = (not args.no_async) and backend.supports_async_uploads()
    if args.batch and not use_async:
        if not args.skip_tests:
            return_code, invalid_specs = test_analysis(args, backend)
            if return_code != 0:
                logging.error(invalid_specs)
                return return_code, ""

        for idx, archive in enumerate(zip_analysis_chunks(args)):
            batch_idx = idx + 1
            logging.info("Uploading Batch %d...", batch_idx)
            return_code, err = upload_zip(backend, args, archive, False)
            if return_code != 0:
                return return_code, err
            logging.info("Uploaded Batch %d", batch_idx)

        return 0, ""

    return_code, archive = zip_analysis(args, backend)
    if return_code != 0:
        return return_code, ""

    return upload_zip(backend, args, archive, use_async)


def print_upload_summary(response: dict) -> None:
    print("\n--------------------------")
    print("Upload Summary")

    # Helper function to print category stats if they exist
    def print_category_stats(category: str, stats: dict) -> None:
        # Show stats if any of total, new, or modified are greater than 0
        if any(stats.get(key, 0) > 0 for key in ["total", "new", "modified"]):
            print(f"\t{category}")
            print(f"\t\tTotal: {stats.get('total', 0)}")
            print(f"\t\tNew: {stats.get('new', 0)}")
            print(f"\t\tModified: {stats.get('modified', 0)}")

    # Print stats for each category
    categories = {
        "Rules": response.get("rules", {}),
        "Queries": response.get("queries", {}),
        "Policies": response.get("policies", {}),
        "Scheduled Rules": response.get("scheduled_rules", {}),
        "Data Models": response.get("data_models", {}),
        "Global Helpers": response.get("global_helpers", {}),
        "Lookup Tables": response.get("lookup_tables", {}),
        "Correlation Rules": response.get("correlation_rules", {}),
    }

    for category, stats in categories.items():
        print_category_stats(category, stats)


def upload_zip(
    backend: BackendClient, args: argparse.Namespace, archive: str, use_async: bool
) -> Tuple[int, str]:
    # Extract max retries we should handle
    max_retries = args.max_retries

    # Validate and limit max_retries
    if max_retries < 0:
        logging.warning("Invalid max-retries value %s, using 0 instead", max_retries)
        max_retries = 0
    elif max_retries > 10:
        logging.warning("max-retries value %s exceeds maximum of 10, using 10 instead", max_retries)
        max_retries = 10

    with open(archive, "rb") as analysis_zip:
        logging.info("Uploading items to Panther")

        upload_params = BulkUploadParams(zip_bytes=analysis_zip.read())
        retry_count = 0

        while True:
            try:
                if use_async:
                    response = backend.async_bulk_upload(upload_params)
                else:
                    response = backend.bulk_upload(upload_params)

                resp_dict = asdict(response.data)
                flags_params = FeatureFlagsParams(
                    flags=[FeatureFlagWithDefault(flag=ENABLE_CORRELATION_RULES_FLAG)]
                )
                try:
                    if not backend.feature_flags(flags_params).data.flags[0].treatment:
                        del resp_dict["correlation_rules"]
                # pylint: disable=broad-except
                except BaseException:
                    del resp_dict["correlation_rules"]

                logging.debug("API Response:\n%s", json.dumps(resp_dict, indent=4))
                print_upload_summary(resp_dict)
                return 0, cli_output.success("Upload succeeded")

            except BackendError as be_err:
                err = cli_output.multipart_error_msg(
                    BulkUploadMultipartError.from_jsons(convert_unicode(be_err)),
                    "Upload failed",
                )
                if be_err.permanent is True:
                    return 1, f"Failed to upload to Panther: {err}"

                if max_retries - retry_count > 0:
                    logging.debug("Failed to upload to Panther: %s.", err)
                    retry_count += 1

                    # typical bulk upload takes 30 seconds, allow any currently running one to complete
                    logging.debug(
                        "Will retry upload in 30 seconds. Retries remaining: %s",
                        max_retries - retry_count,
                    )
                    time.sleep(30)

                else:
                    logging.warning("Exhausted retries attempting to perform bulk upload.")
                    return 1, f"Failed to upload to Panther: {err}"

            # PEP8 guide states it is OK to catch BaseException if you log it.
            except BaseException as err:  # pylint: disable=broad-except
                return 1, f"Failed to upload to Panther: {err}"


def parse_lookup_table(args: argparse.Namespace) -> dict:
    """Validates and parses a Lookup Table spec file

    Returns a dict representing the Lookup Table

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A dict representing the Lookup Table, empty when parsing fails
    """

    logging.info("Parsing the Lookup Table spec defined in %s", args.path)
    with open(args.path, "r", encoding="utf-8") as input_file:
        try:
            yaml = YAML(typ="safe")
            lookup_spec = yaml.load(input_file)
            logging.info("Successfully parse the Lookup Table file %s", args.path)
        except (YAMLParser.ParserError, YAMLScanner.ScannerError) as err:
            logging.error("Failed to parse the Lookup Table spec file %s", input_file)
            logging.error(err)
            return {}
        try:
            LOOKUP_TABLE_SCHEMA.validate(lookup_spec)
            if "Refresh" in lookup_spec:
                if "AlarmPeriodMinutes" in lookup_spec["Refresh"]:
                    if lookup_spec["Refresh"]["AlarmPeriodMinutes"] > 1440:
                        logging.error(
                            "AlarmPeriodMinutes must not greater than 1 day (1440 minutes)"
                        )
                        return {}
            logging.info("Successfully validated the Lookup Table file %s", args.path)
        except (
            schema.SchemaError,
            schema.SchemaMissingKeyError,
            schema.SchemaWrongKeyError,
            schema.SchemaForbiddenKeyError,
            schema.SchemaUnexpectedTypeError,
            schema.SchemaOnlyOneAllowedError,
        ) as err:
            logging.error("Invalid schema in the Lookup Table spec file %s", input_file)
            logging.error(err)
            return {}
    return lookup_spec


def test_lookup_table(args: argparse.Namespace) -> Tuple[int, str]:
    """Validates a Lookup Table spec file

    Returns 1 if the validation fails

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A tuple of return code and and empty string (to satisfy calling conventions)
    """

    logging.info("Validating the Lookup Table spec defined in %s", args.path)
    lookup_spec = parse_lookup_table(args)
    if not lookup_spec:
        return 1, ""
    return 0, ""


def update_custom_schemas(backend: BackendClient, args: argparse.Namespace) -> Tuple[int, str]:
    """
    Updates or creates custom schemas.
    Returns 1 if any file failed to be updated.
    Args:
        args: The populated Argparse namespace with parsed command-line arguments.
    Returns:
        A tuple of return code and a placeholder string.
    """
    normalized_path = user_defined.normalize_path(args.path)
    if not normalized_path:
        return 1, f"path not found: {args.path}"

    uploader = user_defined.Uploader(normalized_path, backend)
    results = uploader.process()
    has_errors = False
    for failed, summary in user_defined.report_summary(normalized_path, results):
        if failed:
            has_errors = True
            logging.error(summary)
        else:
            logging.info(summary)

    return int(has_errors), ""


def generate_release_assets(args: argparse.Namespace) -> Tuple[int, str]:
    # First, generate the appropriate zip file
    # set the output file to appropriate name for the release: panther-analysis-all.zip
    release_file = args.out + "/" + "panther-analysis-all.zip"
    signature_filename = args.out + "/" + "panther-analysis-all.sig"
    return_code, archive = zip_analysis(args)
    if return_code != 0:
        return return_code, ""
    os.rename(archive, release_file)
    logging.info("Release zip file generated: %s", release_file)
    #  If a key is provided, sign a hash of the file
    if args.kms_key:
        # Then generate the sha512 sum of the zip file
        archive_hash = generate_hash(release_file)

        client = pat_utils.get_client(args.aws_profile, "kms")
        try:
            response = client.sign(
                KeyId=args.kms_key,
                Message=archive_hash,
                MessageType="DIGEST",
                SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_512",
            )
            if response.get("Signature"):
                # write signature out to file
                with open(signature_filename, "wb") as filename:
                    filename.write(base64.b64encode(response.get("Signature")))
                logging.info("Release signature file generated: %s", signature_filename)
            else:
                logging.error("Missing signtaure in response: %s", response)
                return 1, ""
        except botocore.exceptions.ClientError as err:
            logging.error("Failed to sign panther-analysis-all.zip using key (%s)", args.kms_key)
            logging.error(err)
            return 1, ""
    return 0, ""


def generate_hash(filename: str) -> bytes:
    hash_bytes = hashlib.sha512()
    with open(filename, "rb") as name:
        block = name.read(hash_bytes.block_size)
        while block:
            hash_bytes.update(block)
            block = name.read(hash_bytes.block_size)
    # convert to byte string
    return hash_bytes.digest()


def publish_release(args: argparse.Namespace) -> Tuple[int, str]:
    # first, ensure the appropriate github access token is set in the env
    api_token = os.environ.get("GITHUB_TOKEN")
    if not api_token:
        logging.error("error: GITHUB_TOKEN env variable must be set")
        return 1, ""
    release_url = (
        f"https://api.github.com/repos/{args.github_owner}/{args.github_repository}/releases"
    )
    # setup appropriate https headers
    headers = {
        "accept": "application/vnd.github.v3+json",
        "Authorization": f"token {api_token}",
    }
    # check this tag doesn't already exist
    response = requests.get(release_url + f"/tags/{args.github_tag}", headers=headers, timeout=10)
    if response.status_code == 200:
        logging.error("tag already exists %s", args.github_tag)
        return 1, ""
    # create the release directory
    current_time = datetime.now().isoformat(timespec="seconds").replace(":", "-")
    release_dir = args.out if args.out != "." else f"release-{current_time}"
    # setup and generate release assets
    return_code = setup_release(args, release_dir, api_token)
    if return_code != 0:
        return return_code, ""
    # then publish to Github
    return_code = publish_github(args.github_tag, args.body, headers, release_url, release_dir)
    if return_code != 0:
        return return_code, ""
    logging.info("draft release (%s) created in repo (%s)", args.github_tag, release_url)
    return 0, ""


def clone_github(
    owner: str, repo: str, branch: str, path: str, access_token: str
) -> Tuple[int, str]:
    repo_url = (
        f"https://{access_token}@github.com/{owner}/{repo}"
        if access_token
        else f"https://github.com/{owner}/{repo}"
    )
    repo_dir = os.path.join(path, f"{repo}")
    logging.info("Cloning %s branch of %s/%s", branch, owner, repo)
    cmd = [
        "git",
        "clone",
        "--branch",
        branch,
        "--depth",
        "1",
        "-c",
        "advice.detachedHead=false",
        repo_url,
        repo_dir,
    ]
    result = subprocess.run(cmd, check=False, timeout=120)  # nosec
    return result.returncode, ""


def setup_release(args: argparse.Namespace, release_dir: str, token: str) -> int:
    if not os.path.isdir(release_dir):
        logging.info(
            "Creating release directory: %s",
            release_dir,
        )
        os.makedirs(release_dir)
    # pull latest version of the github repo
    return_code, _ = clone_github(
        args.github_owner,
        args.github_repository,
        args.github_branch,
        release_dir,
        token,
    )
    if return_code != 0:
        return return_code
    # generate zip based on latest version of repo
    owd = os.getcwd()
    # change dir to release directory
    os.chdir(release_dir)
    args.path = "."
    # run generate assets from release directory
    return_code, _ = generate_release_assets(args)
    os.chdir(owd)
    return return_code


def publish_github(tag: str, body: str, headers: dict, release_url: str, release_dir: str) -> int:
    payload = {"tag_name": tag, "draft": True}
    if body:
        payload["body"] = body
    response = requests.post(
        release_url, data=json.dumps(payload, allow_nan=False), headers=headers, timeout=10
    )
    if response.status_code != 201:
        logging.error("error creating release (%s) in repo (%s)", tag, release_url)
        logging.error(response.json())
        return 1
    upload_url = response.json().get("upload_url", "").replace("{?name,label}", "")
    if not upload_url:
        logging.error("no upload url in response - assets not uploaded")
        logging.info("draft release (%s) created in repo (%s)", tag, release_url)
        return 1
    return upload_assets_github(upload_url, headers, release_dir)


def upload_assets_github(upload_url: str, headers: dict, release_dir: str) -> int:
    return_code = 0
    # first, find the release assets
    assets = [
        filename
        for filename in os.listdir(release_dir)
        if os.path.isfile(release_dir + "/" + filename)
    ]
    # add release assets
    for filename in assets:
        headers["Content-Type"] = mimetypes.guess_type(filename)[0]
        params = [("name", filename)]
        with open(release_dir + "/" + filename, "rb") as data:
            response = requests.post(
                upload_url, data=data.read(), headers=headers, params=params, timeout=10
            )
        response = requests.post(upload_url, data=data, headers=headers, params=params, timeout=10)
        if response.status_code != 201:
            logging.error("error uploading release asset (%s)", filename)
            logging.error(response.json())
            return_code = 1
            continue
        logging.info("sucessfull upload of release asset (%s)", filename)
    return return_code


def load_analysis(
    path: str,
    ignore_table_names: bool,
    valid_table_names: List[str],
    ignore_files: List[str],
) -> Tuple[Any, List[Any]]:
    """Loads each policy or rule into memory.

    Args:
        path: path to root folder with rules and policies
        ignore_table_names: validate or ignore table names
        valid_table_names: list of valid table names, other will be treated as invalid
        ignore_files: Files that Panther Analysis Tool should not process

    Returns:
        A tuple of the valid and invalid rules and policies
    """
    search_directories = [path]
    for directory in (
        HELPERS_LOCATION,
        "." + HELPERS_LOCATION,  # Try the parent directory as well
        DATA_MODEL_LOCATION,
        "." + DATA_MODEL_LOCATION,  # Try the parent directory as well
    ):
        absolute_dir_path = os.path.abspath(os.path.join(path, directory))
        absolute_helper_path = os.path.abspath(directory)

        if os.path.exists(absolute_dir_path):
            search_directories.append(absolute_dir_path)
        if os.path.exists(absolute_helper_path):
            search_directories.append(absolute_helper_path)

    # First classify each file, always include globals and data models location
    specs, invalid_specs = classify_analysis(
        list(load_analysis_specs(search_directories, ignore_files)),
        ignore_table_names=ignore_table_names,
        valid_table_names=valid_table_names,
    )

    return specs, invalid_specs


# pylint: disable=too-many-locals
def test_analysis(
    args: argparse.Namespace, backend: typing.Optional[BackendClient] = None
) -> Tuple[int, list]:
    """Imports each policy or rule and runs their tests.

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A tuple of the return code, and a list of tuples containing invalid specs and their error.
    """
    logging.info("Testing analysis items in %s", args.path)

    # First classify each file, always include globals and data models location
    specs, invalid_specs = load_analysis(
        args.path, args.ignore_table_names, args.valid_table_names, args.ignore_files
    )
    if specs.empty():
        if invalid_specs:
            return 1, invalid_specs
        return 1, [f"Nothing to test in {args.path}"]

    # Apply the filters as needed
    if getattr(args, "filter_inverted", None) is None:
        args.filter_inverted = {}
    specs = specs.apply(lambda l: filter_analysis(l, args.filter, args.filter_inverted))

    if specs.empty():
        return 1, [
            f"No analysis in {args.path} matched filters {args.filter} - {args.filter_inverted}"
        ]

    # enrich simple detections with transpiled python as necessary
    if len(specs.simple_detections) > 0:
        specs.simple_detections = get_simple_detections_as_python(specs.simple_detections, backend)

    transpile_inline_filters(specs, backend)

    ignore_exception_types: List[Type[Exception]] = []

    available_destinations: List[str] = []
    if args.available_destination:
        available_destinations.extend(args.available_destination)
    else:
        ignore_exception_types.append(UnknownDestinationError)

    destinations_by_name = {
        name: FakeDestination(destination_id=str(uuid4()), destination_display_name=name)
        for name in available_destinations
    }

    # import each data model, global, policy, or rule and run its tests
    # first import the globals
    #   add them sys.modules to be used by rule and/or policies tests
    setup_global_helpers(specs.globals)

    # then, setup data model dictionary to be used in rule/policy tests
    log_type_to_data_model, invalid_data_models = setup_data_models(specs.data_models)
    invalid_specs.extend(invalid_data_models)

    all_test_results = (
        None
        if not bool(args.sort_test_results | args.print_failed_test_results_only)
        else TestResultsContainer(passed={}, errored={})
    )
    # then, import rules and policies; run tests
    failed_tests, invalid_detections, skipped_tests = setup_run_tests(
        log_type_to_data_model,
        specs.detections + specs.simple_detections,
        args.minimum_tests,
        args.skip_disabled_tests,
        destinations_by_name=destinations_by_name,
        ignore_exception_types=ignore_exception_types,
        all_test_results=all_test_results,
        backend=backend,
        test_names=getattr(args, "test_names", None),
    )
    invalid_specs.extend(invalid_detections)

    # finally, validate pack defs
    invalid_packs = validate_packs(specs)
    invalid_specs.extend(invalid_packs)

    # cleanup tmp global dir
    cleanup_global_helpers(specs.globals)

    if all_test_results and (all_test_results.passed or all_test_results.errored):
        for outcome in ["passed", "errored"]:
            # Skip if test passed and we only want to print failed tests:
            if args.print_failed_test_results_only and outcome != "errored":
                continue
            sorted_results = sorted(getattr(all_test_results, outcome).items())
            for detection_id, test_result_packages in sorted_results:
                if test_result_packages:
                    print(detection_id)
                for test_result_package in test_result_packages:
                    if len(test_result_package.output) > 0:
                        print(test_result_package.output)
                    _print_test_result(
                        detection=test_result_package.detection,
                        test_result=test_result_package.result,
                        failed_tests=test_result_package.failed_tests,
                    )
                    print("")
    print_summary(
        args.path,
        len(specs.detections + specs.simple_detections),
        failed_tests,
        invalid_specs,
        skipped_tests,
    )

    #  if the classic format was invalid, just exit
    if invalid_specs:
        return 1, invalid_specs

    return int(bool(failed_tests)), invalid_specs


def setup_global_helpers(global_analysis: List[ClassifiedAnalysis]) -> None:
    # ensure the directory does not exist, else clear it
    cleanup_global_helpers(global_analysis)
    os.makedirs(TMP_HELPER_MODULE_LOCATION)
    # setup temp dir for globals
    if TMP_HELPER_MODULE_LOCATION not in sys.path:
        sys.path.append(TMP_HELPER_MODULE_LOCATION)
    # place globals in temp dir
    for item in global_analysis:
        dir_name = item.dir_name
        analysis_spec = item.analysis_spec
        analysis_id = analysis_spec["GlobalID"]
        source = os.path.join(dir_name, analysis_spec["Filename"])
        destination = os.path.join(TMP_HELPER_MODULE_LOCATION, f"{analysis_id}.py")
        shutil.copyfile(source, destination)
        # force reload of the module as necessary
        if analysis_id in sys.modules:
            logging.warning(
                "module name collision: global (%s) has same name as a module in python path",
                analysis_id,
            )
            importlib.reload(sys.modules[analysis_id])


def cleanup_global_helpers(global_analysis: List[ClassifiedAnalysis]) -> None:
    # clear the modules from the modules cache
    for item in global_analysis:
        analysis_id = item.analysis_spec["GlobalID"]
        # delete the helpers that were added to sys.modules for testing
        if analysis_id in sys.modules:
            del sys.modules[analysis_id]
    # ensure the directory does not exist, else clear it
    if os.path.exists(TMP_HELPER_MODULE_LOCATION):
        shutil.rmtree(TMP_HELPER_MODULE_LOCATION)


def setup_data_models(
    data_models: List[ClassifiedAnalysis],
) -> Tuple[Dict[str, DataModel], List[Any]]:
    invalid_specs = []
    # log_type_to_data_model is a dict used to map LogType to a unique
    # data model, ensuring there is at most one DataModel per LogType
    log_type_to_data_model: Dict[str, DataModel] = {}
    for item in data_models:
        analysis_spec_filename = item.file_name
        dir_name = item.dir_name
        analysis_spec = item.analysis_spec
        analysis_id = analysis_spec["DataModelID"]
        if analysis_spec["Enabled"]:
            body = None
            if "Filename" in analysis_spec:
                _, load_err = load_module(os.path.join(dir_name, analysis_spec["Filename"]))
                # If the module could not be loaded, continue to the next
                if load_err:
                    invalid_specs.append((analysis_spec_filename, load_err))
                    continue
                data_model_module_path = os.path.join(dir_name, analysis_spec["Filename"])
                with open(data_model_module_path, "r", encoding="utf-8") as python_module_file:
                    body = python_module_file.read()

            # setup the mapping lookups
            params = {
                "id": analysis_id,
                "mappings": [
                    pat_utils.convert_keys_to_lowercase(mapping)
                    for mapping in analysis_spec["Mappings"]
                ],
                "versionId": "",
            }

            if body is not None:
                params["body"] = body

            data_model = DataModel(params)
            # check if the LogType already has an enabled data model
            for log_type in analysis_spec["LogTypes"]:
                if log_type in log_type_to_data_model:
                    print("\t[ERROR] Conflicting Enabled LogTypes\n")
                    invalid_specs.append(
                        (
                            analysis_spec_filename,
                            f"Conflicting Enabled LogType [{log_type}] in Data Model [{analysis_id}]",
                        )
                    )
                    continue
                log_type_to_data_model[log_type] = data_model
    return log_type_to_data_model, invalid_specs


def setup_run_tests(  # pylint: disable=too-many-locals,too-many-arguments,too-many-statements
    log_type_to_data_model: Dict[str, DataModel],
    analysis: List[ClassifiedAnalysis],
    minimum_tests: int,
    skip_disabled_tests: bool,
    destinations_by_name: Dict[str, FakeDestination],
    ignore_exception_types: List[Type[Exception]],
    all_test_results: typing.Optional[TestResultsContainer] = None,
    backend: typing.Optional[BackendClient] = None,
    test_names: typing.Optional[List[str]] = None,
) -> Tuple[DefaultDict[str, List[Any]], List[Any], List[Tuple[str, dict]]]:
    invalid_specs = []
    failed_tests: DefaultDict[str, list] = defaultdict(list)
    skipped_tests: List[Tuple[str, dict]] = []
    for item in analysis:
        analysis_spec_filename = item.file_name
        dir_name = item.dir_name
        analysis_spec = item.analysis_spec
        if skip_disabled_tests and not analysis_spec.get("Enabled", False):
            skipped_tests.append((analysis_spec_filename, analysis_spec))
            continue
        analysis_type = analysis_spec["AnalysisType"]

        detection_args = {
            "id": analysis_spec.get("PolicyID") or analysis_spec["RuleID"],
            "analysisType": analysis_type.upper(),
            "versionId": "0000-0000-0000",
            "filters": analysis_spec.get(BACKEND_FILTERS_ANALYSIS_SPEC_KEY) or None,
        }

        if test_names:
            if not set(test_names) & {t["Name"] for t in analysis_spec.get("Tests", [])}:
                print(
                    analysis_spec.get("RuleID")
                    or analysis_spec.get("PolicyID")
                    or analysis_spec_filename
                )
                print(f"\tNo tests match the provided test names: {test_names}\n")
                skipped_tests.append((analysis_spec_filename, analysis_spec))
                continue

        correlation_rule_results = []
        is_corr_rule = is_correlation_rule(analysis_spec)
        if is_corr_rule:
            correlation_rule_results = test_correlation_rule(analysis_spec, backend, test_names)
            if not correlation_rule_results:
                skipped_tests.append((analysis_spec_filename, analysis_spec))

        base_id = analysis_spec.get("BaseDetection", "")
        if base_id != "":
            # this is a derived detection
            found_base_detection = None
            found_base_path = None
            found_base_tests = None
            for other_item in analysis:
                if other_item.analysis_spec.get("RuleID", "") != base_id:
                    continue
                found_base_detection = other_item.analysis_spec
                found_base_path = other_item.dir_name
                found_base_tests = other_item.analysis_spec.get("Tests")
                break
            # inherit the tests from the base if we dont have any
            if "Tests" not in analysis_spec and found_base_tests:
                analysis_spec["Tests"] = found_base_tests
            if not found_base_detection:
                base_lookup = lookup_base_detection(base_id, backend)
                if "body" in base_lookup:
                    found_base_detection = base_lookup
                if "tests" in base_lookup and "Tests" not in analysis_spec:
                    tests = base_lookup["tests"]
                    if len(tests) > 0:
                        analysis_spec["Tests"] = tests
            if not found_base_detection:
                logging.warning(
                    "Skipping Derived Detection '%s', could not lookup base detection '%s'",
                    analysis_spec.get("RuleID"),
                    base_id,
                )
                continue
            if "body" in found_base_detection:
                detection_args["body"] = found_base_detection.get("body")
            else:
                detection_args["path"] = os.path.join(
                    found_base_path, found_base_detection["Filename"]  # type: ignore
                )
        elif is_simple_detection(analysis_spec):
            # skip tests when the body is empty
            if not analysis_spec.get("body"):
                continue
            detection_args["body"] = analysis_spec.get("body")
        elif not is_corr_rule:
            detection_args["path"] = os.path.join(dir_name, analysis_spec["Filename"])
        if "CreateAlert" in analysis_spec:
            detection_args["suppressAlert"] = not bool(analysis_spec["CreateAlert"])

        detection = (
            None
            if is_corr_rule
            else (
                Policy(detection_args)
                if analysis_type == AnalysisTypes.POLICY
                else Rule(detection_args)
            )
        )

        detection_id = (
            detection.detection_id if detection is not None else analysis_spec.get("RuleID", "")
        )
        if not all_test_results:
            print(detection_id)

        # if there is a setup exception, no need to run tests
        if detection is not None and detection.setup_exception:
            invalid_specs.append((analysis_spec_filename, detection.setup_exception))
            print("\n")
            continue

        failed_tests = run_tests(
            analysis_spec,
            log_type_to_data_model,
            detection,
            detection_id,
            failed_tests,
            minimum_tests,
            destinations_by_name,
            ignore_exception_types,
            all_test_results,
            correlation_rule_results,
            test_names,
        )

        if not all_test_results:
            print("")
    return failed_tests, invalid_specs, skipped_tests


def print_summary(
    test_path: str,
    num_tests: int,
    failed_tests: Dict[str, list],
    invalid_specs: List[Any],
    skipped_tests: List[Tuple[str, dict]],
) -> None:
    """Print a summary of passed, failed, and invalid specs"""
    err_message = "\t{}\n\t\t{}\n"

    if skipped_tests:
        print("--------------------------")
        print("Skipped Tests Summary")
        for spec_filename, spec in skipped_tests:
            print(err_message.format(spec_filename, spec.get("RuleID") or spec.get("PolicyID")))

    if failed_tests:
        print("--------------------------")
        print("Failed Tests Summary")
        for analysis_id in failed_tests:
            print(err_message.format(analysis_id, failed_tests[analysis_id]))

    if invalid_specs:
        print("--------------------------")
        print("Invalid Tests Summary")
        for spec_filename, spec_error in invalid_specs:
            print(err_message.format(spec_filename, spec_error))

    print("--------------------------")
    print("Test Summary")
    print(f"\tPath: {test_path}")
    print(f"\tPassed: {num_tests - (len(failed_tests) + len(invalid_specs) + len(skipped_tests))}")
    print(f"\tSkipped: {len(skipped_tests)}")
    print(f"\tFailed: {len(failed_tests)}")
    print(f"\tInvalid: {len(invalid_specs)}\n")


# pylint: disable=too-many-locals,too-many-statements
def classify_analysis(
    specs: List[Tuple[str, str, Any, Any]],
    ignore_table_names: bool,
    valid_table_names: List[str],
) -> Tuple[ClassifiedAnalysisContainer, List[Any]]:
    # First setup return dict containing different
    # types of detections, meta types that can be zipped
    # or uploaded
    all_specs = ClassifiedAnalysisContainer()

    invalid_specs = []
    # each analysis type must have a unique id, track used ids and
    # add any duplicates to the invalid_specs
    analysis_ids: List[Any] = []

    # Create a json validator and check the schema only once rather than during every loop
    json_validator = Draft202012Validator(ANALYSIS_CONFIG_SCHEMA)

    # pylint: disable=too-many-nested-blocks
    for analysis_spec_filename, dir_name, analysis_spec, error in specs:
        keys: List[Any] = []
        tmp_logtypes: Any = None
        tmp_logtypes_key: Any = None
        try:
            # check for parsing errors from json.loads (ValueError) / yaml.safe_load (YAMLError)
            if error:
                raise error
            # validate the schema has a valid analysis type
            TYPE_SCHEMA.validate(analysis_spec)
            analysis_type = analysis_spec["AnalysisType"]
            if analysis_spec.get("BaseDetection"):
                analysis_schema = SCHEMAS["derived"]
            else:
                analysis_schema = SCHEMAS[analysis_type]
            keys = list(analysis_schema.schema.keys())
            # Special case for ScheduledQueries to only validate the types
            if "ScheduledQueries" in analysis_spec:
                for each_key in analysis_schema.schema.keys():
                    if str(each_key) == "Or('LogTypes', 'ScheduledQueries')":
                        tmp_logtypes_key = each_key
                        break
                if not tmp_logtypes:
                    tmp_logtypes = analysis_schema.schema[tmp_logtypes_key]
                analysis_schema.schema[tmp_logtypes_key] = [str]

            analysis_schema.validate(analysis_spec)

            # lookup the analysis type id and validate there aren't any conflicts
            analysis_id = lookup_analysis_id(analysis_spec, analysis_type)
            if analysis_id in analysis_ids:
                raise AnalysisIDConflictException(analysis_id)
            # check for duplicates where panther expects a unique set
            invalid_fields = contains_invalid_field_set(analysis_spec)
            if invalid_fields:
                raise AnalysisContainsDuplicatesException(analysis_id, invalid_fields)
            if analysis_type == AnalysisTypes.SCHEDULED_QUERY and not ignore_table_names:
                invalid_table_names = contains_invalid_table_names(
                    analysis_spec, analysis_id, valid_table_names
                )
                if invalid_table_names:
                    raise AnalysisContainsInvalidTableNamesException(
                        analysis_id, invalid_table_names
                    )
            analysis_ids.append(analysis_id)

            # Raise warnings for dedup minutes
            if "DedupPeriodMinutes" in analysis_spec:
                if analysis_spec["DedupPeriodMinutes"] == 0:
                    msg = (
                        f"DedupPeriodMinutes is set to 0 for {analysis_id}. "
                        "This will be ignored by the backend. "
                        "If you want to disable dedup, "
                        "alter the `dedup` function to return 'p_row_id' instead."
                    )
                    logging.warning(msg)
                elif analysis_spec["DedupPeriodMinutes"] < 5:
                    msg = (
                        f"DedupPeriodMinutes for {analysis_id} is less than 5. "
                        "This is below Panther's DedupPeriodMinutes threshold, "
                        "and will be treated as '5' upon upload."
                    )
                    logging.warning(msg)

            classified_analysis = ClassifiedAnalysis(
                analysis_spec_filename, dir_name, analysis_spec
            )

            json_validator.validate(analysis_spec)

            all_specs.add_classified_analysis(analysis_type, classified_analysis)

        except SchemaWrongKeyError as err:
            invalid_specs.append((analysis_spec_filename, handle_wrong_key_error(err, keys)))
        except (
            SchemaMissingKeyError,
            SchemaForbiddenKeyError,
            SchemaUnexpectedTypeError,
        ) as err:
            invalid_specs.append((analysis_spec_filename, err))
            continue
        except SchemaError as err:
            # Intercept the error, otherwise the error message becomes confusing and unreadable
            error = err
            err_str = str(err)
            first_half = err_str.split(":", maxsplit=1)[0]
            second_half = err_str.split(")", maxsplit=1)[-1]
            if "LogTypes" in str(err):
                error = SchemaError(f"{first_half}: LOG_TYPE_REGEX{second_half}")
            elif "ResourceTypes" in str(err):
                error = SchemaError(f"{first_half}: RESOURCE_TYPE_REGEX{second_half}")
            invalid_specs.append((analysis_spec_filename, error))
        except jsonschema.exceptions.ValidationError as err:
            error_message = f"{getattr(err, 'json_path', 'error')}: {err.message}"
            invalid_specs.append(
                (
                    analysis_spec_filename,
                    jsonschema.exceptions.ValidationError(error_message),
                )
            )
        except Exception as err:  # pylint: disable=broad-except
            # Catch arbitrary exceptions thrown by bad specification files
            invalid_specs.append((analysis_spec_filename, err))
            continue
        finally:
            # Restore original values
            if tmp_logtypes and tmp_logtypes_key:
                analysis_schema.schema[tmp_logtypes_key] = tmp_logtypes

    return all_specs, invalid_specs


def enrich_test_data(backend: BackendClient, args: argparse.Namespace) -> Tuple[int, str]:
    """Imports each policy or rule and enriches their test data, if any. The
        modifications are saved in the Analysis YAML files, but not committed
        to git. Users of panther_analysis_tool are expected to commit the changes
        after review.

    Args:
        backend: Backend API client.
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A tuple of the return code, and a list of the rules whose test content was enriched.
    """

    if not backend.supports_enrich_test_data():
        msg = "enrich-test-data is only supported through token authentication"
        logging.error(msg)
        return 1, msg

    logging.info("Enriching test data for analysis items in %s\n", args.path)

    ignored_files = args.ignore_files
    search_directories = [args.path]

    # Load all of the anlaysis specs based on the search directories and ignored files.
    # We use the load_analysis_specs_ex variant to get a nice round object that includes
    # the YAML context for each analysis item. This means we can roundtrip without sadness.
    raw_analysis_items = list(
        load_analysis_specs_ex(search_directories, ignore_files=ignored_files, roundtrip_yaml=True)
    )
    specs, invalid_specs = classify_analysis(
        # unpack the nice dataclass into a tuple because we use Tuples too much everywhere
        [
            (
                raw_item.spec_filename,
                raw_item.relative_path,
                raw_item.analysis_spec,
                raw_item.error,
            )
            for raw_item in raw_analysis_items
        ],
        ignore_table_names=args.ignore_table_names,
        valid_table_names=args.valid_table_names,
    )

    # If no specs were found, nothing to do
    if specs.empty():
        if invalid_specs:
            msg = "Encountered invalid specs: " + ", ".join(invalid_specs)
            return 1, msg
        return 1, f"No analysis content to enrich tests data for in {args.path}"

    # Apply the filters as needed
    if getattr(args, "filter_inverted", None) is None:
        args.filter_inverted = {}
    specs = specs.apply(lambda l: filter_analysis(l, args.filter, args.filter_inverted))

    # If no specs after filtering, nothing to do
    if specs.empty():
        return (
            1,
            f"No analysis content in {args.path} matched filters {args.filter} - {args.filter_inverted}",
        )

    # We only used classify_analysis to figure out what to filter out, if anything.
    # We need to filter our own list of items now, using what's left in the `specs` variable.
    raw_analysis_items_by_id = {}
    for item in raw_analysis_items:
        if item.analysis_spec is not None:
            rule_id = item.analysis_spec.get("RuleID", "")
            if rule_id != "":
                raw_analysis_items_by_id[rule_id] = item
                continue

            policy_id = item.analysis_spec.get("PolicyID", "")
            if policy_id != "":
                raw_analysis_items_by_id[policy_id] = item
                continue

            logging.info(
                "Analysis item %s is not a Rule, Scheduled Rule, or Policy - skipping",
                item.spec_filename,
            )

    filtered_raw_analysis_items_by_id = {}
    all_relevant_specs = specs.detections + specs.simple_detections

    for spec in all_relevant_specs:
        rule_id = spec.analysis_spec.get("RuleID", "")
        if rule_id != "":
            filtered_raw_analysis_items_by_id[rule_id] = raw_analysis_items_by_id[rule_id]
            continue

        policy_id = spec.analysis_spec.get("PolicyID", "")
        if policy_id != "":
            filtered_raw_analysis_items_by_id[policy_id] = raw_analysis_items_by_id[policy_id]
            continue

    # Enrich the test data for each analysis item
    enricher = EnrichedEventGenerator(backend)
    result = enricher.enrich_test_data(list(filtered_raw_analysis_items_by_id.values()))

    # just report the detection IDs that were enriched
    enriched_analysis_ids = [analysis_spec.analysis_id() for analysis_spec in result]
    result_str = "No analysis specs enriched"
    if any(enriched_analysis_ids):
        result_str = "Analysis specs enriched:\n\t" + "\n\t".join(enriched_analysis_ids)
    return (0, result_str)


def get_shallow_dependencies(spec_: ClassifiedAnalysis) -> set[str]:
    """Returns a set of all IDs of dependencies of this analysis item."""

    spec = spec_.analysis_spec
    analysis_type = spec["AnalysisType"]

    # Check for global helper imports
    if analysis_type in ("rule", "scheduled_rule", "policy", "global", "data_model"):
        # Ignore any helper files like global_filter_*
        if analysis_type == "global" and get_spec_id(spec).startswith("global_filter_"):
            return set()
        return get_imports(spec, spec_.dir_name)
    # Ensure any sub-rules used in a correlation rule are also added to the pack
    if analysis_type == "correlation_rule":
        detection_spec = spec["Detection"][0]  # Detections are a list for some reason
        subrules = detection_spec.get("Sequence") or detection_spec.get("Group")
        return set(subrule["RuleID"] for subrule in subrules)
    # Otherwise, return empty set
    return set()


def check_packs(args: argparse.Namespace) -> Tuple[int, str]:
    """
    Checks each existing pack whether it includes all necessary rules and other items. Also checks
    if any detections, queries, etc. are not included in any packs
    """
    specs, _ = load_analysis(args.path, True, [], [])

    dependencies = {}  # Create a mapping of dependencies of each analysis item
    log_types = {}  # Which items depend on which log types
    queries = {}  # Which items depend on which queries?
    data_models = {}  # Mapping of log types to corresponding data model
    all_analysis_item_ids = set()  # Record all valid analysis items by ID
    for spec_ in specs.items():
        # _spec is a ClassifiedAnalysis object - the dictionary spec is a property
        spec = spec_.analysis_spec
        id_ = get_spec_id(spec)

        # Record dependencies
        dependencies[id_] = get_shallow_dependencies(spec_)
        if spec_log_types := spec.get("LogTypes"):
            log_types[id_] = set(spec_log_types)
        if spec_queries := spec.get("ScheduledQueries"):
            queries[id_] = set(spec_queries)

        # Map log types to Data Models
        if spec["AnalysisType"] == "datamodel":
            for log_type in spec["LogTypes"]:
                data_models[log_type] = id_

        # Record the ID
        all_analysis_item_ids.add(id_)

    # Now we scan through each pack and check if it has all the required items
    missing_pack_items: list[dict[str, Any]] = []
    for spec_ in specs.packs:
        spec = spec_.analysis_spec
        path = os.path.join(spec_.dir_name, spec_.file_name)

        # Load current pack items
        pack_item_ids = spec["PackDefinition"]["IDs"]

        # Maintain a set of required pack items
        pack_dependencies = set()
        for pack_item_id in pack_item_ids:
            pack_dependencies.update(get_recursive_mappings(pack_item_id, dependencies))

        # Sometimes this returns dependiencies that aren't analysis items (such as datetime module)
        #   We ensure we only include the IDs of things that are real analysis items
        pack_dependencies = pack_dependencies & all_analysis_item_ids

        # Make a list of all log types and scheduled queries referenced in the pack items.
        pack_log_types = set()
        pack_queries = set()
        for dependency in list(pack_dependencies):
            pack_log_types.update(log_types.get(dependency, set()))
            pack_queries.update(queries.get(dependency, set()))

        # For each log type used by the pack, if a data model exists for that log type, include it
        #   in the pack also.
        pack_data_models = set()
        for log_type in list(pack_log_types):
            if data_model := data_models.get(log_type):
                pack_data_models.add(data_model)

        # Calculate the difference between the calculated pack manifest (with dependencies) vs the
        #   original pack manifest
        calculated_pack_manifest = pack_dependencies | pack_queries | pack_data_models
        if missing_items := calculated_pack_manifest - set(pack_item_ids):
            # We use set logic to get the overlap of the missing items and each type of item
            missing_pack_items.append(
                {
                    "path": path,
                    "queries": missing_items & pack_queries,
                    "data_models": missing_items & pack_data_models,
                    "globals": missing_items & set(specs.globals),
                    "detections": missing_items
                    - (pack_queries | set(specs.globals) | pack_data_models),
                }
            )

    if missing_pack_items:
        err_str = ["The following packs have missing items:\n"]
        for missing_entries in missing_pack_items:
            err_str += [str(missing_entries.pop("path"))]
            for key, val in missing_entries.items():
                if not val:
                    continue
                err_str += [f"    {key.upper()}:"]
                for missing_item_id in sorted(list(val)):
                    err_str += [f"\t{missing_item_id}"]
                err_str += [""]

        return 1, "\n".join(err_str)

    # Look for items not in packs
    all_items_in_packs = set()
    for pack in specs.packs:
        pack_spec = pack.analysis_spec
        all_items_in_packs.update(set(pack_spec["PackDefinition"]["IDs"]))

    all_items_not_in_packs = set()
    for spec_ in specs.items():
        spec = spec_.analysis_spec
        id_ = get_spec_id(spec)
        tags = set(tag.lower() for tag in spec.get("Tags", []))
        # Only check rules, not luts, policies, queries, etc.
        if spec.get("AnalysisType") not in ("rule", "scheduled_rule", "correlation_rule"):
            continue
        # Ignore rules with DEPRECATED in the title
        if "deprecated" in spec.get("DisplayName", "").lower():
            continue
        # Ignore rules with certain tags
        if {"deprecated", "no pack", "configuration required", "multi-table query"} & tags:
            continue

        if id_ not in all_items_in_packs:
            all_items_not_in_packs.add(id_)

    if all_items_not_in_packs:
        err_str = ["The following items are not included in any packs:"]
        err_str += sorted(list(all_items_not_in_packs))
        return 1, "\n".join(err_str)

    return 0, "Looks like packs are up to date"


def lookup_analysis_id(analysis_spec: Any, analysis_type: str) -> str:
    analysis_id = "UNKNOWN_ID"
    if analysis_type == AnalysisTypes.DATA_MODEL:
        analysis_id = analysis_spec["DataModelID"]
    elif analysis_type == AnalysisTypes.GLOBAL:
        analysis_id = analysis_spec["GlobalID"]
    elif analysis_type == AnalysisTypes.LOOKUP_TABLE:
        analysis_id = analysis_spec["LookupName"]
    elif analysis_type == AnalysisTypes.PACK:
        analysis_id = analysis_spec["PackID"]
    elif analysis_type == AnalysisTypes.POLICY:
        analysis_id = analysis_spec["PolicyID"]
    elif analysis_type == AnalysisTypes.SCHEDULED_QUERY:
        analysis_id = analysis_spec["QueryName"]
    elif analysis_type == AnalysisTypes.SAVED_QUERY:
        analysis_id = analysis_spec["QueryName"]
    elif analysis_type in [
        AnalysisTypes.RULE,
        AnalysisTypes.SCHEDULED_RULE,
        AnalysisTypes.CORRELATION_RULE,
    ]:
        analysis_id = analysis_spec["RuleID"]
    return analysis_id


def handle_wrong_key_error(err: SchemaWrongKeyError, keys: list) -> Exception:
    regex = r"Wrong key(?:s)? (.+?) in (.*)$"
    matches = re.match(regex, str(err))
    msg = "{} not in list of valid keys: {}"
    try:
        if matches:
            raise SchemaWrongKeyError(msg.format(matches.group(1), keys)) from err
        raise SchemaWrongKeyError(msg.format("UNKNOWN_KEY", keys)) from err
    except SchemaWrongKeyError as exc:
        return exc


def run_tests(  # pylint: disable=too-many-arguments
    analysis: Dict[str, Any],
    analysis_data_models: Dict[str, DataModel],
    detection: typing.Optional[Detection],
    detection_id: str,
    failed_tests: DefaultDict[str, list],
    minimum_tests: int,
    destinations_by_name: Dict[str, FakeDestination],
    ignore_exception_types: List[Type[Exception]],
    all_test_results: typing.Optional[TestResultsContainer],
    correlation_rule_test_results: List[Dict[str, Any]],
    test_names: typing.Optional[List[str]] = None,
) -> DefaultDict[str, list]:
    if len(analysis.get("Tests", [])) < minimum_tests:
        failed_tests[detection_id].append(
            f'Insufficient test coverage: {minimum_tests} tests required but only {len(analysis.get("Tests", []))} found'
        )

    # First check if any tests exist, so we can print a helpful message if not
    if "Tests" not in analysis:
        print(f"\tNo tests configured for {detection_id}")
        return failed_tests

    failed_tests = _run_tests(
        analysis_data_models,
        detection,
        analysis["Tests"],
        failed_tests,
        destinations_by_name,
        ignore_exception_types,
        all_test_results,
        correlation_rule_test_results,
        detection_id,
        test_names,
    )

    if minimum_tests > 1 and not (
        [x for x in analysis["Tests"] if x["ExpectedResult"]]
        and [x for x in analysis["Tests"] if not x["ExpectedResult"]]
    ):
        failed_tests[detection_id].append(
            "Insufficient test coverage: expected at least one positive and one negative test"
        )

    return failed_tests


def _process_correlation_rule_test_results(
    detection_id: str,
    correlation_rule_test_results: List[Dict[str, Any]],
    all_test_results: typing.Optional[TestResultsContainer],
    failed_tests: DefaultDict[str, list],
) -> DefaultDict[str, list]:
    status_passed = "passed"
    status_errored = "errored"

    for test_result_payload in correlation_rule_test_results:
        test_case_id = test_result_payload.get("name", "")
        test_case_passed = test_result_payload.get("passed", False)
        test_case_err = test_result_payload.get("error", None)
        test_result = TestResult(
            id=test_case_id,
            name=test_case_id,
            detectionId=detection_id,
            genericError=test_case_err,
            errored=test_case_err is not None,
            passed=test_case_passed,
            error=None,
            trigger_alert=None,
            functions=None,
        )
        if not test_case_passed:
            failed_tests[detection_id].append(f"{test_result.name}")
        if all_test_results:
            test_result_str = status_passed if test_result.passed else status_errored
            stored_test_results = getattr(all_test_results, test_result_str)
            if detection_id not in stored_test_results:
                stored_test_results[detection_id] = []
            stored_test_results[detection_id].append(
                TestResultContainer(
                    detection=None,
                    result=test_result,
                    failed_tests=failed_tests,
                    output="",
                )
            )
        else:
            _print_test_result(None, test_result, failed_tests)
    return failed_tests


def _run_tests(  # pylint: disable=too-many-arguments
    analysis_data_models: Dict[str, DataModel],
    detection: typing.Optional[Detection],
    tests: List[Dict[str, Any]],
    failed_tests: DefaultDict[str, list],
    destinations_by_name: Dict[str, FakeDestination],
    ignore_exception_types: List[Type[Exception]],
    all_test_results: typing.Optional[TestResultsContainer],
    correlation_rule_test_results: List[Dict[str, Any]],
    detection_id: str,
    test_names: typing.Optional[List[str]] = None,
) -> DefaultDict[str, list]:
    status_passed = "passed"
    status_errored = "errored"
    if detection is None:
        return _process_correlation_rule_test_results(
            detection_id,
            correlation_rule_test_results,
            all_test_results,
            failed_tests,
        )

    # Filter tests by name if test_names is provided
    if test_names:
        tests = [test for test in tests if test.get("Name") in test_names]

    for unit_test in tests:
        test_output = ""
        try:
            entry = unit_test.get("Resource") or unit_test["Log"]
            log_type = entry.get("p_log_type", "")
            mocks = unit_test.get("Mocks")
            mock_methods: Dict[str, Any] = {}
            if mocks:
                mock_methods = {
                    each_mock["objectName"]: MagicMock(return_value=each_mock["returnValue"])
                    for each_mock in mocks
                    if "objectName" in each_mock and "returnValue" in each_mock
                }
            test_case: Mapping = entry
            if detection.detection_type.upper() != TYPE_POLICY.upper():
                test_case = PantherEvent(entry, analysis_data_models.get(log_type))
            test_output_buf = io.StringIO()
            with (
                contextlib.redirect_stdout(test_output_buf),
                contextlib.redirect_stderr(test_output_buf),
            ):
                if mock_methods:
                    with patch.multiple(detection.module, **mock_methods):
                        result = detection.run(
                            test_case, {}, destinations_by_name, batch_mode=False
                        )
                else:
                    result = detection.run(test_case, {}, destinations_by_name, batch_mode=False)
            test_output = test_output_buf.getvalue()
        except (AttributeError, KeyError) as err:
            logging.warning("AttributeError: {%s}", err)
            logging.debug(str(err), exc_info=err)
            failed_tests[detection.detection_id].append(unit_test["Name"])
            continue
        except Exception as err:  # pylint: disable=broad-except
            # Catch arbitrary exceptions raised by user code
            logging.warning("Unexpected exception: {%s}", err)
            logging.debug(str(err), exc_info=err)
            failed_tests[detection.detection_id].append(unit_test["Name"])
            continue
        finally:
            if len(test_output) > 0 and not all_test_results:
                # not buffering results for later sorting; print any output from tests here:
                print(test_output)

        # print results
        spec = TestSpecification(
            id=unit_test["Name"],
            name=unit_test["Name"],
            data=unit_test.get("Resource") or unit_test["Log"],
            mocks=unit_test.get("Mocks", {}),
            expectations=TestExpectations(detection=unit_test["ExpectedResult"]),
        )

        test_result = TestCaseEvaluator(spec, result).interpret(
            ignore_exception_types=ignore_exception_types
        )
        if detection.suppress_alert:
            # only keep alert context function
            test_result.functions.dedupFunction = None
            test_result.functions.destinationsFunction = None
            test_result.functions.runbookFunction = None
            test_result.functions.titleFunction = None
            test_result.functions.severityFunction = None
            test_result.functions.descriptionFunction = None
            test_result.functions.referenceFunction = None

        if all_test_results:
            test_result_str = status_passed if test_result.passed else status_errored
            stored_test_results = getattr(all_test_results, test_result_str)
            if test_result.detectionId not in stored_test_results:
                stored_test_results[test_result.detectionId] = []
            stored_test_results[test_result.detectionId].append(
                TestResultContainer(
                    detection=detection,
                    result=test_result,
                    failed_tests=failed_tests,
                    output=test_output,
                )
            )
        else:
            _print_test_result(detection, test_result, failed_tests)

    return failed_tests


def _print_test_result(
    detection: typing.Optional[Detection],
    test_result: TestResult,
    failed_tests: DefaultDict[str, list],
) -> None:
    status_pass = Fore.GREEN + "PASS" + Style.RESET_ALL
    status_fail = Fore.RED + "FAIL" + Style.RESET_ALL

    if test_result.passed:
        outcome = status_pass
    else:
        outcome = status_fail
    # print overall status for this test
    print(f"\t[{outcome}] {test_result.name}")

    if detection is None:
        return

    # print function output and status as necessary
    functions = asdict(test_result.functions)
    for function_name, function_result in functions.items():
        printable_name = function_name.replace("Function", "")
        if printable_name == "detection":
            # extract this detections matcher function name
            printable_name = detection.matcher_function_name
        if function_result:
            if function_result.get("error"):
                # add this as output to the failed test spec as well
                failed_tests[detection.detection_id].append(f"{test_result.name}:{printable_name}")
                print(
                    f'\t\t[{status_fail}] [{printable_name}] {function_result.get("error", {}).get("message")}'
                )
            # if it didn't error, we simply need to check if the output was as expected
            elif not function_result.get("matched", True):
                failed_tests[detection.detection_id].append(f"{test_result.name}:{printable_name}")
                print(f'\t\t[{status_fail}] [{printable_name}] {function_result.get("output")}')
            else:
                print(f'\t\t[{status_pass}] [{printable_name}] {function_result.get("output")}')


def setup_parser() -> argparse.ArgumentParser:
    # pylint: disable=too-many-statements,too-many-locals
    # setup dictionary of named args for some common arguments across commands
    batch_uploads_name = "--batch"
    batch_uploads_arg: Dict[str, Any] = {
        "action": "store_true",
        "default": False,
        "required": False,
        "help": "When set your upload will be broken down into multiple zip files",
    }
    filter_name = "--filter"
    filter_arg: Dict[str, Any] = {
        "required": False,
        "metavar": "KEY=VALUE",
        "nargs": "+",
    }
    kms_key_name = "--kms-key"
    kms_key_arg: Dict[str, Any] = {
        "type": str,
        "help": "The key id to use to sign the release asset.",
        "required": False,
    }
    min_test_name = "--minimum-tests"
    min_test_arg: Dict[str, Any] = {
        "default": 0,
        "type": int,
        "help": "The minimum number of tests in order for a detection to be considered passing. "
        + "If a number greater than 1 is specified, at least one True and one False test is "
        + "required.",
        "required": False,
    }
    out_name = "--out"
    out_arg: Dict[str, Any] = {
        "default": ".",
        "type": str,
        "help": "The path to store output files.",
        "required": False,
    }
    path_name = "--path"
    path_arg: Dict[str, Any] = {
        "default": ".",
        "type": str,
        "help": "The relative path to Panther policies and rules.",
        "required": False,
    }
    skip_test_name = "--skip-tests"
    skip_test_arg: Dict[str, Any] = {
        "action": "store_true",
        "default": False,
        "dest": "skip_tests",
        "required": False,
    }
    skip_disabled_test_name = "--skip-disabled-tests"
    skip_disabled_test_arg: Dict[str, Any] = {
        "action": "store_true",
        "default": False,
        "dest": "skip_disabled_tests",
        "required": False,
    }
    ignore_extra_keys_name = "--ignore-extra-keys"
    ignore_extra_keys_arg: Dict[str, Any] = {
        "required": False,
        "default": False,
        "type": strtobool,
        "help": "Meant for advanced users; allows skipping of extra keys from schema validation.",
    }
    ignore_files_name = "--ignore-files"
    ignore_files_arg: Dict[str, Any] = {
        "required": False,
        "dest": "ignore_files",
        "nargs": "+",
        "help": "Relative path to files in this project to be ignored by panther-analysis tool, "
        + "space separated. Example ./foo.yaml ./bar/baz.yaml",
        "type": str,
        "default": [],
    }
    available_destination_name = "--available-destination"
    available_destination_arg: Dict[str, Any] = {
        "required": False,
        "default": None,
        "type": str,
        "action": "append",
        "help": "A destination name that may be returned by the destinations function. "
        "Repeat the argument to define more than one name.",
    }
    sort_test_results_name = "--sort-test-results"
    sort_test_results_arg: Dict[str, Any] = {
        "action": "store_true",
        "required": False,
        "default": False,
        "dest": "sort_test_results",
        "help": "Sort test results by whether the test passed or failed (passing tests first), "
        "then by rule ID",
    }
    print_failed_only_name = "--show-failures-only"
    print_failed_only_arg: Dict[str, Any] = {
        "action": "store_true",
        "required": False,
        "default": False,
        "dest": "print_failed_test_results_only",
        "help": "Only print test results for failed tests.",
    }
    ignore_table_names_name = "--ignore-table-names"
    ignore_table_names_arg: Dict[str, Any] = {
        "action": "store_true",
        "default": False,
        "dest": "ignore_table_names",
        "required": False,
        "help": "Allows skipping of table name validation from schema validation. Useful when querying "
        "non-Panther or non-Snowflake tables",
    }
    valid_table_names_name = "--valid-table-names"
    valid_table_names_arg: Dict[str, Any] = {
        "required": False,
        "dest": "valid_table_names",
        "nargs": "+",
        "help": "Fully qualified table names that should be considered valid during schema validation "
        + "(in addition to standard Panther/Snowflake tables), space separated. "
        + "Accepts '*' as wildcard character matching 0 or more characters. "
        + "Example foo.bar.baz bar.baz.* foo.*bar.baz baz.* *.foo.*",
        "type": str,
        "default": [],
    }
    test_names_name = "--test-names"
    test_names_arg: Dict[str, Any] = {
        "required": False,
        "metavar": "TEST_NAME",
        "nargs": "+",
        "help": "Only run tests with these names. Can be used with --filter to run specific tests for specific rules.",
    }

    # -- root parser

    parser = argparse.ArgumentParser(
        description="Panther Analysis Tool: A command line tool for "
        + "managing Panther policies and rules.",
        prog="panther_analysis_tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=VERSION_STRING)
    parser.add_argument("--debug", action="store_true", dest="debug")
    parser.add_argument("--skip-version-check", dest="skip_version_check", action="store_true")
    subparsers = parser.add_subparsers()

    # -- release command

    release_help_text = (
        "Create release assets for repository containing panther detections. "
        + "Generates a file called panther-analysis-all.zip and optionally generates "
        + "panther-analysis-all.sig"
    )
    release_parser = subparsers.add_parser(
        "release",
        help=release_help_text,
        description=release_help_text,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    standard_args.for_public_api(release_parser, required=False)
    standard_args.using_aws_profile(release_parser)

    release_parser.add_argument(filter_name, **filter_arg)
    release_parser.add_argument(ignore_files_name, **ignore_files_arg)
    release_parser.add_argument(kms_key_name, **kms_key_arg)
    release_parser.add_argument(min_test_name, **min_test_arg)
    release_parser.add_argument(out_name, **out_arg)
    release_parser.add_argument(path_name, **path_arg)
    release_parser.add_argument(skip_test_name, **skip_test_arg)
    release_parser.add_argument(skip_disabled_test_name, **skip_disabled_test_arg)
    release_parser.add_argument(available_destination_name, **available_destination_arg)
    release_parser.add_argument(sort_test_results_name, **sort_test_results_arg)
    release_parser.add_argument(print_failed_only_name, **print_failed_only_arg)
    release_parser.add_argument(ignore_table_names_name, **ignore_table_names_arg)
    release_parser.add_argument(valid_table_names_name, **valid_table_names_arg)
    release_parser.set_defaults(func=generate_release_assets)

    # -- test command

    test_help_text = "Validate analysis specifications and run policy and rule tests."
    test_parser = subparsers.add_parser(
        "test",
        help=test_help_text,
        description=test_help_text,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    standard_args.for_public_api(test_parser, required=False)
    test_parser.add_argument(filter_name, **filter_arg)
    test_parser.add_argument(min_test_name, **min_test_arg)
    test_parser.add_argument(path_name, **path_arg)
    test_parser.add_argument(ignore_extra_keys_name, **ignore_extra_keys_arg)
    test_parser.add_argument(ignore_files_name, **ignore_files_arg)
    test_parser.add_argument(skip_disabled_test_name, **skip_disabled_test_arg)
    test_parser.add_argument(available_destination_name, **available_destination_arg)
    test_parser.add_argument(sort_test_results_name, **sort_test_results_arg)
    test_parser.add_argument(print_failed_only_name, **print_failed_only_arg)
    test_parser.add_argument(ignore_table_names_name, **ignore_table_names_arg)
    test_parser.add_argument(valid_table_names_name, **valid_table_names_arg)
    test_parser.add_argument(test_names_name, **test_names_arg)
    test_parser.set_defaults(func=pat_utils.func_with_optional_backend(test_analysis))

    # -- publish command

    publish_help_text = (
        "Publishes a new release, generates the release assets, and uploads them. "
        + "Generates a file called panther-analysis-all.zip and optionally generates "
        + "panther-analysis-all.sig"
    )
    publish_parser = subparsers.add_parser(
        "publish",
        help=publish_help_text,
        description=publish_help_text,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    publish_parser.add_argument(
        "--body",
        help="The text body for the release",
        type=str,
        default="",
    )
    publish_parser.add_argument(
        "--github-branch",
        help="The branch to base the release on",
        type=str,
        default="main",
    )
    publish_parser.add_argument(
        "--github-owner",
        help="The github owner of the repository",
        type=str,
        default="panther-labs",
    )
    publish_parser.add_argument(
        "--github-repository",
        help="The github repository name",
        type=str,
        default="panther-analysis",
    )
    publish_parser.add_argument(
        "--github-tag",
        help="The tag name for this release",
        type=str,
        required=True,
    )

    standard_args.for_public_api(publish_parser, required=False)
    standard_args.using_aws_profile(publish_parser)

    publish_parser.add_argument(filter_name, **filter_arg)
    publish_parser.add_argument(kms_key_name, **kms_key_arg)
    publish_parser.add_argument(min_test_name, **min_test_arg)
    publish_parser.add_argument(out_name, **out_arg)
    publish_parser.add_argument(skip_test_name, **skip_test_arg)
    publish_parser.add_argument(skip_disabled_test_name, **skip_disabled_test_arg)
    publish_parser.add_argument(available_destination_name, **available_destination_arg)
    publish_parser.add_argument(ignore_files_name, **ignore_files_arg)
    publish_parser.set_defaults(func=publish_release)

    # -- upload command

    upload_help_text = "Upload specified policies and rules to a Panther deployment."
    upload_parser = subparsers.add_parser(
        "upload",
        help=upload_help_text,
        description=upload_help_text,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    upload_parser.add_argument(
        "--auto-disable-base",
        help="If uploading derived detections, set the corresponding base detection's Enabled status to false prior to upload",
        default=False,
        required=False,
        action="store_true",
    )
    upload_parser.add_argument(
        "--max-retries",
        help="Retry to upload on a failure for a maximum number of times",
        default=10,
        type=int,
        required=False,
    )

    no_async_uploads_name = "--no-async"
    no_async_uploads_arg: Dict[str, Any] = {
        "action": "store_true",
        "default": False,
        "required": False,
        "help": "When set your upload will be synchronous",
    }

    standard_args.for_public_api(upload_parser, required=False)
    standard_args.using_aws_profile(upload_parser)

    upload_parser.add_argument(filter_name, **filter_arg)
    upload_parser.add_argument(min_test_name, **min_test_arg)
    upload_parser.add_argument(out_name, **out_arg)
    upload_parser.add_argument(path_name, **path_arg)
    upload_parser.add_argument(skip_test_name, **skip_test_arg)
    upload_parser.add_argument(skip_disabled_test_name, **skip_disabled_test_arg)
    upload_parser.add_argument(ignore_extra_keys_name, **ignore_extra_keys_arg)
    upload_parser.add_argument(ignore_files_name, **ignore_files_arg)
    upload_parser.add_argument(available_destination_name, **available_destination_arg)
    upload_parser.add_argument(sort_test_results_name, **sort_test_results_arg)
    upload_parser.add_argument(print_failed_only_name, **print_failed_only_arg)
    upload_parser.add_argument(batch_uploads_name, **batch_uploads_arg)
    upload_parser.add_argument(no_async_uploads_name, **no_async_uploads_arg)
    upload_parser.add_argument(ignore_table_names_name, **ignore_table_names_arg)
    upload_parser.add_argument(valid_table_names_name, **valid_table_names_arg)
    upload_parser.set_defaults(func=pat_utils.func_with_backend(upload_analysis))

    # -- delete command

    delete_help_text = "Delete policies, rules, or saved queries from a Panther deployment"
    delete_parser = subparsers.add_parser(
        "delete",
        help=delete_help_text,
        description=delete_help_text,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    delete_parser.add_argument(
        "--no-confirm",
        help="Skip manual confirmation of deletion",
        action="store_true",
        dest="confirm_bypass",
    )
    delete_parser.add_argument(
        "--athena-datalake",
        help="Instance DataLake is backed by Athena",
        action="store_true",
        dest="athena_datalake",
    )

    standard_args.for_public_api(delete_parser, required=False)
    standard_args.using_aws_profile(delete_parser)

    delete_parser.add_argument(
        "--analysis-id",
        help="Space separated list of Detection IDs",
        required=False,
        dest="analysis_id",
        type=str,
        default=[],
        nargs="+",
    )

    delete_parser.add_argument(
        "--query-id",
        help="Space separated list of Saved Queries",
        required=False,
        dest="query_id",
        nargs="+",
        type=str,
        default=[],
    )

    delete_parser.set_defaults(func=pat_utils.func_with_backend(bulk_delete.run))

    # -- update custom schemas command

    custom_schemas_help_text = "Update or create custom schemas on a Panther deployment."
    update_custom_schemas_parser = subparsers.add_parser(
        "update-custom-schemas",
        help=custom_schemas_help_text,
        description=custom_schemas_help_text,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    standard_args.for_public_api(update_custom_schemas_parser, required=False)
    standard_args.using_aws_profile(update_custom_schemas_parser)

    custom_schemas_path_arg = path_arg.copy()
    custom_schemas_path_arg["help"] = "The relative or absolute path to Panther custom schemas."
    update_custom_schemas_parser.add_argument(path_name, **custom_schemas_path_arg)
    update_custom_schemas_parser.set_defaults(
        func=pat_utils.func_with_backend(update_custom_schemas)
    )

    # -- test lookup command

    test_lookup_help_text = "Validate a Lookup Table spec file."
    test_lookup_table_parser = subparsers.add_parser(
        "test-lookup-table",
        help=test_lookup_help_text,
        description=test_lookup_help_text,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    standard_args.using_aws_profile(test_lookup_table_parser)

    test_lookup_table_parser.add_argument(
        "--path",
        type=str,
        help="The relative path to a lookup table input file.",
        default=".",
        required=True,
    )

    test_lookup_table_parser.set_defaults(func=test_lookup_table)

    # -- validate command
    validate_help_text = "Validate your bulk uploads against your panther instance"
    validate_parser = subparsers.add_parser(
        "validate",
        help=validate_help_text,
        description=validate_help_text,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    standard_args.for_public_api(validate_parser, required=False)
    validate_parser.add_argument(filter_name, **filter_arg)
    validate_parser.add_argument(ignore_files_name, **ignore_files_arg)
    validate_parser.add_argument(path_name, **path_arg)
    validate_parser.set_defaults(func=pat_utils.func_with_api_backend(validate.run))

    # -- zip command

    zip_help_text = "Create an archive of local policies and rules for uploading to Panther."
    zip_parser = subparsers.add_parser(
        "zip",
        help=zip_help_text,
        description=zip_help_text,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    standard_args.for_public_api(zip_parser, required=False)
    zip_parser.add_argument(filter_name, **filter_arg)
    zip_parser.add_argument(ignore_files_name, **ignore_files_arg)
    zip_parser.add_argument(min_test_name, **min_test_arg)
    zip_parser.add_argument(out_name, **out_arg)
    zip_parser.add_argument(path_name, **path_arg)
    zip_parser.add_argument(skip_test_name, **skip_test_arg)
    zip_parser.add_argument(skip_disabled_test_name, **skip_disabled_test_arg)
    zip_parser.add_argument(available_destination_name, **available_destination_arg)
    zip_parser.add_argument(sort_test_results_name, **sort_test_results_arg)
    zip_parser.add_argument(print_failed_only_name, **print_failed_only_arg)
    zip_parser.add_argument(ignore_table_names_name, **ignore_table_names_arg)
    zip_parser.add_argument(valid_table_names_name, **valid_table_names_arg)
    zip_parser.set_defaults(func=pat_utils.func_with_optional_backend(zip_analysis))

    # -- check-connection command

    check_connection_help_text = "Check your Panther API connection"
    check_conn_parser = subparsers.add_parser(
        "check-connection",
        help=check_connection_help_text,
        description=check_connection_help_text,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    standard_args.for_public_api(check_conn_parser, required=False)

    check_conn_parser.set_defaults(func=pat_utils.func_with_backend(check_connection.run))

    # -- benchmark command
    benchmark_help_text = (
        f"Performance test one rule against one of its log types. The rule must be the only item"
        f" in the working directory or specified by {path_name}, {ignore_files_name}, and {filter_name}. This feature"
        f" is an extension of Data Replay and is subject to the same limitations."
    )
    benchmark_parser = subparsers.add_parser(
        "benchmark",
        help=benchmark_help_text,
        description=benchmark_help_text,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    standard_args.for_public_api(benchmark_parser, required=False)
    benchmark_parser.add_argument(filter_name, **filter_arg)
    benchmark_parser.add_argument(ignore_files_name, **ignore_files_arg)
    benchmark_parser.add_argument(path_name, **path_arg)
    benchmark_parser.add_argument(out_name, **out_arg)
    benchmark_parser.add_argument(
        "--iterations",
        required=False,
        default=50,
        type=int,
        help="The number of iterations of the performance test to perform. Each iteration runs against the selected"
        " hour of data. Fewer iterations will be run if the time limit is reached. Min: 1",
    )
    benchmark_parser.add_argument(
        "--hour",
        required=False,
        type=dateutil.parser.parse,
        help="The hour of historical data to perform the benchmark against, in any parseable format, e.g."
        " '2023-07-31T09:00:00.000-7:00'. Minutes, Seconds, etc will be truncated if specified. If hour is "
        "unspecified, the performance test will run against the hour in the last two weeks with the largest log"
        " volume.",
    )
    benchmark_parser.add_argument(
        "--log-type",
        required=False,
        type=str,
        help="Required if the rule supports multiple log types, optional otherwise. Must be one of the rule's log"
        " types.",
    )
    benchmark_parser.set_defaults(func=pat_utils.func_with_api_backend(benchmark.run))

    # -- enrich-test-data command
    enrich_test_data_parser = subparsers.add_parser(
        "enrich-test-data",
        help="Enrich test data with additional enrichments from the Panther API.",
    )
    standard_args.for_public_api(enrich_test_data_parser, required=False)

    enrich_test_data_parser.add_argument(filter_name, **filter_arg)
    enrich_test_data_parser.add_argument(path_name, **path_arg)
    enrich_test_data_parser.add_argument(ignore_files_name, **ignore_files_arg)
    enrich_test_data_parser.add_argument(ignore_table_names_name, **ignore_table_names_arg)
    enrich_test_data_parser.add_argument(valid_table_names_name, **valid_table_names_arg)
    enrich_test_data_parser.set_defaults(func=pat_utils.func_with_backend(enrich_test_data))

    check_packs_parser = subparsers.add_parser(
        "check-packs",
        help="Ensure that packs don't have missing detections.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    check_packs_parser.add_argument(path_name, **path_arg)
    check_packs_parser.set_defaults(func=check_packs)
    standard_args.for_public_api(check_packs_parser, required=False)

    return parser


def setup_dynaconf() -> Dict[str, Any]:
    config_file_settings_raw = Dynaconf(
        settings_file=CONFIG_FILE,
        envvar_prefix="PANTHER",
        validators=[
            Validator("AWS_PROFILE", is_type_of=str),
            Validator("MINIMUM_TESTS", is_type_of=int),
            Validator("OUT", is_type_of=str),
            Validator("PATH", is_type_of=str),
            Validator("SKIP_TEST", is_type_of=bool),
            Validator("SKIP_DISABLED_TESTS", is_type_of=bool),
            Validator("IGNORE_FILES", is_type_of=(str, list)),
            Validator("AVAILABLE_DESTINATION", is_type_of=(str, list)),
            Validator("TEST_NAMES", is_type_of=(str, list)),
            Validator("KMS_KEY", is_type_of=str),
            Validator("BODY", is_type_of=str),
            Validator("GITHUB_BRANCH", is_type_of=str),
            Validator("GITHUB_OWNER", is_type_of=str),
            Validator("GITHUB_REPOSITORY", is_type_of=str),
            Validator("GITHUB_TAG", is_type_of=str),
            Validator("FILTER", is_type_of=dict),
            Validator("API_TOKEN", is_type_of=str),
            Validator("API_HOST", is_type_of=str),
        ],
    )
    # Dynaconf stores its keys in ALL CAPS
    return {k.lower(): v for k, v in config_file_settings_raw.as_dict().items()}


def dynaconf_argparse_merge(
    argparse_dict: Dict[str, Any], config_file_settings: Dict[str, Any]
) -> None:
    # Set up another parser w/ no defaults
    aux_parser = argparse.ArgumentParser(argument_default=argparse.SUPPRESS)
    for k in argparse_dict:
        arg_name = k.replace("_", "-")
        if isinstance(argparse_dict[k], bool):
            aux_parser.add_argument("--" + arg_name, action="store_true")
        else:
            aux_parser.add_argument("--" + arg_name)
    # cli_args only contains args that were passed in the command line
    cli_args, _ = aux_parser.parse_known_args()
    for key, value in config_file_settings.items():
        if key not in cli_args:
            argparse_dict[key] = value


# Parses the filters, expects a list of strings
def parse_filter(filters: List[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    parsed_filters: Dict[str, Any] = {}
    parsed_filters_inverted: Dict[str, Any] = {}
    for filt in filters:
        split = filt.split("=")
        if len(split) != 2 or split[0] == "" or split[1] == "":
            logging.warning("Filter %s is not in format KEY=VALUE, skipping", filt)
            continue
        # Check for "!="
        invert_filter = split[0].endswith("!")
        if invert_filter:
            split[0] = split[0][:-1]  # Remove the trailing "!"
        key = split[0]
        if not any(
            (
                key
                in (
                    list(GLOBAL_SCHEMA.schema.keys())
                    + list(POLICY_SCHEMA.schema.keys())
                    + list(RULE_SCHEMA.schema.keys())
                )
                for key in (key, Optional(key))
            )
        ):
            logging.warning("Filter key %s is not a valid filter field, skipping", key)
            continue
        if invert_filter:
            parsed_filters_inverted[key] = split[1].split(",")
        else:
            parsed_filters[key] = split[1].split(",")
        # Handle boolean fields
        if key == "Enabled":
            try:
                bool_value = bool(strtobool(split[1]))
            except ValueError:
                logging.warning("Filter key %s should have either true or false, skipping", key)
                continue
            if invert_filter:
                parsed_filters_inverted[key] = [bool_value]
            else:
                parsed_filters[key] = [bool_value]
    return parsed_filters, parsed_filters_inverted


def run() -> None:
    # setup logger and print version info as necessary
    logging.basicConfig(
        format="%(levelname)s: %(message)s",
        level=logging.INFO,
    )

    parser = setup_parser()
    # if no args are passed, print the help output
    args = parser.parse_args(args=None if sys.argv[1:] else ["--help"])

    if not args.skip_version_check:
        latest = pat_utils.get_latest_version()
        if not pat_utils.is_latest(latest):
            logging.warning(
                "%s v%s is available (current: v%s). Run: pip3 install %s --upgrade",
                PACKAGE_NAME,
                latest,
                VERSION_STRING,
                PACKAGE_NAME,
            )

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        aiohttp_logger.setLevel(logging.WARNING)
        logging.getLogger("sqlfluff.parser").setLevel(logging.WARNING)
        logging.getLogger("sqlfluff.linter").setLevel(logging.WARNING)
        logging.getLogger("sqlfluff.lexer").setLevel(logging.WARNING)
        logging.getLogger("sqlfluff.templater").setLevel(logging.WARNING)

    if getattr(args, "filter", None) is not None:
        args.filter, args.filter_inverted = parse_filter(args.filter)
    if getattr(args, "filter_inverted", None) is None:
        args.filter_inverted = {}

    for key in os.environ:
        if key.startswith("PANTHER_"):
            logging.info("Found environment variables prefixed with 'PANTHER'")
            break
    if os.path.exists(CONFIG_FILE):
        logging.info(
            "Found config file %s (note: command line options will override config file settings)",
            CONFIG_FILE,
        )
    config_file_settings = setup_dynaconf()
    dynaconf_argparse_merge(vars(args), config_file_settings)
    if args.debug:
        for key, value in vars(args).items():
            logging.debug(f"{key}={value}")  # pylint: disable=W1203

    # Although not best practice, the alternative is ugly and significantly harder to maintain.
    if bool(getattr(args, "ignore_extra_keys", None)):
        RULE_SCHEMA._ignore_extra_keys = True  # pylint: disable=protected-access
        POLICY_SCHEMA._ignore_extra_keys = True  # pylint: disable=protected-access
        DERIVED_SCHEMA._ignore_extra_keys = True  # pylint: disable=protected-access

    try:
        return_code, out = args.func(args)
    except BackendNotFoundException as err:
        logging.error('Backend not found: "%s"', err)
        sys.exit(1)
    except Exception as err:  # pylint: disable=broad-except
        # Catch arbitrary exceptions without printing help message
        logging.warning('Unhandled exception: "%s"', err)
        logging.debug("Full error traceback:", exc_info=err, stack_info=True)
        sys.exit(1)

    if return_code == 1:
        # out is excpected to be a a list of tuples of (filename, error_message)
        if out and isinstance(out, list):
            try:
                # Try some nicer error printing if we can
                error = ""
                for errspec in out:
                    if isinstance(errspec, tuple):
                        fname, error = errspec
                    else:
                        fname = ""
                        error = errspec
                msg = str(error).replace("\n", " ")  # Remove newlines from error message
                logging.error("%s %s", fname, msg)
            except Exception:  # pylint: disable=broad-except
                logging.error(out)  # Fallback to printing the entire output
    elif return_code == 0:
        if out:
            logging.info(out)

    sys.exit(return_code)


if __name__ == "__main__":
    run()
