# pylint: disable=wrong-import-order, wrong-import-position, ungrouped-imports, too-many-arguments
import base64
import contextlib
import hashlib
import importlib
import io
import json
import logging
import mimetypes
import os
import shutil
import subprocess  # nosec
import sys
import time
import traceback
import zipfile
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime
from functools import wraps
from inspect import signature

# Comment below disabling pylint checks is due to a bug in the CircleCi image with Pylint
# It seems to be unable to import the distutils module, however the module is present and importable
# in the Python Repl.
from typing import (
    Any,
    Callable,
    DefaultDict,
    Dict,
    List,
    Optional,
    TextIO,
    Tuple,
    Type,
    TypeAlias,
    cast,
)
from unittest.mock import MagicMock, patch
from uuid import uuid4

import botocore
import dateutil.parser
import requests
import schema
import typer
from colorama import Fore, Style
from gql.transport.aiohttp import log as aiohttp_logger
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
from typer_config import use_yaml_config
from typing_extensions import Annotated

from panther_analysis_tool import analysis_utils, cli_output
from panther_analysis_tool import util as pat_utils
from panther_analysis_tool.analysis_utils import (
    classify_analysis,
    disable_all_base_detections,
    filter_analysis,
    get_simple_detections_as_python,
    load_analysis,
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
    validate,
)
from panther_analysis_tool.command.standard_args import (
    APIHostType,
    APITokenType,
    AvailableDestinationType,
    AWSProfileType,
    FilterType,
    IgnoreExtraKeysType,
    IgnoreFilesType,
    IgnoreTableNamesType,
    KMSKeyType,
    MinimumTestsType,
    OutType,
    PathType,
    ShowFailuresOnlyType,
    SkipDisabledTestsType,
    SkipTestsType,
    SortTestResultsType,
    ValidTableNamesType,
)
from panther_analysis_tool.constants import (
    BACKEND_FILTERS_ANALYSIS_SPEC_KEY,
    CONFIG_FILE,
    ENABLE_CORRELATION_RULES_FLAG,
    PACKAGE_NAME,
    VERSION_STRING,
    AnalysisTypes,
)
from panther_analysis_tool.core.definitions import (
    ClassifiedAnalysis,
    TestResultContainer,
    TestResultsContainer,
)
from panther_analysis_tool.core.parse import (
    Filter,
    get_filters_with_status_filters,
    parse_filter,
)
from panther_analysis_tool.destination import FakeDestination
from panther_analysis_tool.directory import setup_temp
from panther_analysis_tool.enriched_event_generator import EnrichedEventGenerator
from panther_analysis_tool.log_schemas import user_defined
from panther_analysis_tool.schemas import LOOKUP_TABLE_SCHEMA
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
from panther_analysis_tool.validation import validate_packs
from panther_analysis_tool.zip_chunker import ZipArgs, ZipChunk, analysis_chunks

# This file was generated in whole or in part by GitHub Copilot.

# interpret datetime as str, the backend uses the default behavior for json.loads, which
# interprets these as str.  This sets global config for ruamel SafeConstructor
constructor.SafeConstructor.add_constructor(
    "tag:yaml.org,2002:timestamp", SafeConstructor.construct_yaml_str
)


app = typer.Typer(
    help="Panther Analysis Tool: A command line tool for managing Panther policies and rules.",
    add_completion=True,
    rich_markup_mode="rich",  # optional, nicer help formatting
)


PantherCommand: TypeAlias = Callable[..., Tuple[int, list[Any]]] | Callable[..., Tuple[int, str]]


_DISABLE_PANTHER_EXCEPTION_HANDLER = False
_SKIP_HTTP_VERSION_CHECK = False


def call_and_exit(func: PantherCommand) -> Callable[..., None]:
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> None:
        return_code, out = func(*args, **kwargs)

        if return_code == 1:
            # out is expected to be a list of tuples of (filename, error_message)
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
                except Exception:  # pylint: disable=broad-except`
                    if _DISABLE_PANTHER_EXCEPTION_HANDLER:
                        raise
                    logging.error(out)  # Fallback to printing the entire output
            else:  # If it's not a tuple, just print the output
                logging.error(out)
        elif return_code == 0 and out:
            logging.info(out)

        raise typer.Exit(code=return_code)

    # This is needed to make typer think the signature of the wrapped function is the same as the original function
    # invalid mypy error https://github.com/python/mypy/issues/12472
    wrapper.__signature__ = signature(func, eval_str=True)  # type: ignore[attr-defined]
    return wrapper


def app_command_with_config(
    **command_kwargs: Any,
) -> Callable[[PantherCommand], Callable[..., None]]:
    """
    A combined decorator that applies both @app_command_with_config and @use_yaml_config decorators.

    Args:
        **command_kwargs: Keyword arguments to pass to app_command_with_config()

    Returns:
        A decorator function that applies both decorators
    """

    def decorator(func: PantherCommand) -> Callable[..., None]:
        conf = None
        if os.path.exists(CONFIG_FILE):
            # typer emits a warning if the config file is not found to avoid this we
            # set the config file to None
            conf = CONFIG_FILE

        # Apply use_yaml_config first, then app_command_with_config
        func_2 = call_and_exit(func)
        func_2 = use_yaml_config(default_value=conf)(func_2)
        func_2 = app.command(**command_kwargs)(func_2)
        return func_2

    return decorator


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


# pylint: disable=too-many-locals
def zip_analysis_chunks(
    out: str,
    path: str,
    ignore_files: List[str],
    filters: List[Filter],
    filters_inverted: List[Filter],
) -> List[str]:
    logging.info("Zipping analysis items in %s to %s", path, out)

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
    zip_args = ZipArgs(
        out=out,
        path=path,
        ignore_files=ignore_files,
        filters=filters,
        filters_inverted=filters_inverted,
    )
    chunks = analysis_chunks(zip_args, zip_chunks)
    batch_id = uuid4()
    for idx, chunk in enumerate(chunks):
        filename = f"panther-analysis-{current_time}-{batch_id}-batch-{idx + 1}.zip"
        filename = add_path_to_filename(out, filename)
        filenames.append(filename)
        with zipfile.ZipFile(filename, "w", zipfile.ZIP_DEFLATED) as zip_out:
            for name in chunk.files:
                zip_out.write(name)

    return filenames


# pylint: disable=too-many-instance-attributes
@dataclass
class TestAnalysisArgs:
    path: str
    ignore_files: List[str]
    filters: List[Filter]
    filters_inverted: List[Filter]
    ignore_extra_keys: bool
    ignore_table_names: bool
    valid_table_names: List[str]
    available_destination: List[str]
    sort_test_results: bool
    show_failures_only: bool
    minimum_tests: int
    skip_disabled_tests: bool
    test_names: List[str]


@dataclass
class ZipAnalysisArgs:
    skip_tests: bool
    out: str
    test_analysis_args: TestAnalysisArgs


def zip_analysis(backend: Optional[BackendClient], args: ZipAnalysisArgs) -> Tuple[int, str]:
    """Tests, validates, and then archives all policies and rules into a local zip file.

    Returns 1 if the analysis tests or validation fails.

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A tuple of return code and the archive filename.
    """
    if not args.skip_tests:
        return_code, invalid_specs = test_analysis(backend, args.test_analysis_args)
        if return_code != 0:
            logging.error(invalid_specs)
            return return_code, ""

    logging.info("Zipping analysis items in %s to %s", args.test_analysis_args.path, args.out)
    # example: 2019-08-05T18-23-25
    # The colon character is not valid in filenames.
    current_time = datetime.now().isoformat(timespec="seconds").replace(":", "-")
    filename = f"panther-analysis-{current_time}-{uuid4()}.zip"
    filename = add_path_to_filename(args.out, filename)

    typed_args = ZipArgs(
        out=args.out,
        path=args.test_analysis_args.path,
        ignore_files=args.test_analysis_args.ignore_files,
        filters=args.test_analysis_args.filters,
        filters_inverted=args.test_analysis_args.filters_inverted,
    )
    chunks = analysis_chunks(typed_args)
    if len(chunks) != 1:
        logging.error("something went wrong zipping batches.")
        return 1, ""
    with zipfile.ZipFile(filename, "w", zipfile.ZIP_DEFLATED) as zip_out:
        for name in chunks[0].files:
            zip_out.write(name)

    return 0, filename


@dataclass
class UploadAnalysisArgs:
    auto_disable_base: bool
    max_retries: int
    no_async: bool
    batch: bool
    out: str
    skip_tests: bool
    analysis_args: TestAnalysisArgs


def upload_analysis(backend: BackendClient, args: UploadAnalysisArgs) -> Tuple[int, str]:
    """Tests, validates, packages, and uploads all policies and rules into a Panther deployment.

    Returns 1 if the analysis tests, validation, packaging, or upload fails.

    Args:
        backend: a backend client
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A tuple of return code and error if applicable.
    """
    if args.auto_disable_base:
        zipargs = ZipArgs(
            out=args.out,
            path=args.analysis_args.path,
            ignore_files=args.analysis_args.ignore_files,
            filters=args.analysis_args.filters,
            filters_inverted=args.analysis_args.filters_inverted,
        )
        disable_all_base_detections([zipargs.path], zipargs.ignore_files)

    use_async = (not args.no_async) and backend.supports_async_uploads()
    if args.batch and not use_async:
        if not args.skip_tests:
            return_code, invalid_specs = test_analysis(backend, args.analysis_args)
            if return_code != 0:
                logging.error(invalid_specs)
                return return_code, ""

        for idx, archive in enumerate(
            zip_analysis_chunks(
                args.out,
                args.analysis_args.path,
                args.analysis_args.ignore_files,
                args.analysis_args.filters,
                args.analysis_args.filters_inverted,
            )
        ):
            batch_idx = idx + 1
            logging.info("Uploading Batch %d...", batch_idx)
            return_code, err = upload_zip(backend, args.max_retries, archive, False)
            if return_code != 0:
                return return_code, err
            logging.info("Uploaded Batch %d", batch_idx)

        return 0, ""

    zip_args = ZipAnalysisArgs(
        skip_tests=args.skip_tests,
        out=args.out,
        test_analysis_args=args.analysis_args,
    )
    return_code, archive = zip_analysis(backend, zip_args)
    if return_code != 0:
        return return_code, ""

    return upload_zip(backend, args.max_retries, archive, use_async)


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
    backend: BackendClient, max_retries: int, archive: str, use_async: bool
) -> Tuple[int, str]:
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


def parse_lookup_table(path: str) -> dict:
    """Validates and parses a Lookup Table spec file

    Returns a dict representing the Lookup Table

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A dict representing the Lookup Table, empty when parsing fails
    """

    logging.info("Parsing the Lookup Table spec defined in %s", path)
    with open(path, "r", encoding="utf-8") as input_file:
        try:
            yaml = YAML(typ="safe")
            lookup_spec = yaml.load(input_file)
            logging.info("Successfully parse the Lookup Table file %s", path)
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
            logging.info("Successfully validated the Lookup Table file %s", path)
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


def test_lookup_table(path: str) -> Tuple[int, str]:
    """Validates a Lookup Table spec file

    Returns 1 if the validation fails

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A tuple of return code and and empty string (to satisfy calling conventions)
    """

    logging.info("Validating the Lookup Table spec defined in %s", path)
    lookup_spec = parse_lookup_table(path)
    if not lookup_spec:
        return 1, ""
    return 0, ""


def update_custom_schemas(backend: BackendClient, path: str) -> Tuple[int, str]:
    """
    Updates or creates custom schemas.
    Returns 1 if any file failed to be updated.
    Args:
        args: The populated Argparse namespace with parsed command-line arguments.
    Returns:
        A tuple of return code and a placeholder string.
    """
    normalized_path = user_defined.normalize_path(path)
    if not normalized_path:
        return 1, f"path not found: {path}"

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


@dataclass
class GenerateReleaseAssetsArgs:
    out: str
    kms_key: str
    aws_profile: Optional[str]
    skip_tests: bool


def generate_release_assets(
    args: GenerateReleaseAssetsArgs, analysis_args: TestAnalysisArgs
) -> Tuple[int, str]:
    # First, generate the appropriate zip file
    # set the output file to appropriate name for the release: panther-analysis-all.zip
    release_file = args.out + "/" + "panther-analysis-all.zip"
    signature_filename = args.out + "/" + "panther-analysis-all.sig"
    zip_args = ZipAnalysisArgs(
        skip_tests=args.skip_tests,
        out=args.out,
        test_analysis_args=analysis_args,
    )
    return_code, archive = zip_analysis(None, zip_args)
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


@dataclass
class PublishReleaseArgs:
    github_owner: str
    github_repository: str
    github_branch: str
    github_tag: str
    body: str
    generate_release_assets_args: GenerateReleaseAssetsArgs
    analysis_args: TestAnalysisArgs


def publish_release(args: PublishReleaseArgs) -> Tuple[int, str]:
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
    release_dir = (
        args.generate_release_assets_args.out
        if args.generate_release_assets_args.out != "."
        else f"release-{current_time}"
    )
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


def setup_release(args: PublishReleaseArgs, release_dir: str, token: str) -> int:
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
    args.analysis_args.path = "."
    # run generate assets from release directory
    return_code, _ = generate_release_assets(args.generate_release_assets_args, args.analysis_args)
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


def debug_analysis(
    backend: Optional[BackendClient],
    args: TestAnalysisArgs,
    testname: str,
    ruleid: str,
) -> Tuple[int, list]:
    """Debugs the analysis items in the given path.

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.
        backend: The backend client to use for testing.
    """
    debug_args = {"debug_mode": True, "test_name": testname}

    args.filters = [Filter(key="RuleID", values=[ruleid])]
    # We don't want these options as actual command line arguments because we need them to be
    #  these exact values in order to work well with test_analysis
    args.minimum_tests = 0
    args.sort_test_results = False
    args.show_failures_only = False
    return test_analysis(backend, args, debug_args=debug_args)


# pylint: disable=too-many-locals
def test_analysis(
    backend: Optional[BackendClient],
    args: TestAnalysisArgs,
    debug_args: Optional[Dict[str, Any]] = None,
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
        args.path,
        args.ignore_table_names,
        args.valid_table_names,
        args.ignore_files,
        args.ignore_extra_keys,
    )
    if specs.empty():
        if invalid_specs:
            return 1, invalid_specs
        return 1, [f"Nothing to test in {args.path}"]

    specs = specs.apply(lambda l: filter_analysis(l, args.filters, args.filters_inverted))

    if specs.empty():
        return 1, [
            f"No analysis in {args.path} matched filters {args.filters} - {args.filters_inverted}"
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
        if not bool(args.sort_test_results | args.show_failures_only)
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
        test_names=args.test_names,
        debug_args=debug_args,
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
            if args.show_failures_only and outcome != "errored":
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

    if debug_args is None:
        debug_args = {}
    if not debug_args.get("debug_mode", False):
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
    helper_location = analysis_utils.get_tmp_helper_module_location()
    # ensure the directory does not exist, else clear it
    cleanup_global_helpers(global_analysis)
    os.makedirs(helper_location)
    # setup temp dir for globals
    if helper_location not in sys.path:
        sys.path.append(helper_location)
    # place globals in temp dir
    for item in global_analysis:
        dir_name = item.dir_name
        analysis_spec = item.analysis_spec
        analysis_id = analysis_spec["GlobalID"]
        source = os.path.join(dir_name, analysis_spec["Filename"])
        destination = os.path.join(helper_location, f"{analysis_id}.py")
        shutil.copyfile(source, destination)
        # force reload of the module as necessary
        if analysis_id in sys.modules:
            logging.warning(
                "module name collision: global (%s) has same name as a module in python path",
                analysis_id,
            )
            importlib.reload(sys.modules[analysis_id])


def cleanup_global_helpers(global_analysis: List[ClassifiedAnalysis]) -> None:
    helper_location = analysis_utils.get_tmp_helper_module_location()
    # clear the modules from the modules cache
    for item in global_analysis:
        analysis_id = item.analysis_spec["GlobalID"]
        # delete the helpers that were added to sys.modules for testing
        if analysis_id in sys.modules:
            del sys.modules[analysis_id]
    # ensure the directory does not exist, else clear it
    if os.path.exists(helper_location):
        shutil.rmtree(helper_location)


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
                _, load_err = analysis_utils.load_module(
                    os.path.join(dir_name, analysis_spec["Filename"])
                )
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


def setup_run_tests(  # pylint: disable=too-many-locals,too-many-arguments,too-many-statements,too-many-positional-arguments
    log_type_to_data_model: Dict[str, DataModel],
    analysis: List[ClassifiedAnalysis],
    minimum_tests: int,
    skip_disabled_tests: bool,
    destinations_by_name: Dict[str, FakeDestination],
    ignore_exception_types: List[Type[Exception]],
    all_test_results: Optional[TestResultsContainer] = None,
    backend: Optional[BackendClient] = None,
    test_names: Optional[List[str]] = None,
    debug_args: Optional[Dict[str, Any]] = None,
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
            debug_args,
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


@dataclass
class EnrichTestDataArgs:
    path: str
    ignore_files: List[str]
    ignore_table_names: bool
    valid_table_names: List[str]
    filters: List[Filter]
    filters_inverted: List[Filter]


def enrich_test_data(backend: BackendClient, args: EnrichTestDataArgs) -> Tuple[int, str]:
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
        ignore_extra_keys=False,
    )

    # If no specs were found, nothing to do
    if specs.empty():
        if invalid_specs:
            msg = "Encountered invalid specs: " + ", ".join(invalid_specs)
            return 1, msg
        return 1, f"No analysis content to enrich tests data for in {args.path}"

    specs = specs.apply(lambda l: filter_analysis(l, args.filters, args.filters_inverted))

    # If no specs after filtering, nothing to do
    if specs.empty():
        return (
            1,
            f"No analysis content in {args.path} matched filters {args.filters} - {args.filters_inverted}",
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


# pylint: disable=too-many-statements
def check_packs(path: str) -> Tuple[int, str]:
    """
    Checks each existing pack whether it includes all necessary rules and other items. Also checks
    if any detections, queries, etc. are not included in any packs
    """
    specs, _ = load_analysis(path, True, [], [], False)

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


def run_tests(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    analysis: Dict[str, Any],
    analysis_data_models: Dict[str, DataModel],
    detection: Optional[Detection],
    detection_id: str,
    failed_tests: DefaultDict[str, list],
    minimum_tests: int,
    destinations_by_name: Dict[str, FakeDestination],
    ignore_exception_types: List[Type[Exception]],
    all_test_results: Optional[TestResultsContainer],
    correlation_rule_test_results: List[Dict[str, Any]],
    test_names: Optional[List[str]] = None,
    debug_args: Optional[Dict[str, Any]] = None,
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
        debug_args,
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
    all_test_results: Optional[TestResultsContainer],
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


# pylint: disable=too-many-statements
def _run_tests(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    analysis_data_models: Dict[str, DataModel],
    detection: Optional[Detection],
    tests: List[Dict[str, Any]],
    failed_tests: DefaultDict[str, list],
    destinations_by_name: Dict[str, FakeDestination],
    ignore_exception_types: List[Type[Exception]],
    all_test_results: Optional[TestResultsContainer],
    correlation_rule_test_results: List[Dict[str, Any]],
    detection_id: str,
    test_names: Optional[List[str]] = None,
    debug_args: Optional[Dict[str, Any]] = None,
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

    found_debug_unit_test = False
    for unit_test in tests:
        if debug_args and debug_args.get("debug_mode", False):
            if unit_test.get("Name") != debug_args["test_name"]:
                continue
            found_debug_unit_test = True

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
            # Override buffer redirect if we're in debug mode
            test_output_buf: io.StringIO | TextIO = io.StringIO()
            if debug_args and debug_args.get("debug_mode", False):
                test_output_buf = sys.stdout

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
            test_output = ""
            if not debug_args or not debug_args.get("debug_mode", False):
                test_output = cast(io.StringIO, test_output_buf).getvalue()
            if debug_args and debug_args.get("debug_mode", False):
                # Print excceptiosn relative to the rule.py file
                if err := result.detection_exception:
                    # Get the count of frames
                    frames = traceback.extract_tb(err.__traceback__)
                    n_frames = 0
                    for idx, frame in enumerate(frames):
                        if frame.name == "_run_command":
                            n_frames = idx
                            break
                    err_tb = err.__traceback__
                    for _ in range(n_frames + 1):
                        err_tb = err_tb.tb_next
                    logging.error(err.with_traceback(err_tb))
                    traceback.print_tb(err_tb)

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
        elif not debug_args or not debug_args.get("debug_mode", False):
            # Only print test results if not in debug mode
            _print_test_result(detection, test_result, failed_tests)

    if debug_args and debug_args.get("debug_mode", False) and not found_debug_unit_test:
        logging.warning("No test found with name %s", debug_args["test_name"])

    return failed_tests


def _print_test_result(
    detection: Optional[Detection],
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


def print_and_exit(message: str) -> None:
    print(message)
    raise typer.Exit(code=0)


@app.callback()
def global_options(
    # pylint: disable=unused-argument
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        help="Show the version and exit",
        is_eager=True,
        callback=lambda v: print_and_exit(VERSION_STRING) if v else None,
    ),
    debug: bool = typer.Option(False, "--debug", help="Enable debug mode"),
    skip_version_check: bool = typer.Option(
        False, "--skip-version-check", help="Skip Panther version check"
    ),
) -> None:
    """
    Panther Analysis Tool: A command line tool for managing Panther policies and rules.
    """
    # These options run before any subcommand.
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        aiohttp_logger.setLevel(logging.WARNING)
        logging.getLogger("sqlfluff.parser").setLevel(logging.WARNING)
        logging.getLogger("sqlfluff.linter").setLevel(logging.WARNING)
        logging.getLogger("sqlfluff.lexer").setLevel(logging.WARNING)
        logging.getLogger("sqlfluff.templater").setLevel(logging.WARNING)

    if not skip_version_check and not _SKIP_HTTP_VERSION_CHECK:
        latest = pat_utils.get_latest_version()
        if not pat_utils.is_latest(latest):
            logging.warning(
                "%s v%s is available (current: v%s). Run: pip3 install %s --upgrade",
                PACKAGE_NAME,
                latest,
                VERSION_STRING,
                PACKAGE_NAME,
            )


@app_command_with_config(
    help=(
        "Create release assets for repository containing panther detections. "
        "Generates a file called panther-analysis-all.zip and optionally generates "
        "panther-analysis-all.sig"
    )
)
def release(  # pylint: disable=too-many-positional-arguments
    _filter: FilterType = None,
    ignore_files: IgnoreFilesType = None,
    kms_key: KMSKeyType = "",
    minimum_tests: MinimumTestsType = 0,
    out: OutType = ".",
    path: PathType = ".",
    skip_tests: SkipTestsType = False,
    skip_disabled_tests: SkipDisabledTestsType = False,
    available_destination: AvailableDestinationType = None,
    sort_test_results: SortTestResultsType = False,
    show_failures_only: ShowFailuresOnlyType = False,
    ignore_table_names: IgnoreTableNamesType = False,
    valid_table_names: ValidTableNamesType = None,
    aws_profile: AWSProfileType = None,
) -> Tuple[int, str]:
    if ignore_files is None:
        ignore_files = []

    if valid_table_names is None:
        valid_table_names = []

    if available_destination is None:
        available_destination = []

    # release should parse filter as is, and not filter out Status: deprecated, Status: experimental
    filters, filters_inverted = parse_filter(_filter)

    # Forward to your logic function
    return generate_release_assets(
        GenerateReleaseAssetsArgs(
            skip_tests=skip_tests,
            kms_key=kms_key,
            aws_profile=aws_profile,
            out=out,
        ),
        TestAnalysisArgs(
            filters=filters,
            filters_inverted=filters_inverted,
            ignore_files=ignore_files,
            minimum_tests=minimum_tests,
            path=path,
            ignore_extra_keys=False,
            skip_disabled_tests=skip_disabled_tests,
            available_destination=available_destination,
            sort_test_results=sort_test_results,
            show_failures_only=show_failures_only,
            ignore_table_names=ignore_table_names,
            valid_table_names=valid_table_names,
            test_names=[],
        ),
    )


@app_command_with_config(help="Validate analysis specifications and run policy and rule tests.")
def test(  # pylint: disable=too-many-positional-arguments
    api_token: APITokenType = None,
    api_host: APIHostType = "",
    _filter: FilterType = None,
    minimum_tests: MinimumTestsType = 0,
    path: PathType = ".",
    ignore_extra_keys: IgnoreExtraKeysType = False,
    ignore_files: IgnoreFilesType = None,
    skip_disabled_tests: SkipDisabledTestsType = False,
    available_destination: AvailableDestinationType = None,
    sort_test_results: SortTestResultsType = False,
    show_failures_only: ShowFailuresOnlyType = False,
    ignore_table_names: IgnoreTableNamesType = False,
    valid_table_names: ValidTableNamesType = None,
    test_names: Annotated[
        Optional[List[str]],
        typer.Option(
            envvar="PANTHER_TEST_NAMES",
            metavar="TEST_NAME",
            help="Only run tests with these names. Can be used with --filter to run specific tests for specific rules.",
        ),
    ] = None,
) -> Tuple[int, list[Any]]:
    if ignore_files is None:
        ignore_files = []

    if valid_table_names is None:
        valid_table_names = []
    if available_destination is None:
        available_destination = []
    if test_names is None:
        test_names = []

    filters, filters_inverted = get_filters_with_status_filters(_filter)

    args = TestAnalysisArgs(
        filters=filters,
        filters_inverted=filters_inverted,
        minimum_tests=minimum_tests,
        path=path,
        ignore_extra_keys=ignore_extra_keys,
        ignore_files=ignore_files,
        skip_disabled_tests=skip_disabled_tests,
        available_destination=available_destination,
        sort_test_results=sort_test_results,
        show_failures_only=show_failures_only,
        ignore_table_names=ignore_table_names,
        valid_table_names=valid_table_names,
        test_names=test_names,
    )

    return test_analysis(pat_utils.get_optional_backend(api_token, api_host), args)


@app_command_with_config(
    name="debug",
    help="Run a single rule test in a debug environment, which allows you to see print statements and use breakpoints.",
)
def debug_command(  # pylint: disable=too-many-positional-arguments
    ruleid: Annotated[str, typer.Argument(..., help="The rule ID to debug")],
    testname: Annotated[str, typer.Argument(..., help="The test name to debug")],
    api_token: APITokenType = None,
    api_host: APIHostType = "",
    _filter: FilterType = None,
    path: PathType = ".",
    ignore_extra_keys: IgnoreExtraKeysType = False,
    ignore_files: IgnoreFilesType = None,
    skip_disabled_tests: SkipDisabledTestsType = False,
    available_destination: AvailableDestinationType = None,
    ignore_table_names: IgnoreTableNamesType = False,
    valid_table_names: ValidTableNamesType = None,
) -> Tuple[int, list[Any]]:
    if ignore_files is None:
        ignore_files = []

    if valid_table_names is None:
        valid_table_names = []
    if available_destination is None:
        available_destination = []

    filters, filters_inverted = get_filters_with_status_filters(_filter)

    args = TestAnalysisArgs(
        filters=filters,
        filters_inverted=filters_inverted,
        minimum_tests=0,  # debug_analysis overrides this anyway
        path=path,
        ignore_extra_keys=ignore_extra_keys,
        ignore_files=ignore_files,
        skip_disabled_tests=skip_disabled_tests,
        available_destination=available_destination,
        sort_test_results=False,  # debug_analysis overrides this anyway
        show_failures_only=False,  # debug_analysis overrides this anyway
        ignore_table_names=ignore_table_names,
        valid_table_names=valid_table_names,
        test_names=[],
    )
    return debug_analysis(
        pat_utils.get_optional_backend(api_token, api_host), args, testname, ruleid
    )


@app_command_with_config(
    name="publish",
    help=(
        "Publishes a new release, generates the release assets, and uploads them. "
        + "Generates a file called panther-analysis-all.zip and optionally generates "
        + "panther-analysis-all.sig"
    ),
)
def publish_command(  # pylint: disable=too-many-positional-arguments
    github_tag: Annotated[
        str, typer.Option(envvar="PANTHER_GITHUB_TAG", help="The tag name for this release")
    ],
    aws_profile: AWSProfileType = None,
    # GitHub args
    github_branch: Annotated[
        str, typer.Option(envvar="PANTHER_GITHUB_BRANCH", help="The branch to base the release on")
    ] = "main",
    github_owner: Annotated[
        str, typer.Option(envvar="PANTHER_GITHUB_OWNER", help="The github owner of the repository")
    ] = "panther-labs",
    github_repository: Annotated[
        str, typer.Option(envvar="PANTHER_GITHUB_REPOSITORY", help="The github repository name")
    ] = "panther-analysis",
    body: Annotated[
        str, typer.Option(envvar="PANTHER_BODY", help="The text body for the release")
    ] = "",
    # Standard shared args
    _filter: FilterType = None,
    kms_key: KMSKeyType = "",
    minimum_tests: MinimumTestsType = 0,
    out: OutType = ".",
    skip_tests: SkipTestsType = False,
    skip_disabled_tests: SkipDisabledTestsType = False,
    available_destination: AvailableDestinationType = None,
    ignore_files: IgnoreFilesType = None,
) -> Tuple[int, str]:
    if ignore_files is None:
        ignore_files = []
    if available_destination is None:
        available_destination = []

    filters, filters_inverted = get_filters_with_status_filters(_filter)

    args = PublishReleaseArgs(
        github_tag=github_tag,
        github_branch=github_branch,
        github_owner=github_owner,
        github_repository=github_repository,
        body=body,
        generate_release_assets_args=GenerateReleaseAssetsArgs(
            skip_tests=skip_tests,
            out=out,
            kms_key=kms_key,
            aws_profile=aws_profile,
        ),
        analysis_args=TestAnalysisArgs(
            filters=filters,
            filters_inverted=filters_inverted,
            minimum_tests=minimum_tests,
            skip_disabled_tests=skip_disabled_tests,
            available_destination=available_destination,
            ignore_files=ignore_files,
            path=".",
            ignore_extra_keys=False,
            ignore_table_names=True,
            valid_table_names=[],
            sort_test_results=False,
            show_failures_only=False,
            test_names=[],
        ),
    )
    return publish_release(args)


@app_command_with_config(help="Upload specified policies and rules to a Panther deployment.")
def upload(  # pylint: disable=too-many-positional-arguments
    # Shared dependencies
    api_token: APITokenType = None,
    api_host: APIHostType = "",
    aws_profile: AWSProfileType = None,
    # Upload-specific flags
    auto_disable_base: Annotated[bool, typer.Option(help="Auto-disable base detection")] = False,
    max_retries: Annotated[int, typer.Option(help="Max upload retries")] = 10,
    no_async: Annotated[bool, typer.Option(help="Force synchronous upload")] = False,
    batch: Annotated[bool, typer.Option(help="Break upload into multiple zip files")] = False,
    # Shared args
    _filter: FilterType = None,
    minimum_tests: MinimumTestsType = 0,
    out: OutType = ".",
    path: PathType = ".",
    skip_tests: SkipTestsType = False,
    skip_disabled_tests: SkipDisabledTestsType = False,
    ignore_extra_keys: IgnoreExtraKeysType = False,
    ignore_files: IgnoreFilesType = None,
    available_destination: AvailableDestinationType = None,
    sort_test_results: SortTestResultsType = False,
    show_failures_only: ShowFailuresOnlyType = False,
    ignore_table_names: IgnoreTableNamesType = False,
    valid_table_names: ValidTableNamesType = None,
) -> Tuple[int, str]:
    if ignore_files is None:
        ignore_files = []
    if available_destination is None:
        available_destination = []
    if valid_table_names is None:
        valid_table_names = []

    filters, filters_inverted = get_filters_with_status_filters(_filter)

    args = UploadAnalysisArgs(
        auto_disable_base=auto_disable_base,
        max_retries=max_retries,
        no_async=no_async,
        batch=batch,
        out=out,
        skip_tests=skip_tests,
        analysis_args=TestAnalysisArgs(
            filters=filters,
            filters_inverted=filters_inverted,
            minimum_tests=minimum_tests,
            path=path,
            skip_disabled_tests=skip_disabled_tests,
            ignore_files=ignore_files,
            available_destination=available_destination,
            sort_test_results=sort_test_results,
            show_failures_only=show_failures_only,
            ignore_table_names=ignore_table_names,
            valid_table_names=valid_table_names,
            ignore_extra_keys=ignore_extra_keys,
            test_names=[],
        ),
    )
    return upload_analysis(pat_utils.get_backend(api_token, api_host, aws_profile), args)


@app_command_with_config(help="Delete policies, rules, or saved queries from a Panther deployment.")
def delete(  # pylint: disable=too-many-positional-arguments
    # Shared dependencies
    api_token: APITokenType = None,
    api_host: APIHostType = "",
    aws_profile: AWSProfileType = None,
    # Delete-specific flags
    confirm: Annotated[bool, typer.Option(help="Require manual confirmation")] = True,
    analysis_id: Annotated[
        Optional[List[str]],
        typer.Option(help="List of detection IDs. Repeat the flag to define more than one ID."),
    ] = None,
    query_id: Annotated[
        Optional[List[str]],
        typer.Option(help="List of saved query IDs. Repeat the flag to define more than one ID."),
    ] = None,
) -> Tuple[int, str]:
    if analysis_id is None:
        analysis_id = []
    if query_id is None:
        query_id = []

    args = bulk_delete.BulkDeleteArgs(
        confirm=confirm,
        analysis_id=analysis_id,
        query_id=query_id,
    )

    return bulk_delete.run(pat_utils.get_backend(api_token, api_host, aws_profile), args)


@app_command_with_config(
    name="update-custom-schemas", help="Update or create custom schemas on a Panther deployment."
)
def update_custom_schemas_cmd(
    api_token: APITokenType = None,
    api_host: APIHostType = "",
    aws_profile: AWSProfileType = None,
    path: Annotated[
        str,
        typer.Option(
            envvar="PANTHER_PATH", help="The relative or absolute path to Panther custom schemas."
        ),
    ] = ".",
) -> Tuple[int, str]:
    return update_custom_schemas(pat_utils.get_backend(api_token, api_host, aws_profile), path)


@app_command_with_config(name="test-lookup-table", help="Validate a Lookup Table spec file.")
def test_lookup_table_cmd(
    path: Annotated[
        str,
        typer.Option(envvar="PANTHER_PATH", help="The relative path to a lookup table input file."),
    ] = ".",
) -> Tuple[int, str]:
    return test_lookup_table(path)


@app_command_with_config(
    name="validate", help="Validate your bulk uploads against your panther instance."
)
def validate_cmd(
    api_token: APITokenType = None,
    api_host: APIHostType = "",
    _filter: FilterType = None,
    ignore_files: IgnoreFilesType = None,
    path: PathType = ".",
) -> Tuple[int, str]:
    if ignore_files is None:
        ignore_files = []

    filters, filters_inverted = get_filters_with_status_filters(_filter)

    args = validate.ValidateArgs(
        out=".",
        filters=filters,
        filters_inverted=filters_inverted,
        ignore_files=ignore_files,
        path=path,
    )

    return validate.run(pat_utils.get_api_backend(api_token, api_host), args)


@app_command_with_config(
    name="zip", help="Create an archive of local policies and rules for uploading to Panther."
)
def zip_cmd(  # pylint: disable=too-many-positional-arguments
    api_token: APITokenType = None,
    api_host: APIHostType = "",
    _filter: FilterType = None,
    ignore_files: IgnoreFilesType = None,
    minimum_tests: MinimumTestsType = 0,
    out: OutType = ".",
    path: PathType = ".",
    skip_tests: SkipTestsType = False,
    skip_disabled_tests: SkipDisabledTestsType = False,
    available_destination: AvailableDestinationType = None,
    sort_test_results: SortTestResultsType = False,
    show_failures_only: ShowFailuresOnlyType = False,
    ignore_table_names: IgnoreTableNamesType = False,
    valid_table_names: ValidTableNamesType = None,
) -> Tuple[int, str]:
    if ignore_files is None:
        ignore_files = []
    if valid_table_names is None:
        valid_table_names = []
    if available_destination is None:
        available_destination = []

    filters, filters_inverted = get_filters_with_status_filters(_filter)

    args = ZipAnalysisArgs(
        skip_tests=skip_tests,
        out=out,
        test_analysis_args=TestAnalysisArgs(
            filters=filters,
            filters_inverted=filters_inverted,
            ignore_files=ignore_files,
            minimum_tests=minimum_tests,
            path=path,
            skip_disabled_tests=skip_disabled_tests,
            available_destination=available_destination,
            sort_test_results=sort_test_results,
            show_failures_only=show_failures_only,
            ignore_table_names=ignore_table_names,
            valid_table_names=valid_table_names,
            ignore_extra_keys=False,
            test_names=[],
        ),
    )
    return zip_analysis(pat_utils.get_optional_backend(api_token, api_host), args)


@app_command_with_config(name="check-connection", help="Check your Panther API connection")
def check_connection_cmd(
    api_token: APITokenType = None,
    api_host: APIHostType = "",
    aws_profile: AWSProfileType = None,
) -> Tuple[int, str]:
    return check_connection.run(pat_utils.get_backend(api_token, api_host, aws_profile), api_host)


def parse_date(text: Optional[str]) -> Optional[datetime]:
    # Wrapper to parse date strings using dateutil.parser.parse
    if text is None:
        return None
    return dateutil.parser.parse(text)


@app_command_with_config(
    name="benchmark",
    help=(
        "Performance test one rule against one of its log types. The rule must be the only item "
        "in the working directory or specified by --path, --ignore-files, and --filter. This feature "
        "is an extension of Data Replay and is subject to the same limitations."
    ),
)
def benchmark_command(  # pylint: disable=too-many-positional-arguments
    api_token: APITokenType = None,
    api_host: APIHostType = "",
    _filter: FilterType = None,
    ignore_files: IgnoreFilesType = None,
    path: PathType = ".",
    out: OutType = ".",
    iterations: Annotated[
        int,
        typer.Option(
            help=(
                "The number of iterations of the performance test to perform. Each iteration runs "
                "against the selected hour of data. Fewer iterations will be run if the time limit "
                "is reached. Min: 1"
            ),
            min=1,
        ),
    ] = 50,
    hour: Annotated[
        Optional[datetime],
        typer.Option(
            help=(
                "The hour of historical data to perform the benchmark against, in any parseable format, "
                "e.g. '2023-07-31T09:00:00.000-7:00'. Minutes, Seconds, etc will be truncated if specified. "
                "If hour is unspecified, the performance test will run against the hour in the last two weeks "
                "with the largest log volume."
            ),
            parser=parse_date,
        ),
    ] = None,
    log_type: Annotated[
        Optional[str],
        typer.Option(
            help=(
                "Required if the rule supports multiple log types, optional otherwise. Must be one of the rule's log types."
            ),
        ),
    ] = None,
) -> Tuple[int, str]:
    if ignore_files is None:
        ignore_files = []

    filters, filters_inverted = get_filters_with_status_filters(_filter)

    args = benchmark.BenchmarkArgs(
        filters=filters,
        filters_inverted=filters_inverted,
        ignore_files=ignore_files,
        path=path,
        out=out,
        iterations=iterations,
        hour=hour,
        log_type=log_type,
    )
    return benchmark.run(pat_utils.get_api_backend(api_token, api_host), args)


@app_command_with_config(
    name="enrich-test-data",
    help="Enrich test data with additional enrichments from the Panther API.",
)
def enrich_test_data_command(  # pylint: disable=too-many-positional-arguments
    api_token: APITokenType = None,
    api_host: APIHostType = "",
    aws_profile: AWSProfileType = None,
    _filter: FilterType = None,
    path: PathType = ".",
    ignore_files: IgnoreFilesType = None,
    ignore_table_names: IgnoreTableNamesType = False,
    valid_table_names: ValidTableNamesType = None,
) -> Tuple[int, str]:
    if ignore_files is None:
        ignore_files = []
    if valid_table_names is None:
        valid_table_names = []

    filters, filters_inverted = get_filters_with_status_filters(_filter)

    # Call your backend function with the parsed arguments
    args = EnrichTestDataArgs(
        filters=filters,
        filters_inverted=filters_inverted,
        path=path,
        ignore_files=ignore_files,
        ignore_table_names=ignore_table_names,
        valid_table_names=valid_table_names,
    )
    return enrich_test_data(pat_utils.get_backend(api_token, api_host, aws_profile), args)


@app_command_with_config(
    name="check-packs", help="Ensure that packs don't have missing detections."
)
def check_packs_command(
    path: PathType = ".",
) -> Tuple[int, str]:
    return check_packs(path)


# pylint: disable=too-many-statements
def run() -> None:
    setup_temp()
    # setup logger and print version info as necessary
    logging.basicConfig(
        format="%(levelname)s: %(message)s",
        level=logging.INFO,
    )

    try:
        app()
    except BackendNotFoundException as err:
        logging.error('Backend not found: "%s"', err)
        sys.exit(1)
    except Exception as err:  # pylint: disable=broad-except
        # Catch arbitrary exceptions without printing help message
        logging.warning('Unhandled exception: "%s"', err)
        logging.debug("Full error traceback:", exc_info=err)
        sys.exit(1)


if __name__ == "__main__":
    run()
