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
import base64
import hashlib
import importlib.util
import json
import logging
import mimetypes
import os
import re
import subprocess  # nosec
import sys
import tempfile
import zipfile
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import asdict
from datetime import datetime
from distutils.util import strtobool
from fnmatch import fnmatch
from importlib.abc import Loader
from typing import Any, DefaultDict, Dict, Iterator, List, Set, Tuple, Type
from unittest.mock import MagicMock, patch
from uuid import uuid4

import botocore
import requests
import semver
from ruamel.yaml import YAML
from ruamel.yaml import parser as YAMLParser
from ruamel.yaml import scanner as YAMLScanner
from schema import (
    Optional,
    Schema,
    SchemaError,
    SchemaForbiddenKeyError,
    SchemaMissingKeyError,
    SchemaUnexpectedTypeError,
    SchemaWrongKeyError,
)

from panther_analysis_tool.data_model import DataModel
from panther_analysis_tool.destination import FakeDestination
from panther_analysis_tool.enriched_event import PantherEvent
from panther_analysis_tool.exceptions import UnknownDestinationError
from panther_analysis_tool.log_schemas import user_defined
from panther_analysis_tool.policy import TYPE_POLICY, Policy
from panther_analysis_tool.rule import Detection, Rule
from panther_analysis_tool.schemas import (
    DATA_MODEL_SCHEMA,
    GLOBAL_SCHEMA,
    PACK_SCHEMA,
    POLICY_SCHEMA,
    RULE_SCHEMA,
    SCHEDULED_QUERY_SCHEMA,
    TYPE_SCHEMA,
)
from panther_analysis_tool.testing import (
    TestCaseEvaluator,
    TestExpectations,
    TestResult,
    TestSpecification,
)
from panther_analysis_tool.util import get_client

DATA_MODEL_LOCATION = "./data_models"
HELPERS_LOCATION = "./global_helpers"

DATA_MODEL_PATH_PATTERN = "*data_models*"
HELPERS_PATH_PATTERN = "*/global_helpers"
PACKS_PATH_PATTERN = "*/packs"
POLICIES_PATH_PATTERN = "*policies*"
QUERIES_PATH_PATTERN = "*queries*"
RULES_PATH_PATTERN = "*rules*"

DATAMODEL = "datamodel"
DETECTION = "detection"
GLOBAL = "global"
PACK = "pack"
POLICY = "policy"
QUERY = "scheduled_query"
SCHEDULED_RULE = "scheduled_rule"
RULE = "rule"

RESERVED_FUNCTIONS = (
    "alert_context",
    "dedup",
    "description",
    "destinations",
    "reference",
    "runbook",
    "severity",
    "title",
)

VALID_SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

SCHEMAS: Dict[str, Schema] = {
    DATAMODEL: DATA_MODEL_SCHEMA,
    GLOBAL: GLOBAL_SCHEMA,
    PACK: PACK_SCHEMA,
    POLICY: POLICY_SCHEMA,
    QUERY: SCHEDULED_QUERY_SCHEMA,
    RULE: RULE_SCHEMA,
    SCHEDULED_RULE: RULE_SCHEMA,
}

SET_FIELDS = [
    "LogTypes",
    "PackIDs",
    "OutputIds",
    "SummaryAttributes",
    "Suppressions",
    "Tags",
]

# Environment Variables
# -- Activates sub-commands that are meant for internal use --
ENV_VAR_INCLUDE_INTERNAL_SUBCOMMANDS = "PANTHER_PAT_INCLUDE_INTERNAL_SUBCOMMANDS"


# exception for conflicting ids
class AnalysisIDConflictException(Exception):
    def __init__(self, analysis_id: str):
        self.message = "Conflicting AnalysisID: [{}]".format(analysis_id)
        super().__init__(self.message)


# exception for conflicting ids
class AnalysisContainsDuplicatesException(Exception):
    def __init__(self, analysis_id: str, invalid_fields: List[str]):
        self.message = (
            "Specification file for [{}] contains fields with duplicate values: [{}]".format(
                analysis_id, ", ".join(x for x in invalid_fields)
            )
        )
        super().__init__(self.message)


def load_module(filename: str) -> Tuple[Any, Any]:
    """Loads the analysis function module from a file.

    Args:
        filename: The relative path to the file.

    Returns:
        A loaded Python module.
    """
    module_name = filename.split(".")[0]
    spec = importlib.util.spec_from_file_location(module_name, filename)
    module = importlib.util.module_from_spec(spec)
    try:
        assert isinstance(spec.loader, Loader)  # nosec
        spec.loader.exec_module(module)
    except FileNotFoundError as err:
        print("\t[ERROR] File not found: " + filename + ", skipping\n")
        return None, err
    except Exception as err:  # pylint: disable=broad-except
        # Catch arbitrary exceptions thrown by user code
        print("\t[ERROR] Error loading module, skipping\n")
        return None, err
    return module, None


def load_analysis_specs(
    directories: List[str], ignored_files: List[str]
) -> Iterator[Tuple[str, str, Any, Any]]:
    """Loads the analysis specifications from a file.

    Args:
        directories: The relative path to Panther policies or rules.
        ignored_files: Files that Panther Analysis Tool should not process

    Yields:
        A tuple of the relative filepath, directory name, and loaded analysis specification dict.
    """
    # setup a list of paths to ensure we do not import the same files
    # multiple times, which can happen when testing from root directory without filters
    ignored_normalized = []
    for file in ignored_files:
        ignored_normalized.append(os.path.normpath(file))

    loaded_specs: List[Any] = []
    for directory in directories:
        for relative_path, _, file_list in os.walk(directory):
            # Skip hidden folders
            if (
                relative_path.split("/")[-1].startswith(".")
                and relative_path != "./"
                and relative_path != "."
            ):
                continue
            # setup yaml object
            yaml = YAML(typ="safe")
            # If the user runs with no path args, filter to make sure
            # we only run folders with valid analysis files. Ensure we test
            # files in the current directory by not skipping this iteration
            # when relative_path is the current dir
            if directory in [".", "./"] and relative_path not in [".", "./"]:
                if not any(
                    (
                        fnmatch(relative_path, path_pattern)
                        for path_pattern in (
                            DATA_MODEL_PATH_PATTERN,
                            HELPERS_PATH_PATTERN,
                            RULES_PATH_PATTERN,
                            PACKS_PATH_PATTERN,
                            POLICIES_PATH_PATTERN,
                            QUERIES_PATH_PATTERN,
                        )
                    )
                ):
                    logging.debug("Skipping path %s", relative_path)
                    continue
            for filename in sorted(file_list):
                # Skip hidden files
                if filename.startswith("."):
                    continue
                spec_filename = os.path.abspath(os.path.join(relative_path, filename))
                # skip loading files that have already been imported
                if spec_filename in loaded_specs:
                    continue
                # Dont load files that are explictly ignored
                relative_name = os.path.normpath(os.path.join(relative_path, filename))
                if relative_name in ignored_normalized:
                    logging.info("ignoring file %s", relative_name)
                    continue
                loaded_specs.append(spec_filename)
                if fnmatch(filename, "*.y*ml"):
                    with open(spec_filename, "r") as spec_file_obj:
                        try:
                            yield spec_filename, relative_path, yaml.load(spec_file_obj), None
                        except (YAMLParser.ParserError, YAMLScanner.ScannerError) as err:
                            # recreate the yaml object and yeild the error
                            yaml = YAML(typ="safe")
                            yield spec_filename, relative_path, None, err
                if fnmatch(filename, "*.json"):
                    with open(spec_filename, "r") as spec_file_obj:
                        try:
                            yield spec_filename, relative_path, json.load(spec_file_obj), None
                        except ValueError as err:
                            yield spec_filename, relative_path, None, err


def datetime_converted(obj: Any) -> Any:
    """A helper function for dumping spec files to JSON.

    Args:
        obj: Any object to convert.

    Returns:
        A string representation of the datetime.
    """
    if isinstance(obj, datetime):
        return obj.__str__()
    return obj


def _convert_keys_to_lowercase(mapping: Dict[str, Any]) -> Dict[str, Any]:
    """A helper function for converting top-level dictionary keys to lowercase.
    Converting keys to lowercase maintains compatibility with how the backend
    behaves.

    Args:
        mapping: The dictionary.

    Returns:
        A new dictionary with each key converted with str.lower()
    """
    return {k.lower(): v for k, v in mapping.items()}


def zip_analysis(args: argparse.Namespace) -> Tuple[int, str]:
    """Tests, validates, and then archives all policies and rules into a local zip file.

    Returns 1 if the analysis tests or validation fails.

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A tuple of return code and the archive filename.
    """
    if not args.skip_tests:
        return_code, _ = test_analysis(args)
        if return_code != 0:
            return return_code, ""

    logging.info("Zipping analysis packs in %s to %s", args.path, args.out)
    # example: 2019-08-05T18-23-25
    # The colon character is not valid in filenames.
    current_time = datetime.now().isoformat(timespec="seconds").replace(":", "-")
    filename = "panther-analysis-{}.zip".format(current_time)
    if args.out:
        if not os.path.isdir(args.out):
            logging.info(
                "Creating directory: %s",
                args.out,
            )
            os.makedirs(args.out)
        filename = args.out.rstrip("/") + "/" + filename
    with zipfile.ZipFile(filename, "w", zipfile.ZIP_DEFLATED) as zip_out:
        # Always zip the helpers and data models
        analysis = []
        files: Set[str] = set()
        for (file_name, f_path, spec, _) in list(
            load_analysis_specs(
                [args.path, HELPERS_LOCATION, DATA_MODEL_LOCATION], args.ignored_files
            )
        ):
            if file_name not in files:
                analysis.append((file_name, f_path, spec))
                files.add(file_name)
                files.add("./" + file_name)
        analysis = filter_analysis(analysis, args.filter, args.filter_inverted)
        for analysis_spec_filename, dir_name, analysis_spec in analysis:
            zip_out.write(analysis_spec_filename)
            # datamodels may not have python body
            if "Filename" in analysis_spec:
                zip_out.write(os.path.join(dir_name, analysis_spec["Filename"]))
    return 0, filename


def upload_analysis(args: argparse.Namespace) -> Tuple[int, str]:
    """Tests, validates, packages, and uploads all policies and rules into a Panther deployment.

    Returns 1 if the analysis tests, validation, or packaging fails.

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A tuple of return code and the archive filename.
    """
    return_code, archive = zip_analysis(args)
    if return_code == 1:
        return return_code, ""

    client = get_client(args.aws_profile, "lambda")

    with open(archive, "rb") as analysis_zip:
        zip_bytes = analysis_zip.read()
        payload = {
            "bulkUpload": {
                "data": base64.b64encode(zip_bytes).decode("utf-8"),
                # The UserID is required by Panther for this API call, but we have no way of
                # acquiring it and it isn't used for anything. This is a valid UUID used by the
                # Panther deployment tool to indicate this action was performed automatically.
                "userId": "00000000-0000-4000-8000-000000000000",
            },
        }

        logging.info("Uploading pack to Panther")
        response = client.invoke(
            FunctionName="panther-analysis-api",
            InvocationType="RequestResponse",
            LogType="None",
            Payload=json.dumps(payload),
        )

        response_str = response["Payload"].read().decode("utf-8")
        response_payload = json.loads(response_str)

        if response_payload.get("statusCode") != 200:
            logging.warning(
                "Failed to upload to Panther\n\tstatus code: %s\n\terror message: %s",
                response_payload.get("statusCode", 0),
                response_payload.get("errorMessage", response_payload.get("body")),
            )
            return 1, ""

        body = json.loads(response_payload["body"])
        logging.info("Upload success.")
        logging.info("API Response:\n%s", json.dumps(body, indent=2, sort_keys=True))

    return 0, ""


def update_schemas(args: argparse.Namespace) -> Tuple[int, str]:
    """Updates managed schemas in a Panther deployment.

    Returns 1 if the update fails.

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A tuple of return code and the archive filename.
    """

    client = get_client(args.aws_profile, "lambda")

    logging.info("Fetching updates")
    response = client.invoke(
        FunctionName="panther-logtypes-api",
        InvocationType="RequestResponse",
        Payload=json.dumps({"ListManagedSchemaUpdates": {}}),
    )
    response_str = response["Payload"].read().decode("utf-8")
    response_payload = json.loads(response_str)

    api_err = response_payload.get("error")
    if api_err is not None:
        logging.error(
            "Failed to list managed schema updates\n\tcode: %s\n\terror message: %s",
            api_err["code"],
            api_err["message"],
        )
        return 1, ""

    releases = response_payload.get("releases")
    if not releases:
        logging.info("No updates available.")
        return 0, ""

    tags = [r.get("tag") for r in releases]
    latest_tag = tags[-1]
    while True:
        print("Available versions:")
        for tag in tags:
            print("\t%s" % tag)
        print("Panther will update managed schemas to the latest version (%s)" % latest_tag)

        prompt = "Choose a different version ({0}): ".format(latest_tag)
        choice = input(prompt).strip() or latest_tag  # nosec
        if choice in tags:
            break

        logging.error("Chosen tag %s is not valid", choice)

    manifest_url = releases[tags.index(choice)].get("manifestURL")

    response = client.invoke(
        FunctionName="panther-logtypes-api",
        InvocationType="RequestResponse",
        Payload=json.dumps(
            {"UpdateManagedSchemas": {"release": choice, "manifestURL": manifest_url}}
        ),
    )
    response_str = response["Payload"].read().decode("utf-8")
    response_payload = json.loads(response_str)
    api_err = response_payload.get("error")
    if api_err is not None:
        logging.error(
            "Failed to submit managed schema update to %s\n\tcode: %s\n\terror message: %s",
            choice,
            api_err["code"],
            api_err["message"],
        )
        return 1, ""
    logging.info("Managed schemas updated successfully")
    return 0, ""


def update_custom_schemas(args: argparse.Namespace) -> Tuple[int, str]:
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

    uploader = user_defined.Uploader(normalized_path, args.aws_profile)
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

        client = get_client(args.aws_profile, "kms")
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
    headers = {"accept": "application/vnd.github.v3+json", "Authorization": f"token {api_token}"}
    # check this tag doesn't already exist
    response = requests.get(release_url + f"/tags/{args.github_tag}", headers=headers)
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
        args.github_owner, args.github_repository, args.github_branch, release_dir, token
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
    response = requests.post(release_url, data=json.dumps(payload), headers=headers)
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
        data = open(release_dir + "/" + filename, "rb").read()
        response = requests.post(upload_url, data=data, headers=headers, params=params)
        if response.status_code != 201:
            logging.error("error uploading release asset (%s)", filename)
            logging.error(response.json())
            return_code = 1
            continue
        logging.info("sucessfull upload of release asset (%s)", filename)
    return return_code


# pylint: disable=too-many-locals
def test_analysis(args: argparse.Namespace) -> Tuple[int, list]:
    """Imports each policy or rule and runs their tests.

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A tuple of the return code, and a list of tuples containing invalid specs and their error.
    """
    logging.info("Testing analysis packs in %s\n", args.path)

    ignored_files = args.ignored_files
    search_directories = [args.path]

    # Try the parent directory as well
    for directory in (
        HELPERS_LOCATION,
        "." + HELPERS_LOCATION,
        DATA_MODEL_LOCATION,
        "." + DATA_MODEL_LOCATION,
    ):
        absolute_dir_path = os.path.abspath(os.path.join(args.path, directory))
        absolute_helper_path = os.path.abspath(directory)

        if os.path.exists(absolute_dir_path):
            search_directories.append(absolute_dir_path)
        if os.path.exists(absolute_helper_path):
            search_directories.append(absolute_helper_path)

    # First classify each file, always include globals and data models location
    specs, invalid_specs = classify_analysis(
        list(load_analysis_specs(search_directories, ignored_files=ignored_files))
    )

    if all((len(specs[key]) == 0 for key in specs)):
        if invalid_specs:
            return 1, invalid_specs
        return 1, ["Nothing to test in {}".format(args.path)]

    # Apply the filters as needed
    if getattr(args, "filter_inverted", None) is None:
        args.filter_inverted = {}
    for key in specs:
        specs[key] = filter_analysis(specs[key], args.filter, args.filter_inverted)

    if all((len(specs[key]) == 0 for key in specs)):
        return 1, [
            f"No analysis in {args.path} matched filters {args.filter} - {args.filter_inverted}"
        ]

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
    invalid_globals = setup_global_helpers(specs[GLOBAL])
    invalid_specs.extend(invalid_globals)

    # then, setup data model dictionary to be used in rule/policy tests
    log_type_to_data_model, invalid_data_models = setup_data_models(specs[DATAMODEL])
    invalid_specs.extend(invalid_data_models)

    # then, import rules and policies; run tests
    failed_tests, invalid_detection = setup_run_tests(
        log_type_to_data_model,
        specs[DETECTION],
        args.minimum_tests,
        args.skip_disabled_tests,
        destinations_by_name=destinations_by_name,
        ignore_exception_types=ignore_exception_types,
    )
    invalid_specs.extend(invalid_detection)

    print_summary(args.path, len(specs[DETECTION]), failed_tests, invalid_specs)
    return int(bool(failed_tests or invalid_specs)), invalid_specs


def setup_global_helpers(global_analysis: List[Any]) -> List[Any]:
    invalid_specs = []
    for analysis_spec_filename, dir_name, analysis_spec in global_analysis:
        analysis_id = analysis_spec["GlobalID"]
        module, load_err = load_module(os.path.join(dir_name, analysis_spec["Filename"]))
        # If the module could not be loaded, continue to the next
        if load_err:
            invalid_specs.append((analysis_spec_filename, load_err))
            continue
        sys.modules[analysis_id] = module
    return invalid_specs


def setup_data_models(data_models: List[Any]) -> Tuple[Dict[str, DataModel], List[Any]]:
    invalid_specs = []
    # log_type_to_data_model is a dict used to map LogType to a unique
    # data model, ensuring there is at most one DataModel per LogType
    log_type_to_data_model: Dict[str, DataModel] = dict()
    for analysis_spec_filename, dir_name, analysis_spec in data_models:
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
                with open(data_model_module_path, "r") as python_module_file:
                    body = python_module_file.read()

            # setup the mapping lookups
            params = {
                "id": analysis_id,
                "mappings": [
                    _convert_keys_to_lowercase(mapping) for mapping in analysis_spec["Mappings"]
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
                            "Conflicting Enabled LogType [{}] in Data Model [{}]".format(
                                log_type, analysis_id
                            ),
                        )
                    )
                    continue
                log_type_to_data_model[log_type] = data_model
    return log_type_to_data_model, invalid_specs


def setup_run_tests(  # pylint: disable=too-many-locals,too-many-arguments
    log_type_to_data_model: Dict[str, DataModel],
    analysis: List[Any],
    minimum_tests: int,
    skip_disabled_tests: bool,
    destinations_by_name: Dict[str, FakeDestination],
    ignore_exception_types: List[Type[Exception]],
) -> Tuple[DefaultDict[str, List[Any]], List[Any]]:
    invalid_specs = []
    failed_tests: DefaultDict[str, list] = defaultdict(list)
    for analysis_spec_filename, dir_name, analysis_spec in analysis:
        if skip_disabled_tests and not analysis_spec.get("Enabled", False):
            continue
        analysis_type = analysis_spec["AnalysisType"]
        analysis_id = analysis_spec.get("PolicyID") or analysis_spec["RuleID"]
        module_code_path = os.path.join(dir_name, analysis_spec["Filename"])
        detection: Detection = Rule(
            dict(
                id=analysis_id,
                analysisType=analysis_type,
                path=module_code_path,
                versionId="0000-0000-0000",
            )
        )
        if analysis_type == POLICY:
            detection = Policy(
                dict(
                    id=analysis_id,
                    analysisType=analysis_type,
                    path=module_code_path,
                    versionId="0000-0000-0000",
                )
            )

        print(detection.detection_id)

        # if there is a setup exception, no need to run tests
        if detection.setup_exception:
            invalid_specs.append((analysis_spec_filename, detection.setup_exception))
            print("\n")
            continue

        failed_tests = run_tests(
            analysis_spec,
            log_type_to_data_model,
            detection,
            failed_tests,
            minimum_tests,
            destinations_by_name,
            ignore_exception_types,
        )
        print("")
    return failed_tests, invalid_specs


def print_summary(
    test_path: str, num_tests: int, failed_tests: Dict[str, list], invalid_specs: List[Any]
) -> None:
    """Print a summary of passed, failed, and invalid specs"""
    print("--------------------------")
    print("Panther CLI Test Summary")
    print("\tPath: {}".format(test_path))
    print("\tPassed: {}".format(num_tests - (len(failed_tests) + len(invalid_specs))))
    print("\tFailed: {}".format(len(failed_tests)))
    print("\tInvalid: {}\n".format(len(invalid_specs)))

    err_message = "\t{}\n\t\t{}\n"

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


def filter_analysis(
    analysis: List[Any], filters: Dict[str, List], filters_inverted: Dict[str, List]
) -> List[Any]:
    if filters is None:
        return analysis

    filtered_analysis = []
    for file_name, dir_name, analysis_spec in analysis:
        if fnmatch(dir_name, HELPERS_PATH_PATTERN):
            logging.debug("auto-adding helpers file %s", os.path.join(file_name))
            filtered_analysis.append((file_name, dir_name, analysis_spec))
            continue
        if fnmatch(dir_name, DATA_MODEL_PATH_PATTERN):
            logging.debug("auto-adding data model file %s", os.path.join(file_name))
            filtered_analysis.append((file_name, dir_name, analysis_spec))
            continue
        match = True
        for key, values in filters.items():
            spec_value = analysis_spec.get(key, "")
            spec_value = spec_value if isinstance(spec_value, list) else [spec_value]
            if not set(spec_value).intersection(values):
                match = False
                break
        for key, values in filters_inverted.items():
            spec_value = analysis_spec.get(key, "")
            spec_value = spec_value if isinstance(spec_value, list) else [spec_value]
            if set(spec_value).intersection(values):
                match = False
                break

        if match:
            filtered_analysis.append((file_name, dir_name, analysis_spec))

    return filtered_analysis


# pylint: disable=too-many-locals,too-many-statements
def classify_analysis(
    specs: List[Tuple[str, str, Any, Any]]
) -> Tuple[Dict[str, List[Any]], List[Any]]:

    # First setup return dict containing different
    # types of detections, meta types that can be zipped
    # or uploaded
    classified_specs: Dict[str, List[Any]] = dict()
    for key in [DATAMODEL, DETECTION, GLOBAL, PACK, QUERY]:
        classified_specs[key] = []

    invalid_specs = []
    # each analysis type must have a unique id, track used ids and
    # add any duplicates to the invalid_specs
    analysis_ids: List[Any] = []

    # pylint: disable=too-many-nested-blocks
    for analysis_spec_filename, dir_name, analysis_spec, error in specs:
        keys: List[Any] = list()
        tmp_logtypes: Any = None
        tmp_logtypes_key: Any = None
        try:
            # check for parsing errors from json.loads (ValueError) / yaml.safe_load (YAMLError)
            if error:
                raise error
            # validate the schema has a valid analysis type
            TYPE_SCHEMA.validate(analysis_spec)
            analysis_type = analysis_spec["AnalysisType"]
            # validate the particular analysis type schema
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
            analysis_ids.append(analysis_id)
            # add the validated analysis type to the classified specs
            if analysis_type in [POLICY, RULE, SCHEDULED_RULE]:
                classified_specs[DETECTION].append(
                    (analysis_spec_filename, dir_name, analysis_spec)
                )
            else:
                classified_specs[analysis_type].append(
                    (analysis_spec_filename, dir_name, analysis_spec)
                )
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
            first_half = err_str.split(":")[0]
            second_half = err_str.split(")")[-1]
            if "LogTypes" in str(err):
                error = SchemaError(f"{first_half}: LOG_TYPE_REGEX{second_half}")
            elif "ResourceTypes" in str(err):
                error = SchemaError(f"{first_half}: RESOURCE_TYPE_REGEX{second_half}")
            invalid_specs.append((analysis_spec_filename, error))
        except Exception as err:  # pylint: disable=broad-except
            # Catch arbitrary exceptions thrown by bad specification files
            invalid_specs.append((analysis_spec_filename, err))
            continue
        finally:
            # Restore original values
            if tmp_logtypes and tmp_logtypes_key:
                analysis_schema.schema[tmp_logtypes_key] = tmp_logtypes

    return classified_specs, invalid_specs


def lookup_analysis_id(analysis_spec: Any, analysis_type: str) -> str:
    analysis_id = "UNKNOWN_ID"
    if analysis_type == DATAMODEL:
        analysis_id = analysis_spec["DataModelID"]
    if analysis_type == GLOBAL:
        analysis_id = analysis_spec["GlobalID"]
    if analysis_type == PACK:
        analysis_id = analysis_spec["PackID"]
    if analysis_type == POLICY:
        analysis_id = analysis_spec["PolicyID"]
    if analysis_type == QUERY:
        analysis_id = analysis_spec["QueryName"]
    if analysis_type in [RULE, SCHEDULED_RULE]:
        analysis_id = analysis_spec["RuleID"]
    return analysis_id


def contains_invalid_field_set(analysis_spec: Any) -> List[str]:
    """Checks if the fields that Panther expects as sets have duplicates, returns True if invalid.

    :param analysis_spec: Loaded YAML specification file
    :return: bool - whether or not the specifications file is valid where False denotes valid.
    """
    invalid_fields = []
    for field in SET_FIELDS:
        if field not in analysis_spec:
            continue
        # Handle special case where we need to test for lowercase tags
        if field == "Tags":
            if len(analysis_spec[field]) != len(set(x.lower() for x in analysis_spec[field])):
                invalid_fields.append("LowerTags")
        if len(analysis_spec[field]) != len(set(analysis_spec[field])):
            invalid_fields.append(field)
    return invalid_fields


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
    detection: Detection,
    failed_tests: DefaultDict[str, list],
    minimum_tests: int,
    destinations_by_name: Dict[str, FakeDestination],
    ignore_exception_types: List[Type[Exception]],
) -> DefaultDict[str, list]:

    if len(analysis.get("Tests", [])) < minimum_tests:
        failed_tests[detection.detection_id].append(
            "Insufficient test coverage: {} tests required but only {} found".format(
                minimum_tests, len(analysis.get("Tests", []))
            )
        )

    # First check if any tests exist, so we can print a helpful message if not
    if "Tests" not in analysis:
        print("\tNo tests configured for {}".format(detection.detection_id))
        return failed_tests

    failed_tests = _run_tests(
        analysis_data_models,
        detection,
        analysis["Tests"],
        failed_tests,
        destinations_by_name,
        ignore_exception_types,
    )

    if minimum_tests > 1 and not (
        [x for x in analysis["Tests"] if x["ExpectedResult"]]
        and [x for x in analysis["Tests"] if not x["ExpectedResult"]]
    ):
        failed_tests[detection.detection_id].append(
            "Insufficient test coverage: expected at least one positive and one negative test"
        )

    return failed_tests


def _run_tests(  # pylint: disable=too-many-arguments
    analysis_data_models: Dict[str, DataModel],
    detection: Detection,
    tests: List[Dict[str, Any]],
    failed_tests: DefaultDict[str, list],
    destinations_by_name: Dict[str, FakeDestination],
    ignore_exception_types: List[Type[Exception]],
) -> DefaultDict[str, list]:

    for unit_test in tests:
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
            if mock_methods:
                with patch.multiple(detection.module, **mock_methods):
                    result = detection.run(test_case, {}, destinations_by_name, batch_mode=False)
            else:
                result = detection.run(test_case, {}, destinations_by_name, batch_mode=False)
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

        _print_test_result(detection, test_result, failed_tests)

    return failed_tests


def _print_test_result(
    detection: Detection, test_result: TestResult, failed_tests: DefaultDict[str, list]
) -> None:
    status_pass = "PASS"  # nosec
    status_fail = "FAIL"
    if test_result.passed:
        outcome = status_pass
    else:
        outcome = status_fail
    # print overall status for this test
    print("\t[{}] {}".format(outcome, test_result.name))

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
                    "\t\t[{}] [{}] {}".format(
                        status_fail, printable_name, function_result.get("error", {}).get("message")
                    )
                )
            # if it didn't error, we simply need to check if the output was as expected
            elif not function_result.get("matched", True):
                failed_tests[detection.detection_id].append(f"{test_result.name}:{printable_name}")
                print(
                    "\t\t[{}] [{}] {}".format(
                        status_fail, printable_name, function_result.get("output")
                    )
                )
            else:
                print(
                    "\t\t[{}] [{}] {}".format(
                        status_pass, printable_name, function_result.get("output")
                    )
                )


def setup_parser() -> argparse.ArgumentParser:
    # pylint: disable=too-many-statements,too-many-locals
    # setup dictionary of named args for some common arguments across commands
    aws_profile_name = "--aws-profile"
    aws_profile_arg: Dict[str, Any] = {
        "type": str,
        "help": "The AWS profile to use when updating the AWS Panther deployment.",
        "required": False,
    }
    filter_name = "--filter"
    filter_arg: Dict[str, Any] = {"required": False, "metavar": "KEY=VALUE", "nargs": "+"}
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
        "dest": "ignored_files",
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

    parser = argparse.ArgumentParser(
        description="Panther Analysis Tool: A command line tool for "
        + "managing Panther policies and rules.",
        prog="panther_analysis_tool",
    )
    parser.add_argument("--version", action="version", version="panther_analysis_tool 0.10.2")
    parser.add_argument("--debug", action="store_true", dest="debug")
    subparsers = parser.add_subparsers()

    release_parser = subparsers.add_parser(
        "release",
        help="Create release assets for repository containing panther detections. "
        + "Generates a file called panther-analysis-all.zip and optionally generates "
        + "panther-analysis-all.sig",
    )
    release_parser.add_argument(aws_profile_name, **aws_profile_arg)
    release_parser.add_argument(filter_name, **filter_arg)
    release_parser.add_argument(ignore_files_name, **ignore_files_arg)
    release_parser.add_argument(kms_key_name, **kms_key_arg)
    release_parser.add_argument(min_test_name, **min_test_arg)
    release_parser.add_argument(out_name, **out_arg)
    release_parser.add_argument(path_name, **path_arg)
    release_parser.add_argument(skip_test_name, **skip_test_arg)
    release_parser.add_argument(skip_disabled_test_name, **skip_disabled_test_arg)
    release_parser.add_argument(available_destination_name, **available_destination_arg)
    release_parser.set_defaults(func=generate_release_assets)

    test_parser = subparsers.add_parser(
        "test", help="Validate analysis specifications and run policy and rule tests."
    )
    test_parser.add_argument(filter_name, **filter_arg)
    test_parser.add_argument(min_test_name, **min_test_arg)
    test_parser.add_argument(path_name, **path_arg)
    test_parser.add_argument(ignore_extra_keys_name, **ignore_extra_keys_arg)
    test_parser.add_argument(ignore_files_name, **ignore_files_arg)
    test_parser.add_argument(skip_disabled_test_name, **skip_disabled_test_arg)
    test_parser.add_argument(available_destination_name, **available_destination_arg)
    test_parser.set_defaults(func=test_analysis)

    publish_parser = subparsers.add_parser(
        "publish",
        help="Publishes a new release, generates the release assets, and uploads them"
        + "Generates a file called panther-analysis-all.zip and optionally generates "
        + "panther-analysis-all.sig",
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
    publish_parser.add_argument(aws_profile_name, **aws_profile_arg)
    publish_parser.add_argument(filter_name, **filter_arg)
    publish_parser.add_argument(kms_key_name, **kms_key_arg)
    publish_parser.add_argument(min_test_name, **min_test_arg)
    publish_parser.add_argument(out_name, **out_arg)
    publish_parser.add_argument(skip_test_name, **skip_test_arg)
    publish_parser.add_argument(skip_disabled_test_name, **skip_disabled_test_arg)
    publish_parser.add_argument(available_destination_name, **available_destination_arg)
    publish_parser.add_argument(ignore_files_name, **ignore_files_arg)
    publish_parser.set_defaults(func=publish_release)

    upload_parser = subparsers.add_parser(
        "upload", help="Upload specified policies and rules to a Panther deployment."
    )
    upload_parser.add_argument(aws_profile_name, **aws_profile_arg)
    upload_parser.add_argument(filter_name, **filter_arg)
    upload_parser.add_argument(min_test_name, **min_test_arg)
    upload_parser.add_argument(out_name, **out_arg)
    upload_parser.add_argument(path_name, **path_arg)
    upload_parser.add_argument(skip_test_name, **skip_test_arg)
    upload_parser.add_argument(skip_disabled_test_name, **skip_disabled_test_arg)
    upload_parser.add_argument(ignore_extra_keys_name, **ignore_extra_keys_arg)
    upload_parser.add_argument(ignore_files_name, **ignore_files_arg)
    upload_parser.add_argument(available_destination_name, **available_destination_arg)
    upload_parser.set_defaults(func=upload_analysis)

    update_custom_schemas_parser = subparsers.add_parser(
        "update-custom-schemas", help="Update or create custom schemas on a Panther deployment."
    )
    update_custom_schemas_parser.add_argument(aws_profile_name, **aws_profile_arg)
    custom_schemas_path_arg = path_arg.copy()
    custom_schemas_path_arg["help"] = "The relative or absolute path to Panther custom schemas."
    update_custom_schemas_parser.add_argument(path_name, **custom_schemas_path_arg)
    update_custom_schemas_parser.set_defaults(func=update_custom_schemas)

    if os.environ.get(ENV_VAR_INCLUDE_INTERNAL_SUBCOMMANDS):
        update_managed_schemas_parser = subparsers.add_parser(
            "update-schemas", help="Update managed schemas on a Panther deployment."
        )
        update_managed_schemas_parser.add_argument(aws_profile_name, **aws_profile_arg)
        update_managed_schemas_parser.set_defaults(func=update_schemas)

        zip_parser = subparsers.add_parser(
            "zip", help="Create an archive of local policies and rules for uploading to Panther."
        )
        zip_parser.add_argument(filter_name, **filter_arg)
        zip_parser.add_argument(ignore_files_name, **ignore_files_arg)
        zip_parser.add_argument(min_test_name, **min_test_arg)
        zip_parser.add_argument(out_name, **out_arg)
        zip_parser.add_argument(path_name, **path_arg)
        zip_parser.add_argument(skip_test_name, **skip_test_arg)
        zip_parser.add_argument(skip_disabled_test_name, **skip_disabled_test_arg)
        zip_parser.add_argument(available_destination_name, **available_destination_arg)
        zip_parser.set_defaults(func=zip_analysis)

        zip_schemas_parser = subparsers.add_parser(
            "zip-schemas", help="Create a release asset archive of managed schemas."
        )
        zip_schemas_parser.add_argument(
            "--release", type=str, help="The release tag this asset is for", required=True
        )
        zip_schemas_parser.add_argument(out_name, **out_arg)
        zip_schemas_parser.set_defaults(func=zip_managed_schemas)

    return parser


def zip_managed_schemas(args: argparse.Namespace) -> Tuple[int, str]:
    """Packs managed schemas of a tagged release into a local zip file.

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A tuple of return code and the archive filename.
    """

    manifest = []
    with tempfile.TemporaryDirectory(prefix="zip-managed-schemas-") as tmp_dir:
        repo_url = "https://github.com/panther-labs/panther-analysis"
        repo_dir = os.path.join(tmp_dir, "panther-analysis")
        rel = args.release
        if not semver.VersionInfo.isvalid(rel[1:] if rel.startswith("v") else rel):
            logging.error("Invalid release tag %s", rel)
            return 1, ""

        logging.info("Cloning %s tag of %s", rel, repo_url)
        # nosec
        cmd = [
            "git",
            "clone",
            "--branch",
            rel,
            "--depth",
            "1",
            "-c",
            "advice.detachedHead=false",
            repo_url,
            repo_dir,
        ]
        result = subprocess.run(cmd, check=True, timeout=120)  # nosec
        if result.returncode != 0:
            return result.returncode, ""

        schema_dir = os.path.join(repo_dir, "schemas")
        filenames = [
            os.path.join(root, f)
            for root, dirs, files in os.walk(schema_dir)
            if not fnmatch(root, "*/tests")
            for f in files
            if fnmatch(f, "*.yml")
        ]
        if not filenames:
            logging.error("Release %s does not contain any managed schema file", rel)
            return 1, ""

        logging.info(
            "Building manifest.yml for %d managed schemas found in release %s", len(filenames), rel
        )
        for filename in filenames:
            with open(filename) as yml:
                lines = yml.readlines()
                manifest.append("---\n")
                manifest.extend(lines)

    archive = os.path.join(args.out, "managed-schemas-{}.zip".format(rel))
    logging.info("Zipping release asset archive %s", archive)
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zip_out:
        # Set the archive comment to the release version
        zip_out.comment = bytes(rel, encoding="utf8")
        # Add the manifest.yml file
        zip_out.writestr("manifest.yml", "".join(manifest))

    return 0, archive


# Parses the filters, expects a list of strings
def parse_filter(filters: List[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    parsed_filters = {}
    parsed_filters_inverted = {}
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
    return parsed_filters, parsed_filters_inverted


def run() -> None:
    parser = setup_parser()
    # if no args are passed, print the help output
    args = parser.parse_args(args=None if sys.argv[1:] else ["--help"])

    logging.basicConfig(
        format="[%(levelname)s]: %(message)s",
        level=logging.DEBUG if args.debug else logging.INFO,
    )

    if getattr(args, "filter", None) is not None:
        args.filter, args.filter_inverted = parse_filter(args.filter)
    if getattr(args, "filter_inverted", None) is None:
        args.filter_inverted = {}

    # Although not best practice, the alternative is ugly and significantly harder to maintain.
    if bool(getattr(args, "ignore_extra_keys", None)):
        RULE_SCHEMA._ignore_extra_keys = True  # pylint: disable=protected-access
        POLICY_SCHEMA._ignore_extra_keys = True  # pylint: disable=protected-access

    try:
        return_code, out = args.func(args)
    except Exception as err:  # pylint: disable=broad-except
        # Catch arbitrary exceptions without printing help message
        logging.warning('Unhandled exception: "%s"', err)
        logging.debug("Full error traceback:", exc_info=err)
        sys.exit(1)

    if return_code == 1:
        if out:
            logging.error(out)
    elif return_code == 0:
        if out:
            logging.info(out)

    sys.exit(return_code)


if __name__ == "__main__":
    run()
