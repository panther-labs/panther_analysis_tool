"""
 Analysis Tool is a command line interface for writing,
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
import shutil
import subprocess  # nosec
import sys
import time
import zipfile
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import asdict
from datetime import datetime

# Comment below disabling pylint checks is due to a bug in the CircleCi image with Pylint
# It seems to be unable to import the distutils module, however the module is present and importable
# in the Python Repl.
from distutils.util import strtobool  # pylint: disable=E0611, E0401
from importlib.abc import Loader
from typing import Any, DefaultDict, Dict, List, Tuple, Type
from unittest.mock import MagicMock, patch
from uuid import uuid4

import botocore
import requests
import schema
from dynaconf import Dynaconf, Validator
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
from schema import (
    Optional,
    SchemaError,
    SchemaForbiddenKeyError,
    SchemaMissingKeyError,
    SchemaUnexpectedTypeError,
    SchemaWrongKeyError,
)

from panther_analysis_tool.analysis_utils import filter_analysis, load_analysis_specs
from panther_analysis_tool.backend.client import BackendError, BulkUploadParams
from panther_analysis_tool.backend.client import Client as BackendClient
from panther_analysis_tool.cmd import (
    bulk_delete,
    check_connection,
    panthersdk_test,
    panthersdk_upload,
    standard_args,
)
from panther_analysis_tool.constants import (
    CONFIG_FILE,
    DATA_MODEL_LOCATION,
    DATAMODEL,
    DETECTION,
    GLOBAL,
    HELPERS_LOCATION,
    LOOKUP_TABLE,
    PACK,
    POLICY,
    QUERY,
    RULE,
    SCHEDULED_RULE,
    SCHEMAS,
    SET_FIELDS,
    TMP_HELPER_MODULE_LOCATION,
    VERSION_STRING,
)
from panther_analysis_tool.destination import FakeDestination
from panther_analysis_tool.log_schemas import user_defined
from panther_analysis_tool.schemas import (
    GLOBAL_SCHEMA,
    LOOKUP_TABLE_SCHEMA,
    POLICY_SCHEMA,
    RULE_SCHEMA,
    TYPE_SCHEMA,
)
from panther_analysis_tool.util import func_with_backend, get_client
from panther_analysis_tool.zip_chunker import ZipArgs, ZipChunk, analysis_chunks

# interpret datetime as str, the backend uses the default behavior for json.loads, which
# interprets these as str.  This sets global config for ruamel SafeConstructor
constructor.SafeConstructor.add_constructor(
    "tag:yaml.org,2002:timestamp", SafeConstructor.construct_yaml_str
)


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


def zip_analysis_chunks(args: argparse.Namespace) -> List[str]:
    logging.info("Zipping analysis items in %s to %s", args.path, args.out)

    current_time = datetime.now().isoformat(timespec="seconds").replace(":", "-")
    zip_chunks = [
        # note: all the files we care about have an AnalysisType field in their yml
        # so we can ignore file patterns and leave them empty
        ZipChunk(patterns=[], types=(DATAMODEL, RULE, POLICY, PACK, GLOBAL)),  # type: ignore
        ZipChunk(patterns=[], types=(QUERY, SCHEDULED_RULE)),  # type: ignore
        ZipChunk(patterns=[], types=LOOKUP_TABLE),  # type: ignore
    ]

    filenames = []
    chunks = analysis_chunks(ZipArgs.from_args(args), zip_chunks)
    if len(chunks) != len(zip_chunks):
        logging.error("something went wrong")
        return []
    for idx, chunk in enumerate(chunks):
        filename = f"panther-analysis-{current_time}-batch-{idx+1}.zip".format()
        filename = add_path_to_filename(args.out, filename)
        filenames.append(filename)
        with zipfile.ZipFile(filename, "w", zipfile.ZIP_DEFLATED) as zip_out:
            for name in chunk.files:
                zip_out.write(name)

    return filenames


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

    logging.info("Zipping analysis items in %s to %s", args.path, args.out)
    # example: 2019-08-05T18-23-25
    # The colon character is not valid in filenames.
    current_time = datetime.now().isoformat(timespec="seconds").replace(":", "-")
    filename = "panther-analysis-{}.zip".format(current_time)
    filename = add_path_to_filename(args.out, filename)

    typed_args = ZipArgs.from_args(args)
    chunks = analysis_chunks(typed_args)
    if len(chunks) != 1:
        logging.error("something went wrong")
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
        A tuple of return code and the archive filename.
    """

    if args.batch:
        if not args.skip_tests:
            return_code, _ = test_analysis(args)
            if return_code != 0:
                return return_code, ""

        for idx, archive in enumerate(zip_analysis_chunks(args)):
            batch_idx = idx + 1
            logging.info("Uploading Batch %d...", batch_idx)
            upload_zip(backend, args, archive)
            logging.info("Uploaded Batch %d", batch_idx)

        return 0, ""

    return_code, archive = zip_analysis(args)
    if return_code != 0:
        return return_code, ""

    return upload_zip(backend, args, archive)


def upload_zip(backend: BackendClient, args: argparse.Namespace, archive: str) -> Tuple[int, str]:
    return_archive_fname = ""
    # extract max retries we should handle
    max_retries = 10
    if args.max_retries > 10:
        logging.warning("max_retries cannot be greater than 10, defaulting to 10")
    elif args.max_retries < 0:
        logging.warning("max_retries cannot be negative, defaulting to 0")
        max_retries = 0

    with open(archive, "rb") as analysis_zip:
        logging.info("Uploading items to Panther")

        upload_params = BulkUploadParams(zip_bytes=analysis_zip.read())
        retry_count = 0

        while True:
            try:
                response = backend.bulk_upload(upload_params)

                logging.info("Upload success.")
                logging.info("API Response:\n%s", json.dumps(asdict(response.data), indent=4))

                return_code = 0
                return_archive_fname = ""
                break

            except BackendError as be_err:
                if be_err.permanent is True:
                    logging.error("failed to upload to backend: %s", be_err)
                    return_code = 1
                    break

                if max_retries - retry_count > 0:
                    logging.debug("Failed to upload to Panther: %s.", be_err)
                    retry_count += 1

                    # typical bulk upload takes 30 seconds, allow any currently running one to complete
                    logging.debug(
                        "Will retry upload in 30 seconds. Retries remaining: %s",
                        max_retries - retry_count,
                    )
                    time.sleep(30)

                else:
                    logging.warning("Exhausted retries attempting to perform bulk upload.")
                    return_code = 1
                    return_archive_fname = ""
                    break

            # PEP8 guide states it is OK to catch BaseException if you log it.
            except BaseException as err:  # pylint: disable=broad-except
                logging.error("failed to upload to backend: %s", err)
                return_code = 1
                return_archive_fname = ""
                break

    if return_code != 0:
        return return_code, return_archive_fname

    return_code, _ = panthersdk_upload.run(backend=backend, args=args, indirect_invocation=True)

    return return_code, return_archive_fname


def parse_lookup_table(args: argparse.Namespace) -> dict:
    """Validates and parses a Lookup Table spec file

    Returns a dict representing the Lookup Table

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A dict representing the Lookup Table, empty when parsing fails
    """

    logging.info("Parsing the Lookup Table spec defined in %s", args.path)
    with open(args.path, "r") as input_file:
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
    logging.info("Testing analysis items in %s\n", args.path)

    ignored_files = args.ignore_files
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
        list(load_analysis_specs(search_directories, ignore_files=ignored_files))
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
    setup_global_helpers(specs[GLOBAL])

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

    # finally, validate pack defs
    invalid_packs = validate_packs(specs)
    invalid_specs.extend(invalid_packs)

    # cleanup tmp global dir
    cleanup_global_helpers(specs[GLOBAL])

    print_summary(args.path, len(specs[DETECTION]), failed_tests, invalid_specs)

    #  if the classic format was invalid, just exit
    #  otherwise, run sdk too
    if invalid_specs:
        return 1, invalid_specs

    code, invalids = panthersdk_test.run(args, indirect_invocation=True)
    return int(bool(failed_tests) or bool(code)), invalid_specs + invalids


def setup_global_helpers(global_analysis: List[Any]) -> None:
    # ensure the directory does not exist, else clear it
    cleanup_global_helpers(global_analysis)
    os.makedirs(TMP_HELPER_MODULE_LOCATION)
    # setup temp dir for globals
    if TMP_HELPER_MODULE_LOCATION not in sys.path:
        sys.path.append(TMP_HELPER_MODULE_LOCATION)
    # place globals in temp dir
    for _, dir_name, analysis_spec in global_analysis:
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


def cleanup_global_helpers(global_analysis: List[Any]) -> None:
    # clear the modules from the modules cache
    for _, _, analysis_spec in global_analysis:
        analysis_id = analysis_spec["GlobalID"]
        # delete the helpers that were added to sys.modules for testing
        if analysis_id in sys.modules:
            del sys.modules[analysis_id]
    # ensure the directory does not exist, else clear it
    if os.path.exists(TMP_HELPER_MODULE_LOCATION):
        shutil.rmtree(TMP_HELPER_MODULE_LOCATION)


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


def validate_packs(analysis_specs: Dict[str, List[Any]]) -> List[Any]:
    invalid_specs = []
    # first, setup dictionary of id to detection item
    id_to_detection = {}
    for analysis_type in analysis_specs:
        for analysis_spec_filename, _, analysis_spec in analysis_specs[analysis_type]:
            analysis_id = (
                analysis_spec.get("PolicyID")
                or analysis_spec.get("RuleID")
                or analysis_spec.get("DataModelID")
                or analysis_spec.get("GlobalID")
                or analysis_spec.get("PackID")
                or analysis_spec.get("QueryName")
                or analysis_spec["LookupName"]
            )
            id_to_detection[analysis_id] = analysis_spec
    for analysis_spec_filename, _, analysis_spec in analysis_specs[PACK]:
        # validate each id in the pack def exists
        pack_invalid_ids = []
        for analysis_id in analysis_spec.get("PackDefinition", {}).get("IDs", []):
            if analysis_id not in id_to_detection:
                pack_invalid_ids.append(analysis_id)
        if pack_invalid_ids:
            invalid_specs.append(
                (
                    analysis_spec_filename,
                    f"pack ({analysis_spec['PackID']}) definition includes item(s)"
                    f" that do no exist ({', '.join(pack_invalid_ids)})",
                )
            )
    return invalid_specs


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


# pylint: disable=too-many-locals,too-many-statements
def classify_analysis(
    specs: List[Tuple[str, str, Any, Any]]
) -> Tuple[Dict[str, List[Any]], List[Any]]:
    # First setup return dict containing different
    # types of detections, meta types that can be zipped
    # or uploaded
    classified_specs: Dict[str, List[Any]] = dict()
    for key in [DATAMODEL, DETECTION, LOOKUP_TABLE, GLOBAL, PACK, QUERY]:
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
    if analysis_type == LOOKUP_TABLE:
        analysis_id = analysis_spec["LookupName"]
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
    batch_uploads_name = "--batch"
    batch_uploads_arg: Dict[str, Any] = {
        "action": "store_true",
        "default": False,
        "required": False,
        "help": "When set your upload will be broken down into multiple zip files",
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

    # -- root parser

    parser = argparse.ArgumentParser(
        description="Panther Analysis Tool: A command line tool for "
        + "managing Panther policies and rules.",
        prog="panther_analysis_tool",
    )
    parser.add_argument("--version", action="version", version=VERSION_STRING)
    parser.add_argument("--debug", action="store_true", dest="debug")
    subparsers = parser.add_subparsers()

    # -- release command

    release_parser = subparsers.add_parser(
        "release",
        help="Create release assets for repository containing panther detections. "
        + "Generates a file called panther-analysis-all.zip and optionally generates "
        + "panther-analysis-all.sig",
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
    release_parser.set_defaults(func=generate_release_assets)

    # -- test command

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

    # -- publish command

    publish_parser = subparsers.add_parser(
        "publish",
        help="Publishes a new release, generates the release assets, and uploads them. "
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

    upload_parser = subparsers.add_parser(
        "upload", help="Upload specified policies and rules to a Panther deployment."
    )
    upload_parser.add_argument(
        "--max-retries",
        help="Retry to upload on a failure for a maximum number of times",
        default=10,
        type=int,
        required=False,
    )

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
    upload_parser.add_argument(batch_uploads_name, **batch_uploads_arg)
    upload_parser.set_defaults(func=func_with_backend(upload_analysis))

    # -- delete command

    delete_parser = subparsers.add_parser(
        "delete", help="Delete policies, rules, or saved queries from a Panther deployment"
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

    delete_parser.set_defaults(func=func_with_backend(bulk_delete.run))

    # -- update custom schemas command

    update_custom_schemas_parser = subparsers.add_parser(
        "update-custom-schemas", help="Update or create custom schemas on a Panther deployment."
    )

    standard_args.for_public_api(update_custom_schemas_parser, required=False)
    standard_args.using_aws_profile(update_custom_schemas_parser)

    custom_schemas_path_arg = path_arg.copy()
    custom_schemas_path_arg["help"] = "The relative or absolute path to Panther custom schemas."
    update_custom_schemas_parser.add_argument(path_name, **custom_schemas_path_arg)
    update_custom_schemas_parser.set_defaults(func=func_with_backend(update_custom_schemas))

    # -- test lookup command

    test_lookup_table_parser = subparsers.add_parser(
        "test-lookup-table", help="Validate a Lookup Table spec file."
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

    # -- zip command

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

    # -- check-connection command

    check_conn_parser = subparsers.add_parser(
        "check-connection", help="Check your Panther API connection"
    )

    standard_args.for_public_api(check_conn_parser, required=False)

    check_conn_parser.set_defaults(func=func_with_backend(check_connection.run))

    # -- sdk command

    panthersdk_parser = subparsers.add_parser(
        "sdk",
        help="Perform operations using the Panther SDK exclusively " "(pass sdk --help for more)",
    )
    standard_args.for_public_api(panthersdk_parser, required=False)
    standard_args.using_aws_profile(panthersdk_parser)
    panthersdk_subparsers = panthersdk_parser.add_subparsers()

    panthersdk_upload_parser = panthersdk_subparsers.add_parser(
        "upload", help="Upload policies and rules generated from your Panther content"
    )
    panthersdk_upload_parser.set_defaults(func=func_with_backend(panthersdk_upload.run))

    panthersdk_test_parser = panthersdk_subparsers.add_parser(
        "test", help="Validate analysis specifications and run policy and rule tests."
    )
    panthersdk_test_parser.add_argument(min_test_name, **min_test_arg)
    panthersdk_test_parser.add_argument(skip_disabled_test_name, **skip_disabled_test_arg)
    panthersdk_test_parser.set_defaults(func=panthersdk_test.run)

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
    parser = setup_parser()
    # if no args are passed, print the help output
    args = parser.parse_args(args=None if sys.argv[1:] else ["--help"])

    logging.basicConfig(
        format="[%(levelname)s]: %(message)s",
        level=logging.DEBUG if args.debug else logging.INFO,
    )
    if not args.debug:
        aiohttp_logger.setLevel(logging.WARNING)

    if getattr(args, "filter", None) is not None:
        args.filter, args.filter_inverted = parse_filter(args.filter)
    if getattr(args, "filter_inverted", None) is None:
        args.filter_inverted = {}

    for key in os.environ:
        if key.startswith("PANTHER_"):
            logging.info("Found Environment Variables prefixed with 'PANTHER'.")
            break
    if os.path.exists(CONFIG_FILE):
        logging.info(
            "Found Config File %s . NOTE: SETTINGS IN CONFIG FILE OVERRIDE COMMAND LINE OPTIONS",
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
