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
import fnmatch
import logging
import os
from dataclasses import dataclass
from itertools import filterfalse
from typing import Any, Dict, List, Optional, Tuple, cast

from ruamel.yaml import YAML
from ruamel.yaml.composer import ComposerError
from ruamel.yaml.parser import ParserError
from ruamel.yaml.scanner import ScannerError

from panther_analysis_tool.backend.client import BackendError, BackendResponse
from panther_analysis_tool.backend.client import Client as BackendClient
from panther_analysis_tool.backend.client import (
    ListSchemasParams,
    ManagedSchema,
    UpdateManagedSchemaParams,
)

logger = logging.getLogger(__file__)


@dataclass
class UploaderResult:
    # The path of the schema definition file
    filename: str
    # The schema name / identifier, e.g. Custom.SampleSchema
    name: Optional[str]
    # The Backend Client invocation response payload (PutUserSchema endpoint)
    backend_response: Optional[BackendResponse] = None
    # The schema specification in YAML form
    definition: Optional[Dict[str, Any]] = None
    # Any error encountered during processing will be stored here
    error: Optional[str] = None
    # Flag to signify whether the schema was created or updated
    existed: Optional[bool] = None


@dataclass
class ProcessedFile:
    # Any error message produced during YAML parsing
    error: Optional[str] = None
    # The raw file contents
    raw: str = ""
    # The deserialized schema
    yaml: Optional[Dict[str, Any]] = None


class Uploader:
    _SCHEMA_NAME_PREFIX = "Custom."
    _SCHEMA_FILE_GLOB_PATTERNS = ("*.yml", "*.yaml")

    def __init__(self, path: str, backend: BackendClient):
        self._path = path
        self._files: Optional[List[str]] = None
        self._existing_schemas: Optional[List[ManagedSchema]] = None
        self._backend = backend

    @property
    def files(self) -> List[str]:
        """
        Resolves the list of schema definition files.
        Returns:
            A list of absolute paths to the schema files.
        """
        if self._files is None:
            matching_filenames = discover_files(self._path, self._SCHEMA_FILE_GLOB_PATTERNS)
            self._files = ignore_schema_test_files(matching_filenames)
        return self._files

    @property
    def existing_schemas(self) -> List[ManagedSchema]:
        """
        Retrieves and caches in the instance state the list
        of available user-defined schemas.

        Returns:
             List of user-defined schema records.
        """
        if self._existing_schemas is None:
            resp = self._backend.list_managed_schemas(ListSchemasParams(is_managed=False))
            if not resp.status_code == 200:
                raise RuntimeError("unable to retrieve custom schemas")
            self._existing_schemas = resp.data.schemas
        return self._existing_schemas

    def find_schema(self, name: str) -> Optional[ManagedSchema]:
        """
        Find schema by name.

        Returns:
             The decoded YAML schema or None if no matching name is found.
        """
        for schema in self.existing_schemas:
            if schema.name == name:
                return schema
        return None

    def process(self) -> List[UploaderResult]:
        """
        Processes all potential schema files found in the given path.
        For updates it is required to retrieve description, revision number,
        and reference URL from the backend for each schema. More specifically:
        - Reference URL and description can be included in the definition, but are
          defined as additional metadata in the UI.
        - A matching revision number must be provided when making update requests,
          otherwise validation fails.

        Returns:
             A list of UploaderResult records that can be used
             for reporting the applied changes and errors.
        """
        if not self.files:
            logger.warning("No files found in path '%s'", self._path)
            return []

        processed_files = self._load_from_yaml(self.files)
        results = []
        # Add results for files that could not be loaded first
        for filename, processed_file in processed_files.items():
            if processed_file.error is not None:
                results.append(
                    UploaderResult(
                        name=None,
                        filename=filename,
                        error=processed_file.error,
                    )
                )

        for filename, processed_file in processed_files.items():
            # Skip any files with load errors, we have already included
            # them in the previous loop
            if processed_file.error is not None:
                continue

            logger.info("Processing file %s", filename)

            name, error = self._extract_schema_name(processed_file.yaml)
            result = UploaderResult(filename=filename, name=name, error=error)
            logger.info("uploader result is '%s'", result)
            # Don't attempt to perform an update, if we could not extract the name from the file
            if not result.error:
                try:
                    existed, response = self._update_or_create_schema(name, processed_file)
                    result.existed = existed
                    result.backend_response = response
                except BackendError as exc:
                    result.error = f"failure to update schema {name}: " f"message={exc}"
            results.append(result)
        return results

    @staticmethod
    def _load_from_yaml(files: List[str]) -> Dict[str, ProcessedFile]:
        yaml_parser = YAML(typ="safe")

        processed_files = {}
        for filename in files:
            logger.info("Loading schema from file %s", filename)
            processed_file = ProcessedFile()
            processed_files[filename] = processed_file
            try:
                with open(filename, "r") as schema_file:
                    processed_file.raw = schema_file.read()
                processed_file.yaml = yaml_parser.load(processed_file.raw)
            except (ParserError, ScannerError, ComposerError) as exc:
                processed_file.error = f"invalid YAML: {exc}"
        return processed_files

    def _extract_schema_name(
        self, definition: Optional[Dict[str, Any]]
    ) -> Tuple[str, Optional[str]]:
        if definition is None:
            raise ValueError("definition cannot be None")

        name = definition.get("schema")

        if name is None:
            return "", "key 'schema' not found"

        if not name.startswith(self._SCHEMA_NAME_PREFIX):
            return (
                "",
                f"'schema' field: value must start"
                f" with the prefix '{self._SCHEMA_NAME_PREFIX}'",
            )

        return name, None

    def _update_or_create_schema(
        self, name: str, processed_file: ProcessedFile
    ) -> Tuple[bool, BackendResponse]:
        existing_schema = self.find_schema(name)
        current_reference_url = ""
        current_description = ""
        current_revision = 0
        definition = cast(Dict[str, Any], processed_file.yaml)
        existed = False
        if existing_schema is not None:
            existed = True
            current_reference_url = existing_schema.reference_url
            current_description = existing_schema.description
            current_revision = existing_schema.revision
        reference_url = definition.get("referenceURL", current_reference_url)
        description = definition.get("description", current_description)
        logger.debug(
            "updating schema %s at revision %d, using " "referenceURL=%s, " "description=%s",
            name,
            current_revision,
            reference_url,
            description,
        )
        response = self._backend.update_managed_schema(
            params=UpdateManagedSchemaParams(
                name=name,
                spec=processed_file.raw,
                revision=current_revision,
                reference_url=reference_url,
                description=description,
            )
        )
        return existed, response


def discover_files(base_path: str, patterns: Tuple[str, ...]) -> List[str]:
    """
    Recursively locates files that match the given glob patterns.

    Args:
         base_path: the base directory for recursively searching for files
         patterns: a list of glob patterns that the filenames should match

    Returns:
        A sorted list of absolute paths.
    """
    files = []
    for directory, _, filenames in os.walk(base_path):
        for filename in filenames:
            for pattern in patterns:
                if fnmatch.fnmatch(filename, pattern):
                    files.append(os.path.join(directory, filename))
    return sorted(files)


def ignore_schema_test_files(paths: List[str]) -> List[str]:
    """
    Detect and ignore files that contain schema tests.

    Args:
        paths: the list of file paths from which schema test files will be excluded

    Returns:
        The list of absolute paths of files that possibly contain custom schema definitions.
    """
    return list(filterfalse(_contains_schema_tests, paths))


def _contains_schema_tests(filename: str) -> bool:
    """
    Check if a file contains YAML document(s) that describe test cases for custom schemas.
    Note that a test case file may contain multiple YAML documents.

    Args:
        filename: the full path for the file to be checked

    Returns:
        True if the fields match the test case definition structure
        and the filename suffix & extension match the constraints imposed by pantherlog.
    """
    # pantherlog requires that files containing test cases have a specific suffix and extension:
    # https://github.com/panther-labs/panther-enterprise/blob/75dd7ac2be67d3388edabb914b87f514ea9bd2cf/internal/log_analysis/log_processor/logtypes/logtesting/logtesting.go#L302
    if not filename.endswith("_tests.yml"):
        return False

    yaml_parser = YAML(typ="safe")

    with open(filename, "r") as stream:
        try:
            yaml_documents: List[Dict[str, Any]] = yaml_parser.load_all(stream)
        except (ParserError, ScannerError, ComposerError):
            return False

        documents = list(yaml_documents)

    if not documents:
        return False

    fields = set(map(str.lower, documents[0].keys()))

    # - "input" and "logtype" are expected to be always present
    # - at least one of "result", "results" fields is required
    return {"input", "logtype", "result"}.issubset(fields) or {
        "input",
        "logtype",
        "results",
    }.issubset(fields)


def normalize_path(path: str) -> Optional[str]:
    """Resolve the given path to its absolute form, taking into
    account user home prefix notation.
    Returns:
        The absolute path or None if the path does not exist.
    """
    absolute_path = os.path.abspath(os.path.expanduser(path))
    if not os.path.exists(absolute_path):
        return None
    return absolute_path


def report_summary(base_path: str, results: List[UploaderResult]) -> List[Tuple[bool, str]]:
    """
    Translate uploader results to descriptive status messages.

    Returns:
         A list of status messages along with the corresponding status flag for each message.
         Failure messages are flagged with True.
    """
    summary = []
    for result in sorted(results, key=lambda r: r.filename):
        filename = result.filename.split(base_path)[-1].strip(os.path.sep)
        if result.error:
            summary.append(
                (
                    True,
                    f"Failed to update schema from definition"
                    f" in file '{filename}': {result.error}",
                )
            )
        else:
            if result.existed:
                operation = "updated"
            else:
                operation = "created"
            summary.append(
                (
                    False,
                    f"Successfully {operation} schema '{result.name}' "
                    f"from definition in file '{filename}'",
                )
            )
    return summary
