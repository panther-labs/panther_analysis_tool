import dataclasses
import importlib
import io
import json
import logging
import os
import re
import tempfile
from fnmatch import fnmatch
from importlib.abc import Loader
from typing import Any, Dict, Iterator, List, Optional, Tuple

import jsonschema
import schema
from jsonschema import Draft202012Validator
from ruamel.yaml import YAML
from ruamel.yaml import parser as YAMLParser
from ruamel.yaml import scanner as YAMLScanner

from panther_analysis_tool.backend.client import (
    BackendError,
)
from panther_analysis_tool.backend.client import Client as BackendClient
from panther_analysis_tool.backend.client import (
    GetRuleBodyParams,
    TestCorrelationRuleParams,
    TranspileFiltersParams,
    TranspileToPythonParams,
)
from panther_analysis_tool.constants import (
    BACKEND_FILTERS_ANALYSIS_SPEC_KEY,
    DATA_MODEL_LOCATION,
    DATA_MODEL_PATH_PATTERN,
    HELPERS_LOCATION,
    HELPERS_PATH_PATTERN,
    LUTS_PATH_PATTERN,
    PACKS_PATH_PATTERN,
    POLICIES_PATH_PATTERN,
    QUERIES_PATH_PATTERN,
    RULES_PATH_PATTERN,
    SCHEMAS,
    VERSION_STRING,
    AnalysisTypes,
)
from panther_analysis_tool.core.definitions import (
    ClassifiedAnalysis,
    ClassifiedAnalysisContainer,
)
from panther_analysis_tool.core.parse import Filter
from panther_analysis_tool.schemas import (
    ANALYSIS_CONFIG_SCHEMA,
    DERIVED_SCHEMA,
    POLICY_SCHEMA,
    RULE_SCHEMA,
    TYPE_SCHEMA,
)
from panther_analysis_tool.util import is_simple_detection
from panther_analysis_tool.validation import (
    contains_invalid_field_set,
    contains_invalid_table_names,
)


class AnalysisIDConflictException(Exception):
    """Exception for conflicting ids"""

    def __init__(self, analysis_id: str):
        self.message = f"Conflicting AnalysisID: [{analysis_id}]"
        super().__init__(self.message)


class AnalysisContainsDuplicatesException(Exception):
    """Exception for duplicate values in analysis specs"""

    def __init__(self, analysis_id: str, invalid_fields: List[str]):
        self.message = f'Specification file for [{analysis_id}] contains fields \
        with duplicate values: [{", ".join(x for x in invalid_fields)}]'
        super().__init__(self.message)


class AnalysisContainsInvalidTableNamesException(Exception):
    """Exception for invalid Panther Snowflake table names"""

    def __init__(self, analysis_id: str, invalid_table_names: List[str]):
        self.message = (
            f'Specification file for [{analysis_id}] contains invalid Panther table names: [{", ".join(x for x in invalid_table_names)}]. '
            'Try using a fully qualified table name such as "panther_logs.public.log_type" '
            "or setting --ignore-table-names for queries using non-Panther or non-Snowflake tables."
        )
        super().__init__(self.message)


def filter_analysis(
    analysis: List[ClassifiedAnalysis], filters: List[Filter], filters_inverted: List[Filter]
) -> List[ClassifiedAnalysis]:
    if filters is None:
        return analysis

    filtered_analysis = []
    for item in analysis:
        dir_name = item.dir_name
        file_name = item.file_name
        analysis_spec = item.analysis_spec
        if fnmatch(dir_name, HELPERS_PATH_PATTERN):
            logging.debug("auto-adding helpers file %s", os.path.join(file_name))
            filtered_analysis.append(ClassifiedAnalysis(file_name, dir_name, analysis_spec))
            continue
        if fnmatch(dir_name, DATA_MODEL_PATH_PATTERN):
            logging.debug("auto-adding data model file %s", os.path.join(file_name))
            filtered_analysis.append(ClassifiedAnalysis(file_name, dir_name, analysis_spec))
            continue
        match = True
        for filt in filters:
            key, values = filt.key, filt.values
            spec_value = analysis_spec.get(key, "")
            spec_value = spec_value if isinstance(spec_value, list) else [spec_value]
            if not set(spec_value).intersection(values):
                match = False
                break
        for filt in filters_inverted:
            key, values = filt.key, filt.values
            spec_value = analysis_spec.get(key, "")
            spec_value = spec_value if isinstance(spec_value, list) else [spec_value]
            if set(spec_value).intersection(values):
                match = False
                break

        if match:
            filtered_analysis.append(ClassifiedAnalysis(file_name, dir_name, analysis_spec))

    return filtered_analysis


def load_analysis_specs(
    directories: List[str], ignore_files: List[str]
) -> Iterator[Tuple[str, str, Any, Any]]:
    """Loads the analysis specifications from a file. It calls load_analysis_specs_ex
    and returns the spec_filename, relative_path, analysis_spec, and error to preserve
    historic callers.

    Args:
        directories: The relative path to Panther policies or rules.
        ignore_files: Files that Panther Analysis Tool should not process

    Yields:
        A tuple of the relative filepath, directory name, and loaded analysis specification dict.
    """
    for result in load_analysis_specs_ex(directories, ignore_files, roundtrip_yaml=False):
        yield result.spec_filename, result.relative_path, result.analysis_spec, result.error


def disable_all_base_detections(paths: List[str], ignore_files: List[str]) -> None:
    analysis_specs = list(load_analysis_specs_ex(paths, ignore_files, roundtrip_yaml=True))
    base_ids_to_disable = set()
    base_detection_key = "BaseDetection"
    rule_id_key = "RuleID"
    enabled_key = "Enabled"
    for analysis_spec_res in analysis_specs:
        spec: Dict[str, Any] = analysis_spec_res.analysis_spec
        base_id = spec.get(base_detection_key, "")
        if base_id == "":
            continue
        base_ids_to_disable.add(base_id)
    for base_detection_id in base_ids_to_disable:
        for analysis_spec_res in analysis_specs:
            rule: Dict[str, Any] = analysis_spec_res.analysis_spec
            if rule.get(rule_id_key, "") == base_detection_id:
                logging.info(
                    "Setting %s=False for %s", enabled_key, analysis_spec_res.spec_filename
                )
                rule[enabled_key] = False
                analysis_spec_res.serialize_to_file()


@dataclasses.dataclass
class LoadAnalysisSpecsResult:
    """The result of loading analysis specifications from a file."""

    spec_filename: str
    relative_path: str
    analysis_spec: Any
    yaml_ctx: YAML
    error: Optional[Exception]

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, LoadAnalysisSpecsResult):
            return NotImplemented

        # skipping yaml_ctx because it's not relevant to equality of content
        # in analysis spec files
        same_spec_filename = self.spec_filename == other.spec_filename
        same_relative_path = self.relative_path == other.relative_path
        same_analysis_spec = self.analysis_spec == other.analysis_spec
        same_error = self.error == other.error

        return all(
            [
                same_spec_filename,
                same_relative_path,
                same_analysis_spec,
                same_error,
            ]
        )

    # pylint: disable=no-else-return
    def analysis_id(self) -> str:
        """Returns the analysis ID for this analysis spec."""
        analysis_type = self.analysis_spec["AnalysisType"]
        if analysis_type in [
            AnalysisTypes.RULE,
            AnalysisTypes.SCHEDULED_RULE,
            AnalysisTypes.CORRELATION_RULE,
        ]:
            return self.analysis_spec["RuleID"]
        elif analysis_type == AnalysisTypes.POLICY:
            return self.analysis_spec["PolicyID"]

        raise ValueError(f"Unknown analysis type '{analysis_type}'")

    def analysis_type(self) -> str:
        """Returns the analysis type for this analysis spec."""
        return self.analysis_spec["AnalysisType"]

    # pylint: disable=line-too-long
    def __str__(self) -> str:
        return f"LoadAnalysisSpecsResult(spec_filename={self.spec_filename}, relative_path={self.relative_path}, analysis_spec={self.analysis_spec['AnalysisType']}, error={self.error})"

    def serialize_to_file(self) -> None:
        logging.debug("Writing analysis spec to %s", self.spec_filename)
        with open(self.spec_filename, "w", encoding="utf-8") as file:
            self.yaml_ctx.dump(self.analysis_spec, file)


def get_yaml_loader(roundtrip: bool) -> YAML:
    """Returns a YAML object with the correct settings for loading analysis specifications.

    Args:
        roundtrip: Whether or not the YAML parser should be roundtrip safe. Roundtrip safe YAML
            parser is not compatible with many PAT functions.
    """
    if not roundtrip:
        return YAML(typ="safe")

    # If we need to roundtrip, we have different requirements. Most use cases will not need
    # round-tripping. We only need a roundtrip safe YAML parser if we are going to update
    # the YAML files.
    yaml = YAML(typ="rt")
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.preserve_quotes = True
    yaml.default_flow_style = False
    # allow very long lines to avoid unnecessary line changes
    yaml.width = 4096
    return yaml


# pylint: disable=too-many-locals
def load_analysis_specs_ex(
    directories: List[str], ignore_files: List[str], roundtrip_yaml: bool
) -> Iterator[LoadAnalysisSpecsResult]:
    """Loads the analysis specifications from a file. The _ex variant of this function returns
    a LoadAnalysisSpecsResult object that contains the yaml_ctx object that was used to load
    the specific YAML content. This allows us to roundtrip the YAML content back to the file with
    minimal changes.

    Args:
        directories: The relative path to Panther policies or rules.
        ignore_files: Files that Panther Analysis Tool should not process
        roundtrip_yaml: If True, roundtrip the YAML content back to the file with minimal changes. This
            is incompatible with most of PAT's YAML loading use-cases. However, if you need to modify
            YAML code, this is necessary.

    Yields:
        An instance of LoadAnalysisSpecsResult.
    """
    # setup a list of paths to ensure we do not import the same files
    # multiple times, which can happen when testing from root directory without filters
    ignored_normalized = ["dependabot.yml", "package.json", "package-lock.json"]
    for file in ignore_files:
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
                            LUTS_PATH_PATTERN,
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
                # setup yaml object
                yaml = get_yaml_loader(roundtrip=roundtrip_yaml)
                if fnmatch(filename, "*.y*ml"):
                    with open(spec_filename, "r", encoding="utf-8") as spec_file_obj:
                        try:
                            yield LoadAnalysisSpecsResult(
                                spec_filename=spec_filename,
                                relative_path=relative_path,
                                analysis_spec=yaml.load(spec_file_obj),
                                yaml_ctx=yaml,
                                error=None,
                            )
                        except (YAMLParser.ParserError, YAMLScanner.ScannerError) as err:
                            # recreate the yaml object and yield the error
                            yield LoadAnalysisSpecsResult(
                                spec_filename=spec_filename,
                                relative_path=relative_path,
                                analysis_spec=None,
                                yaml_ctx=yaml,
                                error=err,
                            )


def to_relative_path(filename: str) -> str:
    cwd = os.getcwd()
    return os.path.relpath(filename, cwd)


# This function was generated in whole or in part by GitHub Copilot.
def get_simple_detections_as_python(
    specs: List[ClassifiedAnalysis], backend: Optional[BackendClient] = None
) -> List[ClassifiedAnalysis]:
    """Returns simple detections with transpiled Python."""
    enriched_specs = []
    if backend is not None:
        batch = [json.dumps(spec.analysis_spec, allow_nan=False) for spec in specs]
        try:
            params = TranspileToPythonParams(data=batch)
            response = backend.transpile_simple_detection_to_python(params)
            if response.status_code == 200:
                for i, result in enumerate(response.data.transpiled_python):
                    item = specs[i]
                    spec = item.analysis_spec
                    spec["body"] = result
                    enriched_specs.append(ClassifiedAnalysis(item.file_name, item.dir_name, spec))
            else:
                logging.warning(
                    "Error transpiling simple detection(s) to Python, skipping tests for simple detections."
                )
        except (BackendError, BaseException) as be_err:  # pylint: disable=broad-except
            logging.warning(
                "Error transpiling simple detection(s) to Python, skipping tests for simple detections:  %s",
                be_err,
            )
    else:
        logging.info("No backend client provided, skipping tests for simple detections.")
    return enriched_specs if enriched_specs else specs


def lookup_base_detection(the_id: str, backend: Optional[BackendClient] = None) -> Dict[str, Any]:
    """Attempts to lookup base detection via its id"""
    out: Dict[str, Any] = {}
    if backend is not None:
        try:
            params = GetRuleBodyParams(id=the_id)
            response = backend.get_rule_body(params)
            if response.status_code == 200:
                out["body"] = response.data.body
                out["tests"] = response.data.tests
            else:
                logging.warning(
                    "Unexpected error getting base detection, status code %s", response.status_code
                )
        except (BackendError, BaseException) as be_err:  # pylint: disable=broad-except
            logging.warning(
                "Error getting base detection %s: %s",
                the_id,
                be_err,
            )
    return out


def test_correlation_rule(
    spec: Dict[str, Any],
    backend: Optional[BackendClient] = None,
    test_names: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    # dont make network call if there's no tests to run, or if no backend
    if "Tests" not in spec or backend is None:
        return out
    try:
        # Filter tests by name
        if test_names:
            tests = spec.get("Tests", [])
            tests = [t for t in tests if t["Name"] in test_names]
            spec["Tests"] = tests

        yaml = get_yaml_loader(roundtrip=True)
        string_io = io.StringIO()
        yaml.dump(spec, stream=string_io)
        output_str = string_io.getvalue()
        string_io.close()
        resp = backend.test_correlation_rule(
            TestCorrelationRuleParams(
                yaml=output_str,
            )
        )
        out = resp.data.results
    except Exception as be_err:  # pylint: disable=broad-except
        logging.warning(
            "Error running tests remotely for correlation rule %s: %s",
            spec.get("RuleID", ""),
            be_err,
        )
    return out


def transpile_inline_filters(
    all_specs: ClassifiedAnalysisContainer, backend: Optional[BackendClient] = None
) -> None:
    """
    Transpiles all InlineFilters on detections from simple detection format to the backend format and saves the
    transpiled filter's JSON to the analysis spec under "_backend_filters".
    """
    inline_filters_key = "InlineFilters"

    # separate out all detections with inline filters
    # keep track of the detections without filters so the list can be used later
    all_detections_with_filters, detections, simple_detections = [], [], []
    for det in all_specs.detections:
        if inline_filters_key in det.analysis_spec:
            all_detections_with_filters.append(det)
        else:
            detections.append(det)
    for det in all_specs.simple_detections:
        if inline_filters_key in det.analysis_spec:
            all_detections_with_filters.append(det)
        else:
            simple_detections.append(det)

    # if there are no InlineFilters at all then we can just return
    if len(all_detections_with_filters) == 0:
        return

    if backend is not None:
        batch = [
            json.dumps(d.analysis_spec.get("InlineFilters"), allow_nan=False)
            for d in all_detections_with_filters
        ]
        try:
            params = TranspileFiltersParams(data=batch, pat_version=VERSION_STRING)
            response = backend.transpile_filters(params)

            if response.status_code == 200:
                # set the translated backend filters on the analysis spec
                for i, result in enumerate(response.data.transpiled_filters):
                    all_detections_with_filters[i].analysis_spec[
                        BACKEND_FILTERS_ANALYSIS_SPEC_KEY
                    ] = json.loads(result)
                # separate the simple detections from the other detections
                for det in all_detections_with_filters:
                    if is_simple_detection(det.analysis_spec):
                        simple_detections.append(det)
                    else:
                        detections.append(det)
                # replace the lists in all specs with the new specs
                all_specs.detections = detections
                all_specs.simple_detections = simple_detections
            else:
                logging.warning(
                    "Error transpiling InlineFilter(s), skipping InlineFilters during testing"
                )
        except (BackendError, BaseException) as be_err:  # pylint: disable=broad-except
            logging.warning(
                "Error transpiling InlineFilter(s), skipping InlineFilters during testing:  %s",
                be_err,
            )
    else:
        logging.info("No backend client provided, skipping InlineFilters during testing")


def load_analysis(
    path: str,
    ignore_table_names: bool,
    valid_table_names: List[str],
    ignore_files: List[str],
    ignore_extra_keys: bool,
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
        ignore_extra_keys=ignore_extra_keys,
    )

    return specs, invalid_specs


# pylint: disable=too-many-locals,too-many-statements
def classify_analysis(
    specs: List[Tuple[str, str, Any, Any]],
    ignore_table_names: bool,
    valid_table_names: List[str],
    ignore_extra_keys: bool,
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

            if analysis_schema in [RULE_SCHEMA, POLICY_SCHEMA, DERIVED_SCHEMA]:
                analysis_schema._ignore_extra_keys = (  # pylint: disable=protected-access
                    ignore_extra_keys
                )
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

        except schema.SchemaWrongKeyError as err:
            invalid_specs.append((analysis_spec_filename, handle_wrong_key_error(err, keys)))
        except (
            schema.SchemaMissingKeyError,
            schema.SchemaForbiddenKeyError,
            schema.SchemaUnexpectedTypeError,
        ) as err:
            invalid_specs.append((analysis_spec_filename, err))
            continue
        except schema.SchemaError as err:
            # Intercept the error, otherwise the error message becomes confusing and unreadable
            error = err
            err_str = str(err)
            first_half = err_str.split(":", maxsplit=1)[0]
            second_half = err_str.split(")", maxsplit=1)[-1]
            if "LogTypes" in str(err):
                error = schema.SchemaError(f"{first_half}: LOG_TYPE_REGEX{second_half}")
            elif "ResourceTypes" in str(err):
                error = schema.SchemaError(f"{first_half}: RESOURCE_TYPE_REGEX{second_half}")
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


def handle_wrong_key_error(err: schema.SchemaWrongKeyError, keys: list) -> Exception:
    regex = r"Wrong key(?:s)? (.+?) in (.*)$"
    matches = re.match(regex, str(err))
    msg = "{} not in list of valid keys: {}"
    try:
        if matches:
            raise schema.SchemaWrongKeyError(msg.format(matches.group(1), keys)) from err
        raise schema.SchemaWrongKeyError(msg.format("UNKNOWN_KEY", keys)) from err
    except schema.SchemaWrongKeyError as exc:
        return exc


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


def get_tmp_helper_module_location() -> str:
    return os.path.join(tempfile.gettempdir(), "panther-path", "globals")
