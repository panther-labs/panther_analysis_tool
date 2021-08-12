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

import json
import logging
import os
import re
import tempfile
import traceback
from abc import abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Dict, List, Optional

from panther_analysis_tool.enriched_event import PantherEvent
from panther_analysis_tool.exceptions import (
    FunctionReturnTypeError,
    UnknownDestinationError,
)
from panther_analysis_tool.util import id_to_path, import_file_as_module, store_modules

# Temporary alias for compatibility
get_logger = logging.getLogger

TYPE_RULE = "RULE"
TYPE_SCHEDULED_RULE = "SCHEDULED_RULE"

ERROR_TYPE_RULE = "RULE_ERROR"
ERROR_TYPE_SCHEDULED_RULE = "SCHEDULED_RULE_ERROR"

_RULE_FOLDER = os.path.join(tempfile.gettempdir(), "rules")

# Maximum size for a dedup string
MAX_DEDUP_STRING_SIZE = 1000

# Maximum size for a generated field
MAX_GENERATED_FIELD_SIZE = 1000

# Maximum number of destinations
MAX_DESTINATIONS_SIZE = 10

# The limit for DDB is 400kb per item (we store this one in DDB) and
# the limit for SQS/SNS is 256KB. The limit of 200kb is an approximation - the other
# fields included in the request will be less than the remaining 56kb
MAX_ALERT_CONTEXT_SIZE = 200 * 1024  # 200kb

ALERT_CONTEXT_ERROR_KEY = "_error"

TRUNCATED_STRING_SUFFIX = "... (truncated)"

DEFAULT_RULE_DEDUP_PERIOD_MINS = 60

# Used to check dynamic severity output
SEVERITY_TYPES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

ALERT_CONTEXT_FUNCTION = "alert_context"
DEDUP_FUNCTION = "dedup"
DESCRIPTION_FUNCTION = "description"
DESTINATIONS_FUNCTION = "destinations"
REFERENCE_FUNCTION = "reference"
RUNBOOK_FUNCTION = "runbook"
SEVERITY_FUNCTION = "severity"
TITLE_FUNCTION = "title"

# Auxiliary functions are optional
AUXILIARY_FUNCTIONS = (
    ALERT_CONTEXT_FUNCTION,
    DEDUP_FUNCTION,
    DESCRIPTION_FUNCTION,
    DESTINATIONS_FUNCTION,
    REFERENCE_FUNCTION,
    RUNBOOK_FUNCTION,
    SEVERITY_FUNCTION,
    TITLE_FUNCTION,
)


# pylint: disable=too-many-instance-attributes,unsubscriptable-object
@dataclass
class RuleResult:
    """Class containing the result of running a rule"""

    rule_id: str
    rule_severity: str
    setup_exception: Optional[Exception] = None

    matched: Optional[bool] = None  # rule output
    rule_exception: Optional[Exception] = None

    dedup_output: Optional[str] = None
    dedup_exception: Optional[Exception] = None
    dedup_defined: bool = False

    title_output: Optional[str] = None
    title_exception: Optional[Exception] = None
    title_defined: bool = False

    description_output: Optional[str] = None
    description_exception: Optional[Exception] = None
    description_defined: bool = False

    reference_output: Optional[str] = None
    reference_exception: Optional[Exception] = None
    reference_defined: bool = False

    severity_output: Optional[str] = None
    severity_exception: Optional[Exception] = None
    severity_defined: bool = False

    runbook_output: Optional[str] = None
    runbook_exception: Optional[Exception] = None
    runbook_defined: bool = False

    destinations_output: Optional[List[str]] = None
    destinations_exception: Optional[Exception] = None
    destinations_defined: bool = False

    alert_context_output: Optional[str] = None
    alert_context_exception: Optional[Exception] = None
    alert_context_defined: bool = False

    input_exception: Optional[Exception] = None

    @property
    def fatal_error(self) -> Optional[Exception]:
        """Provide any error that would stop evaluation
        or None, if no blocking error is found"""
        exception = None
        if self.setup_exception:
            exception = self.setup_exception
        elif self.rule_exception:
            exception = self.rule_exception
        elif self.input_exception:
            exception = self.input_exception
        return exception

    @property
    def error_type(self) -> Optional[str]:
        """Returns the type of the exception, None if there was no error"""
        fatal_error = self.fatal_error
        if fatal_error is None:
            return None
        return type(fatal_error).__name__

    @property
    def short_error_message(self) -> Optional[str]:
        """Returns short error message, None if there was no error"""
        fatal_error = self.fatal_error
        if fatal_error is None:
            return None
        return repr(fatal_error)

    @property
    def error_message(self) -> Optional[str]:
        """Returns formatted error message with traceback"""
        exception = self.fatal_error
        if exception is None:
            return None

        trace = traceback.format_tb(exception.__traceback__)
        # we only take last element of trace which will show the
        # rule file name and line of the error, for example:
        #    division by zero: AlwaysFail.py, line 4, in rule 1/0
        file_trace = trace[len(trace) - 1].strip().replace("\n", "")
        # this looks like: File "/tmp/rules/AlwaysFail.py", line 4, in rule 1/0 BUT
        # we want just the file name
        return str(exception) + ": " + re.sub(r'File.*/(.*[.]py)"', r"\1", file_trace)

    @property
    def errored(self) -> bool:
        """Returns whether any of the rule functions raised an error"""
        return bool(
            self.rule_exception
            or self.title_exception
            or self.dedup_exception
            or self.alert_context_exception
            or self.description_exception
            or self.reference_exception
            or self.severity_exception
            or self.runbook_exception
            or self.destinations_exception
            or self.setup_exception
            or self.input_exception
        )

    @property
    def rule_evaluation_failed(self) -> bool:
        """Returns whether the rule function raises an error or an import error occurred"""
        return bool(self.rule_exception or self.setup_exception)


class BaseImporter:
    """Base class for Python module importers"""

    @staticmethod
    def from_file(identifier: str, path: str) -> ModuleType:
        """Import a file as a Python module"""
        return import_file_as_module(path, identifier)

    def from_string(self, identifier: str, body: str, tmp_dir: str) -> ModuleType:
        """Write source code to a temporary file and import as Python module"""
        path = id_to_path(tmp_dir, identifier)
        store_modules(path, body)
        return self.from_file(identifier, path)

    @abstractmethod
    def get_module(self, identifier: str, resource: str) -> ModuleType:
        pass


class FilesystemImporter(BaseImporter):
    """Import a Python module from the filesystem"""

    def get_module(  # pylint: disable=arguments-differ
        self, identifier: str, path: str
    ) -> ModuleType:
        module_path = Path(path)
        if not module_path.exists():
            raise FileNotFoundError(path)
        return super().from_file(identifier, module_path.absolute().as_posix())


class RawStringImporter(BaseImporter):
    """Import a Python module from raw source code"""

    def __init__(self, tmp_dir: str):
        super().__init__()
        self._tmp_dir = tmp_dir

    def get_module(  # pylint: disable=arguments-differ
        self, identifier: str, body: str
    ) -> ModuleType:
        return super().from_string(identifier, body, self._tmp_dir)


# pylint: disable=too-many-instance-attributes
class Rule:
    """Panther rule metadata and imported module."""

    # pylint: disable=too-many-branches,too-many-statements
    def __init__(self, config: Mapping):
        """Create new rule from a dict.

        Args:
            config: Dictionary that we expect to have the following keys:
                analysisType: either RULE or SCHEDULED_RULE
                id: Unique rule identifier
                body: The rule body
                versionId: The version of the rule
                (Optional) path: The rule module path
                (Optional) dedupPeriodMinutes: The period during which
                the events will be deduplicated
        """
        self.logger = get_logger()

        # Check for required string fields
        for each_field in ["id", "versionId"]:
            if not (each_field in config) or not isinstance(config[each_field], str):
                raise AssertionError('Field "%s" of type str is required field' % each_field)

        if not (config.get("body") or config.get("path")):
            raise ValueError('one of "body", "path" must be defined')

        if config.get("body") and config.get("path"):
            raise ValueError('only one of "body", "path" must be defined')

        if not any((isinstance(config.get("body"), str), isinstance(config.get("path"), str))):
            raise TypeError('"body", "path" parameters must be of string type')

        if (
            not "analysisType" in config
        ):  # backwards compatible check for data from before we returned this
            self.rule_type = TYPE_RULE
        else:
            self.rule_type = config["analysisType"]

        self.rule_id = config["id"]
        self.rule_version = config["versionId"]

        # TODO: severity and other rule metadata is not passed through when we run rule tests.
        #       https://app.asana.com/0/1200360676535738/1200403272293475
        if "severity" in config:
            self.rule_severity = config["severity"]
        else:
            self.rule_severity = None

        if not ("dedupPeriodMinutes" in config) or not isinstance(
            config["dedupPeriodMinutes"], int
        ):
            self.rule_dedup_period_mins = DEFAULT_RULE_DEDUP_PERIOD_MINS
        else:
            self.rule_dedup_period_mins = config["dedupPeriodMinutes"]

        if not ("tags" in config) or not isinstance(config["tags"], list):
            self.rule_tags: List[str] = list()
        else:
            config["tags"].sort()
            self.rule_tags = config["tags"]

        if "reports" not in config:
            self.rule_reports: Dict[str, List[str]] = dict()
        else:
            # Reports are Dict[str, List[str]]
            # Sorting the List before setting it
            for values in config["reports"].values():
                values.sort()
            self.rule_reports = config["reports"]

        self._setup_exception = None
        try:
            self._module = self._load_rule(self.rule_id, config)
            if not hasattr(self._module, "rule"):
                raise AssertionError("rule needs to have a method named 'rule'")
        except Exception as err:  # pylint: disable=broad-except
            self._setup_exception = err
            return

        self._default_dedup_string = "defaultDedupString:{}".format(self.rule_id)
        self._auxiliary_function_definitions = self._check_defined_functions()

    @staticmethod
    def _load_rule(identifier: str, config: Mapping) -> ModuleType:
        """Load the rule code as Python module.
        Code can be provided as raw string or a path in the local filesystem.
        """
        has_raw_code = bool(config.get("body"))

        importer: Optional[BaseImporter] = None
        if has_raw_code:
            resource = config["body"]
            importer = RawStringImporter(tmp_dir=_RULE_FOLDER)
        else:
            resource = config["path"]
            importer = FilesystemImporter()

        return importer.get_module(identifier, resource)

    def _check_defined_functions(self) -> Dict[str, bool]:
        function_definitions = {}
        for name in AUXILIARY_FUNCTIONS:
            function_definitions[name] = self._is_function_defined(name)
        return function_definitions

    @property
    def module(self) -> Any:
        """Used to expose the loaded python module to the engine,
        solely added in to support unit test mocking"""
        return self._module

    @property
    def setup_exception(self) -> Any:
        """Used to expose the setup exception to the engine"""
        return self._setup_exception

    @setup_exception.setter
    def setup_exception(self, val: Any) -> Any:
        """Used by the engine to set _setup_exception"""
        self._setup_exception = val

    def run(
        self, event: PantherEvent, outputs: dict, outputs_names: dict, batch_mode: bool = True
    ) -> RuleResult:
        """
        Analyze a log line with this rule and return True, False, or an error.
        :param event: The event to run the rule against
        :param outputs: Destinations loaded from the panther-outputs-api
        :param outputs_names: Destinations mapped by their display name
        :param batch_mode: Whether the rule runs as part of the log analysis
        or as part of a simple rule test. In batch mode, title/dedup functions
        are not checked if the rule won't trigger an alert and also title()/dedup()
        won't raise exceptions, so that an alert won't be missed.
        """
        rule_result = RuleResult(rule_id=self.rule_id, rule_severity=self.rule_severity)
        # If there was an error setting up the rule
        # return early
        if self._setup_exception:
            rule_result.setup_exception = self._setup_exception
            return rule_result

        try:
            rule_result.matched = self._run_rule(event)
        except Exception as err:  # pylint: disable=broad-except
            rule_result.rule_exception = err

        if batch_mode and not rule_result.matched:
            # In batch mode (log analysis), there is no need to run the title/dedup functions
            # if the rule isn't going to trigger an alert
            return rule_result

        try:
            rule_result.title_defined = self._auxiliary_function_definitions[TITLE_FUNCTION]
            if rule_result.title_defined:
                rule_result.title_output = self._get_title(
                    event,
                    use_default_on_exception=batch_mode,
                )
        except Exception as err:  # pylint: disable=broad-except
            rule_result.title_exception = err

        try:
            rule_result.description_defined = self._auxiliary_function_definitions[
                DESCRIPTION_FUNCTION
            ]
            if rule_result.description_defined:
                rule_result.description_output = self._get_description(
                    event,
                    use_default_on_exception=batch_mode,
                )
        except Exception as err:  # pylint: disable=broad-except
            rule_result.description_exception = err

        try:
            rule_result.reference_defined = self._auxiliary_function_definitions[REFERENCE_FUNCTION]
            if rule_result.reference_defined:
                rule_result.reference_output = self._get_reference(
                    event,
                    use_default_on_exception=batch_mode,
                )
        except Exception as err:  # pylint: disable=broad-except
            rule_result.reference_exception = err

        try:
            rule_result.severity_defined = self._auxiliary_function_definitions[SEVERITY_FUNCTION]
            if rule_result.severity_defined:
                rule_result.severity_output = self._get_severity(
                    event,
                    use_default_on_exception=batch_mode,
                )
        except Exception as err:  # pylint: disable=broad-except
            rule_result.severity_exception = err

        try:
            rule_result.runbook_defined = self._auxiliary_function_definitions[RUNBOOK_FUNCTION]
            if rule_result.runbook_defined:
                rule_result.runbook_output = self._get_runbook(
                    event,
                    use_default_on_exception=batch_mode,
                )
        except Exception as err:  # pylint: disable=broad-except
            rule_result.runbook_exception = err

        try:
            rule_result.destinations_defined = self._auxiliary_function_definitions[
                DESTINATIONS_FUNCTION
            ]
            if rule_result.destinations_defined:
                rule_result.destinations_output = self._get_destinations(
                    event,
                    outputs,
                    outputs_names,
                    use_default_on_exception=batch_mode,
                )
        except Exception as err:  # pylint: disable=broad-except
            rule_result.destinations_exception = err

        try:
            rule_result.dedup_defined = self._auxiliary_function_definitions[DEDUP_FUNCTION]
            if not rule_result.dedup_defined:
                rule_result.dedup_output = self._get_dedup_fallback(rule_result.title_output)
            else:
                rule_result.dedup_output = self._get_dedup(
                    event,
                    use_default_on_exception=batch_mode,
                )
        except Exception as err:  # pylint: disable=broad-except
            rule_result.dedup_exception = err

        try:
            rule_result.alert_context_defined = self._auxiliary_function_definitions[
                ALERT_CONTEXT_FUNCTION
            ]
            if rule_result.alert_context_defined:
                rule_result.alert_context_output = self._get_alert_context(
                    event,
                    use_default_on_exception=batch_mode,
                )
        except Exception as err:  # pylint: disable=broad-except
            rule_result.alert_context_exception = err

        return rule_result

    def _run_rule(self, event: PantherEvent) -> bool:
        # for scheduled rules the rule function is optional,
        # defaults to True and will pass the events thru
        if self.rule_type == TYPE_SCHEDULED_RULE and not hasattr(self._module, "rule"):
            return True
        return self._run_command(self._module.rule, event, bool)  # type: ignore[attr-defined]

    def _get_alert_context(
        self, event: PantherEvent, use_default_on_exception: bool = True
    ) -> Optional[str]:

        try:
            command = getattr(self._module, ALERT_CONTEXT_FUNCTION)
            alert_context = self._run_command(command, event, Mapping)
            serialized_alert_context = json.dumps(alert_context, default=PantherEvent.json_encoder)
        except Exception as err:  # pylint: disable=broad-except
            if use_default_on_exception:
                return json.dumps({ALERT_CONTEXT_ERROR_KEY: repr(err)})
            raise

        if len(serialized_alert_context) > MAX_ALERT_CONTEXT_SIZE:
            # If context exceeds max size, return empty one
            alert_context_error = (
                "alert_context size is [{}] characters,"
                " bigger than maximum of [{}] characters".format(
                    len(serialized_alert_context), MAX_ALERT_CONTEXT_SIZE
                )
            )
            return json.dumps({ALERT_CONTEXT_ERROR_KEY: alert_context_error})

        return serialized_alert_context

    # Returns the dedup string for this rule match
    # If the rule match had a custom title, use the title as a deduplication string
    # If no title and no dedup function is defined, return the default dedup string.
    def _get_dedup(
        self,
        event: PantherEvent,
        use_default_on_exception: bool = True,
    ) -> str:

        try:
            command = getattr(self._module, DEDUP_FUNCTION)
            dedup_string = self._run_command(command, event, str)
        except Exception as err:  # pylint: disable=broad-except
            if use_default_on_exception:
                self.logger.info(
                    "dedup method raised exception. "
                    'Defaulting dedup string to "%s". Exception: %s',
                    self.rule_id,
                    err,
                )
                return self._default_dedup_string
            raise

        if not dedup_string:
            # If dedup string is None or empty, return the default dedup string
            return self._default_dedup_string

        if len(dedup_string) > MAX_DEDUP_STRING_SIZE:
            # If dedup_string exceeds max size, truncate it
            self.logger.info(
                "maximum dedup string size is [%d] characters. "
                "Dedup string for rule with ID [%s] is [%d] characters. Truncating.",
                MAX_DEDUP_STRING_SIZE,
                self.rule_id,
                len(dedup_string),
            )
            num_characters_to_keep = MAX_DEDUP_STRING_SIZE - len(TRUNCATED_STRING_SUFFIX)
            return dedup_string[:num_characters_to_keep] + TRUNCATED_STRING_SUFFIX

        return dedup_string

    def _get_dedup_fallback(self, title: Optional[str]) -> str:
        if title:
            # If no dedup function is defined but the rule
            # had a title, use the title as dedup string
            return title
            # If no dedup function defined, return default dedup string
        return self._default_dedup_string

    def _get_description(
        self, event: PantherEvent, use_default_on_exception: bool = True
    ) -> Optional[str]:

        try:
            command = getattr(self._module, DESCRIPTION_FUNCTION)
            description = self._run_command(command, event, str)
        except Exception as err:  # pylint: disable=broad-except
            if use_default_on_exception:
                self.logger.info(
                    "description method for rule with id [%s] raised exception. "
                    "Using default Exception: %s",
                    self.rule_id,
                    err,
                )
                return ""
            raise

        if len(description) > MAX_GENERATED_FIELD_SIZE:
            # If generated field exceeds max size, truncate it
            self.logger.info(
                "maximum field [description] length is [%d]. "
                "[%d] for rule with ID [%s] . Truncating.",
                MAX_GENERATED_FIELD_SIZE,
                len(description),
                self.rule_id,
            )
            num_characters_to_keep = MAX_GENERATED_FIELD_SIZE - len(TRUNCATED_STRING_SUFFIX)
            return description[:num_characters_to_keep] + TRUNCATED_STRING_SUFFIX
        return description

    def _get_destinations(  # pylint: disable=too-many-return-statements,too-many-arguments
        self,
        event: PantherEvent,
        outputs: dict,
        outputs_display_names: dict,
        use_default_on_exception: bool = True,
    ) -> Optional[List[str]]:
        try:
            command = getattr(self._module, DESTINATIONS_FUNCTION)
            destinations = self._run_command(command, event, list())
        except Exception as err:  # pylint: disable=broad-except
            if use_default_on_exception:
                self.logger.info("destinations method raised exception. Exception: %s", err)
                return None
            raise
        # Return early if destinations returned None
        if destinations is None:
            return None

        # Return early if destinations is an empty list (alert dest. suppression)
        if len(destinations) == 0:
            return ["SKIP"]

        # Check for (in)valid destinations
        invalid_destinations = []
        standardized_destinations: List[str] = []

        # Standardize the destinations
        for each_destination in destinations:
            # case for valid display name
            if (
                each_destination in outputs_display_names
                and outputs_display_names[each_destination].destination_id
                not in standardized_destinations
            ):
                standardized_destinations.append(
                    outputs_display_names[each_destination].destination_id
                )
            # case for valid UUIDv4
            elif each_destination in outputs and each_destination not in standardized_destinations:
                standardized_destinations.append(each_destination)
            else:
                invalid_destinations.append(each_destination)

        if invalid_destinations:
            if use_default_on_exception:
                self.logger.info(
                    "destinations method yielded invalid destinations: %s",
                    str(invalid_destinations),
                )
                return None
            raise UnknownDestinationError(
                "Invalid Destinations",
                invalid_destinations,
            )

        if len(standardized_destinations) > MAX_DESTINATIONS_SIZE:
            # If generated field exceeds max size, truncate it
            self.logger.info(
                "maximum len of destinations [%d] for rule with ID "
                "[%s] is [%d] fields. Truncating.",
                MAX_DESTINATIONS_SIZE,
                self.rule_id,
                len(standardized_destinations),
            )
            return standardized_destinations[:MAX_DESTINATIONS_SIZE]
        return standardized_destinations

    def _get_reference(
        self, event: PantherEvent, use_default_on_exception: bool = True
    ) -> Optional[str]:

        try:
            command = getattr(self._module, REFERENCE_FUNCTION)
            reference = self._run_command(command, event, str)
        except Exception as err:  # pylint: disable=broad-except
            if use_default_on_exception:
                self.logger.info(
                    "reference method for rule with id [%s] raised exception. "
                    "Using default. Exception: %s",
                    self.rule_id,
                    err,
                )
                return ""
            raise

        if len(reference) > MAX_GENERATED_FIELD_SIZE:
            # If generated field exceeds max size, truncate it
            self.logger.info(
                "maximum field [reference] length is [%d]. "
                "[%d] for rule with ID [%s] . Truncating.",
                MAX_GENERATED_FIELD_SIZE,
                len(reference),
                self.rule_id,
            )
            num_characters_to_keep = MAX_GENERATED_FIELD_SIZE - len(TRUNCATED_STRING_SUFFIX)
            return reference[:num_characters_to_keep] + TRUNCATED_STRING_SUFFIX
        return reference

    def _get_runbook(
        self, event: PantherEvent, use_default_on_exception: bool = True
    ) -> Optional[str]:

        try:
            command = getattr(self._module, RUNBOOK_FUNCTION)
            runbook = self._run_command(command, event, str)
        except Exception as err:  # pylint: disable=broad-except
            if use_default_on_exception:
                self.logger.info(
                    "runbook method for rule with id [%s] raised exception. "
                    "Using default. Exception: %s",
                    self.rule_id,
                    err,
                )
                return ""
            raise

        if len(runbook) > MAX_GENERATED_FIELD_SIZE:
            # If generated field exceeds max size, truncate it
            self.logger.info(
                "maximum field [runbook] length is [%d]. [%d] for rule with ID [%s] . Truncating.",
                MAX_GENERATED_FIELD_SIZE,
                len(runbook),
                self.rule_id,
            )
            num_characters_to_keep = MAX_GENERATED_FIELD_SIZE - len(TRUNCATED_STRING_SUFFIX)
            return runbook[:num_characters_to_keep] + TRUNCATED_STRING_SUFFIX
        return runbook

    def _get_severity(
        self, event: PantherEvent, use_default_on_exception: bool = True
    ) -> Optional[str]:

        try:
            command = getattr(self._module, SEVERITY_FUNCTION)
            severity = self._run_command(command, event, str).upper()
            if severity not in SEVERITY_TYPES:
                self.logger.info(
                    "severity method for rule with id [%s] yielded [%s], expected [%s]",
                    self.rule_id,
                    severity,
                    str(SEVERITY_TYPES),
                )
                raise AssertionError(
                    "Expected severity to be any of the following: [%s], got [%s] instead."
                    % (str(SEVERITY_TYPES), severity)
                )
        except Exception as err:  # pylint: disable=broad-except
            if use_default_on_exception:
                self.logger.info(
                    "severity method for rule with id [%s] raised exception. "
                    "Using default (%s). Exception: %s",
                    self.rule_id,
                    self.rule_severity,
                    err,
                )
                return self.rule_severity
            raise
        return severity

    def _get_title(self, event: PantherEvent, use_default_on_exception: bool) -> Optional[str]:

        try:
            command = getattr(self._module, TITLE_FUNCTION)
            title = self._run_command(command, event, str)
        except Exception as err:  # pylint: disable=broad-except
            if use_default_on_exception:
                self.logger.info(
                    "title method for rule with id [%s] raised exception. "
                    "Using default. Exception: %s",
                    self.rule_id,
                    err,
                )
                return self.rule_id
            raise

        if len(title) > MAX_GENERATED_FIELD_SIZE:
            # If generated field exceeds max size, truncate it
            self.logger.info(
                "maximum field [title] length is [%d]. " "[%d] for rule with ID [%s] . Truncating.",
                MAX_GENERATED_FIELD_SIZE,
                len(title),
                self.rule_id,
            )
            num_characters_to_keep = MAX_GENERATED_FIELD_SIZE - len(TRUNCATED_STRING_SUFFIX)
            return title[:num_characters_to_keep] + TRUNCATED_STRING_SUFFIX
        return title

    def _run_command(self, function: Callable, event: PantherEvent, expected_type: Any) -> Any:
        result = function(event)
        # Branch in case of list
        if not isinstance(expected_type, list):
            if not isinstance(result, expected_type):
                raise FunctionReturnTypeError(
                    "rule [{}] function [{}] returned [{}], expected [{}]".format(
                        self.rule_id,
                        function.__name__,
                        type(result).__name__,
                        expected_type.__name__,
                    )
                )
        else:
            if result is None:
                return result
            if not isinstance(result, list) or not all(isinstance(x, (str, bool)) for x in result):
                raise FunctionReturnTypeError(
                    "rule [{}] function [{}] returned [{}], expected a list".format(
                        self.rule_id, function.__name__, type(result).__name__
                    )
                )
        return result

    def _is_function_defined(self, name: str) -> bool:
        return hasattr(self._module, name)
