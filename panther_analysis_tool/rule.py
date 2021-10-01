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
import tempfile
from abc import ABC, abstractmethod
from collections.abc import Mapping
from types import ModuleType
from typing import Any, Callable, Dict, List, Optional

from panther_analysis_tool.detection import (
    BaseImporter,
    DetectionResult,
    FilesystemImporter,
    RawStringImporter,
)
from panther_analysis_tool.enriched_event import PantherEvent
from panther_analysis_tool.exceptions import (
    FunctionReturnTypeError,
    UnknownDestinationError,
)

# Temporary alias for compatibility
get_logger = logging.getLogger

TYPE_RULE = "RULE"
TYPE_SCHEDULED_RULE = "SCHEDULED_RULE"

ERROR_TYPE_RULE = "RULE_ERROR"
ERROR_TYPE_SCHEDULED_RULE = "SCHEDULED_RULE_ERROR"

_DETECTION_FOLDER = os.path.join(tempfile.gettempdir(), "detections")

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

DEFAULT_DETECTION_DEDUP_PERIOD_MINS = 60

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


# pylint: disable=too-many-instance-attributes
class Detection(ABC):
    """Panther detection metadata and imported module."""

    # pylint: disable=too-many-branches,too-many-statements
    def __init__(self, config: Mapping):
        """Create new detection from a dict.
        Args:
            config: Dictionary that we expect to have the following keys:
                analysisType: either RULE, SCHEDULED_RULE, or POLICY
                id: Unique detection identifier
                body: The detection body
                versionId: The version of the detection
                (Optional) path: The detection module path
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

        # backwards compatible for data from before we returned this
        self.detection_type = config.get("analysisType", self.default_detection_type)

        self.detection_id = config["id"]
        self.detection_version = config["versionId"]

        # TODO: severity and other detection metadata is not passed through when we run tests.
        #       https://app.asana.com/0/1200360676535738/1200403272293475
        if "severity" in config:
            self.detection_severity = config["severity"]
        else:
            self.detection_severity = None

        if not ("dedupPeriodMinutes" in config) or not isinstance(
            config["dedupPeriodMinutes"], int
        ):
            self.detection_dedup_period_mins = DEFAULT_DETECTION_DEDUP_PERIOD_MINS
        else:
            self.detection_dedup_period_mins = config["dedupPeriodMinutes"]

        if not ("tags" in config) or not isinstance(config["tags"], list):
            self.detection_tags: List[str] = list()
        else:
            config["tags"].sort()
            self.detection_tags = config["tags"]

        if "reports" not in config:
            self.detection_reports: Dict[str, List[str]] = dict()
        else:
            # Reports are Dict[str, List[str]]
            # Sorting the List before setting it
            for values in config["reports"].values():
                values.sort()
            self.detection_reports = config["reports"]

        self._setup_exception = None
        try:
            self._module = self._load_detection(self.detection_id, config)
            if not self._is_function_defined(self.matcher_function_name):
                raise AssertionError(
                    f"detection needs to have a method named '{self.matcher_function_name}'"
                )
        except Exception as err:  # pylint: disable=broad-except
            self._setup_exception = err
            return

        self._default_dedup_string = "defaultDedupString:{}".format(self.detection_id)
        self._auxiliary_function_definitions = self._check_defined_functions()

    @staticmethod
    def _load_detection(identifier: str, config: Mapping) -> ModuleType:
        """Load the detection code as Python module.
        Code can be provided as raw string or a path in the local filesystem.
        """
        has_raw_code = bool(config.get("body"))

        importer: Optional[BaseImporter] = None
        if has_raw_code:
            resource = config["body"]
            importer = RawStringImporter(tmp_dir=_DETECTION_FOLDER)
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
    @abstractmethod
    def default_detection_type(self) -> str:
        pass

    @abstractmethod
    def matcher_function(self, event: Mapping) -> bool:
        pass

    @property
    @abstractmethod
    def matcher_function_name(self) -> str:
        pass

    @property
    @abstractmethod
    def matcher_alert_value(self) -> bool:
        pass

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
        self, event: Mapping, outputs: dict, outputs_names: dict, batch_mode: bool = True
    ) -> DetectionResult:
        """
        Analyze a log line with this detection and return True, False, or an error.
        :param event: The event to run the detection against
        :param outputs: Destinations loaded from the panther-outputs-api
        :param outputs_names: Destinations mapped by their display name
        :param batch_mode: Whether the detection runs as part of the log analysis
        or as part of a simple detection test. In batch mode, title/dedup functions
        are not checked if the detection won't trigger an alert and also title()/dedup()
        won't raise exceptions, so that an alert won't be missed.
        """
        detection_result = DetectionResult(
            detection_id=self.detection_id,
            detection_severity=self.detection_severity,
            detection_type=self.detection_type,
            # set default to not alert
            trigger_alert=False,
        )
        # If there was an error setting up the detection
        # return early
        if self._setup_exception:
            detection_result.setup_exception = self._setup_exception
            return detection_result

        try:
            detection_result.detection_output = self.matcher_function(event)
        except Exception as err:  # pylint: disable=broad-except
            detection_result.detection_exception = err

        detection_result.trigger_alert = (
            detection_result.detection_output is self.matcher_alert_value
        )

        if batch_mode and not detection_result.trigger_alert:
            # In batch mode (log analysis), there is no need to run the title/dedup functions
            # if the detection isn't going to trigger an alert
            return detection_result

        try:
            detection_result.title_defined = self._auxiliary_function_definitions[TITLE_FUNCTION]
            if detection_result.title_defined:
                detection_result.title_output = self._get_title(
                    event,
                    use_default_on_exception=batch_mode,
                )
        except Exception as err:  # pylint: disable=broad-except
            detection_result.title_exception = err

        try:
            detection_result.description_defined = self._auxiliary_function_definitions[
                DESCRIPTION_FUNCTION
            ]
            if detection_result.description_defined:
                detection_result.description_output = self._get_description(
                    event,
                    use_default_on_exception=batch_mode,
                )
        except Exception as err:  # pylint: disable=broad-except
            detection_result.description_exception = err

        try:
            detection_result.reference_defined = self._auxiliary_function_definitions[
                REFERENCE_FUNCTION
            ]
            if detection_result.reference_defined:
                detection_result.reference_output = self._get_reference(
                    event,
                    use_default_on_exception=batch_mode,
                )
        except Exception as err:  # pylint: disable=broad-except
            detection_result.reference_exception = err

        try:
            detection_result.severity_defined = self._auxiliary_function_definitions[
                SEVERITY_FUNCTION
            ]
            if detection_result.severity_defined:
                detection_result.severity_output = self._get_severity(
                    event,
                    use_default_on_exception=batch_mode,
                )
        except Exception as err:  # pylint: disable=broad-except
            detection_result.severity_exception = err

        try:
            detection_result.runbook_defined = self._auxiliary_function_definitions[
                RUNBOOK_FUNCTION
            ]
            if detection_result.runbook_defined:
                detection_result.runbook_output = self._get_runbook(
                    event,
                    use_default_on_exception=batch_mode,
                )
        except Exception as err:  # pylint: disable=broad-except
            detection_result.runbook_exception = err

        try:
            detection_result.destinations_defined = self._auxiliary_function_definitions[
                DESTINATIONS_FUNCTION
            ]
            if detection_result.destinations_defined:
                detection_result.destinations_output = self._get_destinations(
                    event,
                    outputs,
                    outputs_names,
                    use_default_on_exception=batch_mode,
                )
        except Exception as err:  # pylint: disable=broad-except
            detection_result.destinations_exception = err

        try:
            detection_result.dedup_defined = self._auxiliary_function_definitions[DEDUP_FUNCTION]
            if not detection_result.dedup_defined:
                detection_result.dedup_output = self._get_dedup_fallback(
                    detection_result.title_output
                )
            else:
                detection_result.dedup_output = self._get_dedup(
                    event,
                    use_default_on_exception=batch_mode,
                )
        except Exception as err:  # pylint: disable=broad-except
            detection_result.dedup_exception = err

        try:
            detection_result.alert_context_defined = self._auxiliary_function_definitions[
                ALERT_CONTEXT_FUNCTION
            ]
            if detection_result.alert_context_defined:
                detection_result.alert_context_output = self._get_alert_context(
                    event,
                    use_default_on_exception=batch_mode,
                )
        except Exception as err:  # pylint: disable=broad-except
            detection_result.alert_context_exception = err

        return detection_result

    def _get_alert_context(
        self, event: Mapping, use_default_on_exception: bool = True
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

    # Returns the dedup string for this detection match
    # If the detection match had a custom title, use the title as a deduplication string
    # If no title and no dedup function is defined, return the default dedup string.
    def _get_dedup(
        self,
        event: Mapping,
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
                    self.detection_id,
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
                "Dedup string for detection with ID [%s] is [%d] characters. Truncating.",
                MAX_DEDUP_STRING_SIZE,
                self.detection_id,
                len(dedup_string),
            )
            num_characters_to_keep = MAX_DEDUP_STRING_SIZE - len(TRUNCATED_STRING_SUFFIX)
            return dedup_string[:num_characters_to_keep] + TRUNCATED_STRING_SUFFIX

        return dedup_string

    def _get_dedup_fallback(self, title: Optional[str]) -> str:
        if title:
            # If no dedup function is defined but the detection
            # had a title, use the title as dedup string
            return title
            # If no dedup function defined, return default dedup string
        return self._default_dedup_string

    def _get_description(
        self, event: Mapping, use_default_on_exception: bool = True
    ) -> Optional[str]:

        try:
            command = getattr(self._module, DESCRIPTION_FUNCTION)
            description = self._run_command(command, event, str)
        except Exception as err:  # pylint: disable=broad-except
            if use_default_on_exception:
                self.logger.info(
                    "description method for detection with id [%s] raised exception. "
                    "Using default Exception: %s",
                    self.detection_id,
                    err,
                )
                return ""
            raise

        if len(description) > MAX_GENERATED_FIELD_SIZE:
            # If generated field exceeds max size, truncate it
            self.logger.info(
                "maximum field [description] length is [%d]. "
                "[%d] for detection with ID [%s] . Truncating.",
                MAX_GENERATED_FIELD_SIZE,
                len(description),
                self.detection_id,
            )
            num_characters_to_keep = MAX_GENERATED_FIELD_SIZE - len(TRUNCATED_STRING_SUFFIX)
            return description[:num_characters_to_keep] + TRUNCATED_STRING_SUFFIX
        return description

    def _get_destinations(  # pylint: disable=too-many-return-statements,too-many-arguments
        self,
        event: Mapping,
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
                "maximum len of destinations [%d] for detection with ID "
                "[%s] is [%d] fields. Truncating.",
                MAX_DESTINATIONS_SIZE,
                self.detection_id,
                len(standardized_destinations),
            )
            return standardized_destinations[:MAX_DESTINATIONS_SIZE]
        return standardized_destinations

    def _get_reference(
        self, event: Mapping, use_default_on_exception: bool = True
    ) -> Optional[str]:

        try:
            command = getattr(self._module, REFERENCE_FUNCTION)
            reference = self._run_command(command, event, str)
        except Exception as err:  # pylint: disable=broad-except
            if use_default_on_exception:
                self.logger.info(
                    "reference method for detection with id [%s] raised exception. "
                    "Using default. Exception: %s",
                    self.detection_id,
                    err,
                )
                return ""
            raise

        if len(reference) > MAX_GENERATED_FIELD_SIZE:
            # If generated field exceeds max size, truncate it
            self.logger.info(
                "maximum field [reference] length is [%d]. "
                "[%d] for detection with ID [%s] . Truncating.",
                MAX_GENERATED_FIELD_SIZE,
                len(reference),
                self.detection_id,
            )
            num_characters_to_keep = MAX_GENERATED_FIELD_SIZE - len(TRUNCATED_STRING_SUFFIX)
            return reference[:num_characters_to_keep] + TRUNCATED_STRING_SUFFIX
        return reference

    def _get_runbook(self, event: Mapping, use_default_on_exception: bool = True) -> Optional[str]:

        try:
            command = getattr(self._module, RUNBOOK_FUNCTION)
            runbook = self._run_command(command, event, str)
        except Exception as err:  # pylint: disable=broad-except
            if use_default_on_exception:
                self.logger.info(
                    "runbook method for detection with id [%s] raised exception. "
                    "Using default. Exception: %s",
                    self.detection_id,
                    err,
                )
                return ""
            raise

        if len(runbook) > MAX_GENERATED_FIELD_SIZE:
            # If generated field exceeds max size, truncate it
            self.logger.info(
                "maximum field [runbook] length is [%d]. [%d] for detection with ID [%s]. "
                "Truncating.",
                MAX_GENERATED_FIELD_SIZE,
                len(runbook),
                self.detection_id,
            )
            num_characters_to_keep = MAX_GENERATED_FIELD_SIZE - len(TRUNCATED_STRING_SUFFIX)
            return runbook[:num_characters_to_keep] + TRUNCATED_STRING_SUFFIX
        return runbook

    def _get_severity(self, event: Mapping, use_default_on_exception: bool = True) -> Optional[str]:

        try:
            command = getattr(self._module, SEVERITY_FUNCTION)
            severity = self._run_command(command, event, str).upper()
            if severity not in SEVERITY_TYPES:
                self.logger.info(
                    "severity method for detection with id [%s] yielded [%s], expected [%s]",
                    self.detection_id,
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
                    "severity method for detection with id [%s] raised exception. "
                    "Using default (%s). Exception: %s",
                    self.detection_id,
                    self.detection_severity,
                    err,
                )
                return self.detection_severity
            raise
        return severity

    def _get_title(self, event: Mapping, use_default_on_exception: bool) -> Optional[str]:

        try:
            command = getattr(self._module, TITLE_FUNCTION)
            title = self._run_command(command, event, str)
        except Exception as err:  # pylint: disable=broad-except
            if use_default_on_exception:
                self.logger.info(
                    "title method for detection with id [%s] raised exception. "
                    "Using default. Exception: %s",
                    self.detection_id,
                    err,
                )
                return self.detection_id
            raise

        if len(title) > MAX_GENERATED_FIELD_SIZE:
            # If generated field exceeds max size, truncate it
            self.logger.info(
                "maximum field [title] length is [%d]. "
                "[%d] for detection with ID [%s] . Truncating.",
                MAX_GENERATED_FIELD_SIZE,
                len(title),
                self.detection_id,
            )
            num_characters_to_keep = MAX_GENERATED_FIELD_SIZE - len(TRUNCATED_STRING_SUFFIX)
            return title[:num_characters_to_keep] + TRUNCATED_STRING_SUFFIX
        return title

    def _run_command(self, function: Callable, event: Mapping, expected_type: Any) -> Any:
        result = function(event)
        # Branch in case of list
        if not isinstance(expected_type, list):
            if not isinstance(result, expected_type):
                raise FunctionReturnTypeError(
                    "detection [{}] function [{}] returned [{}], expected [{}]".format(
                        self.detection_id,
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
                    "detection [{}] function [{}] returned [{}], expected a list".format(
                        self.detection_id, function.__name__, type(result).__name__
                    )
                )
        return result

    def _is_function_defined(self, name: str) -> bool:
        return hasattr(self._module, name)


class Rule(Detection):
    """Panther rule metadata and imported module."""

    # default detection types for rules
    default_detection_type = TYPE_RULE

    # rules have a rule method
    matcher_function_name = "rule"

    # a rule should trigger an alert on True return value
    matcher_alert_value = True

    def matcher_function(self, event: Mapping) -> bool:
        # for scheduled rules the rule function is optional,
        # defaults to True and will pass the events thru
        if self.detection_type == TYPE_SCHEDULED_RULE and not hasattr(
            self._module, self.matcher_function_name
        ):
            return True
        command = getattr(self._module, self.matcher_function_name)
        return self._run_command(command, event, bool)
