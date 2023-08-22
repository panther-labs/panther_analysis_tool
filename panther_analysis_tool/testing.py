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
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Type, Union

from panther_core.detection import DetectionResult
from panther_core.policy import TYPE_POLICY, Policy
from panther_core.rule import Rule


@dataclass
class TestError:
    """Represents an error caused by any of the functions or a generic one"""

    message: Optional[str] = None


@dataclass
class FunctionTestResult:
    """Defines the result of running a function"""

    # output contains the JSON-encoded return value, None if an error was raised
    output: Optional[str]
    # error contains a TestError instance with the error message or
    # None if no error was raised
    error: Optional[TestError]
    # return value matched expectations
    matched: Optional[bool]

    @classmethod
    def new(
        cls,
        matched: bool,
        output: Optional[Union[bool, str, List[str]]],
        raw_exception: Optional[Exception] = None,
    ) -> Optional["FunctionTestResult"]:
        """Create a new instance while applying
        the necessary transformations to the parameters"""
        if output is None and raw_exception is None:
            return None

        if output is not None and not isinstance(output, str):
            output = json.dumps(output)

        return cls(output=output, error=cls.to_test_error(raw_exception), matched=matched)

    @staticmethod
    def format_exception(exc: Optional[Exception], title: Optional[str] = None) -> Optional[str]:
        """Convert an exception instance to a structured error message"""
        if exc is None:
            return None
        if title is not None:
            prefix = f"{title}: "
        else:
            prefix = ""

        return f"{prefix}{type(exc).__name__}: {exc}"

    @staticmethod
    def to_test_error(exc: Optional[Exception], title: Optional[str] = None) -> Optional[TestError]:
        """Convert an exception instance to a TestError,
        also properly formatting the exception message"""
        if exc is None:
            return None
        return TestError(message=FunctionTestResult.format_exception(exc, title=title))


@dataclass
class TestResultsPerFunction:  # pylint: disable=R0902
    """Container for the results of each function"""

    detectionFunction: Optional[FunctionTestResult]  # pylint: disable=C0103
    titleFunction: Optional[FunctionTestResult] = None  # pylint: disable=C0103
    dedupFunction: Optional[FunctionTestResult] = None  # pylint: disable=C0103
    alertContextFunction: Optional[FunctionTestResult] = None  # pylint: disable=C0103
    descriptionFunction: Optional[FunctionTestResult] = None  # pylint: disable=C0103
    referenceFunction: Optional[FunctionTestResult] = None  # pylint: disable=C0103
    severityFunction: Optional[FunctionTestResult] = None  # pylint: disable=C0103
    runbookFunction: Optional[FunctionTestResult] = None  # pylint: disable=C0103
    destinationsFunction: Optional[FunctionTestResult] = None  # pylint: disable=C0103


@dataclass
class TestResult:  # pylint: disable=R0902
    """The structure of the results for a test case evaluation"""

    id: Optional[str]  # pylint: disable=C0103
    name: str
    # The following two fields do not conform to Python's naming
    # conventions, but the field names correspond
    # to response attributes by API & FE.
    # TODO: provide a field name translation step if necessary
    detectionId: Optional[str]  # pylint: disable=C0103
    genericError: Optional[str]  # pylint: disable=C0103
    error: Optional[TestError]
    errored: bool
    passed: bool
    trigger_alert: Optional[bool]
    functions: TestResultsPerFunction


@dataclass
class TestExpectations:
    """Contains the expected values for performing assertions"""

    detection: bool
    # TODO: include assertions for remaining functions, e.g title and alert context


@dataclass
class TestSpecification:
    """The structure of a test case"""

    id: str  # pylint: disable=C0103
    name: str
    data: Dict[str, Any]
    mocks: List[Dict[str, Any]]
    expectations: TestExpectations


# pylint: disable=too-few-public-methods
class TestCaseEvaluator:
    """Translates detection execution results to test case results,
    by performing assertions and determining the status"""

    def __init__(self, spec: TestSpecification, detection_result: DetectionResult):
        self._spec = spec
        self._detection_result = detection_result

    def _get_result_status(self) -> bool:
        """Get the test status - passing/failing"""
        # Aux functions are executed unconditionally
        # (regardless if the detection matched or not) during testing.
        # Only if the detection is expected to trigger an alert,
        # we want to include errors from other functions in the status.
        if self._spec.expectations.detection == self._get_detection_alert_value():
            return self._detection_result.trigger_alert and not self._detection_result.errored
        # expectations match the detection output
        return self._spec.expectations.detection == self._detection_result.detection_output

    def _get_generic_error_details(self) -> Tuple[Optional[Exception], Optional[str]]:
        generic_error = None
        generic_error_title = None
        if self._detection_result.input_exception is not None:
            generic_error = self._detection_result.input_exception
            generic_error_title = "Invalid event"
        elif self._detection_result.setup_exception is not None:
            generic_error = self._detection_result.setup_exception
        return generic_error, generic_error_title

    def _get_detection_alert_value(self) -> bool:
        if self._detection_result.detection_type.upper() == TYPE_POLICY.upper():
            return Policy.matcher_alert_value
        return Rule.matcher_alert_value

    def interpret(self, ignore_exception_types: List[Type[Exception]] = None) -> TestResult:
        """Evaluate the detection result taking into account
        the errors raised during evaluation and
        the test specification expectations"""

        # first, we should update the detection result, taking into account any
        # ignored exception types passed into this test
        if ignore_exception_types:
            self._detection_result.ignore_errors(ignore_exception_types)

        function_results = dict(
            detectionFunction=FunctionTestResult.new(
                self._spec.expectations.detection == self._detection_result.detection_output,
                self._detection_result.detection_output,
                self._detection_result.detection_exception,
            )
        )

        # We don't include output from other functions
        # unless the test was expected to match and trigger an alert.
        # If the test fails, providing all the output provides a faster feedback loop,
        # on possible additional failures.
        if self._spec.expectations.detection == self._get_detection_alert_value():
            function_results.update(
                dict(
                    titleFunction=FunctionTestResult.new(
                        self._detection_result.title_exception is None,
                        self._detection_result.title_output,
                        self._detection_result.title_exception,
                    ),
                    descriptionFunction=FunctionTestResult.new(
                        self._detection_result.description_exception is None,
                        self._detection_result.description_output,
                        self._detection_result.description_exception,
                    ),
                    referenceFunction=FunctionTestResult.new(
                        self._detection_result.reference_exception is None,
                        self._detection_result.reference_output,
                        self._detection_result.reference_exception,
                    ),
                    severityFunction=FunctionTestResult.new(
                        self._detection_result.severity_exception is None,
                        self._detection_result.severity_output,
                        self._detection_result.severity_exception,
                    ),
                    runbookFunction=FunctionTestResult.new(
                        self._detection_result.runbook_exception is None,
                        self._detection_result.runbook_output,
                        self._detection_result.runbook_exception,
                    ),
                    destinationsFunction=FunctionTestResult.new(
                        self._detection_result.destinations_exception is None,
                        self._detection_result.destinations_output,
                        self._detection_result.destinations_exception,
                    ),
                    dedupFunction=FunctionTestResult.new(
                        self._detection_result.dedup_exception is None,
                        self._detection_result.dedup_output,
                        self._detection_result.dedup_exception,
                    ),
                    alertContextFunction=FunctionTestResult.new(
                        self._detection_result.alert_context_exception is None,
                        self._detection_result.alert_context_output,
                        self._detection_result.alert_context_exception,
                    ),
                )
            )

        generic_error, generic_error_title = self._get_generic_error_details()

        return TestResult(
            id=self._spec.id,
            name=self._spec.name,
            detectionId=self._detection_result.detection_id,
            genericError=FunctionTestResult.format_exception(
                generic_error, title=generic_error_title
            ),
            errored=self._detection_result.errored,
            error=FunctionTestResult.to_test_error(generic_error, title=generic_error_title),
            # Passing or failing test?
            passed=self._get_result_status(),
            trigger_alert=self._detection_result.trigger_alert,
            functions=TestResultsPerFunction(**function_results),
        )
