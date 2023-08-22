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


import unittest

from panther_core.detection import DetectionResult
from panther_core.policy import TYPE_POLICY
from panther_core.rule import TYPE_RULE, Rule

from panther_analysis_tool.testing import (
    FunctionTestResult,
    TestCaseEvaluator,
    TestError,
    TestExpectations,
    TestResult,
    TestResultsPerFunction,
    TestSpecification,
)

TEST_RULE = {
    "body": "def rule(_):\n\treturn True",
    "id": "test-id",
    "severity": "INFO",
    "type": TYPE_RULE,
    "versionId": "my-version",
}


class TestFunctionTestResult(unittest.TestCase):
    def test_new(self) -> None:
        # If output is boolean
        result = FunctionTestResult.new(matched=True, output=True)
        self.assertEqual(result, FunctionTestResult(matched=True, output="true", error=None))

        # If output is string
        result = FunctionTestResult.new(matched=True, output="some output")
        self.assertEqual(result, FunctionTestResult(matched=True, output="some output", error=None))

        # If both parameters are None
        result = FunctionTestResult.new(matched=True, output=None, raw_exception=None)
        self.assertIsNone(result)

        # When an exception is given
        exception = TypeError("wrong type")
        result = FunctionTestResult.new(
            matched=False, output="some output", raw_exception=exception
        )
        expected = FunctionTestResult(
            matched=False, output="some output", error=TestError(message="TypeError: wrong type")
        )
        self.assertEqual(result, expected)

    def test_format_exception(self) -> None:
        self.assertIsNone(FunctionTestResult.format_exception(exc=None))

        # If title is None
        exception = TypeError("wrong type")
        self.assertEqual(
            FunctionTestResult.format_exception(exc=exception), "TypeError: wrong type"
        )
        self.assertEqual(
            FunctionTestResult.format_exception(exc=exception, title="invalid type"),
            "invalid type: TypeError: wrong type",
        )

    def test_to_test_error(self) -> None:
        self.assertIsNone(FunctionTestResult.to_test_error(exc=None))
        exception = TypeError("wrong type")
        self.assertEqual(
            FunctionTestResult.to_test_error(exc=exception),
            TestError(message="TypeError: wrong type"),
        )
        self.assertEqual(
            FunctionTestResult.to_test_error(exc=exception, **dict(title="invalid type")),
            TestError(message="invalid type: TypeError: wrong type"),
        )


class TestTestCaseEvaluator(unittest.TestCase):
    def test_interpret_passing_test_not_expected_to_trigger_alert(self) -> None:
        spec = TestSpecification(
            id="test-id",
            name="test-name",
            data={},
            mocks=[],
            expectations=TestExpectations(detection=False),
        )
        detection_result = DetectionResult(
            detection_id=spec.id,
            trigger_alert=False,
            detection_output=False,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
        )
        expected = TestResult(
            id="test-id",
            name="test-name",
            detectionId="test-id",
            genericError=None,
            error=None,
            errored=False,
            passed=True,
            trigger_alert=False,
            functions=TestResultsPerFunction(
                detectionFunction=FunctionTestResult(output="false", error=None, matched=True),
                titleFunction=None,
                dedupFunction=None,
                alertContextFunction=None,
                descriptionFunction=None,
                referenceFunction=None,
                severityFunction=None,
                runbookFunction=None,
                destinationsFunction=None,
            ),
        )
        actual = TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(expected, actual)

    def test_interpret_passing_test_expected_to_trigger_alert(self) -> None:
        spec = TestSpecification(
            id="test-id",
            name="test-name",
            data={},
            mocks=[],
            expectations=TestExpectations(detection=True),
        )
        detection_result = DetectionResult(
            detection_id=spec.id,
            trigger_alert=True,
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
        )
        expected = TestResult(
            id="test-id",
            name="test-name",
            detectionId="test-id",
            genericError=None,
            error=None,
            errored=False,
            passed=True,
            trigger_alert=True,
            functions=TestResultsPerFunction(
                detectionFunction=FunctionTestResult(output="true", error=None, matched=True),
                titleFunction=None,
                dedupFunction=None,
                alertContextFunction=None,
                descriptionFunction=None,
                referenceFunction=None,
                severityFunction=None,
                runbookFunction=None,
                destinationsFunction=None,
            ),
        )
        actual = TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(actual, expected)

    def test_interpret_failing_test_expected_to_trigger_alert(self) -> None:
        spec = TestSpecification(
            id="test-id",
            name="test-name",
            data={},
            mocks=[],
            expectations=TestExpectations(detection=True),
        )
        detection_result = DetectionResult(
            detection_id=spec.id,
            trigger_alert=False,
            detection_exception=TypeError("wrong type"),
            detection_severity="INFO",
            detection_type=TYPE_RULE,
        )
        expected = TestResult(
            id="test-id",
            name="test-name",
            detectionId="test-id",
            genericError=None,
            error=None,
            errored=True,
            passed=False,
            trigger_alert=False,
            functions=TestResultsPerFunction(
                detectionFunction=FunctionTestResult(
                    output=None, error=TestError(message="TypeError: wrong type"), matched=False
                ),
                titleFunction=None,
                dedupFunction=None,
                alertContextFunction=None,
                descriptionFunction=None,
                referenceFunction=None,
                severityFunction=None,
                runbookFunction=None,
                destinationsFunction=None,
            ),
        )
        actual = TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(expected, actual)

    def test_interpret_failing_test_expected_to_match_aux_function_error(self) -> None:
        spec = TestSpecification(
            id="test-id",
            name="test-name",
            data={},
            mocks=[],
            expectations=TestExpectations(detection=True),
        )
        detection_result = DetectionResult(
            detection_id=spec.id,
            trigger_alert=True,
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            title_exception=TypeError("wrong type"),
        )
        expected = TestResult(
            id="test-id",
            name="test-name",
            detectionId="test-id",
            genericError=None,
            error=None,
            errored=True,
            passed=False,
            trigger_alert=True,
            functions=TestResultsPerFunction(
                detectionFunction=FunctionTestResult(output="true", error=None, matched=True),
                titleFunction=FunctionTestResult(
                    output=None, error=TestError(message="TypeError: wrong type"), matched=False
                ),
                dedupFunction=None,
                alertContextFunction=None,
                descriptionFunction=None,
                referenceFunction=None,
                severityFunction=None,
                runbookFunction=None,
                destinationsFunction=None,
            ),
        )
        actual = TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(expected, actual)

    def test_interpret_failing_test_not_expected_to_trigger_alert_detection_error(self) -> None:
        spec = TestSpecification(
            id="test-id",
            name="test-name",
            data={},
            mocks=[],
            expectations=TestExpectations(detection=False),
        )
        detection_result = DetectionResult(
            detection_id=spec.id,
            trigger_alert=False,
            detection_exception=TypeError("wrong type"),
            detection_severity="INFO",
            detection_type=TYPE_RULE,
        )
        expected = TestResult(
            id="test-id",
            name="test-name",
            detectionId="test-id",
            genericError=None,
            error=None,
            errored=True,
            passed=False,
            trigger_alert=False,
            functions=TestResultsPerFunction(
                detectionFunction=FunctionTestResult(
                    output=None, error=TestError(message="TypeError: wrong type"), matched=False
                ),
                titleFunction=None,
                dedupFunction=None,
                alertContextFunction=None,
                descriptionFunction=None,
                referenceFunction=None,
                severityFunction=None,
                runbookFunction=None,
                destinationsFunction=None,
            ),
        )
        actual = TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(expected, actual)

    def test_interpret_failing_test_not_expected_to_trigger_alert_with_aux_exception(self) -> None:
        spec = TestSpecification(
            id="test-id",
            name="test-name",
            data={},
            mocks=[],
            expectations=TestExpectations(detection=False),
        )
        detection_result = DetectionResult(
            detection_id=spec.id,
            trigger_alert=False,
            detection_output=False,
            detection_exception=None,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            destinations_exception=TypeError("wrong type"),
            reference_exception=TypeError("wrong type"),
            runbook_exception=TypeError("wrong type"),
            severity_exception=TypeError("wrong type"),
            title_exception=TypeError("wrong type"),
        )
        expected = TestResult(
            id="test-id",
            name="test-name",
            detectionId="test-id",
            genericError=None,
            error=None,
            errored=True,
            passed=True,
            trigger_alert=False,
            functions=TestResultsPerFunction(
                detectionFunction=FunctionTestResult(output="false", error=None, matched=True),
                titleFunction=None,
                dedupFunction=None,
                alertContextFunction=None,
                descriptionFunction=None,
                referenceFunction=None,
                severityFunction=None,
                runbookFunction=None,
                destinationsFunction=None,
            ),
        )
        actual = TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(expected, actual)

    def test_interpret_failing_test_policy_not_expected_to_trigger_alert_with_aux_exception(
        self,
    ) -> None:
        spec = TestSpecification(
            id="test-id",
            name="test-name",
            data={},
            mocks=[],
            expectations=TestExpectations(detection=True),
        )
        detection_result = DetectionResult(
            detection_id=spec.id,
            trigger_alert=False,
            detection_output=True,  # policys return true when not triggering an alert
            detection_exception=None,
            detection_severity="INFO",
            detection_type=TYPE_POLICY,
            destinations_exception=TypeError("wrong type"),
            reference_exception=TypeError("wrong type"),
            runbook_exception=TypeError("wrong type"),
            severity_exception=TypeError("wrong type"),
            title_exception=TypeError("wrong type"),
        )
        expected = TestResult(
            id="test-id",
            name="test-name",
            detectionId="test-id",
            genericError=None,
            error=None,
            errored=True,
            passed=True,
            trigger_alert=False,
            functions=TestResultsPerFunction(
                detectionFunction=FunctionTestResult(output="true", error=None, matched=True),
                titleFunction=None,
                dedupFunction=None,
                alertContextFunction=None,
                descriptionFunction=None,
                referenceFunction=None,
                severityFunction=None,
                runbookFunction=None,
                destinationsFunction=None,
            ),
        )
        actual = TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(expected, actual)

    def test_interpret_failing_test_input_error(self) -> None:
        spec = TestSpecification(
            id="test-id",
            name="test-name",
            data={},
            mocks=[],
            expectations=TestExpectations(detection=False),
        )
        detection_result = DetectionResult(
            detection_id=spec.id,
            trigger_alert=False,
            input_exception=TypeError("wrong type"),
            detection_severity="INFO",
            detection_type=TYPE_RULE,
        )
        expected = TestResult(
            id="test-id",
            name="test-name",
            detectionId="test-id",
            genericError="Invalid event: TypeError: wrong type",
            error=TestError(message="Invalid event: TypeError: wrong type"),
            errored=True,
            passed=False,
            trigger_alert=False,
            functions=TestResultsPerFunction(
                detectionFunction=None,
                titleFunction=None,
                dedupFunction=None,
                alertContextFunction=None,
                descriptionFunction=None,
                referenceFunction=None,
                severityFunction=None,
                runbookFunction=None,
                destinationsFunction=None,
            ),
        )
        actual = TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(expected, actual)

    def test_interpret_generic_error(self) -> None:
        spec = TestSpecification(
            id="test-id",
            name="test-name",
            data={},
            mocks=[],
            expectations=TestExpectations(detection=False),
        )
        detection_result = DetectionResult(
            detection_id=spec.id,
            trigger_alert=False,
            setup_exception=TypeError("wrong type"),
            detection_severity="INFO",
            detection_type=TYPE_RULE,
        )
        expected = TestResult(
            id="test-id",
            name="test-name",
            detectionId="test-id",
            genericError="TypeError: wrong type",
            error=TestError(message="TypeError: wrong type"),
            errored=True,
            passed=False,
            trigger_alert=False,
            functions=TestResultsPerFunction(
                detectionFunction=None,
                titleFunction=None,
                dedupFunction=None,
                alertContextFunction=None,
                descriptionFunction=None,
                referenceFunction=None,
                severityFunction=None,
                runbookFunction=None,
                destinationsFunction=None,
            ),
        )
        actual = TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(expected, actual)

        # Event compatibility exception
        spec = TestSpecification(
            id="test-id",
            name="test-name",
            data={},
            mocks=[],
            expectations=TestExpectations(detection=False),
        )
        detection_result = DetectionResult(
            detection_id=spec.id,
            trigger_alert=False,
            input_exception=TypeError("wrong type"),
            detection_severity="INFO",
            detection_type=TYPE_RULE,
        )
        expected = TestResult(
            id="test-id",
            name="test-name",
            detectionId="test-id",
            genericError="Invalid event: TypeError: wrong type",
            error=TestError(message="Invalid event: TypeError: wrong type"),
            errored=True,
            passed=False,
            trigger_alert=False,
            functions=TestResultsPerFunction(
                detectionFunction=None,
                titleFunction=None,
                dedupFunction=None,
                alertContextFunction=None,
                descriptionFunction=None,
                referenceFunction=None,
                severityFunction=None,
                runbookFunction=None,
                destinationsFunction=None,
            ),
        )
        actual = TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(expected, actual)
