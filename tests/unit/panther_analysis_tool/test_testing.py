import unittest

from panther_core.detection import DetectionResult
from panther_core.policy import TYPE_POLICY
from panther_core.rule import TYPE_RULE

from panther_analysis_tool import testing

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
        result = testing.FunctionTestResult.new(matched=True, output=True)
        self.assertEqual(
            result, testing.FunctionTestResult(matched=True, output="true", error=None)
        )

        # If output is string
        result = testing.FunctionTestResult.new(matched=True, output="some output")
        self.assertEqual(
            result, testing.FunctionTestResult(matched=True, output="some output", error=None)
        )

        # If both parameters are None
        result = testing.FunctionTestResult.new(matched=True, output=None, raw_exception=None)
        self.assertIsNone(result)

        # When an exception is given
        exception = TypeError("wrong type")
        result = testing.FunctionTestResult.new(
            matched=False, output="some output", raw_exception=exception
        )
        expected = testing.FunctionTestResult(
            matched=False,
            output="some output",
            error=testing.TestError(message="TypeError: wrong type"),
        )
        self.assertEqual(result, expected)

    def test_format_exception(self) -> None:
        self.assertIsNone(testing.FunctionTestResult.format_exception(exc=None))

        # If title is None
        exception = TypeError("wrong type")
        self.assertEqual(
            testing.FunctionTestResult.format_exception(exc=exception), "TypeError: wrong type"
        )
        self.assertEqual(
            testing.FunctionTestResult.format_exception(exc=exception, title="invalid type"),
            "invalid type: TypeError: wrong type",
        )

    def test_to_test_error(self) -> None:
        self.assertIsNone(testing.FunctionTestResult.to_test_error(exc=None))
        exception = TypeError("wrong type")
        self.assertEqual(
            testing.FunctionTestResult.to_test_error(exc=exception),
            testing.TestError(message="TypeError: wrong type"),
        )
        self.assertEqual(
            testing.FunctionTestResult.to_test_error(exc=exception, **dict(title="invalid type")),
            testing.TestError(message="invalid type: TypeError: wrong type"),
        )


class TestTestCaseEvaluator(unittest.TestCase):
    def test_interpret_passing_test_not_expected_to_trigger_alert(self) -> None:
        spec = testing.TestSpecification(
            id="test-id",
            name="test-name",
            data={},
            mocks=[],
            expectations=testing.TestExpectations(detection=False),
        )
        detection_result = DetectionResult(
            detection_id=spec.id,
            trigger_alert=False,
            detection_output=False,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
        )
        expected = testing.TestResult(
            id="test-id",
            name="test-name",
            detectionId="test-id",
            genericError=None,
            error=None,
            errored=False,
            passed=True,
            trigger_alert=False,
            functions=testing.TestResultsPerFunction(
                detectionFunction=testing.FunctionTestResult(
                    output="false", error=None, matched=True
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
        actual = testing.TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(expected, actual)

    def test_interpret_passing_test_expected_to_trigger_alert(self) -> None:
        spec = testing.TestSpecification(
            id="test-id",
            name="test-name",
            data={},
            mocks=[],
            expectations=testing.TestExpectations(detection=True),
        )
        detection_result = DetectionResult(
            detection_id=spec.id,
            trigger_alert=True,
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
        )
        expected = testing.TestResult(
            id="test-id",
            name="test-name",
            detectionId="test-id",
            genericError=None,
            error=None,
            errored=False,
            passed=True,
            trigger_alert=True,
            functions=testing.TestResultsPerFunction(
                detectionFunction=testing.FunctionTestResult(
                    output="true", error=None, matched=True
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
        actual = testing.TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(actual, expected)

    def test_interpret_failing_test_expected_to_trigger_alert(self) -> None:
        spec = testing.TestSpecification(
            id="test-id",
            name="test-name",
            data={},
            mocks=[],
            expectations=testing.TestExpectations(detection=True),
        )
        detection_result = DetectionResult(
            detection_id=spec.id,
            trigger_alert=False,
            detection_exception=TypeError("wrong type"),
            detection_severity="INFO",
            detection_type=TYPE_RULE,
        )
        expected = testing.TestResult(
            id="test-id",
            name="test-name",
            detectionId="test-id",
            genericError=None,
            error=None,
            errored=True,
            passed=False,
            trigger_alert=False,
            functions=testing.TestResultsPerFunction(
                detectionFunction=testing.FunctionTestResult(
                    output=None,
                    error=testing.TestError(message="TypeError: wrong type"),
                    matched=False,
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
        actual = testing.TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(expected, actual)

    def test_interpret_failing_test_expected_to_match_aux_function_error(self) -> None:
        spec = testing.TestSpecification(
            id="test-id",
            name="test-name",
            data={},
            mocks=[],
            expectations=testing.TestExpectations(detection=True),
        )
        detection_result = DetectionResult(
            detection_id=spec.id,
            trigger_alert=True,
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            title_exception=TypeError("wrong type"),
        )
        expected = testing.TestResult(
            id="test-id",
            name="test-name",
            detectionId="test-id",
            genericError=None,
            error=None,
            errored=True,
            passed=False,
            trigger_alert=True,
            functions=testing.TestResultsPerFunction(
                detectionFunction=testing.FunctionTestResult(
                    output="true", error=None, matched=True
                ),
                titleFunction=testing.FunctionTestResult(
                    output=None,
                    error=testing.TestError(message="TypeError: wrong type"),
                    matched=False,
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
        actual = testing.TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(expected, actual)

    def test_interpret_failing_test_not_expected_to_trigger_alert_detection_error(self) -> None:
        spec = testing.TestSpecification(
            id="test-id",
            name="test-name",
            data={},
            mocks=[],
            expectations=testing.TestExpectations(detection=False),
        )
        detection_result = DetectionResult(
            detection_id=spec.id,
            trigger_alert=False,
            detection_exception=TypeError("wrong type"),
            detection_severity="INFO",
            detection_type=TYPE_RULE,
        )
        expected = testing.TestResult(
            id="test-id",
            name="test-name",
            detectionId="test-id",
            genericError=None,
            error=None,
            errored=True,
            passed=False,
            trigger_alert=False,
            functions=testing.TestResultsPerFunction(
                detectionFunction=testing.FunctionTestResult(
                    output=None,
                    error=testing.TestError(message="TypeError: wrong type"),
                    matched=False,
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
        actual = testing.TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(expected, actual)

    def test_interpret_failing_test_not_expected_to_trigger_alert_with_aux_exception(self) -> None:
        spec = testing.TestSpecification(
            id="test-id",
            name="test-name",
            data={},
            mocks=[],
            expectations=testing.TestExpectations(detection=False),
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
        expected = testing.TestResult(
            id="test-id",
            name="test-name",
            detectionId="test-id",
            genericError=None,
            error=None,
            errored=True,
            passed=True,
            trigger_alert=False,
            functions=testing.TestResultsPerFunction(
                detectionFunction=testing.FunctionTestResult(
                    output="false", error=None, matched=True
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
        actual = testing.TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(expected, actual)

    def test_interpret_failing_test_policy_not_expected_to_trigger_alert_with_aux_exception(
        self,
    ) -> None:
        spec = testing.TestSpecification(
            id="test-id",
            name="test-name",
            data={},
            mocks=[],
            expectations=testing.TestExpectations(detection=True),
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
        expected = testing.TestResult(
            id="test-id",
            name="test-name",
            detectionId="test-id",
            genericError=None,
            error=None,
            errored=True,
            passed=True,
            trigger_alert=False,
            functions=testing.TestResultsPerFunction(
                detectionFunction=testing.FunctionTestResult(
                    output="true", error=None, matched=True
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
        actual = testing.TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(expected, actual)

    def test_interpret_failing_test_input_error(self) -> None:
        spec = testing.TestSpecification(
            id="test-id",
            name="test-name",
            data={},
            mocks=[],
            expectations=testing.TestExpectations(detection=False),
        )
        detection_result = DetectionResult(
            detection_id=spec.id,
            trigger_alert=False,
            input_exception=TypeError("wrong type"),
            detection_severity="INFO",
            detection_type=TYPE_RULE,
        )
        expected = testing.TestResult(
            id="test-id",
            name="test-name",
            detectionId="test-id",
            genericError="Invalid event: TypeError: wrong type",
            error=testing.TestError(message="Invalid event: TypeError: wrong type"),
            errored=True,
            passed=False,
            trigger_alert=False,
            functions=testing.TestResultsPerFunction(
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
        actual = testing.TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(expected, actual)

    def test_interpret_generic_error(self) -> None:
        spec = testing.TestSpecification(
            id="test-id",
            name="test-name",
            data={},
            mocks=[],
            expectations=testing.TestExpectations(detection=False),
        )
        detection_result = DetectionResult(
            detection_id=spec.id,
            trigger_alert=False,
            setup_exception=TypeError("wrong type"),
            detection_severity="INFO",
            detection_type=TYPE_RULE,
        )
        expected = testing.TestResult(
            id="test-id",
            name="test-name",
            detectionId="test-id",
            genericError="TypeError: wrong type",
            error=testing.TestError(message="TypeError: wrong type"),
            errored=True,
            passed=False,
            trigger_alert=False,
            functions=testing.TestResultsPerFunction(
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
        actual = testing.TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(expected, actual)

        # Event compatibility exception
        spec = testing.TestSpecification(
            id="test-id",
            name="test-name",
            data={},
            mocks=[],
            expectations=testing.TestExpectations(detection=False),
        )
        detection_result = DetectionResult(
            detection_id=spec.id,
            trigger_alert=False,
            input_exception=TypeError("wrong type"),
            detection_severity="INFO",
            detection_type=TYPE_RULE,
        )
        expected = testing.TestResult(
            id="test-id",
            name="test-name",
            detectionId="test-id",
            genericError="Invalid event: TypeError: wrong type",
            error=testing.TestError(message="Invalid event: TypeError: wrong type"),
            errored=True,
            passed=False,
            trigger_alert=False,
            functions=testing.TestResultsPerFunction(
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
        actual = testing.TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(expected, actual)
