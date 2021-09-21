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

from panther_analysis_tool.detection import DetectionResult
from panther_analysis_tool.rule import Rule, TYPE_RULE

from panther_analysis_tool.testing import FunctionTestResult, TestError, TestSpecification, \
    TestExpectations, TestCaseEvaluator, TestResult, TestResultsPerFunction

TEST_RULE = {
    'body': 'def rule(_):\n\treturn True',
    'id': 'test-id',
    'severity': 'INFO',
    'type': TYPE_RULE,
    'versionId': 'my-version',
}

class TestFunctionTestResult(unittest.TestCase):

    def test_new(self) -> None:
        # If output is boolean
        result = FunctionTestResult.new(output=True)
        self.assertEqual(result, FunctionTestResult(output='true', error=None, matches_expectations=True))

        # If output is string
        result = FunctionTestResult.new(output='some output')
        self.assertEqual(result, FunctionTestResult(output='some output', error=None, matches_expectations=True))

        # If both parameters are None
        result = FunctionTestResult.new(output=None, raw_exception=None)
        self.assertIsNone(result)

        # When an exception is given
        exception = TypeError('wrong type')
        result = FunctionTestResult.new(output='some output', raw_exception=exception, matches_expectations=True)
        expected = FunctionTestResult(output='some output', error=TestError(message='TypeError: wrong type'), matches_expectations=True)
        self.assertEqual(result, expected)

    def test_format_exception(self) -> None:
        self.assertIsNone(FunctionTestResult.format_exception(exc=None))

        # If title is None
        exception = TypeError('wrong type')
        self.assertEqual(FunctionTestResult.format_exception(exc=exception), 'TypeError: wrong type')
        self.assertEqual(FunctionTestResult.format_exception(exc=exception, title='invalid type'), 'invalid type: TypeError: wrong type')

    def test_to_test_error(self) -> None:
        self.assertIsNone(FunctionTestResult.to_test_error(exc=None))
        exception = TypeError('wrong type')
        self.assertEqual(FunctionTestResult.to_test_error(exc=exception), TestError(message='TypeError: wrong type'))
        self.assertEqual(
            FunctionTestResult.to_test_error(exc=exception, **dict(title='invalid type')),
            TestError(message='invalid type: TypeError: wrong type')
        )

    def test_truncate(self) -> None:
        self.assertIsNone(FunctionTestResult.truncate(None, 1))
        self.assertEqual(FunctionTestResult.truncate('123456789', 3), '123...')


class TestTestCaseEvaluator(unittest.TestCase):


    def test_interpret_passing_test_not_expected_to_match(self) -> None:
        detection = Rule(TEST_RULE)
        spec = TestSpecification(id='test-id', name='test-name', data={}, mocks=[], expectations=TestExpectations(detection=False))
        detection_result = DetectionResult(detection_id=spec.id, matched=False, detection_output=False, detection_severity='INFO', detection_type=TYPE_RULE)
        expected = TestResult(
            id='test-id',
            name='test-name',
            detectionId='test-id',
            genericError=None,
            error=None,
            errored=False,
            passed=True,
            matched=False,
            functions=TestResultsPerFunction(
                detectionFunction=FunctionTestResult(output='false', error=None, matches_expectations=True),
                titleFunction=None,
                dedupFunction=None,
                alertContextFunction=None,
                descriptionFunction=None,
                referenceFunction=None,
                severityFunction=None,
                runbookFunction=None,
                destinationsFunction=None
            )
        )
        actual = TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        print(actual)
        self.assertEqual(expected, actual)

    def test_interpret_passing_test_expected_to_match(self) -> None:
        detection = Rule(TEST_RULE)
        spec = TestSpecification(id='test-id', name='test-name', data={}, mocks=[], expectations=TestExpectations(detection=True))
        detection_result = DetectionResult(detection_id=spec.id, matched=True, detection_output=True, detection_severity='INFO', detection_type=TYPE_RULE)
        expected = TestResult(
            id='test-id',
            name='test-name',
            detectionId='test-id',
            genericError=None,
            error=None,
            errored=False,
            passed=True,
            matched=True,
            functions=TestResultsPerFunction(
                detectionFunction=FunctionTestResult(output='true', error=None, matches_expectations=True),
                titleFunction=None,
                dedupFunction=None,
                alertContextFunction=None,
                descriptionFunction=None,
                referenceFunction=None,
                severityFunction=None,
                runbookFunction=None,
                destinationsFunction=None
            )
        )
        actual = TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        print(actual)
        self.assertEqual(actual, expected)

    def test_interpret_failing_test_expected_to_match(self) -> None:
        detection = Rule(TEST_RULE)
        spec = TestSpecification(id='test-id', name='test-name', data={}, mocks=[], expectations=TestExpectations(detection=True))
        detection_result = DetectionResult(
            detection_id=spec.id,
            matched=None,
            detection_exception=TypeError('wrong type'),
            detection_severity='INFO',
            detection_type=TYPE_RULE
        )
        expected = TestResult(
            id='test-id',
            name='test-name',
            detectionId='test-id',
            genericError=None,
            error=None,
            errored=True,
            passed=False,
            matched=None,
            functions=TestResultsPerFunction(
                detectionFunction=FunctionTestResult(output=None, error=TestError(message='TypeError: wrong type'), matches_expectations=False),
                titleFunction=None,
                dedupFunction=None,
                alertContextFunction=None,
                descriptionFunction=None,
                referenceFunction=None,
                severityFunction=None,
                runbookFunction=None,
                destinationsFunction=None
            )
        )
        actual = TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(expected, actual)

    def test_interpret_failing_test_not_expected_to_match(self) -> None:
        detection = Rule(TEST_RULE)
        spec = TestSpecification(id='test-id', name='test-name', data={}, mocks=[], expectations=TestExpectations(detection=False))
        detection_result = DetectionResult(
            detection_id=spec.id,
            matched=None,
            detection_exception=TypeError('wrong type'),
            detection_severity='INFO',
            detection_type=TYPE_RULE
        )
        expected = TestResult(
            id='test-id',
            name='test-name',
            detectionId='test-id',
            genericError=None,
            error=None,
            errored=True,
            passed=False,
            matched=None,
            functions=TestResultsPerFunction(
                detectionFunction=FunctionTestResult(output=None, error=TestError(message='TypeError: wrong type'), matches_expectations=False),
                titleFunction=None,
                dedupFunction=None,
                alertContextFunction=None,
                descriptionFunction=None,
                referenceFunction=None,
                severityFunction=None,
                runbookFunction=None,
                destinationsFunction=None
            )
        )
        actual = TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(expected, actual)

    def test_interpret_failing_test_input_error(self) -> None:
        detection = Rule(TEST_RULE)
        spec = TestSpecification(id='test-id', name='test-name', data={}, mocks=[], expectations=TestExpectations(detection=False))
        detection_result = DetectionResult(
            detection_id=spec.id,
            matched=None,
            input_exception=TypeError('wrong type'),
            detection_severity='INFO',
            detection_type=TYPE_RULE
        )
        expected = TestResult(
            id='test-id',
            name='test-name',
            detectionId='test-id',
            genericError='Invalid event: TypeError: wrong type',
            error=TestError(message='Invalid event: TypeError: wrong type'),
            errored=True,
            passed=False,
            matched=None,
            functions=TestResultsPerFunction(
                detectionFunction=None,
                titleFunction=None,
                dedupFunction=None,
                alertContextFunction=None,
                descriptionFunction=None,
                referenceFunction=None,
                severityFunction=None,
                runbookFunction=None,
                destinationsFunction=None
            )
        )
        actual = TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(expected, actual)

    def test_interpret_generic_error(self) -> None:
        detection = Rule(TEST_RULE)
        spec = TestSpecification(id='test-id', name='test-name', data={}, mocks=[], expectations=TestExpectations(detection=False))
        detection_result = DetectionResult(
            detection_id=spec.id,
            matched=None,
            setup_exception=TypeError('wrong type'),
            detection_severity='INFO',
            detection_type=TYPE_RULE
        )
        expected = TestResult(
            id='test-id',
            name='test-name',
            detectionId='test-id',
            genericError='TypeError: wrong type',
            error=TestError(message='TypeError: wrong type'),
            errored=True,
            passed=False,
            matched=None,
            functions=TestResultsPerFunction(
                detectionFunction=None,
                titleFunction=None,
                dedupFunction=None,
                alertContextFunction=None,
                descriptionFunction=None,
                referenceFunction=None,
                severityFunction=None,
                runbookFunction=None,
                destinationsFunction=None
            )
        )
        actual = TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(expected, actual)

        # Event compatibility exception
        spec = TestSpecification(id='test-id', name='test-name', data={}, mocks=[], expectations=TestExpectations(detection=False))
        detection_result = DetectionResult(
            detection_id=spec.id,
            matched=None,
            input_exception=TypeError('wrong type'),
            detection_severity='INFO',
            detection_type=TYPE_RULE
        )
        expected = TestResult(
            id='test-id',
            name='test-name',
            detectionId='test-id',
            genericError='Invalid event: TypeError: wrong type',
            error=TestError(message='Invalid event: TypeError: wrong type'),
            errored=True,
            passed=False,
            matched=None,
            functions=TestResultsPerFunction(
                detectionFunction=None,
                titleFunction=None,
                dedupFunction=None,
                alertContextFunction=None,
                descriptionFunction=None,
                referenceFunction=None,
                severityFunction=None,
                runbookFunction=None,
                destinationsFunction=None
            )
        )
        actual = TestCaseEvaluator(spec=spec, detection_result=detection_result).interpret()
        self.assertEqual(expected, actual)
