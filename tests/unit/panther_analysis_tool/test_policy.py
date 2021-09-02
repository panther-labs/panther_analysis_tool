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

"""Unit tests for src/policy.py"""
import unittest

from panther_analysis_tool.exceptions import FunctionReturnTypeError
from panther_analysis_tool.rule import DetectionResult
from panther_analysis_tool.policy import Policy


class TestPolicy(unittest.TestCase):
    """Unit tests for policy.Policy"""

    def test_run_true(self) -> None:
        """Imported policy body returns True."""
        policy = Policy({'id': 'test-id', 'body': 'def policy(resource):\n\treturn True', 'severity': 'INFO', 'versionId': 'abcdegh123456'})
        result = policy.run(
            {
                'id': 'resourceId',
                'integrationId': 'integration-id',
                'type': 'a.resource.type',
                'attributes': {
                    'hello': 'world'
                }
            },
            {},
            {},
        )
        self.assertTrue(result.matched)

    def test_run_false(self) -> None:
        """Imported policy body returns False."""
        policy = Policy({'id': 'test-id', 'body': 'def policy(resource): return False', 'severity': 'INFO', 'versionId': 'abcdegh123456'})
        result = policy.run(
            {
                'id': 'resourceId',
                'integrationId': 'integration-id',
                'type': 'a.resource.type',
                'attributes': {
                    'hello': 'world'
                }
            },
            {},
            {},
        )
        self.assertFalse(result.matched)

    def test_run_import_error(self) -> None:
        """A policy which failed to import will raise errors for every resource."""
        policy = Policy({'id': 'test-id', 'body': 'def... initely not valid Python', 'severity': 'INFO', 'versionId': 'abcdegh123456'})
        result = policy.run(
            {
                'id': 'resourceId',
                'integrationId': 'integration-id',
                'type': 'a.resource.type',
                'attributes': {
                    'hello': 'world'
                }
            },
            {},
            {},
        )
        self.assertIsInstance(result.setup_exception, SyntaxError)

    def test_run_runtime_error(self) -> None:
        """Runtime errors are reported."""
        policy = Policy({'id': 'test-id', 'body': 'def policy(resource): return 0/0', 'severity': 'INFO', 'versionId': 'abcdegh123456'})
        result = policy.run(
            {
                'id': 'resourceId',
                'integrationId': 'integration-id',
                'type': 'a.resource.type',
                'attributes': {
                    'hello': 'world'
                }
            },
            {},
            {},
        )
        self.assertIsInstance(result.detection_exception, ZeroDivisionError)

    def test_run_non_bool(self) -> None:
        """Non-boolean returns raise an error."""
        result = Policy(
            {
                'id': 'test-id',
                'body': 'def policy(resource): return len(resource)',
                'severity': 'INFO',
                'versionId': 'abcdegh123456'
            }
        ).run({
                'id': 'resourceId',
                'integrationId': 'integration-id',
                'type': 'a.resource.type',
                'attributes': {
                    'hello': 'world'
                },
            },
            {},
            {},
        )
        self.assertIsInstance(result.detection_exception, FunctionReturnTypeError)
        self.assertEqual('detection [test-id] function [policy] returned [int], expected [bool]', str(result.detection_exception))


class TestDetectionResult(unittest.TestCase):

    def test_fatal_error(self) -> None:
        result = DetectionResult(
            dedup_output='failed.policy',
            detection_id='failed.policy',
            detection_severity='INFO',
        )
        self.assertIsNone(result.fatal_error)
        fields = ('detection_exception', 'setup_exception', 'input_exception')
        exc = TypeError('something went wrong')
        for field in fields:
            # https://github.com/python/mypy/issues/1969
            params = {
                field: exc,
                'detection_id': 'failed.policy',
                'detection_severity': 'INFO',
                'dedup_output': 'failed.policy'
            }
            result = DetectionResult(**params)
            self.assertIs(result.fatal_error, exc)

    def test_error_type(self) -> None:
        result = DetectionResult(
            dedup_output='failed.policy',
            detection_id='failed.policy',
            detection_severity='INFO',
        )
        self.assertIsNone(result.error_type)
        result = DetectionResult(
            dedup_output='failed.policy',
            detection_id='failed.policy',
            detection_severity='INFO',
            detection_exception=TypeError('something went wrong'),
        )
        self.assertEqual(result.error_type, 'TypeError')

    def test_short_error_message(self) -> None:
        result = DetectionResult(
            dedup_output='failed.policy',
            detection_id='failed.policy',
            detection_severity='INFO',
        )
        self.assertIsNone(result.short_error_message)
        result = DetectionResult(
            dedup_output='failed.policy',
            detection_severity='INFO',
            detection_id='failed.policy',
            detection_exception=TypeError('something went wrong'),
        )
        self.assertEqual(result.short_error_message, "TypeError('something went wrong')")

    def test_error_message(self) -> None:
        # Generate traceback
        try:
            raise TypeError('policy failed')
        except TypeError as exception:
            exc = exception

        result = DetectionResult(
            dedup_output='failed.policy',
            detection_exception=exc,
            detection_id='failed.policy',
            detection_severity='INFO',
        )
        self.assertRegex(
            # error_message return value is Optional[str]
            # but here we know that it is a string
            result.error_message,
            r"policy failed: test_policy.py, line [0-9]+, "
            r"in test_error_message\s+raise TypeError\('policy failed'\)"
        )

        result = DetectionResult(
            dedup_output='failed.policy',
            detection_id='failed.policy',
            detection_severity='INFO',
        )
        self.assertIsNone(result.error_message)

    def test_errored(self) -> None:
        result = DetectionResult(
            dedup_output='failed.policy',
            detection_id='failed.policy',
            detection_severity='INFO',
            detection_exception=TypeError(),
        )
        self.assertTrue(result.errored)

        result = DetectionResult(
            dedup_output='failed.policy',
            detection_id='failed.policy',
            detection_severity='INFO',
        )
        self.assertFalse(result.errored)

    def test_policy_evaluation_failed(self) -> None:
        result = DetectionResult(
            dedup_output='failed.policy',
            detection_id='failed.policy',
            detection_severity='INFO',
        )
        self.assertFalse(result.errored)

        self.assertTrue(
            DetectionResult(
                dedup_output='failed.policy',
                detection_id='failed.policy',
                detection_severity='INFO',
                detection_exception=TypeError(),
            ).detection_evaluation_failed
        )
        self.assertTrue(
            DetectionResult(
                dedup_output='failed.policy',
                detection_id='failed.policy',
                detection_severity='INFO',
                setup_exception=TypeError(),
            ).detection_evaluation_failed
        )
