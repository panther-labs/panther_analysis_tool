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

import dataclasses
import json
import inspect
import os
import pathlib
import shutil
from typing import Tuple, Optional, Any
from unittest import TestCase
import tempfile
from types import ModuleType

from panther_analysis_tool.rule import MAX_DEDUP_STRING_SIZE, MAX_GENERATED_FIELD_SIZE, \
    Rule, RuleResult, TRUNCATED_STRING_SUFFIX, FilesystemImporter, RawStringImporter
from panther_analysis_tool.enriched_event import PantherEvent
from panther_analysis_tool.exceptions import FunctionReturnTypeError


class TestRule(TestCase):  # pylint: disable=too-many-public-methods
    # TODO: update type annotation for checked objects to be dataclass in Python 3.8+
    def assertDataclassEqual(  # pylint: disable=invalid-name
            self,
            first: Any,
            second: Any,
            fields_as_string: Optional[Tuple[str, ...]] = None) -> None:
        """
        Compare two dataclass instances by first converting them to dictionaries.
        In order to allow comparison for non-comparable objects, such as exception instances,
        a list of fields to be converted to their string representation can be given.
        """
        self.assertIsInstance(first, type(second))
        fields_as_string = fields_as_string or ()
        first = dataclasses.asdict(first)
        second = dataclasses.asdict(second)
        for string_repr_field in fields_as_string:
            first[string_repr_field] = str(first[string_repr_field])
            second[string_repr_field] = str(second[string_repr_field])
        return self.assertDictEqual(first, second)

    def test_create_rule_missing_id(self) -> None:
        exception = False
        try:
            Rule({'body': 'rule', 'versionId': 'version'})
        except AssertionError:
            exception = True

        self.assertTrue(exception)

    def test_create_rule_missing_body_and_path(self) -> None:
        with self.assertRaisesRegex(ValueError, r'one of "body", "path" must be defined'):
            Rule({'id': 'test_create_rule_missing_body', 'versionId': 'version'})

    def test_create_rule_defined_body_and_path(self) -> None:
        with self.assertRaises(ValueError):
            Rule({'id': 'test_create_rule_missing_body',
                  'versionId': 'version',
                  'body': 'def rule(event): pass',
                  'path': pathlib.Path()})

    def test_create_rule_missing_version(self) -> None:
        exception = False
        try:
            Rule({'id': 'test_create_rule_missing_version', 'body': 'rule'})
        except AssertionError:
            exception = True

        self.assertTrue(exception)

    def test_rule_default_dedup_time(self) -> None:
        rule_body = 'def rule(event):\n\treturn True'
        rule = Rule({'id': 'test_rule_default_dedup_time', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})

        self.assertEqual(60, rule.rule_dedup_period_mins)

    def test_rule_tags(self) -> None:
        rule_body = 'def rule(event):\n\treturn True'
        rule = Rule(
            {
                'id': 'test_rule_default_dedup_time',
                'body': rule_body,
                'versionId': 'versionId',
                'tags': ['tag2', 'tag1'],
                'severity': 'INFO'
            }
        )

        self.assertEqual(['tag1', 'tag2'], rule.rule_tags)

    def test_rule_reports(self) -> None:
        rule_body = 'def rule(event):\n\treturn True'
        rule = Rule(
            {
                'id': 'test_rule_default_dedup_time',
                'body': rule_body,
                'versionId': 'versionId',
                'reports': {
                    'key1': ['value2', 'value1'],
                    'key2': ['value1']
                },
                'severity': 'INFO'
            }
        )

        self.assertEqual({'key1': ['value1', 'value2'], 'key2': ['value1']}, rule.rule_reports)

    def test_create_rule_missing_method(self) -> None:
        exception = False
        rule_body = 'def another_method(event):\n\treturn False'
        try:
            Rule({'id': 'test_create_rule_missing_method', 'body': rule_body})
        except AssertionError:
            exception = True

        self.assertTrue(exception)

    def test_rule_matches(self) -> None:
        rule_body = 'def rule(event):\n\treturn True'
        rule = Rule({'id': 'test_rule_matches', 'body': rule_body, 'dedupPeriodMinutes': 100, 'versionId': 'test', 'severity': 'INFO'})

        self.assertEqual('test_rule_matches', rule.rule_id)
        self.assertEqual(rule_body, inspect.getsource(rule.module).strip())
        self.assertEqual('test', rule.rule_version)
        self.assertEqual(100, rule.rule_dedup_period_mins)

        expected_rule = RuleResult(
            rule_id='test_rule_matches',
            matched=True,
            dedup_output='defaultDedupString:test_rule_matches',
            rule_severity='INFO',
        )
        self.assertEqual(expected_rule, rule.run(PantherEvent({}, None), {}, {}))

    def test_rule_doesnt_match(self) -> None:
        rule_body = 'def rule(event):\n\treturn False'
        rule = Rule({'id': 'test_rule_doesnt_match', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})
        expected_rule = RuleResult(matched=False, rule_id='test_rule_doesnt_match', rule_severity='INFO')
        self.assertEqual(expected_rule, rule.run(PantherEvent({}, None), {}, {}))

    def test_rule_with_dedup(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn "testdedup"'
        rule = Rule({'id': 'test_rule_with_dedup', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})
        expected_rule = RuleResult(rule_id='test_rule_with_dedup', matched=True,
                                   dedup_output='testdedup', rule_severity='INFO', dedup_defined=True)
        self.assertEqual(expected_rule, rule.run(PantherEvent({}, None), {}, {}))

    def test_restrict_dedup_size(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn "".join("a" for i in range({}))'. \
            format(MAX_DEDUP_STRING_SIZE + 1)
        rule = Rule({'id': 'test_restrict_dedup_size', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})

        expected_dedup_string_prefix = ''.join('a' for _ in range(MAX_DEDUP_STRING_SIZE - len(TRUNCATED_STRING_SUFFIX)))
        expected_rule = RuleResult(
            rule_id='test_restrict_dedup_size',
            matched=True,
            dedup_output=expected_dedup_string_prefix + TRUNCATED_STRING_SUFFIX,
            rule_severity='INFO',
            dedup_defined=True,
        )
        self.assertEqual(expected_rule, rule.run(PantherEvent({}, None), {}, {}))

    def test_restrict_title_size(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\n' \
                    'def dedup(event):\n\treturn "test"\n' \
                    'def title(event):\n\treturn "".join("a" for i in range({}))'. \
            format(MAX_GENERATED_FIELD_SIZE + 1)
        rule = Rule({'id': 'test_restrict_title_size', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})

        expected_title_string_prefix = ''.join('a' for _ in range(MAX_GENERATED_FIELD_SIZE - len(TRUNCATED_STRING_SUFFIX)))
        expected_rule = RuleResult(
            rule_id='test_restrict_title_size',
            matched=True,
            dedup_output='test',
            title_output=expected_title_string_prefix + TRUNCATED_STRING_SUFFIX,
            rule_severity='INFO',
            dedup_defined=True,
            title_defined=True,
        )
        self.assertEqual(expected_rule, rule.run(PantherEvent({}, None), {}, {}))

    def test_empty_dedup_result_to_default(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn ""'
        rule = Rule({'id': 'test_empty_dedup_result_to_default', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})

        expected_rule = RuleResult(
            rule_id='test_empty_dedup_result_to_default',
            matched=True,
            dedup_output='defaultDedupString:test_empty_dedup_result_to_default',
            rule_severity='INFO',
            dedup_defined=True,
        )
        self.assertEqual(expected_rule, rule.run(PantherEvent({}, None), {}, {}))

    def test_rule_throws_exception(self) -> None:
        rule_body = 'def rule(event):\n\traise Exception("test")'
        rule = Rule({'id': 'test_rule_throws_exception', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})
        rule_result = rule.run(PantherEvent({}, None), {}, {})
        self.assertIsNone(rule_result.matched)
        self.assertIsNone(rule_result.dedup_output)
        self.assertIsNotNone(rule_result.rule_exception)

    def test_invalid_python_syntax(self) -> None:
        rule_body = 'def rule(test):this is invalid python syntax'
        rule = Rule({'id': 'test_invalid_python_syntax', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})
        rule_result = rule.run(PantherEvent({}, None), {}, {})
        self.assertIsNone(rule_result.matched)
        self.assertIsNone(rule_result.dedup_output)
        self.assertIsNone(rule_result.rule_exception)

        self.assertTrue(rule_result.errored)
        self.assertEqual(rule_result.error_type, "SyntaxError")
        self.assertIsNotNone(rule_result.short_error_message)
        self.assertIsNotNone(rule_result.error_message)

    def test_rule_invalid_rule_return(self) -> None:
        rule_body = 'def rule(event):\n\treturn "test"'
        rule = Rule({'id': 'test_rule_invalid_rule_return', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})
        rule_result = rule.run(PantherEvent({}, None), {}, {})
        self.assertIsNone(rule_result.matched)
        self.assertIsNone(rule_result.dedup_output)
        self.assertTrue(rule_result.errored)

        expected_short_msg = "FunctionReturnTypeError('rule [test_rule_invalid_rule_return] function [rule] returned [str], expected [bool]')"
        self.assertEqual(expected_short_msg, rule_result.short_error_message)
        self.assertEqual(rule_result.error_type, 'FunctionReturnTypeError')

    def test_dedup_throws_exception(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\traise Exception("test")'
        rule = Rule({'id': 'test_dedup_throws_exception', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})

        expected_rule = RuleResult(
            rule_id='test_dedup_throws_exception',
            matched=True,
            dedup_output='defaultDedupString:test_dedup_throws_exception',
            rule_severity='INFO',
            dedup_defined=True,
        )
        self.assertEqual(expected_rule, rule.run(PantherEvent({}, None), {}, {}))

    def test_dedup_exception_batch_mode(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\traise Exception("test")'
        rule = Rule({'id': 'test_dedup_throws_exception', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})

        actual = rule.run(PantherEvent({}, None), {}, {}, batch_mode=False)

        self.assertTrue(actual.matched)
        self.assertIsNotNone(actual.dedup_exception)
        self.assertTrue(actual.errored)

    def test_rule_invalid_dedup_return(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn {}'
        rule = Rule({'id': 'test_rule_invalid_dedup_return', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})

        expected_rule = RuleResult(
            rule_id='test_rule_invalid_dedup_return',
            matched=True,
            dedup_output='defaultDedupString:test_rule_invalid_dedup_return',
            rule_severity='INFO',
            dedup_defined=True,
        )
        self.assertEqual(expected_rule, rule.run(PantherEvent({}, None), {}, {}))

    def test_rule_dedup_returns_empty_string(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn ""'
        rule = Rule({'id': 'test_rule_dedup_returns_empty_string', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})

        expected_result = RuleResult(
            rule_id='test_rule_dedup_returns_empty_string',
            matched=True,
            dedup_output='defaultDedupString:test_rule_dedup_returns_empty_string',
            rule_severity='INFO',
            dedup_defined=True,
        )
        self.assertEqual(rule.run(PantherEvent({}, None), {}, {}), expected_result)

    def test_rule_matches_with_title_without_dedup(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef title(event):\n\treturn "title"'
        rule = Rule({'id': 'test_rule_matches_with_title', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})

        expected_result = RuleResult(
            rule_id='test_rule_matches_with_title', matched=True,
            dedup_output='title', title_output='title', rule_severity='INFO',
            title_defined=True,
        )
        self.assertEqual(rule.run(PantherEvent({}, None), {}, {}), expected_result)

    def test_rule_title_throws_exception(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef title(event):\n\traise Exception("test")'
        rule = Rule({'id': 'test_rule_title_throws_exception', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})

        expected_result = RuleResult(
            rule_id='test_rule_title_throws_exception',
            matched=True,
            dedup_output='test_rule_title_throws_exception',
            title_output='test_rule_title_throws_exception',
            rule_severity='INFO',
            title_defined=True,
        )
        self.assertEqual(rule.run(PantherEvent({}, None), {}, {}), expected_result)

    def test_rule_invalid_title_return(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef title(event):\n\treturn {}'
        rule = Rule({'id': 'test_rule_invalid_title_return', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})

        expected_result = RuleResult(
            rule_id='test_rule_invalid_title_return',
            matched=True,
            dedup_output='test_rule_invalid_title_return',
            title_output='test_rule_invalid_title_return',
            rule_severity='INFO',
            title_defined=True,
        )
        self.assertEqual(rule.run(PantherEvent({}, None), {}, {}), expected_result)

    def test_rule_title_returns_empty_string(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef title(event):\n\treturn ""'
        rule = Rule({'id': 'test_rule_title_returns_empty_string', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})

        expected_result = RuleResult(
            rule_id='test_rule_title_returns_empty_string',
            matched=True,
            dedup_output='defaultDedupString:test_rule_title_returns_empty_string',
            title_output='',
            rule_severity='INFO',
            title_defined=True,
        )
        self.assertEqual(expected_result, rule.run(PantherEvent({}, None), {}, {}))

    def test_alert_context(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef alert_context(event):\n\treturn {"string": "string", "int": 1, "nested": {}}'
        rule = Rule({'id': 'test_alert_context', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})

        expected_result = RuleResult(
            rule_id='test_alert_context',
            matched=True,
            dedup_output='defaultDedupString:test_alert_context',
            alert_context_output='{"string": "string", "int": 1, "nested": {}}',
            rule_severity='INFO',
            alert_context_defined=True,
        )
        self.assertEqual(expected_result, rule.run(PantherEvent({}, None), {}, {}))

    def test_alert_context_invalid_return_value(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef alert_context(event):\n\treturn ""'
        rule = Rule({'id': 'test_alert_context_invalid_return_value', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})

        expected_alert_context = json.dumps(
            {
                '_error':
                    'FunctionReturnTypeError(\'rule [test_alert_context_invalid_return_value] function [alert_context] returned [str], expected [Mapping]\')'  # pylint: disable=C0301
            }
        )
        expected_result = RuleResult(
            rule_id='test_alert_context_invalid_return_value',
            matched=True,
            dedup_output='defaultDedupString:test_alert_context_invalid_return_value',
            alert_context_output=expected_alert_context,
            rule_severity='INFO',
            alert_context_defined=True,
        )
        self.assertEqual(expected_result, rule.run(PantherEvent({}, None), {}, {}))

    def test_alert_context_too_big(self) -> None:
        # Function should generate alert_context exceeding limit
        alert_context_function = 'def alert_context(event):\n' \
                                 '\ttest_dict = {}\n' \
                                 '\tfor i in range(300000):\n' \
                                 '\t\ttest_dict[str(i)] = "value"\n' \
                                 '\treturn test_dict'
        rule_body = 'def rule(event):\n\treturn True\n{}'.format(alert_context_function)
        rule = Rule({'id': 'test_alert_context_too_big', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})
        expected_alert_context = json.dumps(
            {'_error': 'alert_context size is [5588890] characters, bigger than maximum of [204800] characters'}
        )
        expected_result = RuleResult(
            rule_id='test_alert_context_too_big',
            matched=True,
            dedup_output='defaultDedupString:test_alert_context_too_big',
            alert_context_output=expected_alert_context,
            rule_severity='INFO',
            alert_context_defined=True,
        )
        self.assertEqual(expected_result, rule.run(PantherEvent({}, None), {}, {}))

    def test_alert_context_immutable_event(self) -> None:
        alert_context_function = 'def alert_context(event):\n' \
                                 '\treturn {"headers": event["headers"],\n' \
                                 '\t\t"get_params": event["query_string_args"]}'
        rule_body = 'def rule(event):\n\treturn True\n{}'.format(alert_context_function)
        rule = Rule({'id': 'test_alert_context_immutable_event', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})
        event = {'headers': {'User-Agent': 'Chrome'}, 'query_string_args': [{'a': '1'}, {'b': '2'}]}

        expected_alert_context = json.dumps({'headers': event['headers'], 'get_params': event['query_string_args']})
        expected_result = RuleResult(
            rule_id='test_alert_context_immutable_event',
            matched=True,
            dedup_output='defaultDedupString:test_alert_context_immutable_event',
            alert_context_output=expected_alert_context,
            rule_severity='INFO',
            alert_context_defined=True,
        )
        self.assertEqual(expected_result, rule.run(PantherEvent(event, None), {}, {}))

    def test_alert_context_returns_full_event(self) -> None:
        alert_context_function = 'def alert_context(event):\n\treturn event'
        rule_body = 'def rule(event):\n\treturn True\n{}'.format(alert_context_function)
        rule = Rule({'id': 'test_alert_context_returns_full_event', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})
        event = {'test': 'event'}

        expected_alert_context = json.dumps(event)
        expected_result = RuleResult(
            rule_id='test_alert_context_returns_full_event',
            matched=True,
            dedup_output='defaultDedupString:test_alert_context_returns_full_event',
            alert_context_output=expected_alert_context,
            rule_severity='INFO',
            alert_context_defined=True,
        )
        self.assertEqual(expected_result, rule.run(PantherEvent(event, None), {}, {}))

    # Generated Fields Tests
    def test_rule_with_all_generated_fields(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\n' \
                    'def alert_context(event):\n\treturn {}\n' \
                    'def title(event):\n\treturn "test_rule_with_all_generated_fields"\n' \
                    'def description(event):\n\treturn "test description"\n' \
                    'def severity(event):\n\treturn "HIGH"\n' \
                    'def reference(event):\n\treturn "test reference"\n' \
                    'def runbook(event):\n\treturn "test runbook"\n' \
                    'def destinations(event):\n\treturn []'
        rule = Rule({'id': 'test_rule_with_all_generated_fields', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})

        expected_result = RuleResult(
            rule_id='test_rule_with_all_generated_fields',
            matched=True,
            alert_context_output='{}',
            title_output='test_rule_with_all_generated_fields',
            dedup_output='test_rule_with_all_generated_fields',
            description_output='test description',
            severity_output='HIGH',
            reference_output='test reference',
            runbook_output='test runbook',
            destinations_output=["SKIP"],
            rule_severity='INFO',
            alert_context_defined=True,
            title_defined=True,
            description_defined=True,
            severity_defined=True,
            reference_defined=True,
            runbook_defined=True,
            destinations_defined=True,
        )
        self.assertEqual(expected_result, rule.run(PantherEvent({}, None), {}, {}, batch_mode=False))

    def test_rule_with_invalid_severity(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\n' \
                    'def alert_context(event):\n\treturn {}\n' \
                    'def title(event):\n\treturn "test_rule_with_invalid_severity"\n' \
                    'def severity(event):\n\treturn "CRITICAL-ISH"\n'
        rule = Rule({'id': 'test_rule_with_invalid_severity', 'body': rule_body, 'versionId': 'versionId', 'severity': 'INFO'})

        expected_result = RuleResult(
            rule_id='test_rule_with_invalid_severity',
            matched=True,
            alert_context_output='{}',
            title_output='test_rule_with_invalid_severity',
            dedup_output='test_rule_with_invalid_severity',
            severity_exception=AssertionError(
                "Expected severity to be any of the following: [['INFO', 'LOW', 'MEDIUM', 'HIGH', "
                "'CRITICAL']], got [CRITICAL-ISH] instead."
            ),
            rule_severity='INFO',
            alert_context_defined=True,
            title_defined=True,
            severity_defined=True,
        )
        result = rule.run(PantherEvent({}, None), {}, {}, batch_mode=False)
        self.assertEqual(str(expected_result), str(result))
        self.assertTrue(result.errored)
        self.assertIsNotNone(result.severity_exception)

    def test_rule_with_valid_severity_case_insensitive(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\n' \
                    'def alert_context(event):\n\treturn {}\n' \
                    'def title(event):\n\treturn "test_rule_with_valid_severity_case_insensitive"\n' \
                    'def severity(event):\n\treturn "cRiTiCaL"\n'
        rule = Rule(
            {
                'id': 'test_rule_with_valid_severity_case_insensitive',
                'body': rule_body,
                'versionId': 'versionId',
                'severity': 'INFO'
            }
        )

        expected_result = RuleResult(
            matched=True,
            rule_id='test_rule_with_valid_severity_case_insensitive',
            alert_context_output='{}',
            title_output='test_rule_with_valid_severity_case_insensitive',
            dedup_output='test_rule_with_valid_severity_case_insensitive',
            severity_output="CRITICAL",
            rule_severity='INFO',
            alert_context_defined=True,
            title_defined=True,
            severity_defined=True,
        )
        result = rule.run(PantherEvent({}, None), {}, {})
        self.assertEqual(expected_result, result)

    def test_rule_with_invalid_destinations_type(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\n' \
                    'def alert_context(event):\n\treturn {}\n' \
                    'def title(event):\n\treturn "test_rule_with_valid_severity_case_insensitive"\n' \
                    'def severity(event):\n\treturn "cRiTiCaL"\n' \
                    'def destinations(event):\n\treturn "bad input"\n'
        rule = Rule(
            {
                'id': 'test_rule_with_valid_severity_case_insensitive',
                'body': rule_body,
                'versionId': 'versionId',
                'severity': 'INFO'
            }
        )

        expected_result = RuleResult(
            rule_id='test_rule_with_valid_severity_case_insensitive',
            matched=True,
            alert_context_output='{}',
            title_output='test_rule_with_valid_severity_case_insensitive',
            dedup_output='test_rule_with_valid_severity_case_insensitive',
            severity_output="CRITICAL",
            destinations_output=None,
            destinations_exception=FunctionReturnTypeError(
                'rule [{}] function [{}] returned [{}], expected a list'.format(rule.rule_id, 'destinations', 'str')
            ),
            rule_severity='INFO',
            alert_context_defined=True,
            title_defined=True,
            severity_defined=True,
            destinations_defined=True,
        )
        result = rule.run(PantherEvent({}, None), {}, {}, batch_mode=False)
        self.assertEqual(str(expected_result), str(result))
        self.assertTrue(result.errored)
        self.assertIsNotNone(result.destinations_exception)

    def test_rule_with_severity_raising_exception_unit_test(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\n' \
                    'def title(event):\n\treturn"test_rule_with_severity_raising_exception_unit_test"\n' \
                    'def severity(event):\n\traise AssertionError("something bad happened")\n'
        rule = Rule(
            {
                'id': 'test_rule_with_severity_raising_exception_unit_test',
                'body': rule_body,
                'versionId': 'versionId',
                'severity': 'INFO'
            }
        )
        expected_result = RuleResult(
            rule_id='test_rule_with_severity_raising_exception_unit_test',
            matched=True,
            title_output='test_rule_with_severity_raising_exception_unit_test',
            dedup_output='test_rule_with_severity_raising_exception_unit_test',
            severity_output=None,
            severity_exception=AssertionError("something bad happened"),
            rule_severity='INFO',
            title_defined=True,
            severity_defined=True,
        )
        result = rule.run(PantherEvent({}, None), {}, {}, batch_mode=False)
        self.assertTrue(result.errored)
        self.assertIsNotNone(result.severity_exception)
        # Exception instances cannot be compared
        self.assertDataclassEqual(expected_result, result, fields_as_string=('severity_exception',))

    def test_rule_with_severity_raising_exception_batch_mode(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\n' \
                    'def title(event):\n\treturn"test_rule_with_severity_raising_exception_batch_mode"\n' \
                    'def severity(event):\n\traise AssertionError("something bad happened")\n'
        rule = Rule(
            {
                'id': 'test_rule_with_severity_raising_exception_batch_mode',
                'body': rule_body,
                'versionId': 'versionId',
                'severity': 'INFO'
            }
        )

        expected_result = RuleResult(
            rule_id='test_rule_with_severity_raising_exception_batch_mode',
            matched=True,
            title_output='test_rule_with_severity_raising_exception_batch_mode',
            dedup_output='test_rule_with_severity_raising_exception_batch_mode',
            severity_output='INFO',
            rule_severity='INFO',
            title_defined=True,
            severity_defined=True,
        )
        result = rule.run(PantherEvent({}, None), {}, {}, batch_mode=True)
        self.assertEqual(str(expected_result), str(result))


class TestRuleResult(TestCase):

    def test_fatal_error(self) -> None:
        result = RuleResult(rule_id='failed.rule', rule_severity='INFO')
        self.assertIsNone(result.fatal_error)
        fields = ('rule_exception', 'setup_exception', 'input_exception')
        exc = TypeError('something went wrong')
        for field in fields:
            # https://github.com/python/mypy/issues/1969
            params = {
                field: exc,
                'rule_id': 'failed.rule',
                'rule_severity': 'INFO',
            }
            result = RuleResult(**params)  # type: ignore
            self.assertIs(result.fatal_error, exc)

    def test_error_type(self) -> None:
        result = RuleResult(rule_id='failed.rule', rule_severity='INFO')
        self.assertIsNone(result.error_type)
        result = RuleResult(rule_id='failed.rule', rule_severity='INFO', rule_exception=TypeError('something went wrong'))
        self.assertEqual(result.error_type, 'TypeError')

    def test_short_error_message(self) -> None:
        result = RuleResult(rule_id='failed.rule', rule_severity='INFO')
        self.assertIsNone(result.short_error_message)
        result = RuleResult(
            rule_severity='INFO',
            rule_id='failed.rule',
            rule_exception=TypeError('something went wrong'),
        )
        self.assertEqual(result.short_error_message, "TypeError('something went wrong')")

    def test_error_message(self) -> None:
        # Generate traceback
        try:
            raise TypeError('rule failed')
        except TypeError as exception:
            exc = exception

        result = RuleResult(rule_exception=exc, rule_id='failed.rule', rule_severity='INFO')
        self.assertRegex(  # type: ignore
            # error_message return value is Optional[str]
            # but here we know that it is a string
            result.error_message,
            r"rule failed: test_rule.py, line [0-9]+, "
            r"in test_error_message\s+raise TypeError\('rule failed'\)"
        )

        result = RuleResult(rule_id='failed.rule', rule_severity='INFO')
        self.assertIsNone(result.error_message)

    def test_errored(self) -> None:
        result = RuleResult(rule_id='failed.rule', rule_severity='INFO', rule_exception=TypeError())
        self.assertTrue(result.errored)
        result = RuleResult(rule_id='failed.rule', rule_severity='INFO', title_exception=TypeError())
        self.assertTrue(result.errored)

        result = RuleResult(rule_id='failed.rule', rule_severity='INFO')
        self.assertFalse(result.errored)

    def test_rule_evaluation_failed(self) -> None:
        result = RuleResult(rule_id='failed.rule', rule_severity='INFO')
        self.assertFalse(result.errored)

        self.assertTrue(RuleResult(rule_id='failed.rule', rule_severity='INFO', rule_exception=TypeError()).rule_evaluation_failed)
        self.assertTrue(RuleResult(rule_id='failed.rule', rule_severity='INFO', setup_exception=TypeError()).rule_evaluation_failed)
        self.assertFalse(RuleResult(rule_id='failed.rule', rule_severity='INFO', title_exception=TypeError()).rule_evaluation_failed)


class TestRawStringImporter(TestCase):
    def setUp(self) -> None:
        fixtures_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../', 'fixtures'))
        self.detections_fixtures_path = os.path.join(fixtures_path, 'detections')
        self.tmp_dir = tempfile.mkdtemp(prefix=self.__class__.__name__ + '_')

    def tearDown(self) -> None:
        if self.tmp_dir.startswith(tempfile.gettempdir()):
            shutil.rmtree(self.tmp_dir)

    def test_load_valid_module(self) -> None:
        valid_module_path = os.path.join(self.detections_fixtures_path,
                                         'valid_analysis/rules/example_rule_generated_functions.py')
        with open(valid_module_path, 'r') as f:
            code = f.read()

        module = RawStringImporter(self.tmp_dir).get_module(
            "TestRawStringImporter_identifier_test_load_valid_module",
            code
        )
        self.assertIsInstance(module, ModuleType)
        self.assertTrue(hasattr(module, 'rule'))
        self.assertEqual(inspect.getsource(module), code)

    def test_load_module_with_error(self) -> None:
        invalid_module_path = os.path.join(self.detections_fixtures_path,
                                           'example_unhandled_exception_on_import.py')
        with open(invalid_module_path, 'r') as f:
            code = f.read()

        with self.assertRaisesRegex(ModuleNotFoundError, "No module named 'unknown_module'"):
            _ = RawStringImporter(self.tmp_dir).get_module("identifier1", code)


class TestFilesystemImporter(TestCase):
    def setUp(self) -> None:
        fixtures_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../', 'fixtures'))
        self.detections_fixtures_path = os.path.join(fixtures_path, 'detections')

    def test_load_valid_module(self) -> None:
        valid_module_path = os.path.join(self.detections_fixtures_path,
                                         'valid_analysis/rules/example_rule_generated_functions.py')
        module = FilesystemImporter().get_module(
            "TestFilesystemImporter_test_load_valid_module",
            valid_module_path
        )
        self.assertIsInstance(module, ModuleType)
        self.assertTrue(hasattr(module, 'rule'))
        with open(valid_module_path, 'r') as f:
            self.assertEqual(inspect.getsource(module), f.read())

    def test_load_module_with_error(self) -> None:
        invalid_module_path = os.path.join(self.detections_fixtures_path,
                                           'example_unhandled_exception_on_import.py')
        with self.assertRaisesRegex(ModuleNotFoundError, "No module named 'unknown_module'"):
            _ = FilesystemImporter().get_module("identifier1", invalid_module_path)

