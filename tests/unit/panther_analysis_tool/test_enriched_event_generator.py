import io
import logging
import sys
import unittest
from unittest import mock, TestCase
from pprint import pformat

from panther_analysis_tool.analysis_utils import LoadAnalysisSpecsResult, get_yaml_loader
from panther_analysis_tool.backend.client import Client
from panther_analysis_tool.enriched_event_generator import EnrichedEventGenerator
from panther_analysis_tool.backend.mocks import MockBackend


def get_specs_for_test():
    return [
        LoadAnalysisSpecsResult(
            f"filname.rule",
            f"filepath.rule",
            {
                "RuleID": f"foo.bar.rule",
                "AnalysisType": "rule",
                "Tests": [
                    {
                        "Key": "event_type",
                        "Condition": "Equals",
                        "Value": f"team_privacy_settings_changed"
                    },
                    {
                        "DeepKey": ["details", "new_value"],
                        "Condition": "Equals",
                        "Value": f"public"
                    }
                ]
            },
            yaml_ctx=get_yaml_loader(),
            error=None
        ),
        LoadAnalysisSpecsResult(
            f"filname.scheduled_rule",
            f"filepath.scheduled_rule",
            {
                "RuleID": f"foo.bar.scheduled_rule",
                "AnalysisType": "scheduled_rule",
                "Tests": [
                    {
                        "Key": "event_type",
                        "Condition": "Equals",
                        "Value": f"team_privacy_settings_changed"
                    },
                    {
                        "DeepKey": ["details", "new_value"],
                        "Condition": "Equals",
                        "Value": f"public"
                    }
                ]
            },
            yaml_ctx=get_yaml_loader(),
            error=None
        ),
        LoadAnalysisSpecsResult(
            f"filname.policy",
            f"filepath.policy",
            {
                "PolicyID": f"foo.bar.policy",
                "AnalysisType": "policy",
                "Tests": [
                    {
                        "Key": "event_type",
                        "Condition": "Equals",
                        "Value": f"team_privacy_settings_changed"
                    },
                    {
                        "DeepKey": ["details", "new_value"],
                        "Condition": "Equals",
                        "Value": f"public"
                    }
                ]
            },
            yaml_ctx=get_yaml_loader(),
            error=None
        )
    ]


class TestEnrichedEventGenerator(TestCase):
    def test__convert_inline_json_dict_to_python_dict(self) -> None:
        test_data = [
            {
                "name": "valid inline json",
                "input_yaml": 'other_field: blah\njson: {"foo": {"herp": ["bar", "baz"]}}\n',
                "expected": 'other_field: blah\njson:\n  "foo":\n    "herp":\n      - "bar"\n      - "baz"\n',
            },
            {
                "name": "no inline json",
                "input_yaml": 'other_field: blah\nfoo:\n  bar:\n    - baz\njson:\n',
                "expected": 'other_field: blah\nfoo:\n  bar:\n    - baz\njson:\n',
            },
            {
                "name": "argument is not json",
                "input_yaml": 'other_field: blah\nfoo:\n  bar:\n    - baz\njson: 5\n',
                "expected": 'other_field: blah\nfoo:\n  bar:\n    - baz\njson: 5\n',
            },
        ]

        for test in test_data:
            logging.info(f"Running test: {test['name']}")
            yaml = get_yaml_loader()
            as_commented_map = yaml.load(test['input_yaml'])
            inline_json_test_content = as_commented_map['json']

            result = EnrichedEventGenerator._convert_inline_json_dict_to_python_dict(inline_json_test_content)
            as_commented_map['json'] = result
            string_io = io.StringIO()
            yaml.dump(as_commented_map, stream=string_io)

            self.assertEqual(
                string_io.getvalue(),
                test['expected'],
            )
