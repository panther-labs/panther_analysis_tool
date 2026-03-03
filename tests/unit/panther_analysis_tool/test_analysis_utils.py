# This file was generated in whole or in part by GitHub Copilot.

import io
import json
from typing import Any
from unittest import TestCase, mock

import schema
import yaml as pyyaml

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.analysis_utils import (
    AnalysisItem,
    _PATSafeLoader,
    _validate_table_names_batch,
    filters_match_analysis_item,
    get_simple_detections_as_python,
    load_analysis_specs,
    transpile_inline_filters,
)
from panther_analysis_tool.backend.client import (
    BackendError,
    BackendResponse,
    TranspileFiltersResponse,
    TranspileToPythonResponse,
)
from panther_analysis_tool.backend.mocks import MockBackend
from panther_analysis_tool.constants import BACKEND_FILTERS_ANALYSIS_SPEC_KEY
from panther_analysis_tool.core.definitions import (
    ClassifiedAnalysis,
    ClassifiedAnalysisContainer,
)
from panther_analysis_tool.core.parse import Filter
from tests.unit.panther_analysis_tool.test_main import DETECTIONS_FIXTURES_PATH


class TestGetSimpleDetectionsAsPython(TestCase):
    def get_specs_for_test(self):
        specs = []
        for i in range(10):
            specs.append(
                ClassifiedAnalysis(
                    f"filname-{i}",
                    f"filepath-{i}",
                    {
                        "Detection": [
                            {
                                "Key": "event_type",
                                "Condition": "Equals",
                                "Value": f"team_privacy_settings_changed-{i}",
                            },
                            {
                                "DeepKey": ["details", "new_value"],
                                "Condition": "Equals",
                                "Value": f"public-{i}",
                            },
                        ]
                    },
                )
            )
        return specs

    def test_no_backend(self) -> None:
        specs = self.get_specs_for_test()
        self.assertEqual(get_simple_detections_as_python(specs), specs)

    def test_backend_error(self) -> None:
        specs = self.get_specs_for_test()
        backend = MockBackend()
        backend.transpile_simple_detection_to_python = mock.MagicMock(
            side_effect=BackendError("that won't transpile!")
        )
        self.assertEqual(get_simple_detections_as_python(specs, backend), specs)

    def test_base_error(self) -> None:
        specs = self.get_specs_for_test()
        backend = MockBackend()
        backend.transpile_simple_detection_to_python = mock.MagicMock(
            side_effect=BaseException("uh-oh")
        )
        self.assertEqual(get_simple_detections_as_python(specs, backend), specs)

    def test_happy_path(self) -> None:
        specs = self.get_specs_for_test()
        backend = MockBackend()
        backend.transpile_simple_detection_to_python = mock.MagicMock(
            return_value=BackendResponse(
                data=TranspileToPythonResponse(
                    transpiled_python=["def rule(event): return True" for _ in range(len(specs))],
                ),
                status_code=200,
            )
        )
        output = get_simple_detections_as_python(specs, backend)
        for actual in output:
            self.assertEqual(actual.analysis_spec["body"], "def rule(event): return True")


class TestTranspileInlineFilters(TestCase):
    def get_specs_for_test(self) -> ClassifiedAnalysisContainer:
        specs = ClassifiedAnalysisContainer()
        for i in range(2):
            specs.simple_detections.append(
                ClassifiedAnalysis(
                    f"filname-{i}",
                    f"filepath-{i}",
                    {
                        "InlineFilters": [
                            {
                                "PathSpecifier": "event_type",
                                "Condition": "Equals",
                                "Value": "team_privacy_settings_changed",
                            }
                        ],
                        "Detection": [
                            {
                                "Key": "event_type",
                                "Condition": "Equals",
                                "Value": "team_privacy_settings_changed",
                            },
                        ],
                    },
                )
            )
            specs.simple_detections.append(
                ClassifiedAnalysis(
                    f"filname-{i}",
                    f"filepath-{i}",
                    {
                        "Detection": [
                            {
                                "Key": "event_type",
                                "Condition": "Equals",
                                "Value": "team_privacy_settings_changed",
                            },
                        ]
                    },
                )
            )
            specs.detections.append(
                ClassifiedAnalysis(
                    f"filname-{i}",
                    f"filepath-{i}",
                    {
                        "InlineFilters": [
                            {
                                "PathSpecifier": "event_type",
                                "Condition": "Equals",
                                "Value": "team_privacy_settings_changed",
                            }
                        ],
                        "Filename": "python.py",
                    },
                )
            )
            specs.detections.append(
                ClassifiedAnalysis(
                    f"filname-{i}",
                    f"filepath-{i}",
                    {"Filename": "python.py"},
                )
            )
        return specs

    def get_transpiled_filter(self) -> str:
        return json.dumps(
            {
                "statement": {
                    "target": "event_type",
                    "operator": "Equals",
                    "value": "team_privacy_settings_changed",
                }
            }
        )

    def test_happy_path(self) -> None:
        specs = self.get_specs_for_test()
        filters = self.get_transpiled_filter()
        backend = MockBackend()
        backend.transpile_filters = mock.MagicMock(
            return_value=BackendResponse(
                data=TranspileFiltersResponse(
                    transpiled_filters=[
                        filters
                        for d in specs.detections + specs.simple_detections
                        if "InlineFilters" in d.analysis_spec
                    ],
                ),
                status_code=200,
            )
        )
        transpile_inline_filters(specs, backend)

        for actual in specs.detections + specs.simple_detections:
            if "InlineFilters" in actual.analysis_spec:
                self.assertEqual(
                    json.loads(filters), actual.analysis_spec.get(BACKEND_FILTERS_ANALYSIS_SPEC_KEY)
                )
            else:
                self.assertEqual(None, actual.analysis_spec.get(BACKEND_FILTERS_ANALYSIS_SPEC_KEY))

    def test_no_filters(self) -> None:
        import logging

        specs = ClassifiedAnalysisContainer()
        backend = MockBackend()
        specs.simple_detections = [
            ClassifiedAnalysis(
                "filname",
                "filepath",
                {
                    "Detection": [
                        {
                            "Key": "event_type",
                            "Condition": "Equals",
                            "Value": "team_privacy_settings_changed",
                        },
                    ]
                },
            )
        ]
        specs.detections = [ClassifiedAnalysis("filname", "filepath", {"Filename": "python.py"})]
        with mock.patch.multiple(
            logging, debug=mock.DEFAULT, warning=mock.DEFAULT, info=mock.DEFAULT
        ) as logging_mocks:
            transpile_inline_filters(specs, backend)
            self.assertEqual(logging_mocks["warning"].call_count, 0)


class TestMiscUtils(TestCase):
    def test_ignored_files_are_not_loaded(self):
        for spec_filename, _, _, _ in load_analysis_specs(
            [DETECTIONS_FIXTURES_PATH], ignore_files=["./example_ignored.yml"]
        ):
            self.assertTrue(spec_filename != "example_ignored.yml")

    def test_multiple_ignored_files_are_not_loaded(self):
        for spec_filename, _, _, _ in load_analysis_specs(
            [DETECTIONS_FIXTURES_PATH],
            ignore_files=["./example_ignored.yml", "./example_ignored_multi.yml"],
        ):
            self.assertTrue(
                spec_filename != "example_ignored.yml"
                and spec_filename != "example_ignored_multi.yml"
            )


class TestHandleWrongKeyError(TestCase):
    def test_handle_wrong_key_error(self):
        sample_keys = ["DisplayName", "Enabled", "Filename"]
        expected_output = "{} not in list of valid keys: {}"
        # test successful regex match and correct error returned
        test_str = (
            "Wrong key 'DisplaName' in {'DisplaName':'one','Enabled':true, 'Filename':'sample'}"
        )
        exc = schema.SchemaWrongKeyError(test_str)
        err = analysis_utils.handle_wrong_key_error(exc, sample_keys)
        self.assertEqual(str(err), expected_output.format("'DisplaName'", sample_keys))
        # test failing regex match
        test_str = "Will not match"
        exc = schema.SchemaWrongKeyError(test_str)
        err = analysis_utils.handle_wrong_key_error(exc, sample_keys)
        self.assertEqual(str(err), expected_output.format("UNKNOWN_KEY", sample_keys))


def _create_item(
    yaml_spec: dict[str, Any],
    raw_yaml: str | None = None,
    python_content: str | None = None,
) -> AnalysisItem:
    """Helper to create an AnalysisItem for testing."""
    return AnalysisItem(
        yaml_file_contents=yaml_spec,
        raw_yaml_file_contents=raw_yaml.encode("utf-8") if raw_yaml else None,
        python_file_contents=python_content.encode("utf-8") if python_content else None,
    )


def test_empty_filters() -> None:
    """Empty filters should match all items."""
    item = _create_item({"AnalysisType": "rule", "RuleID": "test.rule"})
    assert filters_match_analysis_item([], item)


def test_regular_filter_matches() -> None:
    """Regular filter with matching key-value should match."""
    item = _create_item(
        {"AnalysisType": "rule", "RuleID": "AWS.S3.Bucket.PublicRead", "Severity": "Critical"}
    )
    filters = [Filter(key="RuleID", values=["AWS.S3.Bucket.PublicRead"])]
    assert filters_match_analysis_item(filters, item)


def test_regular_filter_no_match() -> None:
    """Regular filter with non-matching value should not match."""
    item = _create_item(
        {"AnalysisType": "rule", "RuleID": "AWS.S3.Bucket.PublicRead", "Severity": "Critical"}
    )
    filters = [Filter(key="RuleID", values=["Different.Rule"])]
    assert not filters_match_analysis_item(filters, item)


def test_regular_filter_multiple_values_or() -> None:
    """Regular filter with multiple values uses OR logic."""
    item = _create_item(
        {"AnalysisType": "rule", "RuleID": "AWS.S3.Bucket.PublicRead", "Severity": "Critical"}
    )
    filters = [Filter(key="Severity", values=["Critical", "High"])]
    assert filters_match_analysis_item(filters, item)


def test_regular_filter_multiple_filters_and() -> None:
    """Multiple regular filters use AND logic."""
    item = _create_item(
        {
            "AnalysisType": "rule",
            "RuleID": "AWS.S3.Bucket.PublicRead",
            "Severity": "Critical",
        }
    )
    filters = [
        Filter(key="RuleID", values=["AWS.S3.Bucket.PublicRead"]),
        Filter(key="Severity", values=["Critical"]),
    ]
    assert filters_match_analysis_item(filters, item)

    # Should fail if one doesn't match
    filters = [
        Filter(key="RuleID", values=["AWS.S3.Bucket.PublicRead"]),
        Filter(key="Severity", values=["High"]),
    ]
    assert not filters_match_analysis_item(filters, item)


def test_regular_filter_inverted() -> None:
    """Inverted filter should exclude matching values."""
    item = _create_item(
        {"AnalysisType": "rule", "RuleID": "AWS.S3.Bucket.PublicRead", "Severity": "Critical"}
    )
    filters = [Filter(key="RuleID", values=["AWS.S3.Bucket.PublicRead"], inverted=True)]
    assert not filters_match_analysis_item(filters, item)

    # Should match if value is different
    filters = [Filter(key="RuleID", values=["Different.Rule"], inverted=True)]
    assert filters_match_analysis_item(filters, item)


def test_text_filter_matches_both() -> None:
    """Text filter matches if it appears in both YAML and Python."""
    item = _create_item(
        {"AnalysisType": "rule", "RuleID": "test.rule"},
        raw_yaml="AnalysisType: rule\nRuleID: test.rule\ndef rule",
        python_content="def rule(event):\n    return True",
    )
    filters = [Filter(key="", values=["def rule"])]
    assert filters_match_analysis_item(filters, item)


def test_text_filter_matches_in_yaml_only() -> None:
    """Text filter matches if it appears in YAML only."""
    item = _create_item(
        {"AnalysisType": "rule", "RuleID": "test.rule"},
        raw_yaml="AnalysisType: rule\nRuleID: test.rule\ndef rule",
        python_content="def other_function(event):\n    return True",
    )
    filters = [Filter(key="", values=["def rule"])]
    assert filters_match_analysis_item(filters, item)


def test_text_filter_matches_in_python_only() -> None:
    """Text filter matches if it appears in Python only."""
    item = _create_item(
        {"AnalysisType": "rule", "RuleID": "test.rule"},
        raw_yaml="AnalysisType: rule\nRuleID: test.rule",
        python_content="def rule(event):\n    return True",
    )
    filters = [Filter(key="", values=["def rule"])]
    assert filters_match_analysis_item(filters, item)


def test_text_filter_missing_from_both() -> None:
    """Text filter missing from both YAML and Python should not match."""
    item = _create_item(
        {"AnalysisType": "rule", "RuleID": "test.rule"},
        raw_yaml="AnalysisType: rule\nRuleID: test.rule",
        python_content="def other_function(event):\n    return True",
    )
    filters = [Filter(key="", values=["def rule"])]
    assert not filters_match_analysis_item(filters, item)


def test_text_filter_no_yaml_content() -> None:
    """Text filter with no YAML content matches if it appears in Python."""
    item = _create_item(
        {"AnalysisType": "rule", "RuleID": "test.rule"},
        raw_yaml=None,
        python_content="def rule(event):\n    return True",
    )
    filters = [Filter(key="", values=["def rule"])]
    assert filters_match_analysis_item(filters, item)


def test_text_filter_no_python_content() -> None:
    """Text filter with no Python content matches if it appears in YAML."""
    item = _create_item(
        {"AnalysisType": "rule", "RuleID": "test.rule"},
        raw_yaml="AnalysisType: rule\nRuleID: test.rule\ndef rule",
        python_content=None,
    )
    filters = [Filter(key="", values=["def rule"])]
    assert filters_match_analysis_item(filters, item)


def test_text_filter_multiple_text_filters() -> None:
    """Multiple text filters use AND logic - each must appear in YAML OR Python."""
    item = _create_item(
        {"AnalysisType": "rule", "RuleID": "test.rule"},
        raw_yaml="AnalysisType: rule\nRuleID: test.rule\ndef rule\nreturn True",
        python_content="def rule(event):\n    return True",
    )
    filters = [
        Filter(key="", values=["def rule"]),
        Filter(key="", values=["return True"]),
    ]
    assert filters_match_analysis_item(filters, item)

    # Should fail if one doesn't match in either YAML or Python
    filters = [
        Filter(key="", values=["def rule"]),
        Filter(key="", values=["missing text"]),
    ]
    assert not filters_match_analysis_item(filters, item)

    # Test that each filter can match in different files
    item = _create_item(
        {"AnalysisType": "rule", "RuleID": "test.rule"},
        raw_yaml="AnalysisType: rule\nRuleID: test.rule\ndef rule",
        python_content="return True",
    )
    filters = [
        Filter(key="", values=["def rule"]),  # In YAML
        Filter(key="", values=["return True"]),  # In Python
    ]
    assert filters_match_analysis_item(filters, item)


def test_mixed_filters() -> None:
    """Mixed regular and text filters use AND logic."""
    item = _create_item(
        {
            "AnalysisType": "rule",
            "RuleID": "AWS.S3.Bucket.PublicRead",
            "Severity": "Critical",
        },
        raw_yaml="AnalysisType: rule\nRuleID: AWS.S3.Bucket.PublicRead\nSeverity: Critical\ndef rule",
        python_content="def rule(event):\n    return True",
    )
    filters = [
        Filter(key="RuleID", values=["AWS.S3.Bucket.PublicRead"]),
        Filter(key="", values=["def rule"]),
    ]
    assert filters_match_analysis_item(filters, item)

    # Should fail if regular filter doesn't match
    filters = [
        Filter(key="RuleID", values=["Different.Rule"]),
        Filter(key="", values=["def rule"]),
    ]
    assert not filters_match_analysis_item(filters, item)

    # Should fail if text filter doesn't match
    filters = [
        Filter(key="RuleID", values=["AWS.S3.Bucket.PublicRead"]),
        Filter(key="", values=["missing text"]),
    ]
    assert not filters_match_analysis_item(filters, item)


def test_filter_with_list_value() -> None:
    """Filter should handle list values in YAML spec."""
    item = _create_item(
        {
            "AnalysisType": "rule",
            "RuleID": "test.rule",
            "LogTypes": ["CloudTrail", "S3"],
        }
    )
    filters = [Filter(key="LogTypes", values=["CloudTrail"])]
    assert filters_match_analysis_item(filters, item)


def test_filter_missing_key() -> None:
    """Filter for missing key should not match."""
    item = _create_item({"AnalysisType": "rule", "RuleID": "test.rule"})
    filters = [Filter(key="Severity", values=["Critical"])]
    assert not filters_match_analysis_item(filters, item)


def test_empty_string_text_filter() -> None:
    """Empty string text filter should match empty content."""
    item = _create_item(
        {"AnalysisType": "rule", "RuleID": "test.rule"},
        raw_yaml="",
        python_content="",
    )
    filters = [Filter(key="", values=[""])]
    # Empty string is in both empty strings
    assert filters_match_analysis_item(filters, item)


def test_text_filter_no_yaml_or_python_content() -> None:
    """Text filter with no YAML or Python content should not match."""
    item = _create_item(
        {"AnalysisType": "rule", "RuleID": "test.rule"},
        raw_yaml=None,
        python_content=None,
    )
    filters = [Filter(key="", values=["def rule"])]
    assert not filters_match_analysis_item(filters, item)


class TestPATSafeLoader(TestCase):
    """Tests that _PATSafeLoader preserves ruamel.yaml (YAML 1.2) semantics:
    timestamps as strings, YAML 1.1-only booleans (yes/no/on/off) as strings,
    and YAML 1.1 octal/sexagesimal integers as decimal/strings."""

    def test_timestamp_returned_as_string(self) -> None:
        yaml_content = "created: 2024-01-15\n"
        result = pyyaml.load(yaml_content, Loader=_PATSafeLoader)
        self.assertIsInstance(result["created"], str)
        self.assertEqual(result["created"], "2024-01-15")

    def test_datetime_timestamp_returned_as_string(self) -> None:
        yaml_content = "updated: 2024-01-15T10:30:00Z\n"
        result = pyyaml.load(yaml_content, Loader=_PATSafeLoader)
        self.assertIsInstance(result["updated"], str)
        self.assertEqual(result["updated"], "2024-01-15T10:30:00Z")

    def test_non_timestamp_values_unaffected(self) -> None:
        yaml_content = "name: test\ncount: 42\nenabled: true\n"
        result = pyyaml.load(yaml_content, Loader=_PATSafeLoader)
        self.assertEqual(result["name"], "test")
        self.assertEqual(result["count"], 42)
        self.assertEqual(result["enabled"], True)

    def test_yaml_1_2_booleans_remain_bool(self) -> None:
        """true/false (YAML 1.2 booleans) should still parse as Python bools."""
        yaml_content = "a: true\nb: false\nc: True\nd: False\ne: TRUE\nf: FALSE\n"
        result = pyyaml.load(yaml_content, Loader=_PATSafeLoader)
        self.assertIs(result["a"], True)
        self.assertIs(result["b"], False)
        self.assertIs(result["c"], True)
        self.assertIs(result["d"], False)
        self.assertIs(result["e"], True)
        self.assertIs(result["f"], False)

    def test_yaml_1_1_booleans_returned_as_string(self) -> None:
        """yes/no/on/off are booleans in YAML 1.1 but strings in YAML 1.2.
        _PATSafeLoader must return them as strings to match ruamel.yaml."""
        yaml_content = "a: yes\nb: no\nc: on\nd: off\n"
        result = pyyaml.load(yaml_content, Loader=_PATSafeLoader)
        for key in ("a", "b", "c", "d"):
            self.assertIsInstance(result[key], str, f"key '{key}' should be str")
        self.assertEqual(result["a"], "yes")
        self.assertEqual(result["b"], "no")
        self.assertEqual(result["c"], "on")
        self.assertEqual(result["d"], "off")

    def test_yaml_1_1_booleans_case_variants_returned_as_string(self) -> None:
        """Case variants of yes/no/on/off should also remain strings."""
        yaml_content = "a: Yes\nb: No\nc: On\nd: Off\ne: YES\nf: NO\ng: ON\nh: OFF\n"
        result = pyyaml.load(yaml_content, Loader=_PATSafeLoader)
        for key in ("a", "b", "c", "d", "e", "f", "g", "h"):
            self.assertIsInstance(result[key], str, f"key '{key}' should be str")

    def test_leading_zero_parsed_as_decimal(self) -> None:
        """YAML 1.1 treats 0644 as octal (420). YAML 1.2 treats as decimal (644)."""
        yaml_content = "a: 0644\nb: 010\n"
        result = pyyaml.load(yaml_content, Loader=_PATSafeLoader)
        self.assertEqual(result["a"], 644)
        self.assertEqual(result["b"], 10)

    def test_sexagesimal_returned_as_string(self) -> None:
        """YAML 1.1 treats 1:30:00 as sexagesimal (5400). YAML 1.2 returns string."""
        yaml_content = "duration: 1:30:00\n"
        result = pyyaml.load(yaml_content, Loader=_PATSafeLoader)
        self.assertIsInstance(result["duration"], str)
        self.assertEqual(result["duration"], "1:30:00")

    def test_hex_and_binary_integers_unaffected(self) -> None:
        """0x and 0b prefixes are the same in YAML 1.1 and 1.2."""
        yaml_content = "a: 0x1A\nb: 0b1010\n"
        result = pyyaml.load(yaml_content, Loader=_PATSafeLoader)
        self.assertEqual(result["a"], 26)
        self.assertEqual(result["b"], 10)

    def test_plain_integers_unaffected(self) -> None:
        """Regular integers should parse normally."""
        yaml_content = "a: 42\nb: 0\nc: -7\nd: 1000\n"
        result = pyyaml.load(yaml_content, Loader=_PATSafeLoader)
        self.assertEqual(result["a"], 42)
        self.assertEqual(result["b"], 0)
        self.assertEqual(result["c"], -7)
        self.assertEqual(result["d"], 1000)


class TestValidateTableNamesBatch(TestCase):
    """Tests for the _validate_table_names_batch function which handles
    both sequential and parallel (ProcessPoolExecutor) sqlfluff validation."""

    def _make_query_spec(self, query_name: str, query: str) -> tuple:
        return (
            f"{query_name}.yml",
            {
                "AnalysisType": "scheduled_query",
                "QueryName": query_name,
                "Enabled": True,
                "Query": query,
                "Schedule": {"RateMinutes": 60, "TimeoutMinutes": 5},
            },
            query_name,
        )

    def test_sequential_valid_query(self) -> None:
        pending = [self._make_query_spec(
            "Valid.Query",
            "SELECT * FROM snowflake.account_usage.login_history",
        )]
        invalid_specs: list = []
        all_specs = ClassifiedAnalysisContainer()
        all_specs.queries.append(ClassifiedAnalysis(
            "Valid.Query.yml", "/test", pending[0][1],
        ))

        _validate_table_names_batch(pending, [], invalid_specs, all_specs, workers=1)

        self.assertEqual(len(invalid_specs), 0)
        self.assertEqual(len(all_specs.queries), 1)

    def test_sequential_invalid_query(self) -> None:
        pending = [self._make_query_spec(
            "Invalid.Query",
            "SELECT * FROM bad_table",
        )]
        invalid_specs: list = []
        all_specs = ClassifiedAnalysisContainer()
        all_specs.queries.append(ClassifiedAnalysis(
            "Invalid.Query.yml", "/test", pending[0][1],
        ))

        _validate_table_names_batch(pending, [], invalid_specs, all_specs, workers=1)

        self.assertEqual(len(invalid_specs), 1)
        self.assertEqual(invalid_specs[0][0], "Invalid.Query.yml")
        # Invalid query should be removed from all_specs
        self.assertEqual(len(all_specs.queries), 0)

    def test_sequential_exception_removes_query(self) -> None:
        """When contains_invalid_table_names raises, the query should be removed (fail-closed)."""
        pending = [self._make_query_spec(
            "Error.Query",
            "SELECT * FROM snowflake.account_usage.login_history",
        )]
        invalid_specs: list = []
        all_specs = ClassifiedAnalysisContainer()
        all_specs.queries.append(ClassifiedAnalysis(
            "Error.Query.yml", "/test", pending[0][1],
        ))

        with mock.patch(
            "panther_analysis_tool.analysis_utils.contains_invalid_table_names",
            side_effect=RuntimeError("sqlfluff crash"),
        ):
            _validate_table_names_batch(pending, [], invalid_specs, all_specs, workers=1)

        # Query should be removed even though it wasn't proven invalid
        self.assertEqual(len(all_specs.queries), 0)
        # But it shouldn't appear in invalid_specs (we don't know it's invalid, just errored)
        self.assertEqual(len(invalid_specs), 0)

    def test_parallel_produces_same_results_as_sequential(self) -> None:
        valid_spec = self._make_query_spec(
            "Valid.Query",
            "SELECT * FROM snowflake.account_usage.login_history",
        )
        invalid_spec = self._make_query_spec(
            "Invalid.Query",
            "SELECT * FROM bad_table",
        )
        pending = [valid_spec, invalid_spec]

        # Run sequential
        invalid_seq: list = []
        specs_seq = ClassifiedAnalysisContainer()
        specs_seq.queries.append(ClassifiedAnalysis("Valid.Query.yml", "/test", valid_spec[1]))
        specs_seq.queries.append(ClassifiedAnalysis("Invalid.Query.yml", "/test", invalid_spec[1]))
        _validate_table_names_batch(pending, [], invalid_seq, specs_seq, workers=1)

        # Run parallel
        invalid_par: list = []
        specs_par = ClassifiedAnalysisContainer()
        specs_par.queries.append(ClassifiedAnalysis("Valid.Query.yml", "/test", valid_spec[1]))
        specs_par.queries.append(ClassifiedAnalysis("Invalid.Query.yml", "/test", invalid_spec[1]))
        _validate_table_names_batch(pending, [], invalid_par, specs_par, workers=2)

        # Same invalid specs detected
        self.assertEqual(len(invalid_seq), len(invalid_par))
        self.assertEqual(invalid_seq[0][0], invalid_par[0][0])
        # Same valid queries remaining
        self.assertEqual(len(specs_seq.queries), len(specs_par.queries))
