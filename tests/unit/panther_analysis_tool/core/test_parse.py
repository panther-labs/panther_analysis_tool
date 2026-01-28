import os
from unittest import TestCase
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from panther_analysis_tool import main as pat
from panther_analysis_tool.core import parse
from panther_analysis_tool.core.parse import Filter

FIXTURES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../", "fixtures"))
DETECTIONS_FIXTURES_PATH = os.path.join(FIXTURES_PATH, "detections")
runner = CliRunner()


class TestParser(TestCase):
    def test_parse_filters(self) -> None:
        with patch(
            "panther_analysis_tool.main.test_analysis", return_value=(0, [])
        ) as mock_test_analysis:
            result = runner.invoke(
                pat.app,
                [
                    "test",
                    "--path",
                    f"{DETECTIONS_FIXTURES_PATH}/valid_analysis",
                    "--filter",
                    "AnalysisType=policy,global",
                    "--filter",
                    "Severity=Critical",
                    "--filter",
                    "Enabled=true",
                    "--filter",
                    "RuleID!=abc",
                ],
            )

            if result.exception:
                raise result.exception

            self.assertEqual(result.exit_code, 0)

            mock_test_analysis.return_value = (0, [])

            args = mock_test_analysis.call_args[0][1]

            parsed_filters, parsed_filters_inverted = args.filters, args.filters_inverted
            self.assertIn(Filter(key="AnalysisType", values=["policy", "global"]), parsed_filters)
            self.assertIn(Filter(key="Severity", values=["Critical"]), parsed_filters)
            self.assertIn(Filter(key="Enabled", values=[True]), parsed_filters)
            self.assertIn(
                Filter(key="RuleID", values=["abc"], inverted=True), parsed_filters_inverted
            )
            # by default: experimental and deprecated should always be filtered out
            self.assertIn(
                Filter(key="Status", values=["experimental", "deprecated"], inverted=True),
                parsed_filters_inverted,
            )

    def test_parse_filters_status_can_be_overridden(self) -> None:
        with patch(
            "panther_analysis_tool.main.test_analysis", return_value=(0, [])
        ) as mock_test_analysis:
            result = runner.invoke(
                pat.app,
                [
                    "test",
                    "--path",
                    f"{DETECTIONS_FIXTURES_PATH}/valid_analysis",
                    "--filter",
                    "AnalysisType=policy,global",
                    "--filter",
                    "Severity=Critical",
                    "--filter",
                    "Enabled=true",
                    "--filter",
                    "RuleID!=abc",
                    "--filter",
                    "Status=experimental",
                ],
            )

            if result.exception:
                raise result.exception

            self.assertEqual(result.exit_code, 0)

            mock_test_analysis.return_value = (0, [])

            args = mock_test_analysis.call_args[0][1]

            parsed_filters, parsed_filters_inverted = args.filters, args.filters_inverted
            self.assertIn(Filter(key="AnalysisType", values=["policy", "global"]), parsed_filters)
            self.assertIn(Filter(key="Severity", values=["Critical"]), parsed_filters)
            self.assertIn(Filter(key="Enabled", values=[True]), parsed_filters)
            self.assertIn(
                Filter(key="RuleID", values=["abc"], inverted=True), parsed_filters_inverted
            )
            # user explicitly added a filter on status: we should not have added Status != experimental,deprecated
            self.assertNotIn(
                Filter(key="Status", values=["experimental", "deprecated"]), parsed_filters_inverted
            )
            # user's status filter:
            self.assertIn(Filter(key="Status", values=["experimental"]), parsed_filters)


def test_collect_top_level_imports() -> None:
    py = """
from top import foo
import bar
import baz.qux
import goo.foo as goofoo
from baz.qux import quux
from scoob.qux import quux as quuux
from alpha import beta, gamma
from alpha.beta import delta, epsilon
    """
    imports = parse.collect_top_level_imports(py.encode("utf-8"))
    assert imports == {"top", "bar", "baz", "scoob", "goo", "alpha"}


def test_collect_top_level_imports_empty() -> None:
    py = """
    """
    imports = parse.collect_top_level_imports(py.encode("utf-8"))
    assert imports == set()


@pytest.mark.parametrize(
    "search_terms,expected",
    [
        # Empty cases
        ([], []),
        ([""], []),
        # Valid filters - single values
        (
            ["RuleID=AWS.S3.Bucket.PublicRead", "Enabled=true", "Severity=Critical"],
            [
                Filter(key="RuleID", values=["AWS.S3.Bucket.PublicRead"]),
                Filter(key="Enabled", values=[True]),
                Filter(key="Severity", values=["Critical"]),
            ],
        ),
        # Valid filters - inverted
        (
            ["RuleID!=AWS.S3.Bucket.PublicRead", "Enabled=false", "Severity=High"],
            [
                Filter(key="RuleID", values=["AWS.S3.Bucket.PublicRead"], inverted=True),
                Filter(key="Enabled", values=[False]),
                Filter(key="Severity", values=["High"]),
            ],
        ),
        # Multiple comma-separated values
        (
            ["AnalysisType=policy,global,rule", "Severity=Critical,High"],
            [
                Filter(key="AnalysisType", values=["policy", "global", "rule"]),
                Filter(key="Severity", values=["Critical", "High"]),
            ],
        ),
        # Inverted with multiple values
        (
            ["RuleID!=rule1,rule2,rule3"],
            [Filter(key="RuleID", values=["rule1", "rule2", "rule3"], inverted=True)],
        ),
        # Boolean field variations
        (
            ["Enabled=true", "Enabled=false", "Enabled=1", "Enabled=0"],
            [
                Filter(key="Enabled", values=[True]),
                Filter(key="Enabled", values=[False]),
                Filter(key="Enabled", values=[True]),
                Filter(key="Enabled", values=[False]),
            ],
        ),
        # Mixed valid filters and plain text
        (
            ["RuleID=test.rule", "plain search term", "Severity=High"],
            [
                Filter(key="RuleID", values=["test.rule"]),
                Filter(key="", values=["plain search term"]),
                Filter(key="Severity", values=["High"]),
            ],
        ),
        # Plain text (not filters)
        (["just some text"], [Filter(key="", values=["just some text"])]),
        (
            ["multiple", "plain", "terms"],
            [
                Filter(key="", values=["multiple"]),
                Filter(key="", values=["plain"]),
                Filter(key="", values=["terms"]),
            ],
        ),
        # Invalid filter formats - should fall back to plain text
        (["ruleid=Something"], [Filter(key="", values=["ruleid=Something"])]),  # Case sensitive
        (
            ["this => arrow"],
            [Filter(key="", values=["this => arrow"])],
        ),  # Has = but not KEY=VALUE format
        (
            ["this!=>arrow"],
            [Filter(key="", values=["this!=>arrow"])],
        ),  # Has != but not KEY!=VALUE format
        (["=value"], [Filter(key="", values=["=value"])]),  # Empty key
        (["key="], [Filter(key="", values=["key="])]),  # Empty value
        (["noequals"], [Filter(key="", values=["noequals"])]),  # No equals sign
        # Invalid boolean values - should fall back to plain text
        (["Enabled=maybe"], [Filter(key="", values=["Enabled=maybe"])]),
        (["Enabled=yesno"], [Filter(key="", values=["Enabled=yesno"])]),
        # Invalid filter keys - should fall back to plain text
        (["InvalidKey=value"], [Filter(key="", values=["InvalidKey=value"])]),
        (["NotAKey=something"], [Filter(key="", values=["NotAKey=something"])]),
        # Edge cases with special characters
        (["RuleID=test.rule.with.dots"], [Filter(key="RuleID", values=["test.rule.with.dots"])]),
        (
            ["RuleID=test-rule-with-dashes"],
            [Filter(key="RuleID", values=["test-rule-with-dashes"])],
        ),
        (
            ["RuleID=test_rule_with_underscores"],
            [Filter(key="RuleID", values=["test_rule_with_underscores"])],
        ),
        (
            ["Severity=Critical,High,Medium"],
            [Filter(key="Severity", values=["Critical", "High", "Medium"])],
        ),
        # Multiple filters of same type (should create multiple Filter objects)
        (
            ["RuleID=rule1", "RuleID=rule2"],
            [
                Filter(key="RuleID", values=["rule1"]),
                Filter(key="RuleID", values=["rule2"]),
            ],
        ),
        # Mixed inverted and non-inverted of same key
        (
            ["RuleID=rule1", "RuleID!=rule2"],
            [
                Filter(key="RuleID", values=["rule1"]),
                Filter(key="RuleID", values=["rule2"], inverted=True),
            ],
        ),
        # Status field
        (
            ["Status=stable", "Status!=experimental"],
            [
                Filter(key="Status", values=["stable"]),
                Filter(key="Status", values=["experimental"], inverted=True),
            ],
        ),
        # AnalysisType with multiple values
        (
            ["AnalysisType=rule,policy,datamodel"],
            [Filter(key="AnalysisType", values=["rule", "policy", "datamodel"])],
        ),
    ],
)
def test_search_terms_to_filters(search_terms: list[str], expected: list[Filter]) -> None:
    assert parse.search_terms_to_filters(search_terms) == expected
