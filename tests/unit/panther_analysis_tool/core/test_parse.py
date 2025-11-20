import os
from unittest import TestCase
from unittest.mock import patch

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
            self.assertIn(Filter(key="RuleID", values=["abc"]), parsed_filters_inverted)
            # by default: experimental and deprecated should always be filtered out
            self.assertIn(
                Filter(key="Status", values=["experimental", "deprecated"]), parsed_filters_inverted
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
            self.assertIn(Filter(key="RuleID", values=["abc"]), parsed_filters_inverted)
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
