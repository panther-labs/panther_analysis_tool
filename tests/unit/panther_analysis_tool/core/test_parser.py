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
    def test_parse_filters(self):
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

    def test_parse_filters_status_cannot_be_overridden(self):
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
            # experimental/deprecated should always be excluded, even when user explicitly requests them
            # experimental should be stripped from the positive filter
            self.assertIn(Filter(key="Status", values=[]), parsed_filters)

    def test_add_status_filters_no_status_filter(self):
        """Test that defaults are added when no Status filter is provided"""
        filters = [Filter(key="Severity", values=["Critical"])]
        filters_inverted = [Filter(key="RuleID", values=["abc"])]

        result_filters, result_filters_inverted = parse.add_status_filters(
            filters, filters_inverted
        )

        # Original filters should be unchanged
        self.assertIn(Filter(key="Severity", values=["Critical"]), result_filters)
        self.assertIn(Filter(key="RuleID", values=["abc"]), result_filters_inverted)
        # Default status filter should be added
        self.assertIn(
            Filter(key="Status", values=["experimental", "deprecated"]), result_filters_inverted
        )

    def test_add_status_filters_regular_status_filter(self):
        """Test that experimental/deprecated are always excluded even with a positive Status filter"""
        filters = [
            Filter(key="Severity", values=["Critical"]),
            Filter(key="Status", values=["active", "experimental"]),
        ]
        filters_inverted = [Filter(key="RuleID", values=["abc"])]

        result_filters, result_filters_inverted = parse.add_status_filters(
            filters, filters_inverted
        )

        # Original non-Status filters should be unchanged
        self.assertIn(Filter(key="Severity", values=["Critical"]), result_filters)
        self.assertIn(Filter(key="RuleID", values=["abc"]), result_filters_inverted)
        # experimental should be stripped from the positive Status filter
        status_filter = next(f for f in result_filters if f.key == "Status")
        self.assertIn("active", status_filter.values)
        self.assertNotIn("experimental", status_filter.values)
        self.assertNotIn("deprecated", status_filter.values)

    def test_add_status_filters_inverted_status_filter(self):
        """Test that defaults are merged when an inverted Status filter is provided"""
        filters = [Filter(key="Severity", values=["Critical"])]
        filters_inverted = [
            Filter(key="RuleID", values=["abc"]),
            Filter(key="Status", values=["alpha"]),
        ]

        result_filters, result_filters_inverted = parse.add_status_filters(
            filters, filters_inverted
        )

        # Original non-Status filters should be unchanged
        self.assertIn(Filter(key="Severity", values=["Critical"]), result_filters)
        self.assertIn(Filter(key="RuleID", values=["abc"]), result_filters_inverted)
        # Status filter should be merged with defaults
        self.assertIn(
            Filter(key="Status", values=["alpha", "experimental", "deprecated"]),
            result_filters_inverted,
        )
        # Original Status filter should not be there anymore (replaced with merged version)
        self.assertNotIn(Filter(key="Status", values=["alpha"]), result_filters_inverted)

    def test_add_status_filters_inverted_status_filter_with_duplicate(self):
        """Test that duplicates are not added when merging inverted Status filters"""
        filters = []
        filters_inverted = [Filter(key="Status", values=["alpha", "experimental"])]

        result_filters, result_filters_inverted = parse.add_status_filters(
            filters, filters_inverted
        )

        # Status filter should include all values without duplicates
        status_filter = next(f for f in result_filters_inverted if f.key == "Status")
        self.assertEqual(len(status_filter.values), 3)  # alpha, experimental, deprecated
        self.assertIn("alpha", status_filter.values)
        self.assertIn("experimental", status_filter.values)
        self.assertIn("deprecated", status_filter.values)

    def test_add_status_filters_empty_lists(self):
        """Test that defaults are added when both filter lists are empty"""
        filters = []
        filters_inverted = []

        result_filters, result_filters_inverted = parse.add_status_filters(
            filters, filters_inverted
        )

        # Filters should be empty
        self.assertEqual(len(result_filters), 0)
        # Default status filter should be added to inverted filters
        self.assertIn(
            Filter(key="Status", values=["experimental", "deprecated"]), result_filters_inverted
        )

    def test_add_status_filters_both_regular_and_inverted(self):
        """Test that defaults are always merged even when both regular and inverted Status filters are provided"""
        filters = [
            Filter(key="Severity", values=["Critical"]),
            Filter(key="Status", values=["active", "deprecated"]),
        ]
        filters_inverted = [
            Filter(key="RuleID", values=["abc"]),
            Filter(key="Status", values=["alpha"]),
        ]

        result_filters, result_filters_inverted = parse.add_status_filters(
            filters, filters_inverted
        )

        # Original non-Status filters should be unchanged
        self.assertIn(Filter(key="Severity", values=["Critical"]), result_filters)
        self.assertIn(Filter(key="RuleID", values=["abc"]), result_filters_inverted)
        # deprecated should be stripped from the positive Status filter
        status_filter = next(f for f in result_filters if f.key == "Status")
        self.assertIn("active", status_filter.values)
        self.assertNotIn("deprecated", status_filter.values)
        # Inverted Status filter should be merged with defaults
        inverted_status = next(f for f in result_filters_inverted if f.key == "Status")
        self.assertIn("alpha", inverted_status.values)
        self.assertIn("experimental", inverted_status.values)
        self.assertIn("deprecated", inverted_status.values)
