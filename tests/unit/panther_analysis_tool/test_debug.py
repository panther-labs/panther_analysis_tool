import argparse
import io
import logging
import os
import sys
import traceback
import unittest
from unittest import mock
from unittest.mock import MagicMock, patch

from pyfakefs.fake_filesystem_unittest import Pause, TestCase
from typer.testing import CliRunner

from panther_analysis_tool import main as pat
from panther_analysis_tool.backend.mocks import MockBackend
from panther_analysis_tool.main import app, debug_analysis

FIXTURES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../", "fixtures"))
DETECTIONS_FIXTURES_PATH = os.path.join(FIXTURES_PATH, "detections")


runner = CliRunner()


def mock_debug_analysis(tc: TestCase, args: list[str]) -> tuple[int, list[str]]:
    return_code = -1
    invalid_specs = None

    def check_result(*args, **kwargs) -> tuple[int, list[str]]:
        nonlocal return_code, invalid_specs
        return_code, invalid_specs = debug_analysis(*args, **kwargs)
        return return_code, invalid_specs

    with patch(
        "panther_analysis_tool.main.debug_analysis", side_effect=check_result
    ) as mock_test_analysis:
        result = runner.invoke(app, args)
        if result.exception:
            if not isinstance(result.exception, SystemExit):
                # re-raise the exception
                raise result.exception
        tc.assertEqual(mock_test_analysis.call_count, 1)

    return return_code, invalid_specs


class TestDebugFunctionality(TestCase):
    """Test suite for debugging functionality in panther_analysis_tool."""

    def setUp(self):
        """Set up test fixtures and mock filesystem."""
        self.setUpPyfakefs()
        self.fs.add_real_directory(FIXTURES_PATH)

        # Simple path for mock tests (not used by integration test anymore)
        self.test_rule_path = "test_rule"
        pat._DISABLE_PANTHER_EXCEPTION_HANDLER = True

    def tearDown(self):
        pat._DISABLE_PANTHER_EXCEPTION_HANDLER = False

    def test_debug_analysis_basic_functionality(self):
        """Test that debug_analysis function works with basic parameters."""
        # Mock test_analysis to verify it's called with correct debug args
        with patch.object(pat, "test_analysis") as mock_test_analysis:
            mock_test_analysis.return_value = (0, [])

            return_code, invalid_specs = mock_debug_analysis(
                self, ["debug", "Test.Debug.Rule", "Test Case 1", "--path", self.test_rule_path]
            )

            # Verify test_analysis was called with debug args
            mock_test_analysis.assert_called_once()
            call_args = mock_test_analysis.call_args

            # Check that debug_args was passed correctly
            debug_args = call_args[1].get("debug_args", {})
            self.assertTrue(debug_args.get("debug_mode"))
            self.assertEqual(debug_args.get("test_name"), "Test Case 1")

            # Check that filter was set correctly
            args_passed = call_args[0][1]
            self.assertEqual(args_passed.filter, {"RuleID": ["Test.Debug.Rule"]})
            self.assertEqual(args_passed.minimum_tests, 0)
            self.assertFalse(args_passed.sort_test_results)
            self.assertFalse(args_passed.show_failures_only)

    def test_debug_analysis_with_backend(self):
        """Test debug_analysis with a backend client."""
        backend = MockBackend()

        with (
            patch(
                "panther_analysis_tool.main.pat_utils.get_optional_backend", return_value=backend
            ),
            patch.object(pat, "test_analysis") as mock_test_analysis,
        ):
            mock_test_analysis.return_value = (0, [])

            return_code, invalid_specs = mock_debug_analysis(
                self, ["debug", "Test.Debug.Rule", "Test Case 1", "--path", self.test_rule_path]
            )

            # Verify backend was passed through
            mock_test_analysis.assert_called_once()
            call_args = mock_test_analysis.call_args
            self.assertEqual(call_args[0][0], backend)

    def test_debug_parser_arguments(self):
        """Test that the debug command parser accepts correct arguments."""

        # Test basic debug command
        with (patch.object(pat, "test_analysis") as mock_test_analysis,):
            mock_test_analysis.return_value = (0, [])
            mock_debug_analysis(self, ["debug", "Test.Rule.ID", "Test Name"])

            args = mock_test_analysis.call_args[0][1]
            self.assertEqual(args.ruleid, "Test.Rule.ID")
            self.assertEqual(args.testname, "Test Name")

        with (patch.object(pat, "test_analysis") as mock_test_analysis,):
            mock_test_analysis.return_value = (0, [])

            # Test with additional arguments
            mock_debug_analysis(
                self,
                [
                    "debug",
                    "Test.Rule.ID",
                    "Test Name",
                    "--path",
                    "/some/path",
                    "--filter",
                    "Severity=High",
                    "--ignore-files",
                    "file1.yml",
                    "--ignore-files",
                    "file2.yml",
                ],
            )
            args = mock_test_analysis.call_args[0][1]
            self.assertEqual(args.path, "/some/path")
            self.assertEqual(args.ignore_files, ["file1.yml", "file2.yml"])

    def test_run_tests_debug_mode_output_redirection(self):
        """Test that debug mode redirects output to stdout instead of StringIO."""
        # Use the RuleThatPrints fixture
        import os
        from collections import defaultdict

        from panther_core.rule import Rule

        # Use the RuleThatPrints fixture
        fixture_path = os.path.join(FIXTURES_PATH, "detections", "debug", "rule_that_prints.py")
        rule_args = {
            "path": fixture_path,
            "id": "Debug.RuleThatPrints",
            "analysisType": "RULE",
            "versionId": "test",
        }
        detection = Rule(rule_args)
        detection.suppress_alert = False

        tests = [
            {
                "Name": "User MFA enabled passes compliance.",
                "ExpectedResult": True,
                "Log": {
                    "Arn": "arn:aws:iam::123456789012:user/test",
                    "CreateDate": "2019-01-01",
                    "CredentialReport": {"MfaActive": True, "PasswordEnabled": True},
                    "UserName": "test",
                    "p_log_type": "AWS.CloudTrail",
                },
            }
        ]

        failed_tests = defaultdict(list)
        debug_args = {"debug_mode": True, "test_name": "User MFA enabled passes compliance."}

        # Capture stdout to verify debug output goes there
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            result = pat._run_tests(
                analysis_data_models={},
                detection=detection,
                tests=tests,
                failed_tests=failed_tests,
                destinations_by_name={},
                ignore_exception_types=[],
                all_test_results=None,
                correlation_rule_test_results=[],
                detection_id="Debug.RuleThatPrints",
                test_names=["User MFA enabled passes compliance."],
                debug_args=debug_args,
            )

            # In debug mode, output should go to stdout (which we've mocked)
            output = mock_stdout.getvalue()
            self.assertIn("Test output", output)

    def test_run_tests_debug_mode_exception_handling(self):
        """Test that debug mode prints exceptions with traceback."""
        import os
        from collections import defaultdict

        from panther_core.rule import Rule

        # Use the RuleWithError fixture
        fixture_path = os.path.join(FIXTURES_PATH, "detections", "debug", "rule_with_error.py")
        rule_args = {
            "path": fixture_path,
            "id": "Debug.RuleWithError",
            "analysisType": "RULE",
            "versionId": "test",
        }
        detection = Rule(rule_args)
        detection.suppress_alert = False

        tests = [
            {
                "Name": "Root MFA not enabled fails compliance",
                "ExpectedResult": False,
                "Log": {
                    "Arn": "arn:aws:iam::123456789012:user/root",
                    "CreateDate": "2019-01-01T00:00:00Z",
                    "CredentialReport": {"MfaActive": False, "PasswordEnabled": True},
                    "UserName": "root",
                    "p_log_type": "AWS.CloudTrail",
                },
            }
        ]

        failed_tests = defaultdict(list)
        debug_args = {"debug_mode": True, "test_name": "Root MFA not enabled fails compliance"}

        # Mock logging.error to capture exception logging
        with (
            patch("panther_analysis_tool.main.logging.error") as mock_error,
            patch("panther_analysis_tool.main.traceback.print_tb") as mock_print_tb,
        ):
            result = pat._run_tests(
                analysis_data_models={},
                detection=detection,
                tests=tests,
                failed_tests=failed_tests,
                destinations_by_name={},
                ignore_exception_types=[],
                all_test_results=None,
                correlation_rule_test_results=[],
                detection_id="Debug.RuleWithError",
                test_names=["Root MFA not enabled fails compliance"],
                debug_args=debug_args,
            )

            # Verify that the exception was logged in debug mode
            mock_error.assert_called()
            mock_print_tb.assert_called()

    def test_run_tests_debug_mode_traceback_modification(self):
        """Test that debug mode modifies traceback to show exceptions relative to rule.py."""
        import os
        from collections import defaultdict

        from panther_core.rule import Rule

        # Use the fixture that raises an exception
        fixture_path = os.path.join(FIXTURES_PATH, "detections", "debug", "rule_with_error.py")
        rule_args = {
            "path": fixture_path,
            "id": "Debug.RuleWithError",
            "analysisType": "RULE",
            "versionId": "test",
        }
        detection = Rule(rule_args)
        detection.suppress_alert = False

        # Use one of the test cases from the fixture
        tests = [
            {
                "Name": "Root MFA not enabled fails compliance",
                "ExpectedResult": False,
                "Log": {
                    "Arn": "arn:aws:iam::123456789012:user/root",
                    "CreateDate": "2019-01-01T00:00:00Z",
                    "CredentialReport": {"MfaActive": False, "PasswordEnabled": True},
                    "UserName": "root",
                    "p_log_type": "AWS.CloudTrail",
                },
            }
        ]

        failed_tests = defaultdict(list)
        debug_args = {"debug_mode": True, "test_name": "Root MFA not enabled fails compliance"}

        mock_print_tb = MagicMock()
        with patch("traceback.print_tb", mock_print_tb):
            result = pat._run_tests(
                analysis_data_models={},
                detection=detection,
                tests=tests,
                failed_tests=failed_tests,
                destinations_by_name={},
                ignore_exception_types=[],
                all_test_results=None,
                correlation_rule_test_results=[],
                detection_id="Debug.RuleWithError",
                test_names=["Root MFA not enabled fails compliance"],
                debug_args=debug_args,
            )

        self.assertEqual(mock_print_tb.call_count, 1)
        err = mock_print_tb.call_args.args[0]
        self.assertEqual(traceback.extract_tb(err)[0].name, "rule")
        self.assertEqual(len(traceback.extract_tb(err)), 2)

    def test_run_tests_debug_mode_nonexistent_test_warning(self):
        """Test that debug mode warns when specified test doesn't exist."""
        from collections import defaultdict

        from panther_core.rule import Rule

        rule_args = {
            "body": "def rule(event): return True",
            "id": "Test.Debug.Rule",
            "analysisType": "RULE",
            "versionId": "test",
        }
        detection = Rule(rule_args)
        detection.suppress_alert = False

        tests = [
            {
                "Name": "Test Case 1",
                "ExpectedResult": True,
                "Log": {"eventName": "test", "p_log_type": "AWS.CloudTrail"},
            }
        ]

        failed_tests = defaultdict(list)
        debug_args = {"debug_mode": True, "test_name": "Nonexistent Test"}

        with patch("panther_analysis_tool.main.logging.warning") as mock_warning:
            result = pat._run_tests(
                analysis_data_models={},
                detection=detection,
                tests=tests,
                failed_tests=failed_tests,
                destinations_by_name={},
                ignore_exception_types=[],
                all_test_results=None,
                correlation_rule_test_results=[],
                detection_id="Test.Debug.Rule",
                test_names=["Nonexistent Test"],
                debug_args=debug_args,
            )

            # Should warn about nonexistent test
            mock_warning.assert_called_with("No test found with name %s", "Nonexistent Test")

    def test_run_tests_normal_mode_vs_debug_mode(self):
        """Test the difference between normal mode and debug mode behavior."""
        import os
        from collections import defaultdict

        from panther_core.rule import Rule

        # Use the RuleThatPrints fixture
        fixture_path = os.path.join(FIXTURES_PATH, "detections", "debug", "rule_that_prints.py")
        rule_args = {
            "path": fixture_path,
            "id": "Debug.RuleThatPrints",
            "analysisType": "RULE",
            "versionId": "test",
        }
        detection = Rule(rule_args)
        detection.suppress_alert = False

        tests = [
            {
                "Name": "User MFA enabled passes compliance.",
                "ExpectedResult": True,
                "Log": {
                    "Arn": "arn:aws:iam::123456789012:user/test",
                    "CreateDate": "2019-01-01",
                    "CredentialReport": {"MfaActive": True, "PasswordEnabled": True},
                    "UserName": "test",
                    "p_log_type": "AWS.CloudTrail",
                },
            }
        ]

        failed_tests = defaultdict(list)

        # Test normal mode (output should be captured)
        with patch("panther_analysis_tool.main._print_test_result") as mock_print:
            result_normal = pat._run_tests(
                analysis_data_models={},
                detection=detection,
                tests=tests,
                failed_tests=failed_tests,
                destinations_by_name={},
                ignore_exception_types=[],
                all_test_results=None,
                correlation_rule_test_results=[],
                detection_id="Debug.RuleThatPrints",
                debug_args=None,
            )

            # In normal mode, test results should be printed
            mock_print.assert_called_once()

        # Test debug mode (output should go to stdout, no test result printing)
        debug_args = {"debug_mode": True, "test_name": "User MFA enabled passes compliance."}

        with (
            patch("sys.stdout", new_callable=io.StringIO) as mock_stdout,
            patch("panther_analysis_tool.main._print_test_result") as mock_print,
        ):
            result_debug = pat._run_tests(
                analysis_data_models={},
                detection=detection,
                tests=tests,
                failed_tests=failed_tests,
                destinations_by_name={},
                ignore_exception_types=[],
                all_test_results=None,
                correlation_rule_test_results=[],
                detection_id="Debug.RuleThatPrints",
                test_names=["User MFA enabled passes compliance."],
                debug_args=debug_args,
            )

            # In debug mode, test results should NOT be printed by _print_test_result
            mock_print.assert_not_called()

            # But output should go to stdout
            self.assertIn("Test output", mock_stdout.getvalue())

    def test_test_analysis_with_debug_args(self):
        """Test that test_analysis properly handles debug_args parameter."""
        # Set up required args attributes that test_analysis expects
        args = argparse.Namespace(
            path=self.test_rule_path,
            filter=None,
            filter_inverted={},
            ignore_table_names=True,
            valid_table_names=[],
            ignore_files=[],
            available_destination=None,
            sort_test_results=False,
            show_failures_only=False,
            minimum_tests=0,
            skip_disabled_tests=False,
        )

        debug_args = {"debug_mode": True, "test_name": "Test Case 1"}

        # Mock the internal functions to verify debug_args is passed through
        with (
            patch.object(pat, "load_analysis") as mock_load,
            patch.object(pat, "setup_run_tests") as mock_setup_tests,
            patch.object(pat, "setup_global_helpers"),
            patch.object(pat, "setup_data_models") as mock_setup_data_models,
            patch.object(pat, "cleanup_global_helpers"),
            patch.object(pat, "validate_packs") as mock_validate_packs,
        ):
            mock_setup_tests.return_value = ({}, [], [])
            mock_setup_data_models.return_value = ({}, [])
            mock_validate_packs.return_value = []

            # Mock a minimal specs object
            mock_specs = MagicMock()
            mock_specs.empty.return_value = False
            mock_specs.simple_detections = []
            mock_specs.detections = []
            mock_specs.globals = []
            mock_specs.data_models = []

            # Mock the result of specs.apply() to also return a specs-like object
            mock_filtered_specs = MagicMock()
            mock_filtered_specs.empty.return_value = False
            mock_filtered_specs.simple_detections = []
            mock_filtered_specs.detections = []
            mock_filtered_specs.globals = []
            mock_filtered_specs.data_models = []
            mock_specs.apply.return_value = mock_filtered_specs

            mock_load.return_value = (mock_specs, [])

            return_code, invalid_specs = pat.test_analysis(None, args, debug_args=debug_args)

            # Verify that setup_run_tests was called with debug_args
            mock_setup_tests.assert_called_once()
            call_args = mock_setup_tests.call_args
            self.assertEqual(call_args[1]["debug_args"], debug_args)

    def test_debug_analysis_integration(self):
        """Integration test focusing on debug_analysis -> test_analysis integration."""
        # Mock test_analysis to verify integration without filesystem complexity
        with patch.object(pat, "test_analysis") as mock_test_analysis:
            mock_test_analysis.return_value = (0, [])

            return_code, invalid_specs = mock_debug_analysis(
                self, ["debug", "Test.Debug.Rule", "Test Case 1", "--path", self.test_rule_path]
            )

            # Verify debug_analysis correctly calls test_analysis
            mock_test_analysis.assert_called_once()
            call_args = mock_test_analysis.call_args

            # Check that args were modified correctly by debug_analysis
            args_passed = call_args[0][1]
            self.assertEqual(args_passed.filter, {"RuleID": ["Test.Debug.Rule"]})
            self.assertEqual(args_passed.minimum_tests, 0)
            self.assertFalse(args_passed.sort_test_results)
            self.assertFalse(args_passed.show_failures_only)

            # Check that debug_args were passed correctly
            debug_args = call_args[1].get("debug_args", {})
            self.assertTrue(debug_args.get("debug_mode"))
            self.assertEqual(debug_args.get("test_name"), "Test Case 1")

            # Check return values
            self.assertEqual(return_code, 0)
            self.assertEqual(len(invalid_specs), 0)

    def test_debug_with_filters(self):
        """Test debug functionality with additional filters."""
        with patch.object(pat, "test_analysis") as mock_test_analysis:
            mock_test_analysis.return_value = (0, [])

            mock_debug_analysis(
                self,
                [
                    "debug",
                    "Test.Debug.Rule",
                    "Test Case 1",
                    "--path",
                    self.test_rule_path,
                    "--filter",
                    "Severity=Medium",
                ],
            )

            # Verify that both the RuleID filter and additional filters are applied
            call_args = mock_test_analysis.call_args
            args_passed = call_args[0][1]

            # The RuleID filter should be set by debug_analysis
            self.assertEqual(args_passed.filter, {"RuleID": ["Test.Debug.Rule"]})

    def test_test_analysis_skips_summary_in_debug_mode(self):
        """Test that test_analysis skips the summary when in debug mode."""
        args = argparse.Namespace(
            path=self.test_rule_path,
            filter=None,
            filter_inverted={},
            ignore_table_names=True,
            valid_table_names=[],
            ignore_files=[],
            available_destination=None,
            sort_test_results=False,
            show_failures_only=False,
            minimum_tests=0,
            skip_disabled_tests=False,
        )
        # Set up required args attributes that test_analysis expects
        args.filter = None
        args.filter_inverted = {}

        debug_args = {"debug_mode": True, "test_name": "Test Case 1"}

        # Mock the internal functions and print_summary
        with (
            patch.object(pat, "load_analysis") as mock_load,
            patch.object(pat, "setup_run_tests") as mock_setup_tests,
            patch.object(pat, "print_summary") as mock_print_summary,
            patch.object(pat, "setup_global_helpers"),
            patch.object(pat, "setup_data_models") as mock_setup_data_models,
            patch.object(pat, "cleanup_global_helpers"),
            patch.object(pat, "validate_packs") as mock_validate_packs,
        ):
            # Mock minimal setup
            mock_specs = MagicMock()
            mock_specs.empty.return_value = False
            mock_specs.simple_detections = []
            mock_specs.detections = []
            mock_specs.globals = []
            mock_specs.data_models = []

            # Mock the result of specs.apply() to also return a specs-like object
            mock_filtered_specs = MagicMock()
            mock_filtered_specs.empty.return_value = False
            mock_filtered_specs.simple_detections = []
            mock_filtered_specs.detections = []
            mock_filtered_specs.globals = []
            mock_filtered_specs.data_models = []
            mock_specs.apply.return_value = mock_filtered_specs

            mock_load.return_value = (mock_specs, [])
            mock_setup_tests.return_value = ({}, [], [])
            mock_setup_data_models.return_value = ({}, [])
            mock_validate_packs.return_value = []

            # Test without debug args - should print summary
            pat.test_analysis(None, args)
            mock_print_summary.assert_called_once()

            # Reset mock
            mock_print_summary.reset_mock()

            # Test with debug args - should NOT print summary
            pat.test_analysis(None, args, debug_args=debug_args)
            mock_print_summary.assert_not_called()


if __name__ == "__main__":
    unittest.main()
