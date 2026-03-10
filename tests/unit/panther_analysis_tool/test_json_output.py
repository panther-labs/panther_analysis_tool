"""Tests for --output-format json feature: serialization helpers, JSON output functions, and global infrastructure."""

import json
from collections import defaultdict
from io import StringIO
from typing import Any, DefaultDict, Dict, List, Optional, Tuple
from unittest import TestCase, mock

from panther_analysis_tool.command.standard_args import OutputFormat
from panther_analysis_tool.core.definitions import (
    TestResultContainer,
    TestResultsContainer,
)
from panther_analysis_tool.main import (
    _check_packs_json_default,
    _command_emits_own_json,
    _emit_check_packs_json,
    _emit_json_result,
    _print_json_error,
    _print_json_output,
    _serialize_function_result,
    _serialize_test_result,
)
from panther_analysis_tool.output import get_output_format, is_json_mode
from panther_core.testing import TestResult, TestResultsPerFunction


def _make_test_result(
    name: str = "test-1",
    passed: bool = True,
    errored: bool = False,
    generic_error: Optional[str] = None,
    detection_id: str = "Rule.Example",
    functions: Optional[TestResultsPerFunction] = None,
) -> TestResult:
    """Build a minimal TestResult for testing."""
    return TestResult(
        id=name,
        name=name,
        detectionId=detection_id,
        genericError=generic_error,
        error=None,
        errored=errored,
        passed=passed,
        trigger_alert=None,
        functions=functions or TestResultsPerFunction(detectionFunction=None),
    )


class TestSerializeFunctionResult(TestCase):
    """Tests for _serialize_function_result."""

    def test_none_input_returns_none(self) -> None:
        result = _serialize_function_result("titleFunction", None)
        self.assertIsNone(result)

    def test_passing_result(self) -> None:
        func_result = {"output": '"Example Title"', "error": None, "matched": True}
        result = _serialize_function_result("titleFunction", func_result)
        assert result is not None
        self.assertEqual(result["name"], "title")
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["output"], '"Example Title"')

    def test_failing_result(self) -> None:
        func_result = {"output": '"wrong"', "error": None, "matched": False}
        result = _serialize_function_result("detectionFunction", func_result)
        assert result is not None
        self.assertEqual(result["name"], "detection")
        self.assertEqual(result["status"], "fail")

    def test_error_result_with_dict(self) -> None:
        func_result = {"output": None, "error": {"message": "boom"}, "matched": None}
        result = _serialize_function_result("severityFunction", func_result)
        assert result is not None
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error"], "boom")

    def test_error_result_with_string_error(self) -> None:
        func_result = {"output": None, "error": "something broke", "matched": None}
        result = _serialize_function_result("titleFunction", func_result)
        assert result is not None
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error"], "something broke")

    def test_function_name_strips_function_suffix(self) -> None:
        func_result = {"output": "ok", "matched": True}
        result = _serialize_function_result("alertContextFunction", func_result)
        assert result is not None
        self.assertEqual(result["name"], "alertContext")


class TestSerializeTestResult(TestCase):
    """Tests for _serialize_test_result."""

    def test_passing_test_result(self) -> None:
        test_result = _make_test_result(name="pass - example", passed=True)
        container = TestResultContainer(
            detection=None,
            result=test_result,
            failed_tests=defaultdict(list),
            output="",
        )
        serialized = _serialize_test_result(container)
        self.assertEqual(serialized["name"], "pass - example")
        self.assertTrue(serialized["passed"])
        self.assertFalse(serialized["errored"])

    def test_errored_test_result(self) -> None:
        test_result = _make_test_result(
            name="fail - bad", passed=False, errored=True, generic_error="KeyError: foo"
        )
        container = TestResultContainer(
            detection=None,
            result=test_result,
            failed_tests=defaultdict(list),
            output="",
        )
        serialized = _serialize_test_result(container)
        self.assertFalse(serialized["passed"])
        self.assertTrue(serialized["errored"])
        self.assertEqual(serialized["genericError"], "KeyError: foo")


class TestPrintJsonOutput(TestCase):
    """Tests for _print_json_output."""

    def _capture_json_output(
        self,
        num_detections: int = 5,
        failed_tests: Optional[DefaultDict[str, list]] = None,
        invalid_specs: Optional[List[Any]] = None,
        num_invalid_detections: Optional[int] = None,
        skipped_tests: Optional[List[Tuple[str, dict]]] = None,
        all_test_results: Optional[TestResultsContainer] = None,
    ) -> Dict[str, Any]:
        """Call _print_json_output and parse the captured stdout as JSON."""
        if failed_tests is None:
            failed_tests = defaultdict(list)
        if invalid_specs is None:
            invalid_specs = []
        if skipped_tests is None:
            skipped_tests = []
        if all_test_results is None:
            all_test_results = TestResultsContainer(passed={}, errored={})
        if num_invalid_detections is None:
            num_invalid_detections = len(invalid_specs)

        buf = StringIO()
        with mock.patch("panther_analysis_tool.main.print", side_effect=lambda x: buf.write(x)):
            _print_json_output(
                test_path="./rules",
                num_detections=num_detections,
                failed_tests=failed_tests,
                invalid_specs=invalid_specs,
                num_invalid_detections=num_invalid_detections,
                skipped_tests=skipped_tests,
                all_test_results=all_test_results,
            )
        return json.loads(buf.getvalue())

    def test_all_passing_produces_valid_json(self) -> None:
        output = self._capture_json_output(num_detections=3)
        self.assertEqual(output["summary"]["total"], 3)
        self.assertEqual(output["summary"]["passed"], 3)
        self.assertEqual(output["summary"]["failed"], 0)
        self.assertEqual(output["results"], {})
        self.assertEqual(output["failed"], {})
        self.assertEqual(output["invalid"], [])
        self.assertEqual(output["skipped"], [])

    def test_failed_tests_in_output(self) -> None:
        failed: DefaultDict[str, list] = defaultdict(list)
        failed["Rule.Bad"] = ["test-1", "test-2"]
        output = self._capture_json_output(num_detections=5, failed_tests=failed)
        self.assertEqual(output["summary"]["failed"], 1)
        self.assertIn("Rule.Bad", output["failed"])
        self.assertEqual(output["failed"]["Rule.Bad"], ["test-1", "test-2"])

    def test_invalid_specs_in_output(self) -> None:
        invalid = [("bad_rule.yml", "Schema validation failed")]
        output = self._capture_json_output(num_detections=5, invalid_specs=invalid)
        self.assertEqual(output["summary"]["invalid"], 1)
        self.assertEqual(output["invalid"][0]["file"], "bad_rule.yml")
        self.assertEqual(output["invalid"][0]["error"], "Schema validation failed")

    def test_skipped_tests_in_output(self) -> None:
        skipped = [("skipped.yml", {"RuleID": "Rule.Skipped"})]
        output = self._capture_json_output(num_detections=5, skipped_tests=skipped)
        self.assertEqual(output["summary"]["skipped"], 1)
        self.assertEqual(output["skipped"][0]["id"], "Rule.Skipped")

    def test_num_passed_never_negative(self) -> None:
        failed: DefaultDict[str, list] = defaultdict(list)
        failed["R1"] = ["t1"]
        failed["R2"] = ["t2"]
        invalid = [("f1.yml", "err1"), ("f2.yml", "err2"), ("f3.yml", "err3")]
        output = self._capture_json_output(
            num_detections=1,
            failed_tests=failed,
            invalid_specs=invalid,
            num_invalid_detections=3,
        )
        self.assertEqual(output["summary"]["passed"], 0)

    def test_non_detection_invalids_do_not_reduce_passed(self) -> None:
        """Data model and pack errors in invalid_specs should not lower the passed count.

        num_detections only counts rules/simple_detections. Data model load
        failures and pack validation errors are appended to invalid_specs but
        were never counted in num_detections, so subtracting them would
        artificially deflate the passed count.
        """
        invalid = [
            ("data_model.yml", "Conflicting Enabled LogType"),
            ("pack.yml", "pack definition includes items that do not exist"),
            ("bad_rule.yml", "Schema validation failed"),
        ]
        output = self._capture_json_output(
            num_detections=5,
            invalid_specs=invalid,
            num_invalid_detections=1,
        )
        self.assertEqual(output["summary"]["total"], 5)
        self.assertEqual(output["summary"]["passed"], 4)
        self.assertEqual(output["summary"]["invalid"], 3)

    def test_results_include_buffered_test_results(self) -> None:
        test_result = _make_test_result(name="pass - good", passed=True, detection_id="Rule.OK")
        container = TestResultContainer(
            detection=None,
            result=test_result,
            failed_tests=defaultdict(list),
            output="",
        )
        results = TestResultsContainer(
            passed={"Rule.OK": [container]},
            errored={},
        )
        output = self._capture_json_output(num_detections=1, all_test_results=results)
        self.assertIn("Rule.OK", output["results"])
        self.assertEqual(len(output["results"]["Rule.OK"]), 1)
        self.assertTrue(output["results"]["Rule.OK"][0]["passed"])


class TestPrintJsonError(TestCase):
    """Tests for _print_json_error."""

    def test_produces_valid_json_with_errors(self) -> None:
        buf = StringIO()
        with mock.patch("panther_analysis_tool.main.print", side_effect=lambda x: buf.write(x)):
            _print_json_error("./rules", [("bad.yml", "parse error")])
        output = json.loads(buf.getvalue())
        self.assertEqual(output["summary"]["total"], 0)
        self.assertEqual(output["summary"]["passed"], 0)
        self.assertEqual(output["summary"]["invalid"], 1)
        self.assertEqual(output["invalid"][0]["file"], "bad.yml")
        self.assertEqual(output["invalid"][0]["error"], "parse error")

    def test_empty_path_no_specs(self) -> None:
        buf = StringIO()
        with mock.patch("panther_analysis_tool.main.print", side_effect=lambda x: buf.write(x)):
            _print_json_error("./empty", [("./empty", "Nothing to test")])
        output = json.loads(buf.getvalue())
        self.assertEqual(output["summary"]["path"], "./empty")
        self.assertEqual(output["summary"]["total"], 0)


class TestOutputFormatEnum(TestCase):
    """Tests for the OutputFormat enum."""

    def test_enum_values(self) -> None:
        self.assertEqual(OutputFormat.text.value, "text")
        self.assertEqual(OutputFormat.json.value, "json")

    def test_enum_string_comparison(self) -> None:
        self.assertEqual(OutputFormat.text, "text")
        self.assertEqual(OutputFormat.json, "json")

    def test_enum_is_string_subclass(self) -> None:
        self.assertIsInstance(OutputFormat.text, str)


class TestGlobalJsonMode(TestCase):
    """Tests for the global is_json_mode / get_output_format infrastructure."""

    def setUp(self) -> None:
        import panther_analysis_tool.output as output_mod

        self._orig = output_mod._output_format
        output_mod._output_format = OutputFormat.text

    def tearDown(self) -> None:
        import panther_analysis_tool.output as output_mod

        output_mod._output_format = self._orig

    def test_is_json_mode_default_is_text(self) -> None:
        self.assertFalse(is_json_mode())

    def test_is_json_mode_when_json(self) -> None:
        import panther_analysis_tool.output as output_mod

        output_mod._output_format = OutputFormat.json
        self.assertTrue(is_json_mode())

    def test_get_output_format_returns_current(self) -> None:
        self.assertEqual(get_output_format(), OutputFormat.text)
        import panther_analysis_tool.output as output_mod

        output_mod._output_format = OutputFormat.json
        self.assertEqual(get_output_format(), OutputFormat.json)


class TestEmitJsonResult(TestCase):
    """Tests for the generic _emit_json_result envelope."""

    def _capture(self, command: str, return_code: int, out: Any) -> Dict[str, Any]:
        buf = StringIO()
        with mock.patch("panther_analysis_tool.main.print", side_effect=lambda x: buf.write(x)):
            _emit_json_result(command, return_code, out)
        return json.loads(buf.getvalue())

    def test_success_with_message(self) -> None:
        result = self._capture("zip", 0, "archive.zip")
        self.assertEqual(result["command"], "zip")
        self.assertEqual(result["return_code"], 0)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["message"], "archive.zip")

    def test_success_empty_output(self) -> None:
        result = self._capture("fmt", 0, "")
        self.assertEqual(result["status"], "success")
        self.assertNotIn("message", result)

    def test_error_with_string(self) -> None:
        result = self._capture("check_connection", 1, "Connection refused")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["errors"][0]["error"], "Connection refused")

    def test_error_with_tuple_list(self) -> None:
        out = [("rule.yml", "validation failed")]
        result = self._capture("test", 1, out)
        self.assertEqual(result["errors"][0]["file"], "rule.yml")
        self.assertEqual(result["errors"][0]["error"], "validation failed")

    def test_error_with_plain_list(self) -> None:
        out = ["some error string"]
        result = self._capture("upload", 1, out)
        self.assertEqual(result["errors"][0]["error"], "some error string")


class TestCommandEmitsOwnJson(TestCase):
    """Tests for _command_emits_own_json routing logic."""

    def test_test_command_emits_own(self) -> None:
        self.assertTrue(_command_emits_own_json("test"))

    def test_upload_command_emits_own(self) -> None:
        self.assertTrue(_command_emits_own_json("upload"))

    def test_validate_command_emits_own(self) -> None:
        self.assertTrue(_command_emits_own_json("validate"))

    def test_debug_command_emits_own(self) -> None:
        self.assertTrue(_command_emits_own_json("debug"))

    def test_unknown_command_does_not(self) -> None:
        self.assertFalse(_command_emits_own_json("zip"))

    def test_all_known_commands_registered(self) -> None:
        known = [
            "test",
            "debug",
            "upload",
            "validate",
            "benchmark",
            "check_packs",
            "migrate",
            "delete",
            "merge",
            "update",
            "enrich_test_data",
            "update_custom_schemas",
            "init",
        ]
        for cmd in known:
            self.assertTrue(
                _command_emits_own_json(cmd),
                f"{cmd} should emit its own JSON",
            )


class TestEmitCheckPacksJson(TestCase):
    """Tests for _emit_check_packs_json helper."""

    def _capture(self, return_code: int, **data: Any) -> Dict[str, Any]:
        buf = StringIO()
        with mock.patch("panther_analysis_tool.main.print", side_effect=lambda x: buf.write(x)):
            _emit_check_packs_json(return_code, **data)
        return json.loads(buf.getvalue())

    def test_success_no_data(self) -> None:
        result = self._capture(0)
        self.assertEqual(result["command"], "check-packs")
        self.assertEqual(result["return_code"], 0)
        self.assertEqual(result["status"], "success")
        self.assertNotIn("data", result)

    def test_error_with_missing_items(self) -> None:
        items = [{"path": "pack.yml", "missing": {"Rule.A", "Rule.B"}}]
        result = self._capture(1, missing_items=items)
        self.assertEqual(result["status"], "error")
        self.assertIn("data", result)
        missing = result["data"]["missing_items"][0]["missing"]
        self.assertEqual(sorted(missing), ["Rule.A", "Rule.B"])

    def test_error_with_sorted_list(self) -> None:
        result = self._capture(1, items_not_in_packs=["Z.Rule", "A.Rule"])
        self.assertEqual(result["data"]["items_not_in_packs"], ["Z.Rule", "A.Rule"])

    def test_sets_are_sorted_in_output(self) -> None:
        """Verify _check_packs_json_default converts sets to sorted lists."""
        self.assertEqual(_check_packs_json_default({"c", "a", "b"}), ["a", "b", "c"])

    def test_non_set_falls_back_to_str(self) -> None:
        """Non-set, non-serializable objects fall back to str()."""
        self.assertIsInstance(_check_packs_json_default(object()), str)


class TestEmitValidateJson(TestCase):
    """Tests for _emit_validate_json helper."""

    def _capture(self, return_code: int, **kwargs: Any) -> Dict[str, Any]:
        from panther_analysis_tool.command.validate import _emit_validate_json

        buf = StringIO()
        with mock.patch(
            "panther_analysis_tool.command.validate.print",
            side_effect=lambda x: buf.write(x),
        ):
            _emit_validate_json(return_code, **kwargs)
        return json.loads(buf.getvalue())

    def test_error_with_string(self) -> None:
        result = self._capture(1, error="Invalid backend")
        self.assertEqual(result["command"], "validate")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["errors"][0]["error"], "Invalid backend")

    def test_success_no_result(self) -> None:
        result = self._capture(0)
        self.assertEqual(result["status"], "success")
        self.assertNotIn("data", result)
        self.assertNotIn("errors", result)

    def test_error_with_mock_result(self) -> None:
        """Verify the result object branch when has_error/has_issues are present."""

        class _MockResult:
            def is_valid(self) -> bool:
                return False

            def has_error(self) -> bool:
                return True

            def get_error(self) -> str:
                return "some error"

            def has_issues(self) -> bool:
                return False

            def get_issues(self) -> list:
                return []

        result = self._capture(1, result=_MockResult())
        self.assertEqual(result["status"], "error")
        self.assertFalse(result["data"]["valid"])
        self.assertEqual(result["data"]["error"], "some error")
        self.assertEqual(result["data"]["issues"], [])


class TestEmitDeleteJson(TestCase):
    """Tests for _emit_delete_json helper."""

    def _capture(self, return_code: int, **data: Any) -> Dict[str, Any]:
        from panther_analysis_tool.command.bulk_delete import _emit_delete_json

        buf = StringIO()
        with mock.patch(
            "panther_analysis_tool.command.bulk_delete.print",
            side_effect=lambda x: buf.write(x),
        ):
            _emit_delete_json(return_code, **data)
        return json.loads(buf.getvalue())

    def test_success_with_deletions(self) -> None:
        result = self._capture(0, detections=["Rule.A"], queries=["Q1"])
        self.assertEqual(result["command"], "delete")
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["data"]["detections"], ["Rule.A"])
        self.assertEqual(result["data"]["queries"], ["Q1"])

    def test_success_empty(self) -> None:
        result = self._capture(0)
        self.assertEqual(result["status"], "success")
        self.assertNotIn("data", result)


class TestEmitMergeJson(TestCase):
    """Tests for _emit_merge_json helper."""

    def _capture(
        self,
        updated: list[str],
        conflicts: list[str],
        **kwargs: Any,
    ) -> Dict[str, Any]:
        from panther_analysis_tool.command.merge import _emit_merge_json

        buf = StringIO()
        with mock.patch(
            "panther_analysis_tool.command.merge.print",
            side_effect=lambda x: buf.write(x),
        ):
            _emit_merge_json(updated, conflicts, **kwargs)
        return json.loads(buf.getvalue())

    def test_empty_merge(self) -> None:
        result = self._capture([], [])
        self.assertEqual(result["command"], "merge")
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["data"]["updated_items"], [])
        self.assertEqual(result["data"]["merge_conflicts"], [])

    def test_with_updates_and_conflicts(self) -> None:
        result = self._capture(["Rule.A"], ["Rule.B"], preview=True)
        self.assertTrue(result["data"]["preview"])
        self.assertEqual(result["data"]["updated_items"], ["Rule.A"])
        self.assertEqual(result["data"]["merge_conflicts"], ["Rule.B"])

    def test_with_message(self) -> None:
        result = self._capture([], [], message="Not found")
        self.assertEqual(result["data"]["message"], "Not found")
