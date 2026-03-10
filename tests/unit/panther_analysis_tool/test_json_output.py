"""Tests for --output-format json feature: serialization helpers and JSON output functions."""

import json
from collections import defaultdict
from io import StringIO
from typing import Any, DefaultDict, Dict, List, Optional, Tuple
from unittest import TestCase, mock

from panther_core.testing import TestResult, TestResultsPerFunction

from panther_analysis_tool.command.standard_args import OutputFormat
from panther_analysis_tool.core.definitions import (
    TestResultContainer,
    TestResultsContainer,
)
from panther_analysis_tool.main import (
    _print_json_error,
    _print_json_output,
    _serialize_function_result,
    _serialize_test_result,
)


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

        buf = StringIO()
        with mock.patch("panther_analysis_tool.main.print", side_effect=lambda x: buf.write(x)):
            _print_json_output(
                test_path="./rules",
                num_detections=num_detections,
                failed_tests=failed_tests,
                invalid_specs=invalid_specs,
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
            num_detections=1, failed_tests=failed, invalid_specs=invalid
        )
        self.assertEqual(output["summary"]["passed"], 0)

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
