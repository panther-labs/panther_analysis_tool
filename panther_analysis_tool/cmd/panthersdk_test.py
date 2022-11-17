import argparse
import base64
import enum
import json
import logging
from collections import defaultdict
from functools import reduce
from typing import Any, Dict, Final, List, Tuple

from panther_analysis_tool.cmd import panthersdk_utils


class DetectionType(enum.Enum):
    UNKNOWN = 1
    RULE = 2
    POLICY = 3
    SCHEDULED_RULE = 4


class Filter:
    _PATH_TO_FILTER_SRC: Final = ["d", "func", "src"]
    _PATH_TO_FILTER_NAME: Final = ["d", "func", "name"]

    def __init__(self, _filter: Dict):
        self.src = _deep_get(_filter, self._PATH_TO_FILTER_SRC, "No source found")
        self.name = _deep_get(_filter, self._PATH_TO_FILTER_NAME, "No name found")

    def get_code(self) -> str:
        return base64.standard_b64decode(self.src).decode("utf8")

    def get_name(self) -> str:
        return self.name


class UnitTest:
    def __init__(self, test: Dict):
        self.origin: str = _deep_get(test, ["o", "name"], "No origin found")
        self.data: Dict = json.loads(_deep_get(test, ["d", "data"], "{}"))
        self.name: str = _deep_get(test, ["d", "name"], "No name found")
        self.expect_match: bool = bool(_deep_get(test, ["d", "expect_match"], True))
        self.fail_reasons: List[str] = []  # only used if test failed

    def get_prg(self, filters: List[Filter], detection_type: DetectionType) -> str:
        prg = "_filters = [] \n\n"
        for filt in filters:
            prg += f"{filt.get_code()} \n\n"
            prg += f"_filters.append({filt.get_name()}) \n\n"

        # flip the return vals if it is a policy
        match_val = False
        if detection_type is DetectionType.POLICY:
            match_val = True
        no_match_val = not match_val

        prg += "def _execute(event):\n"
        prg += "    global _filters\n"
        prg += "    for f in _filters:\n"
        prg += f"        if f(event) == {match_val}:\n"
        prg += f"            return {match_val}\n"
        prg += f"    return {no_match_val}\n\n"
        prg += f"_event = {self.data}\n\n"
        prg += "_result = _execute(_event)\n"

        return prg

    def add_fail_reason(self, reason: str) -> None:
        self.fail_reasons.append(reason)


class Detection:
    _PATH_TO_UNIT_TESTS: Final = ["val", "d", "unit_tests"]
    _PATH_TO_FILTERS: Final = ["val", "d", "filters"]
    _PATH_TO_RULE_ID: Final = ["val", "d", "rule_id"]
    _PATH_TO_POLICY_ID: Final = ["val", "d", "policy_id"]
    _PATH_TO_ENABLED: Final = ["val", "d", "enabled"]
    _PATH_TO_ORIGIN: Final = ["val", "o", "name"]

    def __init__(self, detection: Dict):
        self.detection_type = _detection_key_to_type(detection["key"])

        tests = _deep_get(detection, self._PATH_TO_UNIT_TESTS, [])
        self.unit_tests: List[UnitTest] = [UnitTest(t) for t in _to_list(tests)]

        filts = _deep_get(detection, self._PATH_TO_FILTERS, [])
        self.filters: List[Filter] = [Filter(f) for f in _to_list(filts)]

        self.detection_id = _deep_get(
            detection,
            self._PATH_TO_RULE_ID,
            _deep_get(detection, self._PATH_TO_POLICY_ID, "No ID found"),
        )

        self.enabled = _deep_get(detection, self._PATH_TO_ENABLED, False)

        self.origin = _deep_get(detection, self._PATH_TO_ORIGIN, "No origin found")

    def has_unit_tests(self) -> bool:
        return len(self.unit_tests) > 0

    def has_pass_and_fail_tests(self) -> bool:
        pass_test, fail_test = False, False
        for unit_test in self.unit_tests:
            if unit_test.expect_match:
                pass_test = True
            if not unit_test.expect_match:
                fail_test = True
        return pass_test and fail_test

    def disabled(self) -> bool:
        return not self.enabled


class TestSummary:
    def __init__(self) -> None:
        self.failed_tests: Dict[str, List[UnitTest]] = defaultdict(
            list
        )  # detection id to list of unit tests
        self.fail_count = 0
        self.pass_count = 0

    def total_count(self) -> int:
        return self.pass_count + self.fail_count

    def add_failure(self, detection_id: str, test: UnitTest) -> None:
        self.failed_tests[detection_id].append(test)
        self.fail_count += 1

    def test_passed(self) -> None:
        self.pass_count += 1

    def summary(self) -> str:
        summary = "--------------------------\nPanther CLI Test Summary\n"
        summary += f"    Passed: {self.pass_count}\n"
        summary += f"    Failed: {self.fail_count}\n"
        summary += f"    Total:  {self.total_count()}\n\n"

        if len(self.failed_tests) > 0:
            summary += "--------------------------\nFailed Tests Summary\n"

            for detection_id, failures in self.failed_tests.items():
                summary += f"   {detection_id}\n"
                for unit_test in failures:
                    summary += f"       {unit_test.name} ({unit_test.origin})\n"
                    for reason in unit_test.fail_reasons:
                        summary += f"            {reason}\n"
                    summary += "\n"  # new line between tests
        return summary

    def tests_failed(self) -> bool:
        return self.fail_count > 0


_TEST_SUMMARY = TestSummary()


def run(args: argparse.Namespace, indirect_invocation: bool = False) -> Tuple[int, list]:
    """Runs unit tests for Panther SDK detections.

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.
        indirect_invocation: True if this function is being invoked as part of
                                 another command (probably the legacy test command)

    Returns:
        A tuple of the return code, and a list of tuples containing invalid specs and their error.
    """
    panther_sdk_cache_path: Final = panthersdk_utils.get_sdk_cache_path()

    try:
        panthersdk_utils.run_sdk_module(panther_sdk_cache_path)
        detection_intermediates: List[Dict] = panthersdk_utils.load_intermediate_sdk_cache(
            panther_sdk_cache_path
        )
        detections: List[Detection] = [Detection(d) for d in detection_intermediates]
        detections = _filter_detections(args, detections)
        logging.info("Running Unit Tests for Panther Content\n")
        tests_failed = _run_unit_tests(detections, args.minimum_tests)
        return int(tests_failed), []
    except FileNotFoundError as err:
        if indirect_invocation:
            # If this is run automatically at the end of the standard test command,
            # this isn't an error that should cause the invocation to return 1.
            logging.debug(err)
            return 0, []
        logging.error(err)
        return 1, []


def _filter_detections(args: argparse.Namespace, detections: List[Detection]) -> List[Detection]:
    """Filters out the detections to be tested by using the command line args.

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.
        detections: The list of detections that need to be filtered for testing.

    Returns:
        A list of detections to be unit tested.
    """
    filtered = []
    for detection in detections:
        # filter out detections with no unit tests
        if not detection.has_unit_tests():
            continue

        # filter out using filter arg TODO

        # filter using enabled only arg
        if args.skip_disabled_tests and detection.disabled():
            continue

        filtered.append(detection)

    return filtered


def _run_unit_tests(detections: List[Detection], min_tests: int = 0) -> bool:
    """Runs the unit tests for the given detections, printing out test results and a summary.

    Args:
        detections: The list of detections to be unit tested.
        min_tests: The minimum number of unit tests each detection needs to have.

    Returns:
        True if at least one unit test failed, False if all tests pass.
    """
    for detection in detections:
        print(detection.detection_id)
        if len(detection.filters) == 0:
            print("    Detection had no filters to test")
            continue

        for unit_test in detection.unit_tests:
            prg = unit_test.get_prg(detection.filters, detection.detection_type)
            locs: Dict[str, str] = {}
            exec(prg, {}, locs)  # nosec B102 pylint: disable=W0122
            result = locs["_result"]

            if result != unit_test.expect_match:
                reason = f"Expected match to be {unit_test.expect_match} but got {result}"
                unit_test.add_fail_reason(reason)
                print(f"    [FAIL] {unit_test.name}: {reason}")
                _TEST_SUMMARY.add_failure(detection.detection_id, unit_test)
            else:
                print(f"    [PASS] {unit_test.name}")
                _TEST_SUMMARY.test_passed()

        has_pass_and_fail_tests = False
        if min_tests >= 2:
            has_pass_and_fail_tests = detection.has_pass_and_fail_tests()

        n_tests = len(detection.unit_tests)
        if n_tests < min_tests or (min_tests >= 2 and not has_pass_and_fail_tests):
            # create a fake unit test to represent the minimum tests failure
            unit_test = UnitTest({})
            unit_test.name = "minimum required tests"
            unit_test.origin = detection.origin  # origin will be the origin of the detection
            if n_tests < min_tests:
                unit_test.add_fail_reason(
                    f"Insufficient test coverage, {min_tests} tests required but only {n_tests} found"
                )
            if min_tests >= 2 and not has_pass_and_fail_tests:
                unit_test.add_fail_reason(
                    "Insufficient test coverage: expected at least one passing and one failing test"
                )
            _TEST_SUMMARY.add_failure(detection.detection_id, unit_test)

        print()  # print blank line in between tests

    print(_TEST_SUMMARY.summary())
    return _TEST_SUMMARY.tests_failed()


def _deep_get(obj: Dict, path: List[str], default: Any = None) -> Any:
    result = reduce(lambda val, key: val.get(key) if val else None, path, obj)  # type: ignore
    return result if result is not None else default


def _to_list(listish: Any) -> List:
    return listish if isinstance(listish, list) else [listish]


def _detection_key_to_type(key: str) -> DetectionType:
    if "rule" in key:
        return DetectionType.RULE
    if "policy" in key:
        return DetectionType.POLICY
    if "scheduled-rule" in key:
        return DetectionType.SCHEDULED_RULE
    return DetectionType.UNKNOWN
