import argparse
import logging
from collections import defaultdict
from typing import Dict, Final, List, Optional, Tuple

import panther_core.rule

from panther_analysis_tool import panthersdk


class TestSummary:
    def __init__(self) -> None:
        self.failed_tests: Dict[str, List[panthersdk.UnitTest]] = defaultdict(
            list
        )  # detection id to list of unit tests
        self.fail_count = 0
        self.pass_count = 0

    def total_count(self) -> int:
        return self.pass_count + self.fail_count

    def add_failure(self, detection_id: str, test: panthersdk.UnitTest) -> None:
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
    panther_sdk_cache_path: Final = panthersdk.get_sdk_cache_path()

    try:
        panthersdk.run_sdk_module(panther_sdk_cache_path)
        intermediates = panthersdk.load_intermediate_sdk_cache(panther_sdk_cache_path)
        sdk_content = panthersdk.unmarshal_sdk_intermediates(intermediates)
        detections = _filter_detections(args, sdk_content.detections)
        logging.info("Running Unit Tests for Panther Content\n")
        tests_failed = _run_unit_tests(detections, sdk_content.data_models, args.minimum_tests)
        return int(tests_failed), []
    except FileNotFoundError as err:
        if indirect_invocation:
            # If this is run automatically at the end of the standard test command,
            # this isn't an error that should cause the invocation to return 1.
            logging.debug(err)
            return 0, []
        logging.error(err)
        return 1, []


def _filter_detections(
    args: argparse.Namespace, detections: List[panthersdk.Detection]
) -> List[panthersdk.Detection]:
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


def _run_unit_tests(
    detections: List[panthersdk.Detection],
    data_models: List[panthersdk.DataModel],
    min_tests: int = 0,
) -> bool:
    """Runs the unit tests for the given detections, printing out test results and a summary.

    Args:
        detections: The list of detections to be unit tested.
        min_tests: The minimum number of unit tests each detection needs to have.

    Returns:
        True if at least one unit test failed, False if all tests pass.
    """

    # organize data models by log_type
    data_models_by_log_type = {}
    for data_model in data_models:
        if data_model.log_type in data_models_by_log_type:
            logging.error(
                "Conflicting Data Model (%s) for LogType %s",
                data_model.data_model_id,
                data_model.log_type,
            )

            return True  # data model conflicting is considered failing
        data_models_by_log_type[data_model.log_type] = data_model.to_panther_core_data_model()

    for detection in detections:
        print(detection.detection_id)
        if len(detection.filters) == 0:
            print("    Detection had no filters to test")
            continue

        for unit_test in detection.unit_tests:
            logs_data_model: Optional[panthersdk.DataModel] = data_models_by_log_type.get(
                unit_test.data.get("p_log_type")  # get the log type from the test event
            )
            detection_result = detection.to_panther_core_detection().run(
                panther_core.PantherEvent(unit_test.data, logs_data_model),  # pylint: disable=E1101
                outputs={},
                outputs_names={},
            )
            result = detection_result.detection_output

            if detection_result.detection_exception:
                unit_test.add_fail_reason(str(detection_result.detection_exception))
                print(
                    f"    [FAIL] {unit_test.name}: An exception occured while running the unit test: "
                    f"{str(detection_result.detection_exception)}"
                )
                _TEST_SUMMARY.add_failure(detection.detection_id, unit_test)
            elif result != unit_test.expect_match:
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
            unit_test = panthersdk.UnitTest({})
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
