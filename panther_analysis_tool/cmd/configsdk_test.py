import argparse
import base64
import json
import logging
import traceback
from collections import defaultdict
from functools import reduce
from typing import Tuple, Final, Dict, List, Any

from panther_analysis_tool.cmd import config_utils


class Filter:
    _PATH_TO_FILTER_SRC: Final = ['d', 'func', 'src']
    _PATH_TO_FILTER_NAME: Final = ['d', 'func', 'name']

    def __init__(self, filter: Dict):
        self.src = _deep_get(filter, self._PATH_TO_FILTER_SRC, "")
        self.name = _deep_get(filter, self._PATH_TO_FILTER_NAME, "")

    def get_code(self) -> str:
        return base64.standard_b64decode(self.src).decode('utf8')

    def get_name(self) -> str:
        return self.name


class UnitTest:
    fail_reason: str = ''  # only used if test failed

    def __init__(self, test: Dict):
        self.origin: str = _deep_get(test, ['o', 'name'])
        self.data: Dict = json.loads(_deep_get(test, ['d', 'data']))
        self.name: str = _deep_get(test, ['d', 'name'])
        self.expect_match: bool = bool(_deep_get(test, ['d', 'expect_match']))
        # TODO: mocks?

    def get_prg(self, filters: List[Filter]) -> str:
        # TODO policy prg needs to be the opposite
        prg = '_filters = [] \n\n'
        for filt in filters:
            prg += f'{filt.get_code()} \n\n'
            prg += f'_filters.append({filt.get_name()}) \n\n'
        prg += f'''
def _execute(event):
    global _filters
    for f in _filters:
        if f(event) == False:
            return False
    return True

_event = {self.data}

_result = _execute(_event)
'''
        return prg


class TestSummary:
    failed_tests: Dict[str, List[UnitTest]] = defaultdict(list)
    fail_count = 0
    pass_count = 0

    def total_count(self) -> int:
        return self.pass_count + self.fail_count

    def add_failure(self, detection_name: str, test: UnitTest) -> None:
        self.failed_tests[detection_name].append(test)
        self.fail_count += 1

    def test_passed(self) -> None:
        self.pass_count += 1

    def summary(self) -> str:
        summary = f"""--------------------------
Panther CLI Test Summary
    Passed: {self.pass_count}
    Failed: {self.fail_count}
    Total:  {self.total_count()}

--------------------------
Failed Tests Summary
"""
        for detection_name, failures in self.failed_tests.items():
            summary += f'   {detection_name}\n'
            for unit_test in failures:
                summary += f'       {unit_test.name} ({unit_test.origin})\n'
                summary += f'            {unit_test.fail_reason}\n\n'
        return summary


_TEST_SUMMARY = TestSummary()


class Detection:
    _PATH_TO_UNIT_TESTS: Final = ['val', 'd', 'unit_tests']
    _PATH_TO_FILTERS: Final = ['val', 'd', 'filters']
    _PATH_TO_RULE_ID: Final = ['val', 'd', 'rule_id']
    _PATH_TO_POLICY_ID: Final = ['val', 'd', 'policy_id']

    def __init__(self, detection: Dict):
        tests = _deep_get(detection, self._PATH_TO_UNIT_TESTS, [])
        self.unit_tests: List[UnitTest] = [UnitTest(t) for t in _to_list(tests)]

        filts = _deep_get(detection, self._PATH_TO_FILTERS, [])
        self.filters: List[Filter] = [Filter(f) for f in _to_list(filts)]

        self.id = _deep_get(detection, self._PATH_TO_RULE_ID,
                            _deep_get(detection, self._PATH_TO_POLICY_ID))

    def has_unit_tests(self) -> bool:
        return len(self.unit_tests) > 0


def run(args: argparse.Namespace) -> Tuple[int, list]:
    """Runs unit tests for config sdk detections.

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A tuple of the return code, and a list of tuples containing invalid specs and their error.
    """
    panther_config_cache_path: Final = config_utils.get_config_cache_path()

    try:
        logging.info('Running Unit Tests for Panther Content\n')

        config_utils.run_config_module(panther_config_cache_path)
        detections = config_utils.load_intermediate_config_cache(panther_config_cache_path)
        detections = [Detection(d) for d in detections]
        detections = _filter_detections(detections)
        _run_unit_tests(detections)
    except FileNotFoundError as e:
        logging.error(e)
        return 1, []
    except:  # DEBUG
        traceback.print_exc()

    return 0, []


def _filter_detections(detections: List[Detection]) -> List[Detection]:
    filtered = []
    for d in detections:
        # filter out detections with no unit tests
        if d.has_unit_tests():
            filtered.append(d)

        # filter out using filter arg TODO

        # filter using enabled only arg TODO

    return filtered


def _run_unit_tests(detections: List[Detection]) -> None:
    for d in detections:
        print(d.id)
        if len(d.filters) == 0:
            print('Detection had no filters to test')
            continue

        for u in d.unit_tests:
            prg = u.get_prg(d.filters)
            locs = {}
            exec(prg, {}, locs)
            result = locs['_result']

            if result != u.expect_match:
                u.fail_reason = f'Expected match to be {u.expect_match} but got {result}'
                print(f'    [FAIL] {u.name}: {u.fail_reason}')
                _TEST_SUMMARY.add_failure(d.id, u)
            else:
                print(f'    [PASS] {u.name}')
                _TEST_SUMMARY.test_passed()

        print()  # print blank line in between tests

    print(_TEST_SUMMARY.summary())


def _deep_get(d: Dict, path: List[str], default: Any = None) -> Any:
    result = reduce(lambda val, key: val.get(key) if val else None, path, d)
    return result if result is not None else default


def _to_list(l: Any) -> List:
    return l if type(l) is list else [l]
