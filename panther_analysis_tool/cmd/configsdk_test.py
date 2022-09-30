import argparse
import base64
import enum
import json
import logging
import traceback
from collections import defaultdict
from functools import reduce
from typing import Tuple, Final, Dict, List, Any

from panther_analysis_tool.cmd import config_utils


class DetectionType(enum.Enum):
    UNKNOWN = 1
    RULE = 2
    POLICY = 3
    SCHEDULED_RULE = 4


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

    def get_prg(self, filters: List[Filter], detection_type: DetectionType) -> str:
        # TODO policy prg needs to be the opposite
        prg = '_filters = [] \n\n'
        for filt in filters:
            prg += f'{filt.get_code()} \n\n'
            prg += f'_filters.append({filt.get_name()}) \n\n'

        # flip the return vals if it is a policy
        fail_return_val = False
        if detection_type is DetectionType.POLICY:
            fail_return_val = True
        pass_return_val = not fail_return_val

        prg += 'def _execute(event):\n'
        prg += '    global _filters\n'
        prg += '    for f in _filters:\n'
        prg += f'        if f(event) == {fail_return_val}:\n'
        prg += f'            return {fail_return_val}\n'
        prg += f'    return {pass_return_val}\n\n'
        prg += f'_event = {self.data}\n\n'
        prg += '_result = _execute(_event)\n'

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
        summary = '--------------------------\nPanther CLI Test Summary\n'
        summary += f'\tPassed: {self.pass_count}\n'
        summary += f'\tFailed: {self.fail_count}\n'
        summary += f'\tTotal:  {self.total_count()}\n\n'

        if len(self.failed_tests) > 0:
            summary += '--------------------------\nFailed Tests Summary\n'

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
    _PATH_TO_ENABLED: Final = ['val', 'd', 'enabled']

    def __init__(self, detection: Dict):
        self.detection_type = _detection_key_to_type(detection['key'])

        tests = _deep_get(detection, self._PATH_TO_UNIT_TESTS, [])
        self.unit_tests: List[UnitTest] = [UnitTest(t) for t in _to_list(tests)]

        filts = _deep_get(detection, self._PATH_TO_FILTERS, [])
        self.filters: List[Filter] = [Filter(f) for f in _to_list(filts)]

        self.id = _deep_get(detection, self._PATH_TO_RULE_ID,
                            _deep_get(detection, self._PATH_TO_POLICY_ID))

        self.enabled = _deep_get(detection, self._PATH_TO_ENABLED, False)

    def has_unit_tests(self) -> bool:
        return len(self.unit_tests) > 0

    def disabled(self) -> bool:
        return not self.enabled


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
        detection_intermediates: List[Dict] = config_utils.load_intermediate_config_cache(panther_config_cache_path)
        detections: List[Detection] = [Detection(d) for d in detection_intermediates]
        detections = _filter_detections(args, detections)
        _run_unit_tests(detections)
    except FileNotFoundError as e:
        logging.error(e)
        return 1, []
    except:  # DEBUG
        traceback.print_exc()

    return 0, []


def _filter_detections(args: argparse.Namespace, detections: List[Detection]) -> List[Detection]:
    filtered = []
    for d in detections:
        # filter out detections with no unit tests
        if not d.has_unit_tests():
            continue

        # filter out using filter arg TODO

        # filter using enabled only arg
        if args.skip_disabled_tests and d.disabled():
            continue

        filtered.append(d)

    return filtered


def _run_unit_tests(detections: List[Detection]) -> None:
    for d in detections:
        print(d.id)
        if len(d.filters) == 0:
            print('Detection had no filters to test')
            continue

        for u in d.unit_tests:
            prg = u.get_prg(d.filters, d.detection_type)
            locs: Dict[str, str] = {}
            exec(prg, {}, locs)
            result = locs['_result']

            if result != u.expect_match:
                u.fail_reason = f'Expected match to be {u.expect_match} but got {result}'
                print(f'    [FAIL] {u.name}: {u.fail_reason}')
                _TEST_SUMMARY.add_failure(d.id, u)

                if d.detection_type is DetectionType.POLICY \
                        and u.name == 'check for yo test' \
                        and d.id == 'policy.with.one.test1':
                    print(prg)
            else:
                print(f'    [PASS] {u.name}')
                _TEST_SUMMARY.test_passed()

        print()  # print blank line in between tests

    print(_TEST_SUMMARY.summary())


def _deep_get(d: Dict, path: List[str], default: Any = None) -> Any:
    result = reduce(lambda val, key: val.get(key) if val else None, path, d)  # type: ignore
    return result if result is not None else default


def _to_list(l: Any) -> List:
    return l if type(l) is list else [l]


def _detection_key_to_type(key: str) -> DetectionType:
    if 'rule' in key:
        return DetectionType.RULE
    elif 'policy' in key:
        return DetectionType.POLICY
    elif 'scheduled-rule' in key:
        return DetectionType.SCHEDULED_RULE
    else:
        return DetectionType.UNKNOWN
