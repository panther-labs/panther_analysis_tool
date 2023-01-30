import base64
import enum
import json
from typing import Any, Dict, Final, List

import panther_core.data_model

from panther_analysis_tool import util as pat_utils


class SdkContentType(enum.Enum):
    UNKNOWN = 1
    RULE = 2
    POLICY = 3
    SCHEDULED_RULE = 4
    DATA_MODEL = 5
    QUERY = 6


class PythonFunc:
    _PATH_TO_SRC: Final = ["src"]
    _PATH_TO_NAME: Final = ["name"]

    def __init__(self, _func: Dict):
        self.src = pat_utils.deep_get(_func, self._PATH_TO_SRC, "No source found")
        self.name = pat_utils.deep_get(_func, self._PATH_TO_NAME, "No name found")

    def get_code(self) -> str:
        return base64.standard_b64decode(self.src).decode("utf8")

    def get_name(self) -> str:
        return self.name


class DataModelMapping:
    _PATH_TO_NAME = ["d", "name"]
    _PATH_TO_PATH = ["d", "path"]
    _PATH_TO_FUNC = ["d", "func"]

    def __init__(self, _mapping: Dict):
        self.name: str = pat_utils.deep_get(_mapping, self._PATH_TO_NAME, "no name found")
        self.path: str = pat_utils.deep_get(_mapping, self._PATH_TO_PATH) or ""
        _func = pat_utils.deep_get(_mapping, self._PATH_TO_FUNC) or None
        if not self.using_path():
            self.func = PythonFunc(_func)

    def using_path(self) -> bool:
        return self.path != ""

    def get_name(self, lowercase: bool = False) -> str:
        if lowercase:
            return self.name.lower()
        return self.name

    def to_panther_core_mapping(self) -> Dict[str, Any]:
        return {"name": self.get_name(lowercase=True), "path": self.path, "method": self.func}


class DataModel:
    _PATH_TO_LOG_TYPE = ["val", "d", "log_type"]
    _PATH_TO_MAPPINGS = ["val", "d", "mappings"]
    _PATH_TO_ID = ["val", "d", "data_model_id"]
    _PATH_TO_ENABLED = ["val", "d", "enabled"]
    _PATH_TO_NAME = ["val", "d", "name"]

    def __init__(self, _data_model: Dict):
        self.log_type = pat_utils.deep_get(_data_model, self._PATH_TO_LOG_TYPE, "no log type found")
        _mappings = pat_utils.deep_get(_data_model, self._PATH_TO_MAPPINGS, [])
        self.mappings = [DataModelMapping(m) for m in _mappings]
        self.name = pat_utils.deep_get(_data_model, self._PATH_TO_NAME, "no name found")
        self.id = pat_utils.deep_get(_data_model, self._PATH_TO_ID, "no id found")
        self.enabled = bool(pat_utils.deep_get(_data_model, self._PATH_TO_ENABLED, False))

    def module_body(self) -> str:
        return "\n\n\n".join([m.func.get_code() for m in self.mappings if not m.using_path()])

    def to_panther_core_data_model(self) -> panther_core.data_model.DataModel:
        return panther_core.data_model.DataModel(
            {
                "id": self.id,
                "versionId": "",
                "mappings": [m.to_panther_core_mapping() for m in self.mappings],
                "body": self.module_body(),
            }
        )


class Filter:
    _PATH_TO_FILTER_FUNC: Final = ["d", "func"]

    def __init__(self, _filter: Dict):
        self.func = PythonFunc(pat_utils.deep_get(_filter, self._PATH_TO_FILTER_FUNC, {}))

    def get_code(self) -> str:
        return self.func.get_code()

    def get_name(self) -> str:
        return self.func.get_name()


class UnitTest:
    def __init__(self, test: Dict):
        self.origin: str = pat_utils.deep_get(test, ["o", "name"], "No origin found")
        self.data: Dict = json.loads(pat_utils.deep_get(test, ["d", "data"], "{}"))
        self.name: str = pat_utils.deep_get(test, ["d", "name"], "No name found")
        self.expect_match: bool = bool(pat_utils.deep_get(test, ["d", "expect_match"], True))
        self.fail_reasons: List[str] = []  # only used if test failed

    def get_prg(self, filters: List[Filter], detection_type: SdkContentType) -> str:
        prg = "_filters = [] \n\n"
        for filt in filters:
            prg += f"{filt.get_code()} \n\n"
            prg += f"_filters.append({filt.get_name()}) \n\n"

        # flip the return vals if it is a policy
        match_val = False
        if detection_type is SdkContentType.POLICY:
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
        self.detection_type = panther_sdk_key_to_type(detection.get("key"))

        tests = pat_utils.deep_get(detection, self._PATH_TO_UNIT_TESTS, [])
        self.unit_tests: List[UnitTest] = [UnitTest(t) for t in pat_utils.to_list(tests)]

        filts = pat_utils.deep_get(detection, self._PATH_TO_FILTERS, [])
        self.filters: List[Filter] = [Filter(f) for f in pat_utils.to_list(filts)]

        self.detection_id = pat_utils.deep_get(
            detection,
            self._PATH_TO_RULE_ID,
            pat_utils.deep_get(detection, self._PATH_TO_POLICY_ID, "No ID found"),
        )

        self.enabled = pat_utils.deep_get(detection, self._PATH_TO_ENABLED, False)

        self.origin = pat_utils.deep_get(detection, self._PATH_TO_ORIGIN, "No origin found")

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


def panther_sdk_key_to_type(key: str) -> SdkContentType:
    if "rule" in key:
        return SdkContentType.RULE
    if "policy" in key:
        return SdkContentType.POLICY
    if "scheduled-rule" in key:
        return SdkContentType.SCHEDULED_RULE
    if "data-model" in key:
        return SdkContentType.DATA_MODEL
    if "query" in key:
        return SdkContentType.QUERY
    return SdkContentType.UNKNOWN
