import io
from typing import Any, Iterable

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.scalarstring import DoubleQuotedScalarString, FoldedScalarString

from panther_analysis_tool.constants import AnalysisTypes

_yaml = YAML(typ="safe")
_yaml.indent(mapping=2, sequence=4, offset=2)

_rt_yaml = YAML(typ="rt")
_rt_yaml.indent(mapping=2, sequence=4, offset=2)
_rt_yaml.width = 80


def analysis_spec_dump(data: Any, sort: bool = True) -> bytes:
    if isinstance(data, bytes):
        data = _yaml.load(io.BytesIO(data))
    elif isinstance(data, str):
        data = _yaml.load(io.StringIO(data))
    if sort:
        data = sort_yaml(data)
    data = {k: v.strip() if isinstance(v, str) else v for k, v in data.items()}
    data = analysis_spec_to_ruamel(data)
    dumped = io.BytesIO()
    _rt_yaml.dump(data, dumped)
    return dumped.getvalue()


def analysis_spec_to_ruamel(data: Any) -> Any:
    if not isinstance(data, dict):
        return data

    match data["AnalysisType"]:
        case AnalysisTypes.RULE | AnalysisTypes.CORRELATION_RULE | AnalysisTypes.SCHEDULED_RULE:
            return rule_to_ruamel(data)
        case AnalysisTypes.GLOBAL:
            return global_to_ruamel(data)
        case AnalysisTypes.DATA_MODEL:
            return datamodel_to_ruamel(data)
        case AnalysisTypes.POLICY:
            return policy_to_ruamel(data)
        case AnalysisTypes.SAVED_QUERY | AnalysisTypes.SCHEDULED_QUERY:
            return query_to_ruamel(data)
        case AnalysisTypes.LOOKUP_TABLE:
            return lookuptable_to_ruamel(data)
        case _:
            return data


def rule_to_ruamel(data: Any) -> Any:
    for key, value in data.items():
        if key in ["Description", "Runbook"]:
            if isinstance(value, str):
                data[key] = FoldedScalarString(value)
        if key in ["Tests"]:
            format_tests(value)
        if key in ["DisplayName", "RuleID"]:
            data[key] = DoubleQuotedScalarString(value)
    return data


def global_to_ruamel(data: Any) -> Any:
    for key, value in data.items():
        if key in ["Description"]:
            if isinstance(value, str):
                data[key] = FoldedScalarString(value)
        if key in ["GlobalID"]:
            data[key] = DoubleQuotedScalarString(value)
    return data


def datamodel_to_ruamel(data: Any) -> Any:
    for key, value in data.items():
        if key in ["DataModelID", "DisplayName"]:
            data[key] = DoubleQuotedScalarString(value)
    return data


def policy_to_ruamel(data: Any) -> Any:
    for key, value in data.items():
        if key in ["Description", "Runbook"]:
            if isinstance(value, str):
                data[key] = FoldedScalarString(value)
        if key in ["Tests"]:
            format_tests(value)
        if key in ["PolicyID", "DisplayName"]:
            data[key] = DoubleQuotedScalarString(value)
    return data


def query_to_ruamel(data: Any) -> Any:
    for key, value in data.items():
        if key in ["Query"]:
            if isinstance(value, str):
                data[key] = FoldedScalarString(value)
        if key in ["Tests"]:
            format_tests(value)
        if key in ["QueryName"]:
            data[key] = DoubleQuotedScalarString(value)
    return data


def lookuptable_to_ruamel(data: Any) -> Any:
    for key, value in data.items():
        if key in ["LookupName"]:
            data[key] = DoubleQuotedScalarString(value)
    return data


def format_tests(tests: Iterable[Any]) -> Any:
    for test in tests:
        if isinstance(test, dict):
            for key, value in test.items():
                if key in ["Log", "Resource"]:
                    test[key] = to_inline_map(value)

            format_tests(test)
        elif isinstance(test, list):
            format_tests(test)


def to_inline_map(data: Any) -> Any:
    if isinstance(data, dict):
        m = CommentedMap()
        m.fa.set_flow_style()
        m.fa.set_block_style()
        for k, v in data.items():
            m[to_inline_map(k)] = to_inline_map(v)
        return m
    elif isinstance(data, list):
        s = CommentedSeq()
        for v in data:
            s.append(to_inline_map(v))
        return s
    elif isinstance(data, str):
        return DoubleQuotedScalarString(data)
    return data


def sort_yaml(data: Any) -> Any:
    if isinstance(data, dict):
        keys = sorted(data.keys())
        return {k: sort_yaml(data[k]) for k in keys}
    elif isinstance(data, list):
        return [sort_yaml(v) for v in data]
    elif isinstance(data, tuple):
        return tuple(sort_yaml(v) for v in data)
    return data