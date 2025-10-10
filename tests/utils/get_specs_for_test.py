import typing

from panther_analysis_tool.analysis_utils import (
    LoadAnalysisSpecsResult,
    get_yaml_loader,
)
from panther_analysis_tool.constants import AnalysisTypes


def get_specs_for_test() -> typing.Dict[str, LoadAnalysisSpecsResult]:
    return {
        AnalysisTypes.RULE: LoadAnalysisSpecsResult(
            "filname.rule",
            "filepath.rule",
            get_yaml_loader(roundtrip=True).load(
                """
                RuleID: foo.bar.rule
                AnalysisType: rule
                Tests:
                  - Name: Test1
                    ExpectedResult: true
                    Log:
                        a: event_type
                        b: Equals
                        c: 1234
                        json: {"foo": "bar"}
                """
            ),
            yaml_ctx=get_yaml_loader(roundtrip=True),
            error=None,
            raw_spec_file_content=None,
        ),
        AnalysisTypes.SCHEDULED_RULE: LoadAnalysisSpecsResult(
            "filname.scheduled_rule",
            "filepath.scheduled_rule",
            get_yaml_loader(roundtrip=True).load(
                """
                RuleID: foo.bar.scheduled_rule
                AnalysisType: scheduled_rule
                Tests:
                  - Name: Test1
                    ExpectedResult: true
                    Log:
                        a: event_type
                        b: Equals
                        c: 1234
                        json: {"foo": "bar"}
                """
            ),
            yaml_ctx=get_yaml_loader(roundtrip=True),
            error=None,
            raw_spec_file_content=None,
        ),
        AnalysisTypes.POLICY: LoadAnalysisSpecsResult(
            "filname.policy",
            "filepath.policy",
            get_yaml_loader(roundtrip=True).load(
                """
                PolicyID: foo.bar.policy
                AnalysisType: policy
                Tests:
                  - Name: Test1
                    ExpectedResult: true
                    Resource:
                        a: event_type
                        b: Equals
                        c: 1234
                        json: {"foo": "bar"}
                """
            ),
            yaml_ctx=get_yaml_loader(roundtrip=True),
            error=None,
            raw_spec_file_content=None,
        ),
    }
