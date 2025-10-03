import unittest

from ruamel import yaml

from panther_analysis_tool.core import yaml_formatter


class TestYamlFormatter(unittest.TestCase):
    def test_sort_yaml_dict(self) -> None:
        data = {
            "b": 1,
            "a": 2,
            "c": 3,
        }
        self.assertEqual(
            yaml_formatter.sort_yaml(data),
            {
                "a": 2,
                "b": 1,
                "c": 3,
            },
        )

    def test_sort_yaml_list(self) -> None:
        data = [
            {"b": 1, "a": 2, "c": 3},
            {"f": 4, "e": 5, "d": 6},
            "h",
            [3, 2],
            (5, 4, 6),
            "j",
        ]
        self.assertEqual(
            yaml_formatter.sort_yaml(data),
            [
                {"a": 2, "b": 1, "c": 3},
                {"d": 6, "e": 5, "f": 4},
                "h",
                [3, 2],
                (5, 4, 6),
                "j",
            ],
        )

    def test_sort_yaml_tuple(self) -> None:
        data = (
            {"b": 1, "a": 2, "c": 3},
            {"f": 4, "e": 5, "d": 6},
            "h",
            [3, 2],
            (5, 4, 6),
            "j",
        )
        self.assertEqual(
            yaml_formatter.sort_yaml(data),
            (
                {"a": 2, "b": 1, "c": 3},
                {"d": 6, "e": 5, "f": 4},
                "h",
                [3, 2],
                (5, 4, 6),
                "j",
            ),
        )

    def test_sort_yaml_string(self) -> None:
        data = "b"
        self.assertEqual(yaml_formatter.sort_yaml(data), "b")

    def test_sort_yaml_int(self) -> None:
        data = 1
        self.assertEqual(yaml_formatter.sort_yaml(data), 1)

    def test_analysis_spec_dump_rule_quotes_rule_id(self) -> None:
        input_yaml = "AnalysisType: rule\nRuleID: foo.bar.rule\n"
        expected_yaml = 'AnalysisType: rule\nRuleID: "foo.bar.rule"\n'
        result = yaml_formatter.analysis_spec_dump(yaml.safe_load(input_yaml)).decode("utf-8")
        self.assertEqual(result, expected_yaml)

    def test_analysis_spec_dump_rule_quotes_display_name(self) -> None:
        input_yaml = "AnalysisType: rule\DisplayName: foo.bar.rule\n"
        expected_yaml = 'AnalysisType: rule\DisplayName: "foo.bar.rule"\n'
        result = yaml_formatter.analysis_spec_dump(yaml.safe_load(input_yaml)).decode("utf-8")
        self.assertEqual(result, expected_yaml)

    def test_analysis_spec_dump_rule_folds_desc(self) -> None:
        input_yaml = "AnalysisType: rule\nDescription: foo.bar.rule\n"
        expected_yaml = "AnalysisType: rule\nDescription: >-\n  foo.bar.rule\n"
        result = yaml_formatter.analysis_spec_dump(yaml.safe_load(input_yaml)).decode("utf-8")
        self.assertEqual(result, expected_yaml)

    def test_analysis_spec_dump_rule_folds_runbook(self) -> None:
        input_yaml = "AnalysisType: rule\nRunbook: foo.bar.rule\n"
        expected_yaml = "AnalysisType: rule\nRunbook: >-\n  foo.bar.rule\n"
        result = yaml_formatter.analysis_spec_dump(yaml.safe_load(input_yaml)).decode("utf-8")
        self.assertEqual(result, expected_yaml)

    def test_analysis_spec_dump_rule_formats_tests(self) -> None:
        input_yaml = 'AnalysisType: rule\nTests:\n  - Name: Test1\n    ExpectedResult: true\n    Log: {"a": "thing"}\n'
        expected_yaml = 'AnalysisType: rule\nTests:\n  - ExpectedResult: true\n    Log:\n      "a": "thing"\n    Name: Test1\n'
        result = yaml_formatter.analysis_spec_dump(yaml.safe_load(input_yaml)).decode("utf-8")
        self.assertEqual(result, expected_yaml)

    def test_analysis_spec_dump_global_folds_desc(self) -> None:
        input_yaml = "AnalysisType: global\nDescription: duh\n"
        expected_yaml = "AnalysisType: global\nDescription: >-\n  duh\n"
        result = yaml_formatter.analysis_spec_dump(yaml.safe_load(input_yaml)).decode("utf-8")
        self.assertEqual(result, expected_yaml)

    def test_analysis_spec_dump_global_quotes_global_id(self) -> None:
        input_yaml = "AnalysisType: global\nGlobalID: foo.bar.global\n"
        expected_yaml = 'AnalysisType: global\nGlobalID: "foo.bar.global"\n'
        result = yaml_formatter.analysis_spec_dump(yaml.safe_load(input_yaml)).decode("utf-8")
        self.assertEqual(result, expected_yaml)

    def test_analysis_spec_dump_datamodel_quotes_id(self) -> None:
        input_yaml = "AnalysisType: datamodel\nDataModelID: foo.bar.datamodel\n"
        expected_yaml = 'AnalysisType: datamodel\nDataModelID: "foo.bar.datamodel"\n'
        result = yaml_formatter.analysis_spec_dump(yaml.safe_load(input_yaml)).decode("utf-8")
        self.assertEqual(result, expected_yaml)

    def test_analysis_spec_dump_datamodel_quotes_display_name(self) -> None:
        input_yaml = "AnalysisType: datamodel\nDisplayName: foo.bar.datamodel\n"
        expected_yaml = 'AnalysisType: datamodel\nDisplayName: "foo.bar.datamodel"\n'
        result = yaml_formatter.analysis_spec_dump(yaml.safe_load(input_yaml)).decode("utf-8")
        self.assertEqual(result, expected_yaml)

    def test_analysis_spec_dump_policy_quotes_policy_id(self) -> None:
        input_yaml = "AnalysisType: policy\nPolicyID: foo.bar.policy\n"
        expected_yaml = 'AnalysisType: policy\nPolicyID: "foo.bar.policy"\n'
        result = yaml_formatter.analysis_spec_dump(yaml.safe_load(input_yaml)).decode("utf-8")
        self.assertEqual(result, expected_yaml)

    def test_analysis_spec_dump_policy_quotes_display_name(self) -> None:
        input_yaml = "AnalysisType: policy\nDisplayName: foo.bar.policy\n"
        expected_yaml = 'AnalysisType: policy\nDisplayName: "foo.bar.policy"\n'
        result = yaml_formatter.analysis_spec_dump(yaml.safe_load(input_yaml)).decode("utf-8")
        self.assertEqual(result, expected_yaml)

    def test_analysis_spec_dump_policy_folds_desc(self) -> None:
        input_yaml = "AnalysisType: policy\nDescription: foo.bar.policy\n"
        expected_yaml = "AnalysisType: policy\nDescription: >-\n  foo.bar.policy\n"
        result = yaml_formatter.analysis_spec_dump(yaml.safe_load(input_yaml)).decode("utf-8")
        self.assertEqual(result, expected_yaml)

    def test_analysis_spec_dump_policy_folds_runbook(self) -> None:
        input_yaml = "AnalysisType: policy\nRunbook: foo.bar.policy\n"
        expected_yaml = "AnalysisType: policy\nRunbook: >-\n  foo.bar.policy\n"
        result = yaml_formatter.analysis_spec_dump(yaml.safe_load(input_yaml)).decode("utf-8")
        self.assertEqual(result, expected_yaml)

    def test_analysis_spec_dump_policy_formats_tests(self) -> None:
        input_yaml = 'AnalysisType: policy\nTests:\n  - Name: Test1\n    ExpectedResult: true\n    Log: {"a": "thing"}\n'
        expected_yaml = 'AnalysisType: policy\nTests:\n  - ExpectedResult: true\n    Log:\n      "a": "thing"\n    Name: Test1\n'
        result = yaml_formatter.analysis_spec_dump(yaml.safe_load(input_yaml)).decode("utf-8")
        self.assertEqual(result, expected_yaml)

    def test_analysis_spec_dump_saved_query_quotes_query_name(self) -> None:
        input_yaml = "AnalysisType: saved_query\nQueryName: foo.bar.query\n"
        expected_yaml = 'AnalysisType: saved_query\nQueryName: "foo.bar.query"\n'
        result = yaml_formatter.analysis_spec_dump(yaml.safe_load(input_yaml)).decode("utf-8")
        self.assertEqual(result, expected_yaml)

    def test_analysis_spec_dump_saved_query_folds_query(self) -> None:
        input_yaml = "AnalysisType: saved_query\nQuery: foo.bar.query\n"
        expected_yaml = "AnalysisType: saved_query\nQuery: >-\n  foo.bar.query\n"
        result = yaml_formatter.analysis_spec_dump(yaml.safe_load(input_yaml)).decode("utf-8")
        self.assertEqual(result, expected_yaml)

    def test_analysis_spec_dump_saved_query_formats_tests(self) -> None:
        input_yaml = 'AnalysisType: saved_query\nTests:\n  - Name: Test1\n    ExpectedResult: true\n    Log: {"a": "thing"}\n'
        expected_yaml = 'AnalysisType: saved_query\nTests:\n  - ExpectedResult: true\n    Log:\n      "a": "thing"\n    Name: Test1\n'
        result = yaml_formatter.analysis_spec_dump(yaml.safe_load(input_yaml)).decode("utf-8")
        self.assertEqual(result, expected_yaml)

    def test_analysis_spec_dump_scheduled_query_quotes_query_name(self) -> None:
        input_yaml = "AnalysisType: scheduled_query\nQueryName: foo.bar.query\n"
        expected_yaml = 'AnalysisType: scheduled_query\nQueryName: "foo.bar.query"\n'
        result = yaml_formatter.analysis_spec_dump(yaml.safe_load(input_yaml)).decode("utf-8")
        self.assertEqual(result, expected_yaml)

    def test_analysis_spec_dump_scheduled_query_folds_query(self) -> None:
        input_yaml = "AnalysisType: scheduled_query\nQuery: foo.bar.query\n"
        expected_yaml = "AnalysisType: scheduled_query\nQuery: >-\n  foo.bar.query\n"
        result = yaml_formatter.analysis_spec_dump(yaml.safe_load(input_yaml)).decode("utf-8")
        self.assertEqual(result, expected_yaml)

    def test_analysis_spec_dump_scheduled_query_formats_tests(self) -> None:
        input_yaml = 'AnalysisType: scheduled_query\nTests:\n  - Name: Test1\n    ExpectedResult: true\n    Log: {"a": "thing"}\n'
        expected_yaml = 'AnalysisType: scheduled_query\nTests:\n  - ExpectedResult: true\n    Log:\n      "a": "thing"\n    Name: Test1\n'
        result = yaml_formatter.analysis_spec_dump(yaml.safe_load(input_yaml)).decode("utf-8")
        self.assertEqual(result, expected_yaml)

    def test_analysis_spec_dump_lookuptable_quotes_lookup_name(self) -> None:
        input_yaml = "AnalysisType: lookuptable\nLookupName: foo.bar.lookuptable\n"
        expected_yaml = 'AnalysisType: lookuptable\nLookupName: "foo.bar.lookuptable"\n'
        result = yaml_formatter.analysis_spec_dump(yaml.safe_load(input_yaml)).decode("utf-8")
        self.assertEqual(result, expected_yaml)

    def test_analysis_spec_dump_lookuptable_folds_query(self) -> None:
        input_yaml = "AnalysisType: lookuptable\nQuery: foo.bar.lookuptable\n"
        expected_yaml = "AnalysisType: lookuptable\nQuery: >-\n  foo.bar.lookuptable\n"
        result = yaml_formatter.analysis_spec_dump(yaml.safe_load(input_yaml)).decode("utf-8")
        self.assertEqual(result, expected_yaml)

    def test_analysis_spec_dump_lookuptable_formats_tests(self) -> None:
        input_yaml = 'AnalysisType: lookuptable\nTests:\n  - Name: Test1\n    ExpectedResult: true\n    Log: {"a": "thing"}\n'
        expected_yaml = 'AnalysisType: lookuptable\nTests:\n  - ExpectedResult: true\n    Log:\n      "a": "thing"\n    Name: Test1\n'
        result = yaml_formatter.analysis_spec_dump(yaml.safe_load(input_yaml)).decode("utf-8")
        self.assertEqual(result, expected_yaml)
