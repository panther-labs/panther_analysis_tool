import copy
import io
import logging
import typing
from unittest import TestCase, mock
from unittest.mock import call, mock_open, patch

from nose.tools import nottest

from panther_analysis_tool.analysis_utils import (
    AnalysisTypes,
    LoadAnalysisSpecsResult,
    get_yaml_loader,
)
from panther_analysis_tool.backend.client import (
    BackendResponse,
    Client,
    GenerateEnrichedEventResponse,
)
from panther_analysis_tool.backend.mocks import MockBackend
from panther_analysis_tool.enriched_event_generator import (
    TEST_CASE_FIELD_KEY_LOG,
    TEST_CASE_FIELD_KEY_RESOURCE,
    EnrichedEventGenerator,
)


@nottest
def get_specs_for_test() -> typing.Dict[str, LoadAnalysisSpecsResult]:
    return {
        AnalysisTypes.RULE: LoadAnalysisSpecsResult(
            f"filname.rule",
            f"filepath.rule",
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
        ),
        AnalysisTypes.SCHEDULED_RULE: LoadAnalysisSpecsResult(
            f"filname.scheduled_rule",
            f"filepath.scheduled_rule",
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
        ),
        AnalysisTypes.POLICY: LoadAnalysisSpecsResult(
            f"filname.policy",
            f"filepath.policy",
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
        ),
    }


class TestEnrichedEventGenerator(TestCase):
    def test__convert_inline_json_dict_to_python_dict(self) -> None:
        test_data = [
            {
                "name": "valid inline json",
                "input_yaml": 'other_field: blah\njson: {"foo": {"herp": ["bar", "baz"]}}\n',
                "expected": 'other_field: blah\njson:\n  "foo":\n    "herp":\n      - "bar"\n      - "baz"\n',
            },
            {
                "name": "no inline json",
                "input_yaml": "other_field: blah\nfoo:\n  bar:\n    - baz\njson:\n",
                "expected": "other_field: blah\nfoo:\n  bar:\n    - baz\njson:\n",
            },
            {
                "name": "argument is not json",
                "input_yaml": "other_field: blah\nfoo:\n  bar:\n    - baz\njson: 5\n",
                "expected": "other_field: blah\nfoo:\n  bar:\n    - baz\njson: 5\n",
            },
        ]

        for test in test_data:
            logging.info(f"Running test: {test['name']}")
            yaml = get_yaml_loader(roundtrip=True)
            as_commented_map = yaml.load(test["input_yaml"])
            inline_json_test_content = as_commented_map["json"]

            result = EnrichedEventGenerator._convert_inline_json_dict_to_python_dict(
                inline_json_test_content
            )
            as_commented_map["json"] = result
            string_io = io.StringIO()
            yaml.dump(as_commented_map, stream=string_io)

            self.assertEqual(
                string_io.getvalue(),
                test["expected"],
            )

    def test__handle_rule_test(self) -> None:
        # the unit test content for rules and scheduled_rules is the same
        for analysis_type in [AnalysisTypes.RULE, AnalysisTypes.SCHEDULED_RULE]:
            test_data = get_specs_for_test()[analysis_type]
            test_case = test_data.analysis_spec["Tests"][0]

            mock_result = copy.deepcopy(test_case)
            mock_result[TEST_CASE_FIELD_KEY_LOG]["p_enrichment"] = {"p_foo": "bar"}

            backend = MockBackend()
            backend.generate_enriched_event_input = mock.MagicMock(
                return_value=BackendResponse(
                    data=GenerateEnrichedEventResponse(
                        enriched_event=mock_result[TEST_CASE_FIELD_KEY_LOG],
                    ),
                    status_code=200,
                )
            )

            enricher = EnrichedEventGenerator(backend=backend)

            result = enricher._handle_rule_test(test_data.analysis_spec["RuleID"], test_case)

            self.assertEqual(result.enriched_test, mock_result)
            self.assertTrue(result.was_enriched())

    def test__handle_rule_test_no_enrichment(self) -> None:
        test_data = get_specs_for_test()[AnalysisTypes.RULE]
        test_case = test_data.analysis_spec["Tests"][0]

        mock_result = copy.deepcopy(test_case)

        backend = MockBackend()
        backend.generate_enriched_event_input = mock.MagicMock(
            return_value=BackendResponse(
                data=GenerateEnrichedEventResponse(
                    enriched_event=mock_result[TEST_CASE_FIELD_KEY_LOG],
                ),
                status_code=200,
            )
        )

        enricher = EnrichedEventGenerator(backend=backend)

        result = enricher._handle_policy_test(test_data.analysis_spec["RuleID"], test_case)

        self.assertEqual(result.enriched_test, mock_result)
        self.assertFalse(result.was_enriched())

    def test__handle_policy_test(self) -> None:
        test_data = get_specs_for_test()[AnalysisTypes.POLICY]
        test_case = test_data.analysis_spec["Tests"][0]

        mock_result = copy.deepcopy(test_case)
        mock_result[TEST_CASE_FIELD_KEY_RESOURCE]["p_enrichment"] = {"p_foo": "bar"}

        backend = MockBackend()
        backend.generate_enriched_event_input = mock.MagicMock(
            return_value=BackendResponse(
                data=GenerateEnrichedEventResponse(
                    enriched_event=mock_result[TEST_CASE_FIELD_KEY_RESOURCE],
                ),
                status_code=200,
            )
        )

        enricher = EnrichedEventGenerator(backend=backend)

        result = enricher._handle_policy_test(test_data.analysis_spec["PolicyID"], test_case)

        self.assertEqual(result.enriched_test, mock_result)
        self.assertTrue(result.was_enriched())

    def test__filter_analysis_items(self) -> None:
        analysis_items = get_specs_for_test()

        # now add one we filter
        analysis_items[AnalysisTypes.DATA_MODEL] = LoadAnalysisSpecsResult(
            f"filname.data_model",
            f"filepath.data_model",
            {
                "DataModelID": f"foo.bar.data_model",
                "AnalysisType": "data_model",
            },
            yaml_ctx=get_yaml_loader(roundtrip=True),
            error=None,
        )

        input = list(analysis_items.values())
        filtered = EnrichedEventGenerator._filter_analysis_items(input)

        self.assertEqual(filtered, list(get_specs_for_test().values()))

    def test_enrich_test_data(self) -> None:
        test_data = get_specs_for_test()
        enriched_test_data = []

        for key, test_datum in test_data.items():
            # we only have a single test case in the test data per detection type
            enriched_event = copy.deepcopy(test_datum.analysis_spec["Tests"][0])
            if key == AnalysisTypes.POLICY:
                enriched_event[TEST_CASE_FIELD_KEY_RESOURCE]["p_enrichment"] = {"p_foo": "bar"}
                enriched_test_data.append(enriched_event[TEST_CASE_FIELD_KEY_RESOURCE])
            else:
                enriched_event[TEST_CASE_FIELD_KEY_LOG]["p_enrichment"] = {"p_foo": "bar"}
                enriched_test_data.append(enriched_event[TEST_CASE_FIELD_KEY_LOG])

        backend = MockBackend()
        backend.generate_enriched_event_input = mock.MagicMock(
            side_effect=[
                BackendResponse(
                    data=GenerateEnrichedEventResponse(
                        enriched_event=enriched_test_datum,
                    ),
                    status_code=200,
                )
                for enriched_test_datum in enriched_test_data
            ]
        )

        enricher = EnrichedEventGenerator(backend=backend)

        # The `enrich_test_data` method writes to the operating system so we'll
        # mock `open` and assert on the content from the writes.
        m = mock_open()
        with patch("builtins.open", m):
            result = enricher.enrich_test_data(test_data.values())

        m().write.assert_has_calls(
            [
                call("RuleID"),
                call(":"),
                call(" "),
                call("foo.bar.rule"),
                call("\n"),
                call("AnalysisType"),
                call(":"),
                call(" "),
                call("rule"),
                call("\n"),
                call("Tests"),
                call(":"),
                call("\n"),
                call("  -"),
                call(" "),
                call("Name"),
                call(":"),
                call(" "),
                call("Test1"),
                call("\n"),
                call("    "),
                call("ExpectedResult"),
                call(":"),
                call(" "),
                call("true"),
                call("\n"),
                call("    "),
                call("Log"),
                call(":"),
                call("\n"),
                call("      "),
                call("a"),
                call(":"),
                call(" "),
                call("event_type"),
                call("\n"),
                call("      "),
                call("b"),
                call(":"),
                call(" "),
                call("Equals"),
                call("\n"),
                call("      "),
                call("c"),
                call(":"),
                call(" "),
                call("1234"),
                call("\n"),
                call("      "),
                call("json"),
                call(":"),
                call("\n"),
                call("        "),
                call('"'),
                call("foo"),
                call('"'),
                call(":"),
                call(' "'),
                call("bar"),
                call('"'),
                call("\n"),
                call("      "),
                call("p_enrichment"),
                call(":"),
                call("\n"),
                call("        "),
                call("p_foo"),
                call(":"),
                call(" "),
                call("bar"),
                call("\n"),
                call("RuleID"),
                call(":"),
                call(" "),
                call("foo.bar.scheduled_rule"),
                call("\n"),
                call("AnalysisType"),
                call(":"),
                call(" "),
                call("scheduled_rule"),
                call("\n"),
                call("Tests"),
                call(":"),
                call("\n"),
                call("  -"),
                call(" "),
                call("Name"),
                call(":"),
                call(" "),
                call("Test1"),
                call("\n"),
                call("    "),
                call("ExpectedResult"),
                call(":"),
                call(" "),
                call("true"),
                call("\n"),
                call("    "),
                call("Log"),
                call(":"),
                call("\n"),
                call("      "),
                call("a"),
                call(":"),
                call(" "),
                call("event_type"),
                call("\n"),
                call("      "),
                call("b"),
                call(":"),
                call(" "),
                call("Equals"),
                call("\n"),
                call("      "),
                call("c"),
                call(":"),
                call(" "),
                call("1234"),
                call("\n"),
                call("      "),
                call("json"),
                call(":"),
                call("\n"),
                call("        "),
                call('"'),
                call("foo"),
                call('"'),
                call(":"),
                call(' "'),
                call("bar"),
                call('"'),
                call("\n"),
                call("      "),
                call("p_enrichment"),
                call(":"),
                call("\n"),
                call("        "),
                call("p_foo"),
                call(":"),
                call(" "),
                call("bar"),
                call("\n"),
                call("PolicyID"),
                call(":"),
                call(" "),
                call("foo.bar.policy"),
                call("\n"),
                call("AnalysisType"),
                call(":"),
                call(" "),
                call("policy"),
                call("\n"),
                call("Tests"),
                call(":"),
                call("\n"),
                call("  -"),
                call(" "),
                call("Name"),
                call(":"),
                call(" "),
                call("Test1"),
                call("\n"),
                call("    "),
                call("ExpectedResult"),
                call(":"),
                call(" "),
                call("true"),
                call("\n"),
                call("    "),
                call("Resource"),
                call(":"),
                call("\n"),
                call("      "),
                call("a"),
                call(":"),
                call(" "),
                call("event_type"),
                call("\n"),
                call("      "),
                call("b"),
                call(":"),
                call(" "),
                call("Equals"),
                call("\n"),
                call("      "),
                call("c"),
                call(":"),
                call(" "),
                call("1234"),
                call("\n"),
                call("      "),
                call("json"),
                call(":"),
                call("\n"),
                call("        "),
                call('"'),
                call("foo"),
                call('"'),
                call(":"),
                call(' "'),
                call("bar"),
                call('"'),
                call("\n"),
                call("      "),
                call("p_enrichment"),
                call(":"),
                call("\n"),
                call("        "),
                call("p_foo"),
                call(":"),
                call(" "),
                call("bar"),
                call("\n"),
            ]
        )
