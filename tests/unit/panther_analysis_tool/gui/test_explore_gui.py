import pytest

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.gui import explore_gui, widgets

_all_test_specs = [
    analysis_utils.AnalysisItem(
        yaml_file_contents={
            "AnalysisType": "rule",
            "RuleID": "test.rule.1",
            "Description": "Test rule 1",
        },
        raw_yaml_file_contents=b"AnalysisType: rule\nRuleID: test.rule.1\nDescription: Test rule 1",
        yaml_file_path="test.rule.1.yml",
    ),
    analysis_utils.AnalysisItem(
        yaml_file_contents={
            "AnalysisType": "rule",
            "RuleID": "test.rule.2",
            "Description": "Test rule 2",
        },
        raw_yaml_file_contents=b"AnalysisType: rule\nRuleID: test.rule.2\nDescription: Test rule 2",
        yaml_file_path="test.rule.2.yml",
    ),
    analysis_utils.AnalysisItem(
        yaml_file_contents={
            "AnalysisType": "policy",
            "PolicyID": "test.policy.1",
            "Description": "Test policy 1",
        },
        raw_yaml_file_contents=b"AnalysisType: policy\nPolicyID: test.policy.1\nDescription: Test policy 1",
        yaml_file_path="test.policy.1.yml",
    ),
]


@pytest.mark.asyncio
async def test_explore_gui_starts() -> None:
    app = explore_gui.ExploreApp(all_specs=[], user_spec_ids=set())
    async with app.run_test():
        pass


@pytest.mark.asyncio
async def test_explore_gui_starts_with_all_specs() -> None:
    app = explore_gui.ExploreApp(all_specs=_all_test_specs, user_spec_ids=set())
    async with app.run_test():
        table = app.query_one("#table", widgets.AnalysisItemDataTable)
        for row_key in table.rows:
            status, type_label, id_label, desc_label = table.get_row(row_key)
            assert status != ""
            assert type_label != ""
            assert id_label != ""
            assert desc_label != ""


@pytest.mark.asyncio
async def test_cloned_items_are_marked_in_table() -> None:
    app = explore_gui.ExploreApp(all_specs=_all_test_specs, user_spec_ids={"test.rule.1"})
    async with app.run_test():
        table = app.query_one("#table", widgets.AnalysisItemDataTable)
        for row_key in table.rows:
            status, type_label, id_label, _ = table.get_row(row_key)
            if "test.rule.1" in id_label:
                assert status == "[green]Yes ✓[/green]", table.get_row(row_key)
            else:
                assert status == "No", table.get_row(row_key)
