import pathlib

import pytest

from panther_analysis_tool.gui import widgets, yaml_conflict_resolver_gui

conflict_files_path = pathlib.Path(__file__).parent.parent.parent.parent/ "fixtures" / "yaml_merge_conflict"
base_yaml_path = conflict_files_path / "base_yaml.yml"
customer_yaml_path = conflict_files_path / "customer_yaml.yml"
panther_yaml_path = conflict_files_path / "panther_yaml.yml"


@pytest.mark.asyncio
async def test_yaml_conflict_resolver_gui() -> None:
    app = yaml_conflict_resolver_gui.YAMLConflictResolverApp(
        customer_python="def rule(event):\n    return True\n",
        raw_customer_yaml=customer_yaml_path.read_text(),
        raw_panther_yaml=panther_yaml_path.read_text(),
        raw_base_yaml=base_yaml_path.read_text(),
    )
    async with app.run_test() as pilot:
        customer_yaml_window = app.query_one(widgets.CustomerYAMLWindow)
        assert customer_yaml_window.text == customer_yaml_path.read_text()
        panther_yaml_window = app.query_one(widgets.PantherYAMLWindow)
        assert panther_yaml_window.text == panther_yaml_path.read_text()
        customer_python_window = app.query_one(widgets.CustomerPythonWindow)
        assert customer_python_window.text == "def rule(event):\n    return True\n"
        customer_python_window = app.query_one(widgets.CustomerPythonWindow)
        assert customer_python_window.text == "def rule(event):\n    return True\n"

        
