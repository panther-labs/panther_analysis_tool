import io
import logging
import pathlib

import pytest
from textual.widgets import Label

from panther_analysis_tool.core import diff, yaml
from panther_analysis_tool.gui import widgets, yaml_conflict_resolver_gui

conflict_files_path = (
    pathlib.Path(__file__).parent.parent.parent.parent / "fixtures" / "yaml_merge_conflict"
)
base_yaml_path = conflict_files_path / "base_yaml.yml"
customer_yaml_path = conflict_files_path / "customer_yaml.yml"
panther_yaml_path = conflict_files_path / "panther_yaml.yml"

raw_customer_yaml = customer_yaml_path.read_text()
raw_panther_yaml = panther_yaml_path.read_text()
raw_base_yaml = base_yaml_path.read_text()

yaml_loader = yaml.BlockStyleYAML()
customer_dict = yaml_loader.load(raw_customer_yaml)
conflict_items = diff.Dict(customer_dict).merge_dict(
    yaml_loader.load(raw_base_yaml), yaml_loader.load(raw_panther_yaml)
)


@pytest.mark.asyncio
async def test_yaml_conflict_resolver_gui_starts() -> None:
    app = yaml_conflict_resolver_gui.YAMLConflictResolverApp(
        customer_python="def rule(event):\n    return True\n",
        raw_customer_yaml=raw_customer_yaml,
        raw_panther_yaml=raw_panther_yaml,
        raw_base_yaml=raw_base_yaml,
        customer_dict=customer_dict,
        conflict_items=conflict_items,
    )
    async with app.run_test():
        customer_yaml_window = app.query_one(widgets.CustomerYAMLWindow)
        assert customer_yaml_window.text == raw_customer_yaml
        panther_yaml_window = app.query_one(widgets.PantherYAMLWindow)
        assert panther_yaml_window.text == raw_panther_yaml
        customer_python_window = app.query_one(widgets.CustomerPythonWindow)
        assert customer_python_window.text == "def rule(event):\n    return True\n"
        customer_python_window = app.query_one(widgets.CustomerPythonWindow)
        assert customer_python_window.text == "def rule(event):\n    return True\n"

        diff_resolver = app.query_one(widgets.DiffResolver)
        assert diff_resolver.diff_item.key == "DisplayName"
        assert diff_resolver.diff_item.panther_val == "Panther name change"
        assert diff_resolver.diff_item.cust_val == "Customer name change"


@pytest.mark.asyncio
async def test_yaml_conflict_resolver_gui_switches_views() -> None:
    app = yaml_conflict_resolver_gui.YAMLConflictResolverApp(
        customer_python="def rule(event):\n    return True\n",
        raw_customer_yaml=raw_customer_yaml,
        raw_panther_yaml=raw_panther_yaml,
        raw_base_yaml=raw_base_yaml,
        customer_dict=customer_dict,
        conflict_items=conflict_items,
    )
    async with app.run_test() as pilot:
        customer_yaml_window = app.query_one(widgets.CustomerYAMLWindow)
        panther_yaml_window = app.query_one(widgets.PantherYAMLWindow)
        customer_python_window = app.query_one(widgets.CustomerPythonWindow)

        assert panther_yaml_window.styles.display == "block"
        assert customer_yaml_window.styles.display == "block"
        assert customer_python_window.styles.display == "none"

        await pilot.press("s")
        assert customer_yaml_window.styles.display == "none"
        assert panther_yaml_window.styles.display == "none"
        assert customer_python_window.styles.display == "block"

        await pilot.press("s")
        assert panther_yaml_window.styles.display == "block"
        assert customer_yaml_window.styles.display == "block"
        assert customer_python_window.styles.display == "none"


@pytest.mark.asyncio
async def test_yaml_conflict_resolver_gui_retains_formatting() -> None:
    app = yaml_conflict_resolver_gui.YAMLConflictResolverApp(
        customer_python="def rule(event):\n    return True\n",
        raw_customer_yaml=raw_customer_yaml,
        raw_panther_yaml=raw_panther_yaml,
        raw_base_yaml=raw_base_yaml,
        customer_dict=customer_dict,
        conflict_items=conflict_items,
    )
    async with app.run_test() as pilot:
        await pilot.press("y")
        await pilot.press("y")
        await pilot.press("y")
        await pilot.press("y")
        await pilot.press("y")

        assert pilot.app._exit
        out = io.StringIO()
        yaml_loader.dump(app.final_dict, out)
        assert out.getvalue() == raw_customer_yaml


@pytest.mark.asyncio
async def test_yaml_conflict_resolver_gui_can_choose_all_your_values() -> None:
    app = yaml_conflict_resolver_gui.YAMLConflictResolverApp(
        customer_python="def rule(event):\n    return True\n",
        raw_customer_yaml=raw_customer_yaml,
        raw_panther_yaml=raw_panther_yaml,
        raw_base_yaml=raw_base_yaml,
        customer_dict=customer_dict,
        conflict_items=conflict_items,
    )
    async with app.run_test() as pilot:
        customer_yaml_window = app.query_one(widgets.CustomerYAMLWindow)
        panther_yaml_window = app.query_one(widgets.PantherYAMLWindow)
        diff_resolver = app.query_one(widgets.DiffResolver)

        customer_lines = customer_yaml_window.text.splitlines()
        panther_lines = panther_yaml_window.text.splitlines()

        assert "DisplayName:" in customer_lines[customer_yaml_window.cursor_location[0]]
        assert "DisplayName:" in panther_lines[panther_yaml_window.cursor_location[0]]
        assert diff_resolver.diff_item.key == "DisplayName"
        assert diff_resolver.diff_item.panther_val == "Panther name change"
        assert diff_resolver.diff_item.cust_val == "Customer name change"
        assert (
            diff_resolver.query_one(Label).content
            == 'Resolving conflict for: DisplayName (press "y" for your value or "p" for Panther\'s value)'
        )
        assert (
            diff_resolver.query_one(widgets.PantherValueYAMLWindow).text
            == '"Panther name change"\n'
        )
        assert (
            diff_resolver.query_one(widgets.CustomerValueYAMLWindow).text
            == '"Customer name change"\n'
        )

        await pilot.press("y")
        assert "TotallyNewField:" in customer_lines[customer_yaml_window.cursor_location[0]]
        assert "TotallyNewField:" in panther_lines[panther_yaml_window.cursor_location[0]]
        assert diff_resolver.diff_item.key == "TotallyNewField"
        assert (
            diff_resolver.diff_item.panther_val == "This is a totally new field that Panther added"
        )
        assert diff_resolver.diff_item.cust_val == "This is a totally new field the customer added"
        assert (
            diff_resolver.query_one(Label).content
            == 'Resolving conflict for: TotallyNewField (press "y" for your value or "p" for Panther\'s value)'
        )
        assert (
            diff_resolver.query_one(widgets.PantherValueYAMLWindow).text
            == '"This is a totally new field that Panther added"\n'
        )
        assert (
            diff_resolver.query_one(widgets.CustomerValueYAMLWindow).text
            == '"This is a totally new field the customer added"\n'
        )

        await pilot.press("y")
        assert "Tests:" in customer_lines[customer_yaml_window.cursor_location[0]]
        assert "Tests:" in panther_lines[panther_yaml_window.cursor_location[0]]
        assert diff_resolver.diff_item.key == "Tests"
        assert isinstance(diff_resolver.diff_item.panther_val, list)
        assert len(diff_resolver.diff_item.panther_val) == 3
        assert isinstance(diff_resolver.diff_item.cust_val, list)
        assert len(diff_resolver.diff_item.cust_val) == 3
        assert (
            diff_resolver.query_one(Label).content
            == 'Resolving conflict for: Tests (press "y" for your value or "p" for Panther\'s value)'
        )

        await pilot.press("y")
        assert "LogTypes:" in customer_lines[customer_yaml_window.cursor_location[0]]
        assert "LogTypes:" in panther_lines[panther_yaml_window.cursor_location[0]]
        assert diff_resolver.diff_item.key == "LogTypes"
        assert diff_resolver.diff_item.panther_val == ["Asana.Audit", "New.Panther.LogType"]
        assert diff_resolver.diff_item.cust_val == ["New.Customer.LogType", "Asana.Audit"]
        assert (
            diff_resolver.query_one(Label).content
            == 'Resolving conflict for: LogTypes (press "y" for your value or "p" for Panther\'s value)'
        )
        assert (
            diff_resolver.query_one(widgets.PantherValueYAMLWindow).text
            == "- Asana.Audit\n- New.Panther.LogType\n"
        )
        assert (
            diff_resolver.query_one(widgets.CustomerValueYAMLWindow).text
            == "- New.Customer.LogType\n- Asana.Audit\n"
        )

        await pilot.press("y")
        assert "Runbook:" in customer_lines[customer_yaml_window.cursor_location[0]]
        assert "Runbook:" in panther_lines[panther_yaml_window.cursor_location[0]]
        assert diff_resolver.diff_item.key == "Runbook"
        assert diff_resolver.diff_item.panther_val == "Panther runbook change"
        assert diff_resolver.diff_item.cust_val == "Customer runbook change and line move"
        assert (
            diff_resolver.query_one(Label).content
            == 'Resolving conflict for: Runbook (press "y" for your value or "p" for Panther\'s value)'
        )
        logging.warning(diff_resolver.query_one(widgets.PantherValueYAMLWindow).text)
        logging.warning(diff_resolver.query_one(widgets.CustomerValueYAMLWindow).text)
        assert (
            diff_resolver.query_one(widgets.PantherValueYAMLWindow).text
            == "Panther runbook change\n...\n"
        )
        assert (
            diff_resolver.query_one(widgets.CustomerValueYAMLWindow).text
            == "Customer runbook change and line move\n...\n"
        )

        await pilot.press("y")
        assert pilot.app._exit


@pytest.mark.asyncio
async def test_yaml_conflict_resolver_gui_can_choose_all_panther_values() -> None:
    app = yaml_conflict_resolver_gui.YAMLConflictResolverApp(
        customer_python="def rule(event):\n    return True\n",
        raw_customer_yaml=raw_customer_yaml,
        raw_panther_yaml=raw_panther_yaml,
        raw_base_yaml=raw_base_yaml,
        customer_dict=customer_dict,
        conflict_items=conflict_items,
    )
    async with app.run_test() as pilot:
        customer_yaml_window = app.query_one(widgets.CustomerYAMLWindow)
        panther_yaml_window = app.query_one(widgets.PantherYAMLWindow)
        diff_resolver = app.query_one(widgets.DiffResolver)

        customer_lines = customer_yaml_window.text.splitlines()
        panther_lines = panther_yaml_window.text.splitlines()

        assert "DisplayName:" in customer_lines[customer_yaml_window.cursor_location[0]]
        assert "DisplayName:" in panther_lines[panther_yaml_window.cursor_location[0]]
        assert diff_resolver.diff_item.key == "DisplayName"
        assert diff_resolver.diff_item.panther_val == "Panther name change"
        assert diff_resolver.diff_item.cust_val == "Customer name change"
        assert (
            diff_resolver.query_one(Label).content
            == 'Resolving conflict for: DisplayName (press "y" for your value or "p" for Panther\'s value)'
        )
        assert (
            diff_resolver.query_one(widgets.PantherValueYAMLWindow).text
            == '"Panther name change"\n'
        )
        assert (
            diff_resolver.query_one(widgets.CustomerValueYAMLWindow).text
            == '"Customer name change"\n'
        )

        await pilot.press("p")
        assert "TotallyNewField:" in customer_lines[customer_yaml_window.cursor_location[0]]
        assert "TotallyNewField:" in panther_lines[panther_yaml_window.cursor_location[0]]
        assert diff_resolver.diff_item.key == "TotallyNewField"
        assert (
            diff_resolver.diff_item.panther_val == "This is a totally new field that Panther added"
        )
        assert diff_resolver.diff_item.cust_val == "This is a totally new field the customer added"
        assert (
            diff_resolver.query_one(Label).content
            == 'Resolving conflict for: TotallyNewField (press "y" for your value or "p" for Panther\'s value)'
        )
        assert (
            diff_resolver.query_one(widgets.PantherValueYAMLWindow).text
            == '"This is a totally new field that Panther added"\n'
        )
        assert (
            diff_resolver.query_one(widgets.CustomerValueYAMLWindow).text
            == '"This is a totally new field the customer added"\n'
        )

        await pilot.press("p")
        assert "Tests:" in customer_lines[customer_yaml_window.cursor_location[0]]
        assert "Tests:" in panther_lines[panther_yaml_window.cursor_location[0]]
        assert diff_resolver.diff_item.key == "Tests"
        assert isinstance(diff_resolver.diff_item.panther_val, list)
        assert len(diff_resolver.diff_item.panther_val) == 3
        assert isinstance(diff_resolver.diff_item.cust_val, list)
        assert len(diff_resolver.diff_item.cust_val) == 3
        assert (
            diff_resolver.query_one(Label).content
            == 'Resolving conflict for: Tests (press "y" for your value or "p" for Panther\'s value)'
        )

        await pilot.press("p")
        assert "LogTypes:" in customer_lines[customer_yaml_window.cursor_location[0]]
        assert "LogTypes:" in panther_lines[panther_yaml_window.cursor_location[0]]
        assert diff_resolver.diff_item.key == "LogTypes"
        assert diff_resolver.diff_item.panther_val == ["Asana.Audit", "New.Panther.LogType"]
        assert diff_resolver.diff_item.cust_val == ["New.Customer.LogType", "Asana.Audit"]
        assert (
            diff_resolver.query_one(Label).content
            == 'Resolving conflict for: LogTypes (press "y" for your value or "p" for Panther\'s value)'
        )
        assert (
            diff_resolver.query_one(widgets.PantherValueYAMLWindow).text
            == "- Asana.Audit\n- New.Panther.LogType\n"
        )
        assert (
            diff_resolver.query_one(widgets.CustomerValueYAMLWindow).text
            == "- New.Customer.LogType\n- Asana.Audit\n"
        )

        await pilot.press("p")
        assert "Runbook:" in customer_lines[customer_yaml_window.cursor_location[0]]
        assert "Runbook:" in panther_lines[panther_yaml_window.cursor_location[0]]
        assert diff_resolver.diff_item.key == "Runbook"
        assert diff_resolver.diff_item.panther_val == "Panther runbook change"
        assert diff_resolver.diff_item.cust_val == "Customer runbook change and line move"
        assert (
            diff_resolver.query_one(Label).content
            == 'Resolving conflict for: Runbook (press "y" for your value or "p" for Panther\'s value)'
        )
        logging.warning(diff_resolver.query_one(widgets.PantherValueYAMLWindow).text)
        logging.warning(diff_resolver.query_one(widgets.CustomerValueYAMLWindow).text)
        assert (
            diff_resolver.query_one(widgets.PantherValueYAMLWindow).text
            == "Panther runbook change\n...\n"
        )
        assert (
            diff_resolver.query_one(widgets.CustomerValueYAMLWindow).text
            == "Customer runbook change and line move\n...\n"
        )

        await pilot.press("p")
        assert pilot.app._exit


@pytest.mark.asyncio
async def test_yaml_conflict_resolver_gui_can_quit() -> None:
    app = yaml_conflict_resolver_gui.YAMLConflictResolverApp(
        customer_python="def rule(event):\n    return True\n",
        raw_customer_yaml=raw_customer_yaml,
        raw_panther_yaml=raw_panther_yaml,
        raw_base_yaml=raw_base_yaml,
        customer_dict=customer_dict,
        conflict_items=conflict_items,
    )
    async with app.run_test() as pilot:
        await pilot.press("ctrl+q")
        assert pilot.app._exit
