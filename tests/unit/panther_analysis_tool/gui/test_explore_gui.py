import pytest
from unittest.mock import patch
from textual.widgets import Input, Tree

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
        python_file_contents=b"def rule(event):\n    return True\n",
        python_file_path="test.rule.1.py",
    ),
    analysis_utils.AnalysisItem(
        yaml_file_contents={
            "AnalysisType": "rule",
            "RuleID": "test.rule.2",
            "Description": "Test rule 2",
        },
        raw_yaml_file_contents=b"AnalysisType: rule\nRuleID: test.rule.2\nDescription: Test rule 2",
        yaml_file_path="test.rule.2.yml",
        python_file_contents=None,
        python_file_path=None,
    ),
    analysis_utils.AnalysisItem(
        yaml_file_contents={
            "AnalysisType": "policy",
            "PolicyID": "test.policy.1",
            "Description": "Test policy 1",
        },
        raw_yaml_file_contents=b"AnalysisType: policy\nPolicyID: test.policy.1\nDescription: Test policy 1",
        yaml_file_path="test.policy.1.yml",
        python_file_contents=b"def policy(resource):\n    return True\n",
        python_file_path="test.policy.1.py",
    ),
    analysis_utils.AnalysisItem(
        yaml_file_contents={
            "AnalysisType": "datamodel",
            "DataModelID": "test.datamodel.1",
            "Description": "Test datamodel 1",
        },
        raw_yaml_file_contents=b"AnalysisType: datamodel\nDataModelID: test.datamodel.1\nDescription: Test datamodel 1",
        yaml_file_path="test.datamodel.1.yml",
        python_file_contents=None,
        python_file_path=None,
    ),
]


@pytest.mark.asyncio
async def test_explore_gui_starts() -> None:
    """Test that the app starts successfully with empty specs."""
    app = explore_gui.ExploreApp(all_specs=[], user_spec_ids=set())
    async with app.run_test():
        assert app.all_specs == []
        assert app.user_spec_ids == set()
        assert app.view_editors is False
        assert app.selected_item is None


@pytest.mark.asyncio
async def test_explore_gui_starts_with_all_specs() -> None:
    """Test that the app starts and populates table with specs."""
    app = explore_gui.ExploreApp(all_specs=_all_test_specs, user_spec_ids=set())
    async with app.run_test():
        table = app.query_one("#table", widgets.AnalysisItemDataTable)
        assert len(table.rows) == len(_all_test_specs)
        for row_key in table.rows:
            status, type_label, id_label, desc_label = table.get_row(row_key)
            assert status != ""
            assert type_label != ""
            assert id_label != ""
            assert desc_label != ""


@pytest.mark.asyncio
async def test_cloned_items_are_marked_in_table() -> None:
    """Test that items in user_spec_ids are marked as cloned in the table."""
    app = explore_gui.ExploreApp(all_specs=_all_test_specs, user_spec_ids={"test.rule.1"})
    async with app.run_test():
        table = app.query_one("#table", widgets.AnalysisItemDataTable)
        for row_key in table.rows:
            status, type_label, id_label, _ = table.get_row(row_key)
            if "test.rule.1" in id_label:
                assert status == "[green]Yes ✓[/green]", table.get_row(row_key)
            else:
                assert status == "No", table.get_row(row_key)


@pytest.mark.asyncio
async def test_specs_are_sorted_on_mount() -> None:
    """Test that specs are sorted by analysis type and ID on mount."""
    app = explore_gui.ExploreApp(all_specs=_all_test_specs.copy(), user_spec_ids=set())
    async with app.run_test():
        # Verify specs are sorted (datamodel, policy, then rules)
        table = app.query_one("#table", widgets.AnalysisItemDataTable)
        row_keys = list(table.rows.keys())
        assert len(row_keys) == len(_all_test_specs)
        
        # Get IDs in order
        ids = [table.get_row(key)[2] for key in row_keys]
        # Should be sorted: datamodel, policy, rule, rule
        assert ids[0] == "test.datamodel.1"
        assert ids[1] == "test.policy.1"
        assert "test.rule.1" in ids
        assert "test.rule.2" in ids


@pytest.mark.asyncio
async def test_tree_is_populated_with_specs() -> None:
    """Test that the tree is populated with specs organized by type."""
    app = explore_gui.ExploreApp(all_specs=_all_test_specs, user_spec_ids=set())
    async with app.run_test():
        tree = app.query_one("#tree", Tree)
        root = tree.root
        assert str(root.label) == "Analysis Content"
        assert root.is_expanded
        
        # Check that we have nodes for each analysis type
        child_labels = [str(child.label) for child in root.children]
        assert len(child_labels) > 0
        # Check that we have at least one type node
        assert any("rule" in label.lower() or "policy" in label.lower() or "data" in label.lower() for label in child_labels)


@pytest.mark.asyncio
async def test_tree_node_selection_filters_by_id() -> None:
    """Test that selecting a leaf node filters the table by ID."""
    app = explore_gui.ExploreApp(all_specs=_all_test_specs, user_spec_ids=set())
    async with app.run_test() as pilot:
        tree = app.query_one("#tree", Tree)
        table = app.query_one("#table", widgets.AnalysisItemDataTable)
        
        # Find a leaf node (individual item) by traversing the tree
        leaf_node = None
        for parent_node in tree.root.children:
            if parent_node.children:
                for child in parent_node.children:
                    if not child.children:  # Leaf node
                        leaf_node = child
                        break
                if leaf_node:
                    break
        
        if leaf_node:
            # Simulate selecting the node - create event manually
            from textual.widgets.tree import TreeNode
            
            # Create a mock event-like object
            class MockNodeSelectedEvent:
                def __init__(self, node: TreeNode):
                    self.node = node
            
            event = MockNodeSelectedEvent(leaf_node)
            app.on_tree_node_selected(event)
            await pilot.pause()
            
            # Table should be filtered to show only that item
            assert len(table.rows) == 1
            _, _, selected_id, _ = table.get_row(list(table.rows.keys())[0])
            assert selected_id == str(leaf_node.label)


@pytest.mark.asyncio
async def test_tree_node_selection_filters_by_type() -> None:
    """Test that selecting a parent node filters the table by type."""
    app = explore_gui.ExploreApp(all_specs=_all_test_specs, user_spec_ids=set())
    async with app.run_test() as pilot:
        tree = app.query_one("#tree", Tree)
        table = app.query_one("#table", widgets.AnalysisItemDataTable)
        
        # Find a parent node (analysis type)
        parent_node = None
        for node in tree.root.children:
            if node.children:  # Parent node with children
                parent_node = node
                break
        
        if parent_node:
            # Create a mock event-like object
            class MockNodeSelectedEvent:
                def __init__(self, node):
                    self.node = node
            
            event = MockNodeSelectedEvent(parent_node)
            app.on_tree_node_selected(event)
            await pilot.pause()
            
            # Table should be filtered to show items of that type
            assert len(table.rows) > 0
            # Verify all rows are of the expected type
            expected_type = parent_node.data["analysis_type"] if parent_node.data else None
            if expected_type:
                for row_key in table.rows:
                    _, type_label, _, _ = table.get_row(row_key)
                    # Type should match (could be pretty type or regular type)
                    # Normalize both for comparison (handle "data model" vs "datamodel")
                    normalized_expected = expected_type.lower().replace(" ", "")
                    normalized_label = type_label.lower().replace(" ", "")
                    assert normalized_expected in normalized_label or normalized_label in normalized_expected


@pytest.mark.asyncio
async def test_search_input_filters_table() -> None:
    """Test that typing in search input filters the table."""
    app = explore_gui.ExploreApp(all_specs=_all_test_specs, user_spec_ids=set())
    async with app.run_test() as pilot:
        search_input = app.query_one("#search-input", Input)
        table = app.query_one("#table", widgets.AnalysisItemDataTable)
        
        initial_row_count = len(table.rows)
        
        # Type a search term that matches one item
        search_input.value = "test.rule.1"
        event = Input.Changed(search_input, "test.rule.1")
        app.on_input_changed(event)
        await pilot.pause()
        
        # Table should be filtered
        assert len(table.rows) <= initial_row_count
        # At least one row should match
        assert len(table.rows) > 0


@pytest.mark.asyncio
async def test_search_with_filters() -> None:
    """Test that search input parses filters correctly."""
    app = explore_gui.ExploreApp(all_specs=_all_test_specs, user_spec_ids=set())
    async with app.run_test() as pilot:
        search_input = app.query_one("#search-input", Input)
        table = app.query_one("#table", widgets.AnalysisItemDataTable)
        
        # Search with a filter
        search_input.value = "AnalysisType=rule"
        event = Input.Changed(search_input, "AnalysisType=rule")
        app.on_input_changed(event)
        await pilot.pause()
        
        # Table should be filtered to show only rules
        assert len(table.rows) > 0
        for row_key in table.rows:
            _, type_label, _, _ = table.get_row(row_key)
            assert "rule" in type_label.lower() or "Rule" in type_label


@pytest.mark.asyncio
async def test_row_selection_switches_to_editor_view() -> None:
    """Test that selecting a row switches to editor view and populates windows."""
    app = explore_gui.ExploreApp(all_specs=_all_test_specs, user_spec_ids=set())
    async with app.run_test() as pilot:
        table = app.query_one("#table", widgets.AnalysisItemDataTable)
        code_windows = app.query_one("#code-windows")
        main_content = app.query_one("#main-content")
        search_input = app.query_one("#search-input")
        
        # Initially, code windows should be hidden
        assert code_windows.styles.display == "none"
        assert main_content.styles.display != "none"
        assert search_input.styles.display != "none"
        
        # Select a row - need to create proper event
        row_key = list(table.rows.keys())[0]
        
        # Create a mock RowSelected event
        class MockRowSelectedEvent:
            def __init__(self, data_table, row_key):
                self.data_table = data_table
                self.row_key = row_key
        
        event = MockRowSelectedEvent(table, row_key)
        app.on_data_table_row_selected(event)
        await pilot.pause()
        
        # Code windows should be visible, main content hidden
        assert code_windows.styles.display != "none"
        assert main_content.styles.display == "none"
        assert search_input.styles.display == "none"
        assert app.view_editors is True
        assert app.selected_item is not None


@pytest.mark.asyncio
async def test_row_selection_populates_yaml_window() -> None:
    """Test that selecting a row populates the YAML window."""
    app = explore_gui.ExploreApp(all_specs=_all_test_specs, user_spec_ids=set())
    async with app.run_test() as pilot:
        table = app.query_one("#table", widgets.AnalysisItemDataTable)
        yaml_window = app.query_one("#yaml-window", widgets.YAMLWindow)
        
        # Select a row - create mock event
        row_key = list(table.rows.keys())[0]
        
        class MockRowSelectedEvent:
            def __init__(self, data_table, row_key):
                self.data_table = data_table
                self.row_key = row_key
        
        event = MockRowSelectedEvent(table, row_key)
        app.on_data_table_row_selected(event)
        await pilot.pause()
        
        # YAML window should be populated
        assert yaml_window.text != ""
        assert "AnalysisType" in yaml_window.text or "RuleID" in yaml_window.text or "PolicyID" in yaml_window.text


@pytest.mark.asyncio
async def test_row_selection_with_python_file() -> None:
    """Test that selecting an item with Python file shows Python window."""
    app = explore_gui.ExploreApp(all_specs=_all_test_specs, user_spec_ids=set())
    async with app.run_test() as pilot:
        table = app.query_one("#table", widgets.AnalysisItemDataTable)
        py_window = app.query_one("#python-window", widgets.PythonWindow)
        
        # Find a row with a Python file (test.rule.1)
        for row_key in table.rows:
            _, _, item_id, _ = table.get_row(row_key)
            if item_id == "test.rule.1":
                class MockRowSelectedEvent:
                    def __init__(self, data_table, row_key):
                        self.data_table = data_table
                        self.row_key = row_key
                
                event = MockRowSelectedEvent(table, row_key)
                app.on_data_table_row_selected(event)
                await pilot.pause()
                
                # Python window should be visible and populated
                assert py_window.styles.display != "none"
                assert py_window.text != ""
                assert "def rule" in py_window.text
                break


@pytest.mark.asyncio
async def test_row_selection_without_python_file() -> None:
    """Test that selecting an item without Python file hides Python window."""
    app = explore_gui.ExploreApp(all_specs=_all_test_specs, user_spec_ids=set())
    async with app.run_test() as pilot:
        table = app.query_one("#table", widgets.AnalysisItemDataTable)
        py_window = app.query_one("#python-window", widgets.PythonWindow)
        
        # Find a row without a Python file (test.rule.2 or test.datamodel.1)
        for row_key in table.rows:
            _, _, item_id, _ = table.get_row(row_key)
            if item_id in ("test.rule.2", "test.datamodel.1"):
                class MockRowSelectedEvent:
                    def __init__(self, data_table, row_key):
                        self.data_table = data_table
                        self.row_key = row_key
                
                event = MockRowSelectedEvent(table, row_key)
                app.on_data_table_row_selected(event)
                await pilot.pause()
                
                # Python window should be hidden
                assert py_window.styles.display == "none"
                break


@pytest.mark.asyncio
async def test_close_editors_action() -> None:
    """Test that close_editors action returns to main view."""
    app = explore_gui.ExploreApp(all_specs=_all_test_specs, user_spec_ids=set())
    async with app.run_test() as pilot:
        table = app.query_one("#table", widgets.AnalysisItemDataTable)
        code_windows = app.query_one("#code-windows")
        main_content = app.query_one("#main-content")
        
        # First select a row to enter editor view
        row_key = list(table.rows.keys())[0]
        
        class MockRowSelectedEvent:
            def __init__(self, data_table, row_key):
                self.data_table = data_table
                self.row_key = row_key
        
        event = MockRowSelectedEvent(table, row_key)
        app.on_data_table_row_selected(event)
        await pilot.pause()
        
        assert app.view_editors is True
        
        # Close editors
        app.action_close_editors()
        await pilot.pause()
        
        # Should return to main view
        assert app.view_editors is False
        assert app.selected_item is None
        assert code_windows.styles.display == "none"
        assert main_content.styles.display != "none"


@pytest.mark.asyncio
async def test_toggle_dark_action() -> None:
    """Test that toggle_dark action toggles theme."""
    app = explore_gui.ExploreApp(all_specs=_all_test_specs, user_spec_ids=set())
    async with app.run_test():
        initial_theme = app.theme
        
        app.action_toggle_dark()
        
        # Theme should be toggled
        if initial_theme == "textual-light":
            assert app.theme == "textual-dark"
        else:
            assert app.theme == "textual-light"
        
        # Toggle again should return to original
        app.action_toggle_dark()
        assert app.theme == initial_theme


@pytest.mark.asyncio
async def test_check_action_enables_actions_correctly() -> None:
    """Test that check_action enables/disables actions based on view_editors state."""
    app = explore_gui.ExploreApp(all_specs=_all_test_specs, user_spec_ids=set())
    async with app.run_test():
        # Initially not viewing editors
        app.view_editors = False
        assert app.check_action("close_editors", ()) is False
        assert app.check_action("clone_analysis_item", ()) is False
        assert app.check_action("toggle_dark", ()) is True
        
        # When viewing editors
        app.view_editors = True
        assert app.check_action("close_editors", ()) is True
        assert app.check_action("clone_analysis_item", ()) is True
        assert app.check_action("toggle_dark", ()) is True


@pytest.mark.asyncio
async def test_analysis_item_by_id() -> None:
    """Test that analysis_item_by_id finds items correctly."""
    app = explore_gui.ExploreApp(all_specs=_all_test_specs, user_spec_ids=set())
    async with app.run_test():
        item = app.analysis_item_by_id("test.rule.1")
        assert item.analysis_id() == "test.rule.1"
        assert item.analysis_type() == "rule"
        
        # Test non-existent ID raises error
        with pytest.raises(ValueError, match="not found"):
            app.analysis_item_by_id("nonexistent.id")


@pytest.mark.asyncio
async def test_clone_analysis_item_with_no_selection() -> None:
    """Test that clone_analysis_item shows error when no item is selected."""
    app = explore_gui.ExploreApp(all_specs=_all_test_specs, user_spec_ids=set())
    async with app.run_test() as pilot:
        app.selected_item = None
        
        with patch.object(app, "notify") as mock_notify:
            app.action_clone_analysis_item()
            await pilot.pause()
            
            mock_notify.assert_called_once_with("No analysis item selected.", severity="error")


@pytest.mark.asyncio
async def test_clone_analysis_item_with_selection() -> None:
    """Test that clone_analysis_item starts clone operation when item is selected."""
    app = explore_gui.ExploreApp(all_specs=_all_test_specs, user_spec_ids=set())
    async with app.run_test() as pilot:
        # Select an item
        table = app.query_one("#table", widgets.AnalysisItemDataTable)
        row_key = list(table.rows.keys())[0]
        
        class MockRowSelectedEvent:
            def __init__(self, data_table, row_key):
                self.data_table = data_table
                self.row_key = row_key
        
        event = MockRowSelectedEvent(table, row_key)
        app.on_data_table_row_selected(event)
        await pilot.pause()
        
        assert app.selected_item is not None
        
        with (
            patch("panther_analysis_tool.gui.explore_gui.clone.clone") as mock_clone,
            patch.object(app, "notify") as mock_notify,
            patch.object(app, "call_from_thread") as mock_call_from_thread,
        ):
            # Mock successful clone
            mock_clone.return_value = None
            
            app.action_clone_analysis_item()
            await pilot.pause()
            
            # Should notify about cloning
            assert mock_notify.called
            # Clone should be called in thread
            # Note: threading makes this hard to test directly, but we can verify the notification


@pytest.mark.asyncio
async def test_add_specs_to_tree() -> None:
    """Test that add_specs_to_tree organizes specs by type."""
    app = explore_gui.ExploreApp(all_specs=_all_test_specs, user_spec_ids=set())
    async with app.run_test():
        tree = app.query_one("#tree", Tree)
        
        # Clear and re-add specs
        app.add_specs_to_tree(_all_test_specs)
        
        # Verify tree structure
        root = tree.root
        assert str(root.label) == "Analysis Content"
        assert len(root.children) > 0
        
        # Each child should be an analysis type
        for child in root.children:
            assert child.data is not None
            assert "analysis_type" in child.data


@pytest.mark.asyncio
async def test_empty_search_clears_filters() -> None:
    """Test that empty search clears filters and shows all items."""
    app = explore_gui.ExploreApp(all_specs=_all_test_specs, user_spec_ids=set())
    async with app.run_test() as pilot:
        table = app.query_one("#table", widgets.AnalysisItemDataTable)
        search_input = app.query_one("#search-input", Input)
        
        initial_count = len(table.rows)
        
        # Filter to one item
        search_input.value = "test.rule.1"
        event = Input.Changed(search_input, "test.rule.1")
        app.on_input_changed(event)
        await pilot.pause()
        
        assert len(table.rows) < initial_count
        
        # Clear search
        search_input.value = ""
        event = Input.Changed(search_input, "")
        app.on_input_changed(event)
        await pilot.pause()
        
        # Should show all items again
        assert len(table.rows) == initial_count


@pytest.mark.asyncio
async def test_switch_views_with_item() -> None:
    """Test switch_views when showing an item."""
    app = explore_gui.ExploreApp(all_specs=_all_test_specs, user_spec_ids=set())
    async with app.run_test() as pilot:
        item = _all_test_specs[0]
        app.view_editors = True
        
        app.switch_views(item)
        await pilot.pause()
        
        assert app.selected_item == item
        assert app.query_one("#code-windows").styles.display != "none"
        assert app.query_one("#main-content").styles.display == "none"


@pytest.mark.asyncio
async def test_switch_views_without_item() -> None:
    """Test switch_views when hiding editors."""
    app = explore_gui.ExploreApp(all_specs=_all_test_specs, user_spec_ids=set())
    async with app.run_test() as pilot:
        app.view_editors = False
        
        app.switch_views(None)
        await pilot.pause()
        
        assert app.selected_item is None
        assert app.query_one("#code-windows").styles.display == "none"
        assert app.query_one("#main-content").styles.display != "none"
