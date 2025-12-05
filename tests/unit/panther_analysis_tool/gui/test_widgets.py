from typing import Callable
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.gui import widgets


@pytest.fixture
def make_analysis_item() -> Callable[..., analysis_utils.AnalysisItem]:
    """Create a helper function to create AnalysisItem objects for testing."""

    def _make_analysis_item(
        analysis_id: str = "Test.Rule",
        analysis_type: str = "RULE",
        description: str = "Test description",
        pretty_type: str = "Rule",
    ) -> analysis_utils.AnalysisItem:
        item = MagicMock(spec=analysis_utils.AnalysisItem)
        item.analysis_id.return_value = analysis_id
        item.analysis_type.return_value = analysis_type
        item.description.return_value = description
        item.pretty_analysis_type.return_value = pretty_type
        return item

    return _make_analysis_item


def test_init(mocker: MockerFixture) -> None:
    mocker.patch("panther_analysis_tool.gui.widgets.DataTable.__init__", return_value=None)
    table = widgets.AnalysisItemDataTable()
    assert table.all_table_data == []
    assert table.table_row_by_id == {}
    assert table.all_specs == []
    assert table.current_rows == []
    assert table.columns == ["Cloned", "Type", "ID", "Description"]


def test_table_item_to_table_row(
    table: widgets.AnalysisItemDataTable,
    make_analysis_item: Callable[..., analysis_utils.AnalysisItem],
) -> None:
    """Test conversion of AnalysisDataTableItem to TableRow."""
    item = make_analysis_item(
        analysis_id="Test.Rule",
        description="Test description",
        pretty_type="Rule",
    )
    table_item = widgets.AnalysisDataTableItem(user_has_item=True, item=item)

    row = table.table_item_to_table_row(table_item)

    assert row.type_label == "Rule"
    assert row.item_id_label == "Test.Rule"
    assert row.description_label == "Test description"
    assert row.user_has_item is True
    assert row.analysis_item == item


def test_table_item_to_table_row_no_description(
    table: widgets.AnalysisItemDataTable,
    make_analysis_item: Callable[..., analysis_utils.AnalysisItem],
) -> None:
    """Test conversion when item has no description."""
    item = make_analysis_item(description="")
    table_item = widgets.AnalysisDataTableItem(user_has_item=False, item=item)

    row = table.table_item_to_table_row(table_item)

    assert row.description_label == "(No description)"


def test_table_item_to_table_row_strips_whitespace(
    table: widgets.AnalysisItemDataTable,
    make_analysis_item: Callable[..., analysis_utils.AnalysisItem],
) -> None:
    """Test that whitespace is stripped from labels."""
    item = make_analysis_item(
        analysis_id="  Test.Rule  ",
        description="  Test description  ",
        pretty_type="  Rule  ",
    )
    table_item = widgets.AnalysisDataTableItem(user_has_item=False, item=item)

    row = table.table_item_to_table_row(table_item)

    assert row.type_label == "Rule"
    assert row.item_id_label == "Test.Rule"
    assert row.description_label == "Test description"


def test_add_row_to_table_with_checkmark(
    table: widgets.AnalysisItemDataTable,
    make_analysis_item: Callable[..., analysis_utils.AnalysisItem],
) -> None:
    """Test adding a row when user has the item (should show green checkmark)."""
    item = make_analysis_item()
    row = widgets.TableRow(
        type_label="Rule",
        item_id_label="Test.Rule",
        description_label="Test description",
        user_has_item=True,
        analysis_item=item,
    )

    table.add_row_to_table(row)

    assert len(table.current_rows) == 1
    assert table.current_rows[0] == row
    table.add_row.assert_called_once_with(  # type: ignore[attr-defined]
        "[green]✓[/green]", "Rule", "Test.Rule", "Test description"
    )


def test_add_row_to_table_without_checkmark(
    table: widgets.AnalysisItemDataTable,
    make_analysis_item: Callable[..., analysis_utils.AnalysisItem],
) -> None:
    """Test adding a row when user doesn't have the item (no checkmark)."""
    item = make_analysis_item()
    row = widgets.TableRow(
        type_label="Rule",
        item_id_label="Test.Rule",
        description_label="Test description",
        user_has_item=False,
        analysis_item=item,
    )

    table.add_row_to_table(row)

    assert len(table.current_rows) == 1
    table.add_row.assert_called_once_with("", "Rule", "Test.Rule", "Test description")  # type: ignore[attr-defined]


def test_add_specs_to_table(
    table: widgets.AnalysisItemDataTable,
    make_analysis_item: Callable[..., analysis_utils.AnalysisItem],
) -> None:
    """Test adding multiple specs to the table."""
    item1 = make_analysis_item(analysis_id="Rule1", pretty_type="Rule")
    item2 = make_analysis_item(analysis_id="Rule2", pretty_type="Policy")
    items = [
        widgets.AnalysisDataTableItem(user_has_item=True, item=item1),
        widgets.AnalysisDataTableItem(user_has_item=False, item=item2),
    ]

    table.add_specs_to_table(items)

    assert len(table.all_table_data) == 2
    assert len(table.all_specs) == 2
    assert len(table.table_row_by_id) == 2
    assert "Rule1" in table.table_row_by_id
    assert "Rule2" in table.table_row_by_id
    assert table.add_row.call_count == 2  # type: ignore[attr-defined]


def test_clear(table: widgets.AnalysisItemDataTable) -> None:
    """Test that clear resets current_rows and calls parent clear."""
    table.current_rows = [MagicMock(), MagicMock()]
    result = table.clear()

    assert table.current_rows == []
    assert result == table
    table.clear.assert_called_once_with(columns=False)  # type: ignore[attr-defined]


def test_add_rows_to_table(
    table: widgets.AnalysisItemDataTable,
    make_analysis_item: Callable[..., analysis_utils.AnalysisItem],
) -> None:
    """Test adding multiple rows to the table."""
    item1 = make_analysis_item(analysis_id="Rule1")
    item2 = make_analysis_item(analysis_id="Rule2")
    rows = [
        widgets.TableRow(
            type_label="Rule",
            item_id_label="Rule1",
            description_label="Desc1",
            user_has_item=True,
            analysis_item=item1,
        ),
        widgets.TableRow(
            type_label="Policy",
            item_id_label="Rule2",
            description_label="Desc2",
            user_has_item=False,
            analysis_item=item2,
        ),
    ]

    table.add_rows_to_table(rows)

    assert len(table.current_rows) == 2
    assert table.add_row.call_count == 2  # type: ignore[attr-defined]


def test_search_matches_item_by_id(
    table: widgets.AnalysisItemDataTable,
    make_analysis_item: Callable[..., analysis_utils.AnalysisItem],
) -> None:
    """Test search matching by analysis ID."""
    item = make_analysis_item(analysis_id="Test.Rule.123")
    assert table.search_matches_item("rule.123", item) is True
    assert table.search_matches_item("test", item) is True
    assert table.search_matches_item("nonexistent", item) is False


def test_search_matches_item_by_type(
    table: widgets.AnalysisItemDataTable,
    make_analysis_item: Callable[..., analysis_utils.AnalysisItem],
) -> None:
    """Test search matching by analysis type."""
    item = make_analysis_item(analysis_type="RULE", pretty_type="Rule")
    assert table.search_matches_item("rule", item) is True
    assert table.search_matches_item("RULE", item) is True


def test_search_matches_item_by_description(
    table: widgets.AnalysisItemDataTable,
    make_analysis_item: Callable[..., analysis_utils.AnalysisItem],
) -> None:
    """Test search matching by description."""
    item = make_analysis_item(description="This is a test rule")
    assert table.search_matches_item("test", item) is True
    assert table.search_matches_item("rule", item) is True
    assert table.search_matches_item("nonexistent", item) is False


def test_search_matches_item_case_insensitive(
    table: widgets.AnalysisItemDataTable,
    make_analysis_item: Callable[..., analysis_utils.AnalysisItem],
) -> None:
    """Test that search is case insensitive."""
    item = make_analysis_item(analysis_id="Test.Rule", description="Test Description")
    assert table.search_matches_item("TEST", item) is True
    assert table.search_matches_item("rule", item) is True
    assert table.search_matches_item("DESCRIPTION", item) is True


def test_filter_by_search_term_empty(
    table: widgets.AnalysisItemDataTable,
    make_analysis_item: Callable[..., analysis_utils.AnalysisItem],
) -> None:
    """Test filtering with empty search term resets table."""
    item = make_analysis_item()
    row = widgets.TableRow(
        type_label="Rule",
        item_id_label="Test.Rule",
        description_label="Test",
        user_has_item=False,
        analysis_item=item,
    )
    table.all_table_data = [row]
    # Mock reset_table to track calls
    table.reset_table = MagicMock()  # type: ignore[method-assign]

    table.filter_by_search_term("")

    # reset_table is called internally, verify via add_rows_to_table being called
    # Since reset_table calls add_rows_to_table with all_table_data
    assert table.add_row.call_count >= 1  # type: ignore[attr-defined]


def test_filter_by_search_term_matches(
    table: widgets.AnalysisItemDataTable,
    make_analysis_item: Callable[..., analysis_utils.AnalysisItem],
) -> None:
    """Test filtering by search term that matches items."""
    item1 = make_analysis_item(analysis_id="Rule1", description="Test rule")
    item2 = make_analysis_item(analysis_id="Rule2", description="Other rule")
    row1 = widgets.TableRow(
        type_label="Rule",
        item_id_label="Rule1",
        description_label="Test rule",
        user_has_item=False,
        analysis_item=item1,
    )
    row2 = widgets.TableRow(
        type_label="Rule",
        item_id_label="Rule2",
        description_label="Other rule",
        user_has_item=False,
        analysis_item=item2,
    )
    table.all_table_data = [row1, row2]

    table.filter_by_search_term("test")

    # Should only add row1 since it matches "test"
    assert table.add_row.call_count == 1  # type: ignore[attr-defined]


def test_filter_by_id(
    table: widgets.AnalysisItemDataTable,
    make_analysis_item: Callable[..., analysis_utils.AnalysisItem],
) -> None:
    """Test filtering by specific ID."""
    item1 = make_analysis_item(analysis_id="Rule1")
    item2 = make_analysis_item(analysis_id="Rule2")
    row1 = widgets.TableRow(
        type_label="Rule",
        item_id_label="Rule1",
        description_label="Desc1",
        user_has_item=False,
        analysis_item=item1,
    )
    row2 = widgets.TableRow(
        type_label="Rule",
        item_id_label="Rule2",
        description_label="Desc2",
        user_has_item=False,
        analysis_item=item2,
    )
    table.all_table_data = [row1, row2]

    table.filter_by_id("Rule1")

    # Should only add row1
    assert table.add_row.call_count == 1  # type: ignore[attr-defined]
    table.add_row.assert_called_once_with("", "Rule", "Rule1", "Desc1")  # type: ignore[attr-defined]


def test_filter_by_id_not_found(
    table: widgets.AnalysisItemDataTable,
    make_analysis_item: Callable[..., analysis_utils.AnalysisItem],
) -> None:
    """Test filtering by ID that doesn't exist."""
    item = make_analysis_item(analysis_id="Rule1")
    row = widgets.TableRow(
        type_label="Rule",
        item_id_label="Rule1",
        description_label="Desc",
        user_has_item=False,
        analysis_item=item,
    )
    table.all_table_data = [row]

    table.filter_by_id("Nonexistent")

    # Should not add any rows
    assert table.add_row.call_count == 0  # type: ignore[attr-defined]


def test_filter_by_type_pretty_type(
    table: widgets.AnalysisItemDataTable,
    make_analysis_item: Callable[..., analysis_utils.AnalysisItem],
) -> None:
    """Test filtering by pretty analysis type."""
    item1 = make_analysis_item(analysis_type="RULE", pretty_type="Rule")
    item2 = make_analysis_item(analysis_type="POLICY", pretty_type="Policy")
    row1 = widgets.TableRow(
        type_label="Rule",
        item_id_label="Rule1",
        description_label="Desc1",
        user_has_item=False,
        analysis_item=item1,
    )
    row2 = widgets.TableRow(
        type_label="Policy",
        item_id_label="Policy1",
        description_label="Desc2",
        user_has_item=False,
        analysis_item=item2,
    )
    table.all_table_data = [row1, row2]

    table.filter_by_type("Rule")

    # Should only add row1
    assert table.add_row.call_count == 1  # type: ignore[attr-defined]


def test_filter_by_type_analysis_type(
    table: widgets.AnalysisItemDataTable,
    make_analysis_item: Callable[..., analysis_utils.AnalysisItem],
) -> None:
    """Test filtering by analysis type string."""
    item1 = make_analysis_item(analysis_type="RULE", pretty_type="Rule")
    item2 = make_analysis_item(analysis_type="POLICY", pretty_type="Policy")
    row1 = widgets.TableRow(
        type_label="Rule",
        item_id_label="Rule1",
        description_label="Desc1",
        user_has_item=False,
        analysis_item=item1,
    )
    row2 = widgets.TableRow(
        type_label="Policy",
        item_id_label="Policy1",
        description_label="Desc2",
        user_has_item=False,
        analysis_item=item2,
    )
    table.all_table_data = [row1, row2]

    table.filter_by_type("RULE")

    # Should only add row1
    assert table.add_row.call_count == 1  # type: ignore[attr-defined]


def test_reset_table(
    table: widgets.AnalysisItemDataTable,
    make_analysis_item: Callable[..., analysis_utils.AnalysisItem],
) -> None:
    """Test resetting the table to show all items."""
    item1 = make_analysis_item(analysis_id="Rule1")
    item2 = make_analysis_item(analysis_id="Rule2")
    row1 = widgets.TableRow(
        type_label="Rule",
        item_id_label="Rule1",
        description_label="Desc1",
        user_has_item=False,
        analysis_item=item1,
    )
    row2 = widgets.TableRow(
        type_label="Rule",
        item_id_label="Rule2",
        description_label="Desc2",
        user_has_item=False,
        analysis_item=item2,
    )
    table.all_table_data = [row1, row2]

    table.reset_table()

    # Should add both rows
    assert table.add_row.call_count == 2  # type: ignore[attr-defined]


def test_mark_user_has_item(
    table: widgets.AnalysisItemDataTable,
    make_analysis_item: Callable[..., analysis_utils.AnalysisItem],
) -> None:
    """Test marking an item as owned by the user."""
    item = make_analysis_item(analysis_id="Test.Rule")
    table_item = widgets.AnalysisDataTableItem(user_has_item=False, item=item)
    table.all_specs = [table_item]

    row = widgets.TableRow(
        type_label="Rule",
        item_id_label="Test.Rule",
        description_label="Test",
        user_has_item=False,
        analysis_item=item,
    )
    table.table_row_by_id["Test.Rule"] = row
    table.current_rows = [row]

    table.mark_user_has_item("Test.Rule")

    assert row.user_has_item is True
    assert table_item.user_has_item is True
    # Should refresh the table
    assert table.add_row.call_count >= 1  # type: ignore[attr-defined]


def test_mark_user_has_item_updates_spec(
    table: widgets.AnalysisItemDataTable,
    make_analysis_item: Callable[..., analysis_utils.AnalysisItem],
) -> None:
    """Test that mark_user_has_item updates the spec in all_specs."""
    item1 = make_analysis_item(analysis_id="Rule1")
    item2 = make_analysis_item(analysis_id="Rule2")
    table_item1 = widgets.AnalysisDataTableItem(user_has_item=False, item=item1)
    table_item2 = widgets.AnalysisDataTableItem(user_has_item=False, item=item2)
    table.all_specs = [table_item1, table_item2]

    row1 = widgets.TableRow(
        type_label="Rule",
        item_id_label="Rule1",
        description_label="Test",
        user_has_item=False,
        analysis_item=item1,
    )
    table.table_row_by_id["Rule1"] = row1
    table.current_rows = [row1]

    table.mark_user_has_item("Rule1")

    assert table_item1.user_has_item is True
    assert table_item2.user_has_item is False  # Should remain unchanged
