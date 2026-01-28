import dataclasses
import io
from typing import Any

from ruamel import yaml
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import DataTable, Label, TextArea

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.core import parse

_EDITOR_THEME = "vscode_dark"

yaml_parser = yaml.YAML(typ="rt")
yaml_parser.preserve_quotes = True


@dataclasses.dataclass
class YamlDiffItem:
    key: str
    cust_val: Any
    panther_val: Any
    base_val: Any


@dataclasses.dataclass
class TableRow:
    type_label: str
    item_id_label: str
    description_label: str
    user_has_item: bool
    analysis_item: analysis_utils.AnalysisItem


class PythonWindow(TextArea):
    def __init__(self, text: str, read_only: bool = True, *args: Any, **kwargs: Any) -> None:
        super().__init__(
            text, theme=_EDITOR_THEME, language="python", read_only=read_only, *args, **kwargs
        )

    def on_mount(self) -> None:
        self.scroll_home(animate=False)


class YAMLWindow(TextArea):
    doc_lines: list[str] = []

    def __init__(self, text: str, read_only: bool = True, *args: Any, **kwargs: Any) -> None:
        super().__init__(
            text, theme=_EDITOR_THEME, language="yaml", read_only=read_only, *args, **kwargs
        )
        self.show_line_numbers = True
        self.highlight_cursor_line = True
        self.doc_lines = []

    def on_mount(self) -> None:
        for wrapped_line in self.wrapped_document.lines:
            for line in wrapped_line:
                self.doc_lines.append(line)

    def highlight_line(self, key: str) -> None:
        for i, line in enumerate(self.doc_lines):
            if line.strip().startswith(f"{key}:"):
                self.move_cursor((i, 0), center=True)
                break


class CustomerYAMLWindow(YAMLWindow):
    BORDER_TITLE = "Your YAML"


class PantherYAMLWindow(YAMLWindow):
    BORDER_TITLE = "Panther YAML"


class CustomerValueYAMLWindow(YAMLWindow):
    BORDER_TITLE = "Your Value [y]"


class PantherValueYAMLWindow(YAMLWindow):
    BORDER_TITLE = "Panther Value [p]"


class CustomerPythonWindow(PythonWindow):
    BORDER_TITLE = "Your Python"


@dataclasses.dataclass
class AnalysisDataTableItem:
    user_has_item: bool
    item: analysis_utils.AnalysisItem


class AnalysisItemDataTable(DataTable):
    all_table_data: list[TableRow]
    table_row_by_id: dict[str, TableRow]
    all_specs: list[AnalysisDataTableItem]
    current_rows: list[TableRow]
    CLONED_INDICATOR = "[green]Yes ✓[/green]"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.add_columns("Cloned", "Type", "ID", "Description")
        self.all_table_data = []
        self.table_row_by_id = {}
        self.all_specs = []
        self.current_rows = []

    def add_specs_to_table(self, items: list[AnalysisDataTableItem]) -> None:
        """Add specs to the table."""
        self.clear()
        self.all_specs = items

        for item in items:
            row = self.table_item_to_table_row(item)
            self.all_table_data.append(row)
            self.add_row_to_table(row)
            self.table_row_by_id[item.item.analysis_id()] = row

    def table_item_to_table_row(self, item: AnalysisDataTableItem) -> TableRow:
        return TableRow(
            type_label=item.item.pretty_analysis_type().strip(),
            item_id_label=item.item.analysis_id().strip(),
            description_label=item.item.description().strip() or "(No description)",
            user_has_item=item.user_has_item,
            analysis_item=item.item,
        )

    def mark_user_has_item(self, item_id: str) -> None:
        self.table_row_by_id[item_id].user_has_item = True
        for spec in self.all_specs:
            if spec.item.analysis_id() == item_id:
                spec.user_has_item = True
                break

        # refresh data in table
        self.add_rows_to_table(self.current_rows)

    def add_row_to_table(self, row: TableRow) -> None:
        self.current_rows.append(row)
        status_indicator = self.CLONED_INDICATOR if row.user_has_item else "No"
        self.add_row(status_indicator, row.type_label, row.item_id_label, row.description_label)

    def clear(self, columns: bool = False) -> "AnalysisItemDataTable":
        self.current_rows = []
        return super().clear(columns=columns)

    def add_rows_to_table(self, rows: list[TableRow]) -> None:
        self.clear()
        for row in rows:
            self.add_row_to_table(row)

    def filter_by_filters(self, filters: list[parse.Filter]) -> None:
        self.clear()

        if not filters:
            self.reset_table()

        else:
            self.add_rows_to_table(
                [
                    row
                    for row in self.all_table_data
                    if analysis_utils.filters_match_analysis_item(filters, row.analysis_item)
                ]
            )

    def filter_by_id(self, _id: str) -> None:
        self.clear()
        for row in self.all_table_data:
            if _id == row.analysis_item.analysis_id():
                self.add_row_to_table(row)
                break

    def filter_by_type(self, _type: str) -> None:
        self.clear()
        for row in self.all_table_data:
            if (
                _type == row.analysis_item.pretty_analysis_type()
                or _type == row.analysis_item.analysis_type()
            ):
                self.add_row_to_table(row)

    def reset_table(self) -> None:
        self.clear()
        self.add_rows_to_table(self.all_table_data)


class DiffResolver(Widget):
    def __init__(self, diff_item: YamlDiffItem):
        super().__init__()
        self.diff_item = diff_item

    def fmt_panther_val(self) -> str:
        out = io.StringIO()
        yaml_parser.dump(self.diff_item.panther_val, out)
        return out.getvalue()

    def fmt_cust_val(self) -> str:
        out = io.StringIO()
        yaml_parser.dump(self.diff_item.cust_val, out)
        return out.getvalue()

    def compose(self) -> ComposeResult:
        yield Label(self.fmt_label())
        yield Horizontal(
            CustomerValueYAMLWindow(text="", id="customer-value-yaml"),
            PantherValueYAMLWindow(text="", id="panther-value-yaml"),
        )

    def fmt_label(self) -> str:
        return f'Resolving conflict for: {self.diff_item.key} (press "y" for your value or "p" for Panther\'s value)'
