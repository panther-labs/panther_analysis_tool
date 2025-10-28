import dataclasses
import io
from typing import Any

from ruamel import yaml
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import DataTable, Label, TextArea

from panther_analysis_tool import analysis_utils

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
    type: str
    item_id: str
    description: str


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


class AnalysisItemDataTable(DataTable):
    all_table_data: list[TableRow]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.add_columns("Type", "ID", "Description")
        self.all_table_data = []

    def add_specs_to_table(self, specs: list[analysis_utils.AnalysisItem]) -> None:
        """Add specs to the table."""
        self.clear()
        for spec in specs:
            row = TableRow(
                type=spec.pretty_analysis_type().strip(),
                item_id=spec.analysis_id().strip(),
                description=spec.description().strip() or "(No description)",
            )
            self.all_table_data.append(row)
            self.add_row_to_table(row)

    def add_row_to_table(self, row: TableRow) -> None:
        self.add_row(row.type, row.item_id, row.description)

    def add_rows_to_table(self, rows: list[TableRow]) -> None:
        self.clear()
        for row in rows:
            self.add_row_to_table(row)

    def filter_by_search_term(self, search_term: str) -> None:
        self.clear()

        if not search_term:
            self.reset_table()
        else:
            # Filter items that match the search term in either ID, type, or Description
            self.add_rows_to_table(
                [
                    row
                    for row in self.all_table_data
                    if search_term in row.item_id.lower()
                    or search_term in row.type.lower()
                    or search_term in row.description.lower()
                ]
            )

    def filter_by_id(self, _id: str) -> None:
        self.clear()
        for row in self.all_table_data:
            if _id == row.item_id:
                self.add_row_to_table(row)
                break

    def filter_by_type(self, _type: str) -> None:
        self.clear()
        for row in self.all_table_data:
            if _type == row.type:
                self.add_row_to_table(row)

    def reset_table(self) -> None:
        self.clear()
        for row in self.all_table_data:
            self.add_row_to_table(row)


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
