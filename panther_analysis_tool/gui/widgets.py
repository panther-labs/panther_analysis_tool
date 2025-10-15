import dataclasses
from typing import Any

from textual.widgets import DataTable, TextArea

from panther_analysis_tool import analysis_utils

_EDITOR_THEME = "vscode_dark"


class PythonWindow(TextArea):
    def __init__(self, text: str, read_only: bool = True, *args: Any, **kwargs: Any) -> None:
        super().__init__(
            text, theme=_EDITOR_THEME, language="python", read_only=read_only, *args, **kwargs
        )

    def on_mount(self) -> None:
        self.scroll_home(animate=False)


class YAMLWindow(TextArea):
    def __init__(self, text: str, read_only: bool = True, *args: Any, **kwargs: Any) -> None:
        super().__init__(
            text, theme=_EDITOR_THEME, language="yaml", read_only=read_only, *args, **kwargs
        )
        self.show_line_numbers = True
        self.highlight_cursor_line = True

    def highlight_line(self, key: str) -> None:
        lines = self.text.splitlines()
        for i, line in enumerate(lines):
            if line.strip().startswith(f"{key}:"):
                self.move_cursor((i, 0))
                self.scroll_to(y=i - 1, animate=True, easing="in_out_cubic", duration=0.5)


@dataclasses.dataclass
class TableRow:
    type: str
    item_id: str
    description: str


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
