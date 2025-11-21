from collections import defaultdict
from typing import Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import DataTable, Footer, Input, Tree

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.command import clone
from panther_analysis_tool.gui import widgets


class ExploreApp(App):
    """A Textual app to explore Panther Analysis content."""

    BINDINGS = [
        Binding("ctrl+d", "toggle_dark", "Toggle dark mode", show=True),
        Binding("ctrl+q", "quit", "Quit", show=True),
        Binding("tab", "switch_focus", "Switch focus", show=True, priority=True),
        Binding(
            "escape", "close_editors", "Back to analysis item explorer", show=True, priority=True
        ),
        Binding(
            "ctrl+v",  # ctrl+c displays a warning prompt about quitting
            "clone_analysis_item",
            "Clone and enable selected analysis item",
            show=True,
            priority=True,
        ),
    ]

    CSS_PATH = "explore_gui.tcss"

    def __init__(
        self, all_specs: list[analysis_utils.AnalysisItem], *args: Any, **kwargs: Any
    ) -> None:
        super().__init__(*args, **kwargs)
        self.all_specs = all_specs
        self.view_editors = False
        self.selected_item: analysis_utils.AnalysisItem | None = None

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Footer()
        yield Input(placeholder="Search by Type, ID, or Description...", id="search-input")

        yield Horizontal(
            Tree(id="tree", label="Analysis Content"),  # Will be populated in on_mount
            widgets.AnalysisItemDataTable(id="table", cursor_type="row", show_row_labels=True),
            id="main-content",
        )

        yield Horizontal(
            widgets.YAMLWindow(text="", id="yaml-window"),
            widgets.PythonWindow(text="", id="python-window"),
            id="code-windows",
        )

    def on_mount(self) -> None:
        """Populate the DataTable and Tree when the app starts."""
        table = self.query_one("#table", widgets.AnalysisItemDataTable)
        table.add_specs_to_table(self.all_specs)

        self.all_specs.sort(key=lambda x: x.pretty_analysis_type() + x.analysis_id())
        self.add_specs_to_tree(self.all_specs)

        self.query_one("#code-windows").styles.display = "none"

    def add_specs_to_tree(self, specs: list[analysis_utils.AnalysisItem]) -> None:
        """Add specs to the tree."""
        tree = self.query_one("#tree", Tree)
        tree.clear()
        tree.root.label = "Analysis Content"
        tree.root.expand()

        spec_by_type = defaultdict(list)

        for spec in specs:
            spec_by_type[spec.pretty_analysis_type()].append(spec)

        for analysis_type, specs in spec_by_type.items():
            analysis_node = tree.root.add(analysis_type, expand=False)

            for spec in specs:
                analysis_node.add_leaf(spec.analysis_id())

    def analysis_item_by_id(self, id: str) -> analysis_utils.AnalysisItem:
        for spec in self.all_specs:
            if spec.analysis_id() == id:
                return spec
        raise ValueError(f"Analysis item with ID {id} not found in all_specs.")

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        """Check if an action should be enabled based on current state."""
        if action == "close_editors" or action == "enable_analysis_item":
            # Only show the "Back to explorer" and "Enable" binding when viewing editors
            return self.view_editors
        return True

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection in the DataTable."""
        _, item_id, _ = event.data_table.get_row(event.row_key)
        item = self.analysis_item_by_id(item_id)
        self.view_editors = True
        self.switch_views(item)
        self.refresh_bindings()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle search input changes to filter the table."""
        search_term = event.value.lower().strip()
        table = self.query_one("#table", widgets.AnalysisItemDataTable)
        table.filter_by_search_term(search_term)

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        """Handle tree node selection to filter the table."""
        table = self.query_one("#table", widgets.AnalysisItemDataTable)
        # If it's a leaf node (individual item), show only that item
        if not event.node.children:
            selected_id = str(event.node.label)
            table.filter_by_id(selected_id)
        else:
            # If it's a parent node, show all items under it
            pretty_analysis_type = str(event.node.label)
            table.filter_by_type(pretty_analysis_type)

    def action_toggle_dark(self) -> None:
        """An action to toggle dark mode."""
        self.theme = "textual-dark" if self.theme == "textual-light" else "textual-light"

    def action_close_editors(self) -> None:
        """Close the editor view and return to the main content."""
        self.view_editors = False
        self.switch_views(None)
        self.refresh_bindings()

    def action_clone_analysis_item(self) -> None:
        """Clone and enable the selected analysis item."""
        if self.selected_item is None:
            self.notify("No analysis item selected.", severity="error")
            return

        try:
            clone.clone(self.selected_item.analysis_id(), [])
            self.notify(
                f"{self.selected_item.pretty_analysis_type()} {self.selected_item.analysis_id()} ready to use!"
            )
        except Exception as err:
            self.notify(str(err), severity="error")

        self.refresh_bindings()

        self.view_editors = False
        self.switch_views(None)

    def switch_views(self, item: analysis_utils.AnalysisItem | None) -> None:
        if self.view_editors and item is not None:
            self.selected_item = item
            yaml_window = self.query_one("#yaml-window", widgets.YAMLWindow)
            yaml_window.text = item.raw_yaml_file_contents.decode("utf-8")  # type: ignore
            yaml_window.focus()

            py_window = self.query_one("#python-window", widgets.PythonWindow)
            if item.python_file_contents is not None:
                py_window.text = item.python_file_contents.decode("utf-8")
                py_window.styles.display = "block"
            else:
                py_window.styles.display = "none"

            self.query_one("#code-windows").styles.display = "block"
            self.query_one("#main-content").styles.display = "none"
            self.query_one("#search-input").styles.display = "none"
        else:
            self.selected_item = None
            self.query_one("#code-windows").styles.display = "none"
            self.query_one("#main-content").styles.display = "block"
            self.query_one("#search-input").styles.display = "block"
            self.query_one("#table").focus()
