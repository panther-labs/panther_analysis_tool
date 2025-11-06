from typing import Any, Literal

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import Footer, Label

from panther_analysis_tool.core import diff
from panther_analysis_tool.gui import widgets


class YAMLConflictResolverApp(App):
    """A Textual app to resolve YAML conflicts."""

    diff_items: list[widgets.YamlDiffItem]
    current_item_index: int = 0
    final_dict: dict[str, Any]
    customer_yaml: str
    panther_yaml: str
    customer_python: str

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=True),
        Binding("p", "choose_panther", r"Select Panther's value", show=True),
        Binding("y", "choose_yours", r"Select your value", show=True),
        Binding("s", "switch_view", "Switch view", show=True),
    ]

    CSS_PATH = "yaml_conflict_resolver_gui.tcss"

    view: Literal["yaml", "python"] = "yaml"

    def __init__(
        self,
        customer_python: str,
        raw_customer_yaml: str,
        raw_panther_yaml: str,
        raw_base_yaml: str,
        customer_dict: dict,
        conflict_items: list[diff.DictMergeConflict],
    ) -> None:
        super().__init__()
        self.customer_python = customer_python
        self.customer_yaml = raw_customer_yaml
        self.panther_yaml = raw_panther_yaml
        self.final_dict = customer_dict
        self.diff_items = [
            widgets.YamlDiffItem(
                conflict.key, conflict.cust_val, conflict.latest_val, conflict.base_val
            )
            for conflict in conflict_items
        ]

    def compose(self) -> ComposeResult:
        yield Horizontal(
            widgets.CustomerPythonWindow(self.customer_python, id="customer-python"),
            widgets.CustomerYAMLWindow(self.customer_yaml, id="customer-yaml"),
            widgets.PantherYAMLWindow(self.panther_yaml, id="panther-yaml"),
            id="file-viewing",
        )
        yield widgets.DiffResolver(self.diff_items[0])
        yield Footer()

    def on_mount(self) -> None:
        self.update_view()
        self.update_diff_item()
        self.query_one("#customer-yaml").focus()

    def action_switch_view(self) -> None:
        self.view = "python" if self.view == "yaml" else "yaml"
        self.update_view()
        self.refresh()

    def update_view(self) -> None:
        if self.view == "yaml":
            self.query_one(widgets.CustomerPythonWindow).styles.display = "none"
            self.query_one(widgets.CustomerYAMLWindow).styles.display = "block"
            self.query_one(widgets.PantherYAMLWindow).styles.display = "block"
        elif self.view == "python":
            self.query_one(widgets.CustomerPythonWindow).styles.display = "block"
            self.query_one(widgets.CustomerYAMLWindow).styles.display = "none"
            self.query_one(widgets.PantherYAMLWindow).styles.display = "none"

    def action_choose_panther(self) -> None:
        self.update_final_dict(self.diff_items[self.current_item_index].panther_val)
        self.next_item()

    def action_choose_yours(self) -> None:
        self.update_final_dict(self.diff_items[self.current_item_index].cust_val)
        self.next_item()

    def update_final_dict(self, val: Any) -> None:
        if isinstance(val, str):
            val = val.strip()
        self.final_dict[self.diff_items[self.current_item_index].key] = val

    def next_item(self) -> None:
        self.current_item_index += 1
        if self.current_item_index >= len(self.diff_items):
            self.exit()
        else:
            self.update_diff_item()

    def update_diff_item(self) -> None:
        diff_resolver = self.query_one(widgets.DiffResolver)
        new_diff_item = self.diff_items[self.current_item_index]
        diff_resolver.diff_item = new_diff_item

        label = diff_resolver.query_one(Label)
        label.update(diff_resolver.fmt_label())

        panther_val = diff_resolver.fmt_panther_val()
        customer_val = diff_resolver.fmt_cust_val()

        diff_resolver.query_one(widgets.PantherValueYAMLWindow).text = panther_val
        diff_resolver.query_one(widgets.CustomerValueYAMLWindow).text = customer_val

        self.query_one("#panther-yaml", widgets.YAMLWindow).highlight_line(new_diff_item.key)
        self.query_one("#customer-yaml", widgets.YAMLWindow).highlight_line(new_diff_item.key)

        self.refresh()

    def get_final_dict(self) -> dict:
        return self.final_dict
