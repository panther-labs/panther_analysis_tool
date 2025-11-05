from typing import Any, Literal

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import Footer, Label

from panther_analysis_tool import analysis_utils
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
    ) -> None:
        super().__init__()
        self.parser = analysis_utils.get_yaml_loader(roundtrip=True)

        base_yaml = self.parser.load(raw_base_yaml)
        panther_yaml = self.parser.load(raw_panther_yaml)
        customer_yaml = self.parser.load(raw_customer_yaml)

        self.customer_python = customer_python
        self.customer_yaml = raw_customer_yaml
        self.panther_yaml = raw_panther_yaml
        self.diff_items, self.final_dict = get_diff_items(base_yaml, panther_yaml, customer_yaml)

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


def get_diff_items(
    base_dict: dict, panther_dict: dict, customer_dict: dict
) -> tuple[list[widgets.YamlDiffItem], dict]:
    """
    Get the diff items and the final dictionary. The base, panther, and customer dictionaries
    are the 3 different yaml specs that are the 3 parts of a 3-way merge.
    Each value in the dicts are compared to determine if there is a merge conflict. A value is
    considered a conflict if the base value is different from the panther value and the customer
    value is different from the base value.
    The customer dict is edited in place as returned as the final dictionary because it has metadata
    for the YAML formatting and comments that need to be preserved.

    Args:
        base_dict: The base dictionary.
        panther_dict: The panther dictionary.
        customer_dict: The customer dictionary.

    Returns:
        A tuple containing the diff items and the final dictionary, which is the customer dictionary with non-conflicting values applied.
    """
    diff_keys = diff_dict_keys(customer_dict, panther_dict)

    for k, v in panther_dict.items():
        if k not in customer_dict:
            # if the key is in the panther dict but not in the customer dict, add it to the customer dict
            # with the panther value
            customer_dict[k] = v.strip() if isinstance(v, str) else v

    diff_items: list[widgets.YamlDiffItem] = []
    for key in diff_keys:
        cust_val = customer_dict[key] if key in customer_dict else None
        panther_val = panther_dict[key] if key in panther_dict else None
        base_val = base_dict[key] if key in base_dict else None

        if base_val == panther_val and base_val != cust_val:
            customer_dict[key] = cust_val
            continue
        elif base_val == cust_val and base_val != panther_val:
            customer_dict[key] = panther_val
            continue
        diff_items.append(widgets.YamlDiffItem(key, cust_val, panther_val, base_val))

    return diff_items, customer_dict


def diff_dict_keys(dict1: dict, dict2: dict) -> list[str]:
    diff = []
    for key in dict1:
        if key in dict2 and dict1[key] != dict2[key]:
            diff.append(key)
    return diff
