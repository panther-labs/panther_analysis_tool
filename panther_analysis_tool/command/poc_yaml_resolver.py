import dataclasses
import sys
from typing import Any, List, Tuple

from ruamel import yaml
from ruamel.yaml.scalarstring import DoubleQuotedScalarString
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Grid
from textual.widget import Widget
from textual.widgets import Footer, Label, Static, TextArea

from . import fake_customer_files


@dataclasses.dataclass
class YamlDiffItem:
    key: str
    cust_val: Any
    panther_val: Any
    base_val: Any

class PythonWindow(TextArea):
    def __init__(self, title: str, text: str, *args: Any, **kwargs: Any) -> None:
        super().__init__(text, theme='monokai', language='python', read_only=True, *args, **kwargs)

    def on_mount(self) -> None:
        self.scroll_home(animate=False)

class YAMLWindow(TextArea):
    def __init__(self, title: str, text: str, *args: Any, **kwargs: Any) -> None:
        super().__init__(text, theme='monokai', language='yaml', read_only=True, *args, **kwargs)
        self.show_line_numbers = True
        self.highlight_cursor_line = True

    def highlight_line(self, key: str) -> None:
        lines = self.text.splitlines()
        for i, line in enumerate(lines):
            if line.strip().startswith(f"{key}:"):
                print(f"Highlighting line {i} {key}")
                self.move_cursor((i, 0))
                self.scroll_to(y=i-1, animate=True, easing="in_out_cubic", duration=0.5)
                

class CustomerYAMLWindow(YAMLWindow):
    BORDER_TITLE = "Customer YAML"

class PantherYAMLWindow(YAMLWindow):
    BORDER_TITLE = "Panther YAML"

class CustomerPythonWindow(PythonWindow):
    BORDER_TITLE = "Customer Python"

class DiffResolver(Static):
    def __init__(self, diff_item: YamlDiffItem):
        super().__init__()
        self.diff_item = diff_item

    def compose(self) -> ComposeResult:
        yield Label(f"Resolving conflict for YAML key: {self.diff_item.key}")
        yield Label(f"Base value: {self.diff_item.base_val}")
        yield Label(f"Panther value [p]: {self.diff_item.panther_val}")
        yield Label(f"Your value [y]: {self.diff_item.cust_val}")


class YAMLResolver(App):
    diff_items: list[YamlDiffItem]
    current_item_index: int = 0
    final_dict: dict[str, Any]
    
    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=True),
        Binding("p", "choose_panther", r"Select Panther's value", show=True),
        Binding("y", "choose_yours", r"Select our value", show=True),
        Binding("tab", "switch_focus", "Switch focus", show=True, priority=True)
    ]

    CSS = """
        Grid {
            grid-size: 2 2;
            height: 3fr;
        }
        #customer-python {
            row-span: 2;
        }
        TitledWindow {
            height: 100%;
            border: solid gray;
        }
        TitledWindow:focus-within {
            border: solid blue;
        }
        TextArea {
            height: 1fr;
            padding: 1;
        }
        DiffResolver {
            height: 1fr;
            background: $surface;
            padding: 1;
            border-top: solid white;
        }
        DiffResolver Horizontal {
            height: auto;
            align: center middle;
        }
        Header {
            background: $boost;
            color: $text;
            text-align: center;
            padding: 1;
        }
    """

    def compose(self) -> ComposeResult:
        yield Grid(
            PantherYAMLWindow("Panther YAML", fake_customer_files.PANTHER_YAML, id="panther-yaml"),
            CustomerPythonWindow("Customer Python", fake_customer_files.CUSTOMER_PYTHON, id="customer-python"),
            CustomerYAMLWindow("Customer YAML", fake_customer_files.CUSTOMER_YAML, id="customer-yaml"),
        )
        yield DiffResolver(self.diff_items[0])
        yield Footer()

    def on_mount(self) -> None:
        self.set_focus(self.query_one("#panther-yaml"))
        self.update_diff_item()

    def action_choose_panther(self) -> None:
        self.update_final_dict(self.diff_items[self.current_item_index].panther_val)
        self.next_item()

    def action_choose_yours(self) -> None:
        self.update_final_dict(self.diff_items[self.current_item_index].cust_val)
        self.next_item()

    def update_final_dict(self, val: Any) -> None:
        if isinstance(val, str):
            val = DoubleQuotedScalarString(val.strip())
        self.final_dict[self.diff_items[self.current_item_index].key] = val

    def next_item(self) -> None:
        self.current_item_index += 1
        if self.current_item_index >= len(self.diff_items):
            self.exit()
        else:
            self.update_diff_item()

    def update_diff_item(self) -> None:
        diff_resolver = self.query_one(DiffResolver)
        new_diff_item = self.diff_items[self.current_item_index]
        diff_resolver.diff_item = new_diff_item
        labels = diff_resolver.query(Label)
        labels[0].update(f"Resolving conflict for YAML key: {new_diff_item.key}")
        labels[1].update(f"Base value: {new_diff_item.base_val}")
        labels[2].update(f"Panther value [p]: {new_diff_item.panther_val}")
        labels[3].update(f"Your value [y]: {new_diff_item.cust_val}")
        self.query_one("#panther-yaml", YAMLWindow).highlight_line(new_diff_item.key)
        self.query_one("#customer-yaml", YAMLWindow).highlight_line(new_diff_item.key)
        self.refresh()

    def action_switch_focus(self) -> None:
        current = self.focused
        windows: List[Widget] = list(self.query(TextArea))
        if isinstance(current, Widget) and current in windows:
            next_index = (windows.index(current) + 1) % len(windows)
            self.set_focus(windows[next_index])



def run() -> Tuple[int, str]:
    yaml_parser = yaml.YAML(typ="rt")
    yaml_parser.preserve_quotes = True
    
    customer_dict = yaml_parser.load(fake_customer_files.CUSTOMER_YAML)
    base_dict = yaml_parser.load(fake_customer_files.BASE_YAML)
    panther_dict = yaml_parser.load(fake_customer_files.PANTHER_YAML)

    app = YAMLResolver()
    get_diff_items(app, base_dict, panther_dict, customer_dict)

    app.run()

    print(yaml_parser.dump(app.final_dict, sys.stdout))
    return 0, ""

def get_diff_items(app: YAMLResolver, base_dict: dict, panther_dict: dict, customer_dict: dict) -> None:
    diff_keys = diff_dict_keys(customer_dict, panther_dict)

    for k, v in panther_dict.items():
        if k not in customer_dict:
            customer_dict[k] = v.strip() if isinstance(v, str) else v

    diff_items: list[YamlDiffItem] = []
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
        diff_items.append(YamlDiffItem(key, cust_val, panther_val, base_val))

    app.diff_items = diff_items
    app.final_dict = customer_dict

def diff_dict_keys(dict1: dict, dict2: dict) -> list[str]:
    diff = []
    for key in dict1:
        if key in dict2 and dict1[key] != dict2[key]:
            diff.append(key)
    return diff