import io
from textual.app import App, ComposeResult
from textual.widgets import Footer, Input, Label, Tree, DataTable, Button, Static
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from ruamel.yaml import YAML
from rich.text import Text

from panther_analysis_tool.core.analysis_cache import AnalysisCache


class RuleDetailsModal(ModalScreen[bool]):
    """Modal screen to display rule details."""
    
    def __init__(self, rule_id: str, description: str, yaml_content: dict) -> None:
        super().__init__()
        self.yaml_content = yaml_content
    
    def get_severity_icon(self, severity: str) -> str:
        """Get an icon for the severity level."""
        severity_icons = {
            "Critical": "🔥",  # Fire emoji for critical
            "High": "🚨",      # Alarm emoji for high
            "Medium": "⚠️",    # Warning emoji for medium
            "Low": "🔹",       # Blue diamond for low
            "Info": "📗",      # Info emoji for info
        }
        return severity_icons.get(severity, "❓")  # Question mark for unknown
    
    def get_enabled_icon(self, enabled: bool) -> str:
        """Get an icon for the enabled status."""
        return "✅" if enabled else "❌"  # Check mark for enabled, X for disabled
    
    def compose(self) -> ComposeResult:
        """Compose the modal content."""
        with Vertical(id="modal-content"):
            if "DisplayName" in self.yaml_content:
                yield Static(f"{self.yaml_content['DisplayName']}", classes="modal-title")

            if "RuleID" in self.yaml_content:
                yield Static(f"ID: {self.yaml_content['RuleID']}", classes="modal-field")
            
            # Show additional YAML fields if available
            if "Enabled" in self.yaml_content:
                enabled = self.yaml_content['Enabled']
                icon = self.get_enabled_icon(enabled)
                yield Static(f"Enabled: {icon} {enabled}", classes="modal-field")
            if "Severity" in self.yaml_content:
                severity = self.yaml_content['Severity']
                icon = self.get_severity_icon(severity)
                yield Static(f"Severity: {icon} {severity}", classes="modal-field")
            if "LogTypes" in self.yaml_content:
                log_types = ", ".join(self.yaml_content['LogTypes'])
                yield Static(f"Log Types: {log_types}", classes="modal-field")
            if "Tags" in self.yaml_content:
                tags = ", ".join(self.yaml_content['Tags'])
                yield Static(f"Tags: {tags}", classes="modal-field")

            if "Description" in self.yaml_content:
                yield Static(f"Description: {self.yaml_content['Description']}", classes="modal-description")
            
            yield Button("Close", id="close-modal", variant="primary")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press to close modal."""
        if event.button.id == "close-modal":
            self.dismiss(True)
    
    def on_key(self, event) -> None:
        """Handle key press to close modal with Escape."""
        if event.key == "escape":
            self.dismiss(True)
    
    def on_click(self, event) -> None:
        """Handle click events to close modal when clicking outside."""
        # Check if the click target is the modal screen itself (not the modal content)
        if event.widget is self:
            self.dismiss(True)

class PantherAnalysisToolApp(App):
    """A Textual app to manage stopwatches."""

    BINDINGS = [("ctrl+d", "toggle_dark", "Toggle dark mode")]

    CSS_PATH = "explore.tcss"
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.all_rules = []  # Store all rules for filtering
        self.all_rules_yaml = {}  # Store YAML content for each rule
        self.organized_content = {}  # Store organized content by AnalysisType -> LogType

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Footer()
        yield Input(placeholder="Search")
        # yield Horizontal(
        #     Label("foo = bar X", classes="facet-label"),
        #     Label("foo = bar X", classes="facet-label"),
        #     id="facets",
        # )

        # Create a horizontal layout with tree on left and DataTable on right
        yield Horizontal(
            create_content_tree({}),  # Will be populated in on_mount
            DataTable(id="rules-table", cursor_type="row"),
            id="main-content"
        ) 

    def on_mount(self) -> None:
        """Populate the DataTable and Tree when the app starts."""
        table = self.query_one("#rules-table", DataTable)
        
        # Add columns to the DataTable
        table.add_columns("ID", "Description")
        
        # Load and store all rules for filtering
        self.all_rules, self.all_rules_yaml, self.organized_content = load_rules()
        
        # Update the tree with organized content
        tree = self.query_one("#tree", Tree)
        tree.clear()
        tree.root.label = "Analysis Content"
        tree.root.expand()
        
        # Build the hierarchical tree structure
        for analysis_type in sorted(self.organized_content.keys()):
            analysis_node = tree.root.add(analysis_type.replace("_", " ").title(), expand=True)
            
            for log_type in sorted(self.organized_content[analysis_type].keys()):
                log_type_node = analysis_node.add(log_type, expand=False)
                
                for item_id, _ in self.organized_content[analysis_type][log_type]:
                    item_label = f"{item_id}"
                    log_type_node.add_leaf(item_label)
        
        # Add all items to the table initially
        for item_id, description in self.all_rules:
            # Check if item is disabled
            yaml_content = self.all_rules_yaml.get(item_id, {})
            is_enabled = yaml_content.get("Enabled", True)  # Default to True if not specified
            
            style = "dim" if not is_enabled else ""
            item_id_text = Text(item_id, style=style)
            description_text = Text(description, style=style)
            table.add_row(item_id_text, description_text)
    
    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection in the DataTable."""
        table = event.data_table
        row_key = event.row_key
        row_data = table.get_row(row_key)
        
        # Get the selected row data
        rule_id: Text
        description: Text
        rule_id, description = row_data
        
        # Get the YAML content for this rule
        yaml_content = self.all_rules_yaml.get(rule_id.plain, {})
        
        # Show the modal with rule details
        modal = RuleDetailsModal(rule_id.plain, description.plain, yaml_content)
        self.push_screen(modal)

    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle search input changes to filter the table."""
        search_term = event.value.lower().strip()
        table = self.query_one("#rules-table", DataTable)
        
        # Clear the current table contents
        table.clear()
        
        # Filter items based on search term
        if not search_term:
            # If search is empty, show all items
            filtered_items = self.all_rules
        else:
            # Filter items that match the search term in either ID or Description
            filtered_items = [
                (item_id, description) for item_id, description in self.all_rules
                if search_term in item_id.lower() or search_term in description.lower()
            ]
        
        # Add filtered items back to the table
        for item_id, description in filtered_items:
            # Check if item is disabled
            yaml_content = self.all_rules_yaml.get(item_id, {})
            is_enabled = yaml_content.get("Enabled", True)  # Default to True if not specified
            
            style = "dim" if not is_enabled else ""
            item_id_text = Text(item_id, style=style)
            description_text = Text(description, style=style)
            table.add_row(item_id_text, description_text)

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        """Handle tree node selection to filter the table."""
        node = event.node
        table = self.query_one("#rules-table", DataTable)
        
        # Clear the current table contents
        table.clear()
        
        # Determine what to filter based on the selected node
        filtered_items = []
        
        # If it's a leaf node (individual item), show only that item
        if not node.children:
            # Extract the item ID from the label (format: "ItemID - Description...")
            item_label = str(node.label)
            item_id = item_label.split(" - ")[0] if " - " in item_label else item_label
            
            # Find the matching item
            for existing_id, description in self.all_rules:
                if existing_id == item_id:
                    filtered_items.append((existing_id, description))
                    break
        else:
            # If it's a parent node, show all items under it
            node_label = str(node.label).lower()
            
            # Check if this is an analysis type node or log type node
            for analysis_type, log_types in self.organized_content.items():
                analysis_display = analysis_type.replace("_", " ").title()
                
                if node_label == analysis_display.lower():
                    # Show all items for this analysis type
                    for log_type_items in log_types.values():
                        filtered_items.extend(log_type_items)
                    break
                else:
                    # Check if it's a log type under this analysis type
                    for log_type, items in log_types.items():
                        if node_label == log_type.lower():
                            filtered_items.extend(items)
                            break
        
        # If no specific filtering, show all items
        if not filtered_items:
            filtered_items = self.all_rules
        
        # Add filtered items to the table
        for item_id, description in filtered_items:
            yaml_content = self.all_rules_yaml.get(item_id, {})
            is_enabled = yaml_content.get("Enabled", True)
            
            style = "dim" if not is_enabled else ""
            item_id_text = Text(item_id, style=style)
            description_text = Text(description, style=style)
            table.add_row(item_id_text, description_text)

    def action_toggle_dark(self) -> None:
        """An action to toggle dark mode."""
        self.theme = (
            "textual-dark" if self.theme == "textual-light" else "textual-light"
        )


def create_content_tree(organized_content: dict) -> Tree[str]:
    tree: Tree[str] = Tree("All", id="tree")
    # tree.show_root = False
    tree.root.expand()
    
    # Sort analysis types for consistent display
    for analysis_type in sorted(organized_content.keys()):
        analysis_node = tree.root.add(analysis_type.replace("_", " ").title(), expand=True)
        
        # Sort log types within each analysis type
        for log_type in sorted(organized_content[analysis_type].keys()):
            log_type_node = analysis_node.add(log_type, expand=False)
            
            # Add individual items under each log type
            for item_id, description in organized_content[analysis_type][log_type]:
                # Truncate description if too long for tree display
                display_desc = description[:50] + "..." if len(description) > 50 else description
                item_label = f"{item_id}" + (f" - {display_desc}" if display_desc else "")
                log_type_node.add_leaf(item_label)
    
    return tree


def load_rules():
    """Load rules from the cache."""
    cache = AnalysisCache()

    yaml = YAML(typ='safe') 
    content = []
    yaml_data = {}
    
    # First pass: collect all analysis types and log types
    analysis_types = set()
    log_types_by_analysis = {}
    
    for spec_id in cache.list_spec_ids():
        spec = cache.get_spec_for_version(spec_id, 1)
        if spec is None:
            continue
        yaml_content = yaml.load(io.BytesIO(spec.spec))
        
        analysis_type = yaml_content.get("AnalysisType")
        if analysis_type:
            analysis_types.add(analysis_type)
            
            # Get log types for this analysis
            log_types = yaml_content.get("LogTypes", [])
            if analysis_type not in log_types_by_analysis:
                log_types_by_analysis[analysis_type] = set()
            log_types_by_analysis[analysis_type].update(log_types)
    
    # Second pass: organize content by analysis type and log type
    organized_content = {}
    for spec_id in cache.list_spec_ids():
        spec = cache.get_spec_for_version(spec_id, 1)
        if spec is None:
            continue
        yaml_content = yaml.load(io.BytesIO(spec.spec))
        
        analysis_type = yaml_content.get("AnalysisType")
        if not analysis_type:
            continue
            
        if analysis_type not in organized_content:
            organized_content[analysis_type] = {}
            
        log_types = yaml_content.get("LogTypes", [])
        
        # If no log types, put under a generic category
        if not log_types:
            log_types = ["General"]
            
        for log_type in log_types:
            if log_type not in organized_content[analysis_type]:
                organized_content[analysis_type][log_type] = []
                
            item_id = spec_id
            description = yaml_content.get("Description", "")
            description = description.replace("\n", " ").strip()
            organized_content[analysis_type][log_type].append((item_id, description))
            yaml_data[item_id] = yaml_content
    
    # Sort everything
    for analysis_type in organized_content:
        for log_type in organized_content[analysis_type]:
            organized_content[analysis_type][log_type].sort(key=lambda x: x[0].lower())
    
    # Also create a flat list for backward compatibility
    content = []
    for analysis_type in organized_content:
        for log_type in organized_content[analysis_type]:
            content.extend(organized_content[analysis_type][log_type])
    
    return content, yaml_data, organized_content
