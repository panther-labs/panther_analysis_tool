# Plan: Analysis Items API for Bulk Updates

## Overview

Create a Python API that allows users to programmatically load, modify, and write back analysis items via a `main.py` script. This will enable bulk updates and dynamic overrides of analysis items.

## Architecture

### 1. Core Components

#### A. Load Function
- **Function**: `load_analysis_items()` 
- **Location**: `panther_analysis_tool/api.py` (new module)
- **Returns**: List of type-specific wrapper objects
- **Implementation**: 
  - Use `load_analysis_specs_ex()` from `analysis_utils.py` to load user analysis items
  - Convert `LoadAnalysisSpecsResult` to `AnalysisItem` using existing utilities
  - Wrap each `AnalysisItem` in appropriate type-specific class
  - Return list of wrapped items
  - **Note**: Only loads user items, not cached Panther items

#### B. Type-Specific Wrapper Classes
- **Base Class**: `BaseAnalysisItem` (abstract base class)
- **Concrete Classes**: One per analysis type (excluding Pack and Derived)
  - `RuleItem`
  - `PolicyItem`
  - `DataModelItem`
  - `GlobalItem`
  - `ScheduledQueryItem`
  - `SavedQueryItem`
  - `LookupTableItem`
  - `CorrelationRuleItem`
  - `ScheduledRuleItem`
  - `SimpleDetectionItem`

#### C. Write Function
- **Function**: `write_analysis_items(items: List[BaseAnalysisItem])`
- **Location**: `panther_analysis_tool/api.py`
- **Implementation**:
  - Convert wrapper objects back to `AnalysisItem`
  - Write YAML using `BlockStyleYAML().dump()`
  - Write Python files as bytes
  - **Note**: Does NOT update cache - only writes user files

### 2. API Design

#### BaseAnalysisItem (Abstract Base Class)

```python
class BaseAnalysisItem(ABC):
    """Base class for all analysis item wrappers.
    
    Users cannot directly access the underlying YAML or Python code.
    All access must go through properties and methods.
    """
    
    def __init__(self, item: AnalysisItem):
        self._item = item
    
    # Properties (read-only)
    @property
    def id(self) -> str:
        """Get the analysis ID."""
        return self._item.analysis_id()
    
    @property
    def analysis_type(self) -> str:
        """Get the analysis type."""
        return self._item.analysis_type()
    
    # Internal helper methods for field access
    def _set_field(self, field: str, value: Any) -> None:
        """Internal method to set a YAML field value."""
        self._item.yaml_file_contents[field] = value
    
    def _get_field(self, field: str, default: Any = None) -> Any:
        """Internal method to get a YAML field value."""
        return self._item.yaml_file_contents.get(field, default)
    
    def _remove_field(self, field: str) -> None:
        """Internal method to remove a YAML field."""
        if field in self._item.yaml_file_contents:
            del self._item.yaml_file_contents[field]
    
    # Python code manipulation (fine-grained, no direct access)
    def add_import(self, import_stmt: str) -> None:
        """Add an import statement to the Python code.
        
        Args:
            import_stmt: Import statement (e.g., "from panther_base import something" 
                        or "import json")
        """
    
    def remove_import(self, module_name: str) -> None:
        """Remove an import statement from the Python code.
        
        Args:
            module_name: Name of the module to remove (e.g., "json", "panther_base")
        """
    
    def add_function(self, function_name: str, function_body: str) -> None:
        """Add a new function to the Python code.
        
        Args:
            function_name: Name of the function (e.g., "helper_function")
            function_body: Complete function definition including signature and body
        """
    
    def remove_function(self, function_name: str) -> None:
        """Remove a function from the Python code.
        
        Args:
            function_name: Name of the function to remove
        """
    
    def get_function(self, function_name: str) -> str | None:
        """Get a function's code from the Python file.
        
        Args:
            function_name: Name of the function (e.g., "rule", "severity")
        
        Returns:
            Function code as string, or None if not found
        """
    
    # Detection-specific Python manipulation
    def add_severity_function(self, severity_body: str) -> None:
        """Add or replace the severity function for rules/policies.
        
        Args:
            severity_body: Complete severity function body
        """
    
    def remove_severity_function(self) -> None:
        """Remove the severity function if it exists."""
    
    def append_to_rule_function(self, code: str) -> None:
        """Append code to the end of the rule() function body.
        
        Args:
            code: Code to append (will be indented appropriately)
        """
    
    def prepend_to_rule_function(self, code: str) -> None:
        """Prepend code to the beginning of the rule() function body.
        
        Args:
            code: Code to prepend (will be indented appropriately)
        """
    
    def append_to_policy_function(self, code: str) -> None:
        """Append code to the end of the policy() function body.
        
        Args:
            code: Code to append (will be indented appropriately)
        """
    
    def prepend_to_policy_function(self, code: str) -> None:
        """Prepend code to the beginning of the policy() function body.
        
        Args:
            code: Code to prepend (will be indented appropriately)
        """
    
    # Type-specific methods (to be overridden)
    @property
    @abstractmethod
    def display_name(self) -> str | None:
        """Get the display name."""
    
    @display_name.setter
    @abstractmethod
    def display_name(self, value: str) -> None:
        """Set the display name."""
```

#### Type-Specific Classes

Each type will have getters and setters for **every YAML field** defined in its schema. This ensures complete programmatic access to all fields.

Example for `RuleItem` (all fields from RULE_SCHEMA):

```python
class RuleItem(BaseAnalysisItem):
    """Wrapper for Rule analysis items with properties for all YAML fields."""
    
    # Required fields
    @property
    def enabled(self) -> bool:
        """Get the Enabled field."""
        return self._get_field("Enabled")
    
    @enabled.setter
    def enabled(self, value: bool) -> None:
        """Set the Enabled field."""
        self._set_field("Enabled", value)
    
    @property
    def rule_id(self) -> str:
        """Get the RuleID field."""
        return self._get_field("RuleID")
    
    @rule_id.setter
    def rule_id(self, value: str) -> None:
        """Set the RuleID field."""
        self._set_field("RuleID", value)
    
    @property
    def filename(self) -> str | None:
        """Get the Filename field."""
        return self._get_field("Filename")
    
    @filename.setter
    def filename(self, value: str) -> None:
        """Set the Filename field."""
        self._set_field("Filename", value)
    
    @property
    def detection(self) -> object | None:
        """Get the Detection field."""
        return self._get_field("Detection")
    
    @detection.setter
    def detection(self, value: object) -> None:
        """Set the Detection field."""
        self._set_field("Detection", value)
    
    @property
    def log_types(self) -> list[str] | None:
        """Get the LogTypes field."""
        return self._get_field("LogTypes")
    
    @log_types.setter
    def log_types(self, value: list[str]) -> None:
        """Set the LogTypes field."""
        self._set_field("LogTypes", value)
    
    @property
    def scheduled_queries(self) -> list[str] | None:
        """Get the ScheduledQueries field."""
        return self._get_field("ScheduledQueries")
    
    @scheduled_queries.setter
    def scheduled_queries(self, value: list[str]) -> None:
        """Set the ScheduledQueries field."""
        self._set_field("ScheduledQueries", value)
    
    @property
    def severity(self) -> str:
        """Get the Severity field."""
        return self._get_field("Severity")
    
    @severity.setter
    def severity(self, value: str) -> None:
        """Set the Severity field. Must be one of: Info, Low, Medium, High, Critical."""
        if value not in ["Info", "Low", "Medium", "High", "Critical"]:
            raise ValueError(f"Invalid severity: {value}")
        self._set_field("Severity", value)
    
    # Optional fields
    @property
    def description(self) -> str | None:
        """Get the Description field."""
        return self._get_field("Description")
    
    @description.setter
    def description(self, value: str) -> None:
        """Set the Description field."""
        self._set_field("Description", value)
    
    @property
    def dedup_period_minutes(self) -> int | None:
        """Get the DedupPeriodMinutes field."""
        return self._get_field("DedupPeriodMinutes")
    
    @dedup_period_minutes.setter
    def dedup_period_minutes(self, value: int) -> None:
        """Set the DedupPeriodMinutes field."""
        self._set_field("DedupPeriodMinutes", value)
    
    @property
    def inline_filters(self) -> object | None:
        """Get the InlineFilters field."""
        return self._get_field("InlineFilters")
    
    @inline_filters.setter
    def inline_filters(self, value: object) -> None:
        """Set the InlineFilters field."""
        self._set_field("InlineFilters", value)
    
    @property
    def display_name(self) -> str | None:
        """Get the DisplayName field."""
        return self._get_field("DisplayName")
    
    @display_name.setter
    def display_name(self, value: str) -> None:
        """Set the DisplayName field."""
        self._set_field("DisplayName", value)
    
    @property
    def only_use_base_risk_score(self) -> bool | None:
        """Get the OnlyUseBaseRiskScore field."""
        return self._get_field("OnlyUseBaseRiskScore")
    
    @only_use_base_risk_score.setter
    def only_use_base_risk_score(self, value: bool) -> None:
        """Set the OnlyUseBaseRiskScore field."""
        self._set_field("OnlyUseBaseRiskScore", value)
    
    @property
    def output_ids(self) -> list[str] | None:
        """Get the OutputIds field."""
        return self._get_field("OutputIds")
    
    @output_ids.setter
    def output_ids(self, value: list[str]) -> None:
        """Set the OutputIds field."""
        self._set_field("OutputIds", value)
    
    @property
    def created_by(self) -> str | None:
        """Get the CreatedBy field."""
        return self._get_field("CreatedBy")
    
    @created_by.setter
    def created_by(self, value: str) -> None:
        """Set the CreatedBy field."""
        self._set_field("CreatedBy", value)
    
    @property
    def reference(self) -> str | None:
        """Get the Reference field."""
        return self._get_field("Reference")
    
    @reference.setter
    def reference(self, value: str) -> None:
        """Set the Reference field."""
        self._set_field("Reference", value)
    
    @property
    def runbook(self) -> str | None:
        """Get the Runbook field."""
        return self._get_field("Runbook")
    
    @runbook.setter
    def runbook(self, value: str) -> None:
        """Set the Runbook field."""
        self._set_field("Runbook", value)
    
    @property
    def status(self) -> str | None:
        """Get the Status field."""
        return self._get_field("Status")
    
    @status.setter
    def status(self, value: str) -> None:
        """Set the Status field."""
        self._set_field("Status", value)
    
    @property
    def summary_attributes(self) -> list[str] | None:
        """Get the SummaryAttributes field."""
        return self._get_field("SummaryAttributes")
    
    @summary_attributes.setter
    def summary_attributes(self, value: list[str]) -> None:
        """Set the SummaryAttributes field."""
        self._set_field("SummaryAttributes", value)
    
    @property
    def threshold(self) -> int | None:
        """Get the Threshold field."""
        return self._get_field("Threshold")
    
    @threshold.setter
    def threshold(self, value: int) -> None:
        """Set the Threshold field."""
        self._set_field("Threshold", value)
    
    @property
    def tags(self) -> list[str] | None:
        """Get the Tags field."""
        return self._get_field("Tags")
    
    @tags.setter
    def tags(self, value: list[str]) -> None:
        """Set the Tags field."""
        self._set_field("Tags", value)
    
    def add_tag(self, tag: str) -> None:
        """Add a tag if it doesn't already exist."""
        current_tags = self.tags or []
        if tag not in current_tags:
            self.tags = current_tags + [tag]
    
    def remove_tag(self, tag: str) -> None:
        """Remove a tag if it exists."""
        current_tags = self.tags or []
        if tag in current_tags:
            self.tags = [t for t in current_tags if t != tag]
    
    @property
    def reports(self) -> dict[str, list] | None:
        """Get the Reports field."""
        return self._get_field("Reports")
    
    @reports.setter
    def reports(self, value: dict[str, list]) -> None:
        """Set the Reports field."""
        self._set_field("Reports", value)
    
    @property
    def tests(self) -> list[dict] | None:
        """Get the Tests field."""
        return self._get_field("Tests")
    
    @tests.setter
    def tests(self, value: list[dict]) -> None:
        """Set the Tests field."""
        self._set_field("Tests", value)
    
    @property
    def dynamic_severities(self) -> object | None:
        """Get the DynamicSeverities field."""
        return self._get_field("DynamicSeverities")
    
    @dynamic_severities.setter
    def dynamic_severities(self, value: object) -> None:
        """Set the DynamicSeverities field."""
        self._set_field("DynamicSeverities", value)
    
    @property
    def alert_title(self) -> str | None:
        """Get the AlertTitle field."""
        return self._get_field("AlertTitle")
    
    @alert_title.setter
    def alert_title(self, value: str) -> None:
        """Set the AlertTitle field."""
        self._set_field("AlertTitle", value)
    
    @property
    def alert_context(self) -> object | None:
        """Get the AlertContext field."""
        return self._get_field("AlertContext")
    
    @alert_context.setter
    def alert_context(self, value: object) -> None:
        """Set the AlertContext field."""
        self._set_field("AlertContext", value)
    
    @property
    def group_by(self) -> object | None:
        """Get the GroupBy field."""
        return self._get_field("GroupBy")
    
    @group_by.setter
    def group_by(self, value: object) -> None:
        """Set the GroupBy field."""
        self._set_field("GroupBy", value)
    
    @property
    def create_alert(self) -> bool | None:
        """Get the CreateAlert field."""
        return self._get_field("CreateAlert")
    
    @create_alert.setter
    def create_alert(self, value: bool) -> None:
        """Set the CreateAlert field."""
        self._set_field("CreateAlert", value)
    
    @property
    def base_version(self) -> int | None:
        """Get the BaseVersion field."""
        return self._get_field("BaseVersion")
    
    @base_version.setter
    def base_version(self, value: int) -> None:
        """Set the BaseVersion field."""
        self._set_field("BaseVersion", value)
```

**Note**: Similar getters/setters will be implemented for all fields in:
- `PolicyItem` (all POLICY_SCHEMA fields)
- `DataModelItem` (all DATA_MODEL_SCHEMA fields)
- `GlobalItem` (all GLOBAL_SCHEMA fields)
- `ScheduledQueryItem` (all SCHEDULED_QUERY_SCHEMA fields)
- `SavedQueryItem` (all SAVED_QUERY_SCHEMA fields)
- `LookupTableItem` (all LOOKUP_TABLE_SCHEMA fields)
- `CorrelationRuleItem` (all CORRELATION_RULE_SCHEMA fields)
- `ScheduledRuleItem` (uses RULE_SCHEMA, same as RuleItem)
- `SimpleDetectionItem` (fields from ANALYSIS_CONFIG_SCHEMA)

### 3. Factory Pattern for Type Creation

```python
def _wrap_analysis_item(item: AnalysisItem) -> BaseAnalysisItem:
    """Internal factory function to wrap AnalysisItem in appropriate type-specific class.
    
    Note: This only wraps existing items. Users cannot create new items via factory.
    """
    analysis_type = item.analysis_type()
    
    type_map = {
        AnalysisTypes.RULE: RuleItem,
        AnalysisTypes.POLICY: PolicyItem,
        AnalysisTypes.DATA_MODEL: DataModelItem,
        AnalysisTypes.GLOBAL: GlobalItem,
        AnalysisTypes.SCHEDULED_QUERY: ScheduledQueryItem,
        AnalysisTypes.SAVED_QUERY: SavedQueryItem,
        AnalysisTypes.LOOKUP_TABLE: LookupTableItem,
        AnalysisTypes.CORRELATION_RULE: CorrelationRuleItem,
        AnalysisTypes.SCHEDULED_RULE: ScheduledRuleItem,
        AnalysisTypes.SIMPLE_DETECTION: SimpleDetectionItem,
    }
    
    wrapper_class = type_map.get(analysis_type)
    if wrapper_class:
        return wrapper_class(item)
    else:
        raise ValueError(f"Unsupported analysis type for API: {analysis_type}")
```

### 4. Public API Functions

```python
# In panther_analysis_tool/api.py

def load_analysis_items(
    # Progress
    show_progress: bool = False,
    
    # Basic filters
    filter_by_type: str | None = None,
    filter_by_id: str | None = None,
    
    # Rule/Policy/CorrelationRule/ScheduledRule filters
    filter_by_rule_id: str | list[str] | None = None,
    filter_by_policy_id: str | list[str] | None = None,
    filter_by_enabled: bool | None = None,
    filter_by_severity: str | list[str] | None = None,
    filter_by_tags: str | list[str] | None = None,
    filter_by_status: str | list[str] | None = None,
    filter_by_display_name: str | list[str] | None = None,
    filter_by_description: str | list[str] | None = None,
    filter_by_created_by: str | list[str] | None = None,
    filter_by_reference: str | list[str] | None = None,
    filter_by_runbook: str | list[str] | None = None,
    filter_by_output_ids: str | list[str] | None = None,
    
    # Rule-specific filters
    filter_by_log_types: str | list[str] | None = None,
    filter_by_scheduled_queries: str | list[str] | None = None,
    filter_by_dedup_period_minutes: int | list[int] | None = None,
    filter_by_threshold: int | list[int] | None = None,
    filter_by_only_use_base_risk_score: bool | None = None,
    filter_by_create_alert: bool | None = None,
    
    # Policy-specific filters
    filter_by_resource_types: str | list[str] | None = None,
    filter_by_action_delay_seconds: int | list[int] | None = None,
    filter_by_auto_remediation_id: str | list[str] | None = None,
    filter_by_suppressions: str | list[str] | None = None,
    
    # DataModel filters
    filter_by_data_model_id: str | list[str] | None = None,
    filter_by_log_types_data_model: str | list[str] | None = None,
    
    # Global filters
    filter_by_global_id: str | list[str] | None = None,
    
    # Query filters
    filter_by_query_name: str | list[str] | None = None,
    filter_by_lookback: bool | None = None,
    filter_by_lookback_window_seconds: int | list[int] | None = None,
    
    # LookupTable filters
    filter_by_lookup_name: str | list[str] | None = None,
    
    # CorrelationRule filters (uses same as Rule)
    
    # Text search (searches in YAML and Python content)
    filter_by_text: str | list[str] | None = None,
) -> list[BaseAnalysisItem]:
    """
    Load all user analysis items from the project with explicit filtering.
    
    Uses analysis_utils.load_analysis_specs_ex() to load only user items
    (not cached Panther items). Items are wrapped in type-specific classes.
    
    All filter parameters accept either a single value or a list of values.
    Multiple values in a list are ORed together (item matches if it matches any value).
    Multiple filter parameters are ANDed together (item must match all filters).
    
    Args:
        show_progress: Whether to show progress bar
        
        # Basic filters
        filter_by_type: Analysis type (e.g., "rule", "policy")
        filter_by_id: Analysis ID (RuleID, PolicyID, etc.)
        
        # Rule/Policy common filters
        filter_by_rule_id: Rule ID(s) to filter by
        filter_by_policy_id: Policy ID(s) to filter by
        filter_by_enabled: Filter by enabled status
        filter_by_severity: Severity level(s) (Info, Low, Medium, High, Critical)
        filter_by_tags: Tag(s) to filter by
        filter_by_status: Status value(s) to filter by
        filter_by_display_name: Display name(s) to filter by
        filter_by_description: Description text(s) to filter by
        filter_by_created_by: Created by value(s)
        filter_by_reference: Reference value(s)
        filter_by_runbook: Runbook value(s)
        filter_by_output_ids: Output ID(s) to filter by
        
        # Rule-specific filters
        filter_by_log_types: Log type(s) for rules
        filter_by_scheduled_queries: Scheduled query name(s)
        filter_by_dedup_period_minutes: Deduplication period(s) in minutes
        filter_by_threshold: Threshold value(s)
        filter_by_only_use_base_risk_score: Filter by OnlyUseBaseRiskScore flag
        filter_by_create_alert: Filter by CreateAlert flag
        
        # Policy-specific filters
        filter_by_resource_types: Resource type(s) for policies
        filter_by_action_delay_seconds: Action delay(s) in seconds
        filter_by_auto_remediation_id: Auto remediation ID(s)
        filter_by_suppressions: Suppression value(s)
        
        # DataModel filters
        filter_by_data_model_id: Data model ID(s)
        filter_by_log_types_data_model: Log type(s) for data models
        
        # Global filters
        filter_by_global_id: Global ID(s)
        
        # Query filters
        filter_by_query_name: Query name(s)
        filter_by_lookback: Filter by lookback flag
        filter_by_lookback_window_seconds: Lookback window(s) in seconds
        
        # LookupTable filters
        filter_by_lookup_name: Lookup table name(s)
        
        # Text search
        filter_by_text: Text to search in YAML and Python content
    
    Returns:
        List of wrapped analysis items matching all specified filters
    
    Raises:
        ValueError: If filter values are invalid
    """

def write_analysis_items(
    items: list[BaseAnalysisItem],
    dry_run: bool = False,
) -> None:
    """
    Write analysis items back to disk.
    
    Writes only to user files. Does NOT update the analysis cache.
    
    Args:
        items: List of analysis items to write
        dry_run: If True, don't actually write files (for validation)
    
    Raises:
        ValueError: If items are invalid or missing required fields
        FileNotFoundError: If original file paths no longer exist
    """
```

### 5. Module Structure

```
panther_analysis_tool/
├── api.py                    # Public API functions
└── api/
    ├── __init__.py
    ├── base.py               # BaseAnalysisItem class
    ├── items.py              # All type-specific wrapper classes
    └── writer.py             # Write functionality
```

### 6. Example Usage in main.py

```python
# main.py
from panther_analysis_tool.api import load_analysis_items, write_analysis_items

# Example 1: Load all enabled rules with High severity
items = load_analysis_items(
    filter_by_type="rule",
    filter_by_enabled=True,
    filter_by_severity="High"
)

# Example 2: Load specific rules by ID
items = load_analysis_items(
    filter_by_rule_id=["AWS.S3.Bucket.PublicRead", "AWS.CloudTrail.ConsoleLogin"]
)

# Example 3: Load rules with specific tags
items = load_analysis_items(
    filter_by_type="rule",
    filter_by_tags=["security", "compliance"]
)

# Example 4: Load policies for specific resource types
items = load_analysis_items(
    filter_by_type="policy",
    filter_by_resource_types=["AWS.S3.Bucket"]
)

# Example 5: Complex filtering - High/Critical severity rules with specific tags
items = load_analysis_items(
    filter_by_type="rule",
    filter_by_severity=["High", "Critical"],
    filter_by_tags="security",
    filter_by_enabled=True
)

# Bulk update: Add a tag to all loaded rules
for item in items:
    if isinstance(item, RuleItem):
        item.add_tag("bulk-updated")
        item.severity = "High"
        # Update any field using properties
        item.description = "Updated via API"
        item.reference = "https://example.com/reference"

# Fine-grained Python code updates for specific rules
for item in items:
    if isinstance(item, RuleItem) and item.display_name and "suspicious" in item.display_name.lower():
        # Add an import
        item.add_import("from panther_base import something")
        
        # Add a severity function
        item.add_severity_function("""
def severity(event):
    return "High"
""")
        
        # Append code to rule function
        item.append_to_rule_function("    # Additional check\n    return True")

# Write all changes back
write_analysis_items(items)
```

### 7. Implementation Steps

1. **Create API module structure**
   - Create `panther_analysis_tool/api/` directory
   - Create `__init__.py` with public exports
   - Create `base.py` with `BaseAnalysisItem`

2. **Implement base class**
   - Abstract base class with common methods
   - Generic field getter/setter methods (`get_field()`, `set_field()`)
   - Python code manipulation methods (fine-grained)
   - Internal `_item` reference

3. **Implement type-specific classes**
   - Start with most common types (Rule, Policy)
   - **For each type, add properties for ALL YAML fields from schema**
   - Use `@property` decorator for getters and `@<field>.setter` for setters
   - Convert field names from PascalCase to snake_case (e.g., `DisplayName` -> `display_name`)
   - Handle list fields with helper methods (e.g., `add_tag()`, `remove_tag()`)
   - Add validation in setters where needed (e.g., severity values, resource types)
   - Use internal `_get_field()` and `_set_field()` methods for actual field access

4. **Implement factory function**
   - Map analysis types to wrapper classes
   - Handle unknown types gracefully

5. **Implement load function**
   - Use `load_analysis_specs_ex()` from `analysis_utils.py`
   - Convert `LoadAnalysisSpecsResult` to `AnalysisItem`
   - Wrap items using internal factory function
   - Implement explicit filtering:
     - Convert all filter parameters to `Filter` objects
     - Map filter parameter names to YAML field names (e.g., `filter_by_rule_id` -> `RuleID`)
     - Handle list values (OR logic within a filter)
     - Apply all filters using `filter_analysis_spec()` and `filters_match_analysis_item()`
     - Handle text search filters separately
   - Only load user items (not cached Panther items)

6. **Implement Python code manipulation**
   - Use AST parsing to manipulate Python code
   - Implement import add/remove functions
   - Implement function add/remove/get functions
   - Implement rule/policy function prepend/append
   - Implement severity function add/remove
   - Preserve code formatting and comments where possible

7. **Implement write function**
   - Convert wrappers back to `AnalysisItem`
   - Write YAML files using `BlockStyleYAML().dump()`
   - Write Python files as bytes
   - Handle file paths correctly
   - Preserve file structure
   - **Do NOT update cache**

8. **Update generate.py**
   - Import and expose API functions
   - Make them available in `main.py` namespace

9. **Add validation**
   - Validate YAML structure before writing
   - Validate Python syntax after manipulation (optional)
   - Check for required fields per type

10. **Add error handling**
    - Handle missing files gracefully
    - Provide clear error messages
    - Support dry-run mode
    - Handle AST parsing errors

11. **Testing**
    - Unit tests for each wrapper class
    - Unit tests for Python manipulation functions
    - Integration tests for load/write cycle
    - Test with real analysis items

### 7. Filter Parameter Mapping

The `load_analysis_items()` function accepts many explicit filter parameters. Internally, these need to be mapped to YAML field names and converted to `Filter` objects for use with `filter_analysis_spec()`.

#### Filter Parameter to YAML Field Mapping

```python
# Mapping dictionary for filter parameters to YAML fields
FILTER_FIELD_MAP = {
    # Basic filters
    "filter_by_type": "AnalysisType",
    "filter_by_id": None,  # Special handling - uses analysis_id()
    
    # Rule/Policy common fields
    "filter_by_rule_id": "RuleID",
    "filter_by_policy_id": "PolicyID",
    "filter_by_enabled": "Enabled",
    "filter_by_severity": "Severity",
    "filter_by_tags": "Tags",
    "filter_by_status": "Status",
    "filter_by_display_name": "DisplayName",
    "filter_by_description": "Description",
    "filter_by_created_by": "CreatedBy",
    "filter_by_reference": "Reference",
    "filter_by_runbook": "Runbook",
    "filter_by_output_ids": "OutputIds",
    
    # Rule-specific
    "filter_by_log_types": "LogTypes",
    "filter_by_scheduled_queries": "ScheduledQueries",
    "filter_by_dedup_period_minutes": "DedupPeriodMinutes",
    "filter_by_threshold": "Threshold",
    "filter_by_only_use_base_risk_score": "OnlyUseBaseRiskScore",
    "filter_by_create_alert": "CreateAlert",
    
    # Policy-specific
    "filter_by_resource_types": "ResourceTypes",
    "filter_by_action_delay_seconds": "ActionDelaySeconds",
    "filter_by_auto_remediation_id": "AutoRemediationID",
    "filter_by_suppressions": "Suppressions",
    
    # DataModel
    "filter_by_data_model_id": "DataModelID",
    "filter_by_log_types_data_model": "LogTypes",
    
    # Global
    "filter_by_global_id": "GlobalID",
    
    # Query
    "filter_by_query_name": "QueryName",
    "filter_by_lookback": "Lookback",
    "filter_by_lookback_window_seconds": "LookbackWindowSeconds",
    
    # LookupTable
    "filter_by_lookup_name": "LookupName",
}
```

#### Filter Implementation Logic

```python
def load_analysis_items(**kwargs) -> list[BaseAnalysisItem]:
    # Extract filter parameters
    filters = []
    text_filters = []
    
    # Handle filter_by_id separately (uses analysis_id())
    if kwargs.get("filter_by_id"):
        # Special handling for ID filter
    
    # Handle text search separately
    if kwargs.get("filter_by_text"):
        text_filters.append(Filter(key="", values=...))
    
    # Convert all other filter parameters to Filter objects
    for param_name, param_value in kwargs.items():
        if param_name.startswith("filter_by_") and param_value is not None:
            field_name = FILTER_FIELD_MAP.get(param_name)
            if field_name:
                # Convert single value or list to Filter
                values = param_value if isinstance(param_value, list) else [param_value]
                filters.append(Filter(key=field_name, values=values))
    
    # Apply filters using existing filter_analysis_spec() function
    # ...
```

### 8. Python Code Manipulation Implementation

Python code manipulation will use Python's `ast` module for reliable parsing and modification:

#### Import Management
- Parse AST to find all import statements
- `add_import()`: Insert new import at appropriate location (after existing imports)
- `remove_import()`: Remove import statements matching module name
- Preserve import formatting and style

#### Function Management
- Parse AST to find function definitions
- `add_function()`: Insert new function at end of file (before main function if exists)
- `remove_function()`: Remove function definition and its body
- `get_function()`: Extract function code as string (with proper formatting)

#### Rule/Policy Function Manipulation
- `append_to_rule_function()`: Find `def rule(event):` and append code to body
- `prepend_to_rule_function()`: Find `def rule(event):` and prepend code to body
- `append_to_policy_function()`: Same for `def policy(resource):`
- `prepend_to_policy_function()`: Same for `def policy(resource):`
- Handle indentation automatically
- Preserve existing function structure

#### Severity Function Management
- `add_severity_function()`: Add or replace `def severity(event):` function
- `remove_severity_function()`: Remove severity function if exists
- Place severity function after rule/policy function

#### Implementation Approach
```python
# Pseudo-code for Python manipulation
import ast
import astor  # or similar for AST to code conversion

class PythonCodeManipulator:
    def __init__(self, python_code: bytes):
        self.code = python_code.decode('utf-8')
        self.tree = ast.parse(self.code)
    
    def add_import(self, import_stmt: str):
        # Parse new import
        # Find insertion point (after existing imports)
        # Insert new import node
        # Regenerate code
    
    def remove_import(self, module_name: str):
        # Find import nodes matching module
        # Remove from AST
        # Regenerate code
    
    def get_function(self, name: str) -> str | None:
        # Find function node in AST
        # Convert node back to code string
        # Return formatted code
    
    # ... similar for other operations
```

**Note**: May need to use `astor` or `unparse` (Python 3.9+) to convert AST back to code, or manually reconstruct code strings.

### 9. Considerations

#### File Paths
- Preserve original file paths when writing
- Handle cases where paths might have changed
- Support writing to new locations (optional)

#### Cache Management
- **Do NOT update cache** - only user files are modified
- Cache will be updated on next `pat pull` or similar operation

#### Validation
- Validate YAML structure matches schema
- Validate Python code syntax (optional, can be slow)
- Check for required fields per type

#### Backwards Compatibility
- Don't break existing `AnalysisItem` usage
- Wrapper classes are only used in API context
- Internal `_item` reference maintains compatibility

#### Python Code Manipulation
- Use AST (Abstract Syntax Tree) parsing for reliable code manipulation
- Preserve formatting, comments, and docstrings where possible
- Handle edge cases (missing functions, malformed code, etc.)
- Functions operate on the actual Python file content, not a copy

#### Field Accessors
- **Complete coverage**: Every YAML field in each schema gets property getters/setters
- **Naming convention**: PascalCase YAML fields become snake_case properties
  - `DisplayName` -> `display_name` property
  - `RuleID` -> `rule_id` property
  - `DedupPeriodMinutes` -> `dedup_period_minutes` property
- **Property decorators**: Uses `@property` and `@<field>.setter` for Pythonic API
- **Type hints**: All properties have proper type hints based on schema
- **Helper methods**: List fields get convenience methods (e.g., `add_tag()`, `remove_tag()`)
- **Validation**: Setters validate values where appropriate (e.g., severity enum values)
- **Usage**: Natural Python syntax - `item.display_name = "New Name"` instead of `item.set_display_name("New Name")`

#### Filtering
- **Explicit parameters**: All filterable fields have explicit parameters in `load_analysis_items()`
- **Type safety**: Parameters are typed (str, list[str], bool, int, etc.)
- **Flexibility**: Single values or lists accepted (lists are ORed together)
- **Composability**: Multiple filter parameters are ANDed together
- **Text search**: Special `filter_by_text` parameter searches both YAML and Python content

#### Performance
- Loading can be slow for large projects
- Consider lazy loading for Python code
- Batch writes for better performance

### 10. Alternative Approaches Considered

#### Option A: Extend AnalysisItem directly
- **Pros**: Simpler, no wrapper layer
- **Cons**: Mixes concerns, harder to add type-specific methods

#### Option B: Use dataclasses with methods
- **Pros**: More Pythonic, better type hints
- **Cons**: Requires more refactoring of existing code

#### Option C: Builder pattern
- **Pros**: Immutable, safer
- **Cons**: More verbose, harder to use

**Chosen**: Wrapper pattern (Option D) - clean separation, easy to use, minimal changes to existing code

## Next Steps

1. Review and approve this plan
2. Create initial implementation of base class
3. Implement RuleItem and PolicyItem as proof of concept
4. Implement load/write functions
5. Test with real use cases
6. Iterate based on feedback
