"""Loader function for analysis items with explicit filtering."""

from typing import Any

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.api.items import Rule
from panther_analysis_tool.api.severity import Severity

# Mapping from filter parameter names to YAML field names
_FILTER_FIELD_MAP = {
    "analysis_type": "AnalysisType",
    "rule_id": "RuleID",
    "policy_id": "PolicyID",
    "enabled": "Enabled",
    "severity": "Severity",
    "tags": "Tags",
    "status": "Status",
    "display_name": "DisplayName",
    "description": "Description",
    "created_by": "CreatedBy",
    "reference": "Reference",
    "runbook": "Runbook",
    "output_ids": "OutputIds",
    "log_types": "LogTypes",
    "scheduled_queries": "ScheduledQueries",
    "dedup_period_minutes": "DedupPeriodMinutes",
    "threshold": "Threshold",
    "only_use_base_risk_score": "OnlyUseBaseRiskScore",
    "create_alert": "CreateAlert",
    "resource_types": "ResourceTypes",
    "action_delay_seconds": "ActionDelaySeconds",
    "auto_remediation_id": "AutoRemediationID",
    "suppressions": "Suppressions",
    "data_model_id": "DataModelID",
    "log_types_data_model": "LogTypes",
    "global_id": "GlobalID",
    "query_name": "QueryName",
    "lookback": "Lookback",
    "lookback_window_seconds": "LookbackWindowSeconds",
    "lookup_name": "LookupName",
}

_ALL_SPECS: list[analysis_utils.LoadAnalysisSpecsResult] | None = None


def load_rules(
    rule_id: str | list[str] | None = None,
    enabled: bool | None = None,
    severity: str | Severity | list[str] | list[Severity] | None = None,
    tags: str | list[str] | None = None,
    status: str | list[str] | None = None,
    display_name: str | list[str] | None = None,
    description: str | list[str] | None = None,
    created_by: str | list[str] | None = None,
    reference: str | list[str] | None = None,
    runbook: str | list[str] | None = None,
    output_ids: str | list[str] | None = None,
    log_types: str | list[str] | None = None,
    threshold: int | list[int] | None = None,
    create_alert: bool | None = None,
) -> list[Rule]:
    """
    Load all user analysis items from the project with explicit filtering.

    Uses analysis_utils.load_analysis_specs_ex() to load only user items
    (not cached Panther items). Items are wrapped in type-specific classes.

    All filter parameters accept either a single value or a list of values.
    Multiple values in a list are ORed together (item matches if it matches any value).
    Multiple filter parameters are ANDed together (item must match all filters).

    The severity parameter accepts Severity enum values (e.g., Severity.HIGH) or strings.
    """
    filter_kwargs = locals()

    # Convert Severity enum values to strings for filtering
    if severity is not None:
        if isinstance(severity, Severity):
            severity = severity.value
        elif isinstance(severity, list):
            severity = [s.value if isinstance(s, Severity) else s for s in severity]

    # Convert to AnalysisItem and wrap
    items: list[Rule] = []

    for item in _load_specs_by_analysis_type("rule"):
        if not _matches_filters(
            item,
            analysis_id=(rule_id if isinstance(rule_id, list) else [rule_id] if rule_id else None),
            filter_field_map=_FILTER_FIELD_MAP,
            **filter_kwargs,
        ):
            continue

        items.append(Rule(item))

    return items


def _load_all_specs() -> list[analysis_utils.LoadAnalysisSpecsResult]:
    global _ALL_SPECS
    if _ALL_SPECS is None:
        _ALL_SPECS = list(analysis_utils.load_analysis_specs_ex(["."], [], True))
    return _ALL_SPECS


def _load_specs_by_analysis_type(analysis_type: str) -> list[analysis_utils.AnalysisItem]:
    items: list[analysis_utils.AnalysisItem] = []

    for spec in _load_all_specs():
        if spec.error:
            continue

        if spec.analysis_type() != analysis_type:
            continue

        # Convert LoadAnalysisSpecsResult to AnalysisItem
        python_file_path = None
        python_file_contents = None
        if "Filename" in spec.analysis_spec:
            py_path = spec.python_file_path()
            if py_path:
                python_file_path = str(py_path)
                python_file_contents = spec.python_file_contents()

        item = analysis_utils.AnalysisItem(
            yaml_file_contents=spec.analysis_spec,
            raw_yaml_file_contents=spec.raw_spec_file_content,
            yaml_file_path=spec.spec_filename,
            python_file_contents=python_file_contents,
            python_file_path=python_file_path,
        )

        items.append(item)

    return items


def _matches_filters(
    item: analysis_utils.AnalysisItem,
    analysis_id: list[str] | None = None,
    filter_field_map: dict[str, str] | None = None,
    **filter_kwargs: Any,
) -> bool:
    """Check if an item matches all specified filters, case-insensitive.

    Filter logic:
    - Multiple filter kwargs are ANDed together (all must match)
    - Multiple values in a filter list are ORed together (any value matches)
    - If YAML field is a list: check if any filter value is in the list
    - If YAML field is a single value: check if it matches any filter value
    """
    # Filter by ID (special handling) - uses OR logic (item ID matches any in list)
    if analysis_id is not None:
        if item.analysis_id() not in analysis_id:
            return False

    if filter_field_map:
        for param_name, param_value in filter_kwargs.items():
            if param_value is None:
                continue

            field_name = filter_field_map.get(param_name)
            if not field_name:
                continue

            if field_name not in item.yaml_file_contents:
                # Field doesn't exist in item, skip this filter
                continue

            yaml_value = item.yaml_file_contents[field_name]

            # Convert filter value to list for consistent handling
            filter_values = param_value if isinstance(param_value, list) else [param_value]
            filter_values_lower = [str(v).lower() for v in filter_values]

            # If YAML field is a list, check if ANY filter value is in the list
            if isinstance(yaml_value, list):
                yaml_values_lower = [str(v).lower() for v in yaml_value]
                # Check if any filter value matches any YAML list value (OR logic)
                if not any(fv in yaml_values_lower for fv in filter_values_lower):
                    return False
            else:
                # YAML field is a single value, check if it matches ANY filter value (OR logic)
                yaml_value_lower = str(yaml_value).lower()
                if not any(yaml_value_lower == fv for fv in filter_values_lower):
                    return False

    return True
