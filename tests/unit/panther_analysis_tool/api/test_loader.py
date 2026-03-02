"""Unit tests for panther_analysis_tool.api.loader module."""

import pathlib
from unittest.mock import MagicMock, patch

import pytest

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.api.items import Rule
from panther_analysis_tool.api.loader import _matches_filters, load_rules


# Pytest fixtures
@pytest.fixture
def filter_field_map():
    """Fixture providing filter field map for tests."""
    return {
        "rule_id": "RuleID",
        "enabled": "Enabled",
        "severity": "Severity",
        "tags": "Tags",
        "log_types": "LogTypes",
    }


def create_test_item(
    rule_id: str = "test.rule.1",
    enabled: bool = True,
    severity: str = "Info",
    tags: list[str] | None = None,
    log_types: list[str] | None = None,
) -> analysis_utils.AnalysisItem:
    """Helper to create a test AnalysisItem."""
    yaml_contents = {
        "AnalysisType": "rule",
        "RuleID": rule_id,
        "Enabled": enabled,
        "Severity": severity,
    }
    if tags:
        yaml_contents["Tags"] = tags
    if log_types:
        yaml_contents["LogTypes"] = log_types

    return analysis_utils.AnalysisItem(
        yaml_file_contents=yaml_contents,
        raw_yaml_file_contents=b"test",
        yaml_file_path="/test/path.yml",
    )


def create_mock_spec(
    rule_id: str = "test.rule.1",
    enabled: bool = True,
    severity: str = "Info",
    tags: list[str] | None = None,
    log_types: list[str] | None = None,
    status: str | None = None,
    display_name: str | None = None,
    description: str | None = None,
    created_by: str | None = None,
    reference: str | None = None,
    runbook: str | None = None,
    output_ids: list[str] | None = None,
    threshold: int | None = None,
    create_alert: bool | None = None,
    has_python_file: bool = True,
    has_error: bool = False,
) -> MagicMock:
    """Helper to create a mock LoadAnalysisSpecsResult."""
    spec = MagicMock()
    spec.error = Exception() if has_error else None

    yaml_contents = {
        "AnalysisType": "rule",
        "RuleID": rule_id,
        "Enabled": enabled,
        "Severity": severity,
    }
    if tags:
        yaml_contents["Tags"] = tags
    if log_types:
        yaml_contents["LogTypes"] = log_types
    if status:
        yaml_contents["Status"] = status
    if display_name:
        yaml_contents["DisplayName"] = display_name
    if description:
        yaml_contents["Description"] = description
    if created_by:
        yaml_contents["CreatedBy"] = created_by
    if reference:
        yaml_contents["Reference"] = reference
    if runbook:
        yaml_contents["Runbook"] = runbook
    if output_ids:
        yaml_contents["OutputIds"] = output_ids
    if threshold is not None:
        yaml_contents["Threshold"] = threshold
    if create_alert is not None:
        yaml_contents["CreateAlert"] = create_alert

    spec.analysis_spec = yaml_contents
    spec.raw_spec_file_content = b"test yaml"
    spec.spec_filename = f"/test/{rule_id}.yml"

    if has_python_file:
        spec.analysis_spec["Filename"] = f"{rule_id}.py"
        py_path = pathlib.Path(f"/test/{rule_id}.py")
        spec.python_file_path.return_value = py_path
        spec.python_file_contents.return_value = b"def rule(event):\n    return True\n"
    else:
        spec.python_file_path.return_value = None
        spec.python_file_contents.return_value = None

    return spec


# Tests for _matches_filters
def test_matches_filters_no_filters(filter_field_map):
    """Test that item matches when no filters are provided."""
    item = create_test_item()
    assert _matches_filters(item, filter_field_map=filter_field_map)


def test_matches_filters_by_analysis_id_single_match(filter_field_map):
    """Test filtering by analysis ID with a single matching ID."""
    item = create_test_item(rule_id="test.rule.1")
    assert _matches_filters(
        item,
        analysis_id=["test.rule.1"],
        filter_field_map=filter_field_map,
    )


def test_matches_filters_by_analysis_id_list_match(filter_field_map):
    """Test filtering by analysis ID with multiple IDs, one matches."""
    item = create_test_item(rule_id="test.rule.1")
    assert _matches_filters(
        item,
        analysis_id=["test.rule.1", "test.rule.2"],
        filter_field_map=filter_field_map,
    )


def test_matches_filters_by_analysis_id_no_match(filter_field_map):
    """Test filtering by analysis ID when ID doesn't match."""
    item = create_test_item(rule_id="test.rule.1")
    assert not _matches_filters(
        item,
        analysis_id=["test.rule.2"],
        filter_field_map=filter_field_map,
    )


def test_matches_filters_by_analysis_id_none(filter_field_map):
    """Test filtering by analysis ID when ID is None (no filter)."""
    item = create_test_item(rule_id="test.rule.1")
    assert _matches_filters(
        item,
        analysis_id=None,
        filter_field_map=filter_field_map,
    )


def test_matches_filters_by_enabled_match(filter_field_map):
    """Test filtering by enabled status when it matches."""
    item = create_test_item(enabled=True)
    assert _matches_filters(
        item,
        filter_field_map=filter_field_map,
        enabled=True,
    )


def test_matches_filters_by_enabled_no_match(filter_field_map):
    """Test filtering by enabled status when it doesn't match."""
    item = create_test_item(enabled=True)
    assert not _matches_filters(
        item,
        filter_field_map=filter_field_map,
        enabled=False,
    )


def test_matches_filters_by_severity_match(filter_field_map):
    """Test filtering by severity when it matches."""
    item = create_test_item(severity="High")
    assert _matches_filters(
        item,
        filter_field_map=filter_field_map,
        severity="High",
    )


def test_matches_filters_by_severity_case_insensitive(filter_field_map):
    """Test that severity filtering is case-insensitive."""
    item = create_test_item(severity="High")
    assert _matches_filters(
        item,
        filter_field_map=filter_field_map,
        severity="high",
    )
    assert _matches_filters(
        item,
        filter_field_map=filter_field_map,
        severity="HIGH",
    )


def test_matches_filters_by_severity_no_match(filter_field_map):
    """Test filtering by severity when it doesn't match."""
    item = create_test_item(severity="High")
    assert not _matches_filters(
        item,
        filter_field_map=filter_field_map,
        severity="Low",
    )


def test_matches_filters_by_severity_list_match(filter_field_map):
    """Test filtering by severity with a list - uses OR logic (any value matches)."""
    item = create_test_item(severity="High")
    # Filter uses OR logic - matches if severity is "High" OR "Critical"
    assert _matches_filters(
        item,
        filter_field_map=filter_field_map,
        severity=["High", "Critical"],
    )


def test_matches_filters_by_severity_list_no_match(filter_field_map):
    """Test filtering by severity with a list - fails if no values match."""
    item = create_test_item(severity="High")
    # Neither "Low" nor "Info" match "High", so this should fail
    assert not _matches_filters(
        item,
        filter_field_map=filter_field_map,
        severity=["Low", "Info"],
    )


def test_matches_filters_by_tags_single_match(filter_field_map):
    """Test filtering by tags with a single tag that matches."""
    item = create_test_item(tags=["security", "compliance"])
    assert _matches_filters(
        item,
        filter_field_map=filter_field_map,
        tags="security",
    )


def test_matches_filters_by_tags_list_match(filter_field_map):
    """Test filtering by tags with a list - ANY value matches (OR logic)."""
    item = create_test_item(tags=["security", "compliance"])
    # Filter values are ORed - if any value is in the item's tags, it matches
    assert _matches_filters(
        item,
        filter_field_map=filter_field_map,
        tags=["security", "compliance"],
    )


def test_matches_filters_by_tags_list_partial_match_passes(filter_field_map):
    """Test filtering by tags with a list - passes if any value matches (OR logic)."""
    item = create_test_item(tags=["security", "compliance"])
    # "security" is in the item's tags, so this should pass (OR logic)
    assert _matches_filters(
        item,
        filter_field_map=filter_field_map,
        tags=["security", "audit"],
    )


def test_matches_filters_by_tags_list_no_match(filter_field_map):
    """Test filtering by tags with a list - fails if no values match."""
    item = create_test_item(tags=["security", "compliance"])
    # Neither "audit" nor "monitoring" are in the item's tags, so this should fail
    assert not _matches_filters(
        item,
        filter_field_map=filter_field_map,
        tags=["audit", "monitoring"],
    )


def test_matches_filters_by_tags_case_insensitive(filter_field_map):
    """Test that tag filtering is case-insensitive."""
    item = create_test_item(tags=["Security", "Compliance"])
    assert _matches_filters(
        item,
        filter_field_map=filter_field_map,
        tags="security",
    )


def test_matches_filters_by_tags_no_match(filter_field_map):
    """Test filtering by tags when no tags match."""
    item = create_test_item(tags=["security", "compliance"])
    assert not _matches_filters(
        item,
        filter_field_map=filter_field_map,
        tags="audit",
    )


def test_matches_filters_by_tags_item_has_no_tags(filter_field_map):
    """Test filtering by tags when item has no tags field."""
    item = create_test_item()  # No tags
    # When field doesn't exist in item, filter is skipped (returns True)
    # This matches the implementation behavior
    assert _matches_filters(
        item,
        filter_field_map=filter_field_map,
        tags="security",
    )


def test_matches_filters_by_log_types_single_match(filter_field_map):
    """Test filtering by log types with a single log type that matches."""
    item = create_test_item(log_types=["AWS.CloudTrail", "AWS.S3"])
    assert _matches_filters(
        item,
        filter_field_map=filter_field_map,
        log_types="AWS.CloudTrail",
    )


def test_matches_filters_by_log_types_list_match(filter_field_map):
    """Test filtering by log types with a list - ANY value matches (OR logic)."""
    item = create_test_item(log_types=["AWS.CloudTrail", "AWS.S3"])
    # Filter values are ORed - if any value is in the item's log types, it matches
    assert _matches_filters(
        item,
        filter_field_map=filter_field_map,
        log_types=["AWS.CloudTrail", "AWS.S3"],
    )


def test_matches_filters_by_log_types_list_partial_match_passes(filter_field_map):
    """Test filtering by log types with a list - passes if any value matches (OR logic)."""
    item = create_test_item(log_types=["AWS.CloudTrail", "AWS.S3"])
    # "AWS.CloudTrail" is in the item's log types, so this should pass (OR logic)
    assert _matches_filters(
        item,
        filter_field_map=filter_field_map,
        log_types=["AWS.CloudTrail", "AWS.VPC"],
    )


def test_matches_filters_by_log_types_list_no_match(filter_field_map):
    """Test filtering by log types with a list - fails if no values match."""
    item = create_test_item(log_types=["AWS.CloudTrail", "AWS.S3"])
    # Neither "AWS.VPC" nor "AWS.EC2" are in the item's log types, so this should fail
    assert not _matches_filters(
        item,
        filter_field_map=filter_field_map,
        log_types=["AWS.VPC", "AWS.EC2"],
    )


def test_matches_filters_by_log_types_no_match(filter_field_map):
    """Test filtering by log types when no log types match."""
    item = create_test_item(log_types=["AWS.CloudTrail", "AWS.S3"])
    assert not _matches_filters(
        item,
        filter_field_map=filter_field_map,
        log_types="AWS.VPC",
    )


def test_matches_filters_multiple_filters_all_match(filter_field_map):
    """Test multiple filters when all match."""
    item = create_test_item(
        enabled=True,
        severity="High",
        tags=["security"],
    )
    assert _matches_filters(
        item,
        filter_field_map=filter_field_map,
        enabled=True,
        severity="High",
        tags="security",
    )


def test_matches_filters_multiple_filters_one_fails(filter_field_map):
    """Test multiple filters when one doesn't match (AND logic between filters)."""
    item = create_test_item(
        enabled=True,
        severity="High",
        tags=["security"],
    )
    assert not _matches_filters(
        item,
        filter_field_map=filter_field_map,
        enabled=True,
        severity="High",
        tags="audit",  # Doesn't match
    )


def test_matches_filters_multiple_filters_with_lists(filter_field_map):
    """Test multiple filters with lists - AND between filters, OR within each filter."""
    item = create_test_item(
        enabled=True,
        severity="High",
        tags=["security", "compliance"],
        log_types=["AWS.CloudTrail", "AWS.S3"],
    )
    # All filters must match (AND), but each list uses OR logic
    # enabled=True AND severity in ["High", "Critical"] AND tags contains "security" or "audit"
    assert _matches_filters(
        item,
        filter_field_map=filter_field_map,
        enabled=True,
        severity=["High", "Critical"],  # OR: matches "High"
        tags=["security", "audit"],  # OR: matches "security"
        log_types=["AWS.CloudTrail", "AWS.VPC"],  # OR: matches "AWS.CloudTrail"
    )


def test_matches_filters_multiple_filters_with_lists_one_fails(filter_field_map):
    """Test multiple filters with lists when one filter fails."""
    item = create_test_item(
        enabled=True,
        severity="High",
        tags=["security"],
    )
    # enabled=True AND severity in ["High"] AND tags contains "audit" or "monitoring"
    # The tags filter fails, so overall should fail
    assert not _matches_filters(
        item,
        filter_field_map=filter_field_map,
        enabled=True,
        severity=["High", "Critical"],  # OR: matches "High"
        tags=["audit", "monitoring"],  # OR: doesn't match (item has "security")
    )


def test_matches_filters_field_not_in_item(filter_field_map):
    """Test filtering by a field that doesn't exist in the item."""
    item = create_test_item()  # No tags field
    # Should not raise error, just skip the filter
    assert _matches_filters(
        item,
        filter_field_map=filter_field_map,
        tags="security",
    )


def test_matches_filters_field_not_in_map(filter_field_map):
    """Test filtering by a field that's not in the filter field map."""
    item = create_test_item()
    # Unknown field should be ignored
    assert _matches_filters(
        item,
        filter_field_map=filter_field_map,
        unknown_field="value",
    )


def test_matches_filters_none_value_ignored(filter_field_map):
    """Test that None filter values are ignored."""
    item = create_test_item()
    assert _matches_filters(
        item,
        filter_field_map=filter_field_map,
        enabled=None,
        severity=None,
        tags=None,
    )


def test_matches_filters_empty_filter_field_map():
    """Test with empty filter field map."""
    item = create_test_item()
    assert _matches_filters(
        item,
        filter_field_map={},
        enabled=True,
    )


def test_matches_filters_no_filter_field_map():
    """Test with no filter field map provided."""
    item = create_test_item()
    assert _matches_filters(item)


# Tests for load_rules
@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_no_specs(mock_load_specs: MagicMock) -> None:
    """Test loading when there are no specs."""
    mock_load_specs.return_value = []
    result = load_rules()
    assert len(result) == 0


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_single_rule(mock_load_specs: MagicMock) -> None:
    """Test loading a single rule."""
    spec = create_mock_spec(rule_id="test.rule.1")
    mock_load_specs.return_value = [spec]

    result = load_rules()
    assert len(result) == 1
    assert isinstance(result[0], Rule)
    assert result[0].rule_id == "test.rule.1"


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_multiple_rules(mock_load_specs: MagicMock) -> None:
    """Test loading multiple rules."""
    spec1 = create_mock_spec(rule_id="test.rule.1")
    spec2 = create_mock_spec(rule_id="test.rule.2")
    mock_load_specs.return_value = [spec1, spec2]

    result = load_rules()
    assert len(result) == 2
    assert result[0].rule_id == "test.rule.1"
    assert result[1].rule_id == "test.rule.2"


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_rule_id_single(mock_load_specs: MagicMock) -> None:
    """Test filtering by rule ID with a single ID."""
    spec1 = create_mock_spec(rule_id="test.rule.1")
    spec2 = create_mock_spec(rule_id="test.rule.2")
    mock_load_specs.return_value = [spec1, spec2]

    result = load_rules(rule_id="test.rule.1")
    assert len(result) == 1
    assert result[0].rule_id == "test.rule.1"


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_rule_id_list(mock_load_specs: MagicMock) -> None:
    """Test filtering by rule ID with a list of IDs - uses OR logic."""
    spec1 = create_mock_spec(rule_id="test.rule.1")
    spec2 = create_mock_spec(rule_id="test.rule.2")
    spec3 = create_mock_spec(rule_id="test.rule.3")
    mock_load_specs.return_value = [spec1, spec2, spec3]

    # Single rule_id works
    result = load_rules(rule_id="test.rule.1")
    assert len(result) == 1
    assert result[0].rule_id == "test.rule.1"

    # List of rule_ids - uses OR logic (matches if rule_id is any value in the list)
    # Since RuleID is a single value field, we check if it matches ANY filter value
    result = load_rules(rule_id=["test.rule.1", "test.rule.3"])
    assert len(result) == 2
    assert {r.rule_id for r in result} == {"test.rule.1", "test.rule.3"}


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_enabled(mock_load_specs: MagicMock) -> None:
    """Test filtering by enabled status."""
    spec1 = create_mock_spec(rule_id="test.rule.1", enabled=True)
    spec2 = create_mock_spec(rule_id="test.rule.2", enabled=False)
    mock_load_specs.return_value = [spec1, spec2]

    result = load_rules(enabled=True)
    assert len(result) == 1
    assert result[0].rule_id == "test.rule.1"
    assert result[0].enabled


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_severity(mock_load_specs: MagicMock) -> None:
    """Test filtering by severity."""
    spec1 = create_mock_spec(rule_id="test.rule.1", severity="High")
    spec2 = create_mock_spec(rule_id="test.rule.2", severity="Low")
    mock_load_specs.return_value = [spec1, spec2]

    result = load_rules(severity="High")
    assert len(result) == 1
    assert result[0].rule_id == "test.rule.1"
    assert result[0].severity == "High"


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_severity_list(mock_load_specs: MagicMock) -> None:
    """Test filtering by severity with a list - uses OR logic (any value matches)."""
    spec1 = create_mock_spec(rule_id="test.rule.1", severity="High")
    spec2 = create_mock_spec(rule_id="test.rule.2", severity="Low")
    spec3 = create_mock_spec(rule_id="test.rule.3", severity="Critical")
    mock_load_specs.return_value = [spec1, spec2, spec3]

    # Filter uses OR logic - matches if severity is "High" OR "Critical"
    result = load_rules(severity=["High", "Critical"])
    assert len(result) == 2
    assert {r.rule_id for r in result} == {"test.rule.1", "test.rule.3"}


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_tags(mock_load_specs: MagicMock) -> None:
    """Test filtering by tags."""
    spec1 = create_mock_spec(rule_id="test.rule.1", tags=["security", "compliance"])
    spec2 = create_mock_spec(rule_id="test.rule.2", tags=["audit"])
    mock_load_specs.return_value = [spec1, spec2]

    result = load_rules(tags="security")
    assert len(result) == 1
    assert result[0].rule_id == "test.rule.1"


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_tags_list(mock_load_specs: MagicMock) -> None:
    """Test filtering by tags with a list - uses OR logic (any tag matches)."""
    spec1 = create_mock_spec(rule_id="test.rule.1", tags=["security", "compliance"])
    spec2 = create_mock_spec(rule_id="test.rule.2", tags=["audit"])
    spec3 = create_mock_spec(rule_id="test.rule.3", tags=["compliance"])
    mock_load_specs.return_value = [spec1, spec2, spec3]

    # Filter uses OR logic - matches if item has "security" OR "audit" tags
    # spec1 has "security", spec2 has "audit", so both match
    result = load_rules(tags=["security", "audit"])
    assert len(result) == 2
    assert {r.rule_id for r in result} == {"test.rule.1", "test.rule.2"}

    # Filter matches if item has "security" OR "compliance" tags
    # spec1 has both, spec3 has "compliance", so both match
    result = load_rules(tags=["security", "compliance"])
    assert len(result) == 2
    assert {r.rule_id for r in result} == {"test.rule.1", "test.rule.3"}


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_log_types(mock_load_specs: MagicMock) -> None:
    """Test filtering by log types."""
    spec1 = create_mock_spec(
        rule_id="test.rule.1", log_types=["AWS.CloudTrail", "AWS.S3"]
    )
    spec2 = create_mock_spec(rule_id="test.rule.2", log_types=["AWS.VPC"])
    mock_load_specs.return_value = [spec1, spec2]

    result = load_rules(log_types="AWS.CloudTrail")
    assert len(result) == 1
    assert result[0].rule_id == "test.rule.1"


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_log_types_list(mock_load_specs: MagicMock) -> None:
    """Test filtering by log types with a list - uses OR logic (any log type matches)."""
    spec1 = create_mock_spec(
        rule_id="test.rule.1", log_types=["AWS.CloudTrail", "AWS.S3"]
    )
    spec2 = create_mock_spec(rule_id="test.rule.2", log_types=["AWS.VPC"])
    spec3 = create_mock_spec(rule_id="test.rule.3", log_types=["AWS.EC2"])
    mock_load_specs.return_value = [spec1, spec2, spec3]

    # Filter uses OR logic - matches if item has "AWS.CloudTrail" OR "AWS.VPC"
    # spec1 has "AWS.CloudTrail", spec2 has "AWS.VPC", so both match
    result = load_rules(log_types=["AWS.CloudTrail", "AWS.VPC"])
    assert len(result) == 2
    assert {r.rule_id for r in result} == {"test.rule.1", "test.rule.2"}


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_multiple_filters(mock_load_specs: MagicMock) -> None:
    """Test filtering with multiple filters (AND logic between filters)."""
    spec1 = create_mock_spec(
        rule_id="test.rule.1",
        enabled=True,
        severity="High",
        tags=["security"],
    )
    spec2 = create_mock_spec(
        rule_id="test.rule.2",
        enabled=True,
        severity="High",
        tags=["audit"],
    )
    spec3 = create_mock_spec(
        rule_id="test.rule.3",
        enabled=False,
        severity="High",
        tags=["security"],
    )
    mock_load_specs.return_value = [spec1, spec2, spec3]

    result = load_rules(enabled=True, severity="High", tags="security")
    assert len(result) == 1
    assert result[0].rule_id == "test.rule.1"


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_multiple_filters_with_lists(mock_load_specs: MagicMock) -> None:
    """Test filtering with multiple filters using lists (AND between filters, OR within each)."""
    spec1 = create_mock_spec(
        rule_id="test.rule.1",
        enabled=True,
        severity="High",
        tags=["security", "compliance"],
        log_types=["AWS.CloudTrail", "AWS.S3"],
    )
    spec2 = create_mock_spec(
        rule_id="test.rule.2",
        enabled=True,
        severity="Critical",
        tags=["audit"],
        log_types=["AWS.VPC"],
    )
    spec3 = create_mock_spec(
        rule_id="test.rule.3",
        enabled=True,
        severity="Low",
        tags=["security"],
        log_types=["AWS.CloudTrail"],
    )
    mock_load_specs.return_value = [spec1, spec2, spec3]

    # Filter: enabled=True AND severity in ["High", "Critical"] AND tags contains "security" or "audit"
    # spec1: enabled=True, severity="High" (matches), tags=["security"] (matches) -> MATCHES
    # spec2: enabled=True, severity="Critical" (matches), tags=["audit"] (matches) -> MATCHES
    # spec3: enabled=True, severity="Low" (doesn't match) -> NO MATCH
    result = load_rules(
        enabled=True,
        severity=["High", "Critical"],  # OR logic
        tags=["security", "audit"],  # OR logic
    )
    assert len(result) == 2
    assert {r.rule_id for r in result} == {"test.rule.1", "test.rule.2"}


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_skips_specs_with_errors(mock_load_specs: MagicMock) -> None:
    """Test that specs with errors are skipped."""
    spec1 = create_mock_spec(rule_id="test.rule.1", has_error=False)
    spec2 = create_mock_spec(rule_id="test.rule.2", has_error=True)
    spec3 = create_mock_spec(rule_id="test.rule.3", has_error=False)
    mock_load_specs.return_value = [spec1, spec2, spec3]

    result = load_rules()
    assert len(result) == 2
    assert {r.rule_id for r in result} == {"test.rule.1", "test.rule.3"}


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_without_python_file(mock_load_specs: MagicMock) -> None:
    """Test loading a rule without a Python file."""
    spec = create_mock_spec(rule_id="test.rule.1", has_python_file=False)
    mock_load_specs.return_value = [spec]

    result = load_rules()
    assert len(result) == 1
    assert result[0].rule_id == "test.rule.1"
    assert result[0]._item.python_file_contents is None


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_with_python_file(mock_load_specs: MagicMock) -> None:
    """Test loading a rule with a Python file."""
    spec = create_mock_spec(rule_id="test.rule.1", has_python_file=True)
    mock_load_specs.return_value = [spec]

    result = load_rules()
    assert len(result) == 1
    assert result[0].rule_id == "test.rule.1"
    assert result[0]._item.python_file_contents is not None
    assert result[0]._item.python_file_contents == b"def rule(event):\n    return True\n"


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_no_filters_returns_all(mock_load_specs: MagicMock) -> None:
    """Test that loading without filters returns all rules."""
    spec1 = create_mock_spec(rule_id="test.rule.1")
    spec2 = create_mock_spec(rule_id="test.rule.2")
    spec3 = create_mock_spec(rule_id="test.rule.3")
    mock_load_specs.return_value = [spec1, spec2, spec3]

    result = load_rules()
    assert len(result) == 3


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_case_insensitive_filtering(mock_load_specs: MagicMock) -> None:
    """Test that filtering is case-insensitive."""
    spec1 = create_mock_spec(rule_id="test.rule.1", severity="High", tags=["Security"])
    spec2 = create_mock_spec(rule_id="test.rule.2", severity="Low", tags=["Audit"])
    mock_load_specs.return_value = [spec1, spec2]

    # Test case-insensitive severity
    result = load_rules(severity="high")
    assert len(result) == 1
    assert result[0].rule_id == "test.rule.1"

    # Test case-insensitive tags
    result = load_rules(tags="security")
    assert len(result) == 1
    assert result[0].rule_id == "test.rule.1"


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_none_values_ignored(mock_load_specs: MagicMock) -> None:
    """Test that None filter values are ignored."""
    spec1 = create_mock_spec(rule_id="test.rule.1")
    spec2 = create_mock_spec(rule_id="test.rule.2")
    mock_load_specs.return_value = [spec1, spec2]

    result = load_rules(
        rule_id=None,
        enabled=None,
        severity=None,
        tags=None,
    )
    assert len(result) == 2


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_empty_result_after_filtering(mock_load_specs: MagicMock) -> None:
    """Test that filtering can result in an empty list."""
    spec1 = create_mock_spec(rule_id="test.rule.1", severity="High")
    spec2 = create_mock_spec(rule_id="test.rule.2", severity="Low")
    mock_load_specs.return_value = [spec1, spec2]

    result = load_rules(severity="Critical")
    assert len(result) == 0


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_preserves_yaml_contents(mock_load_specs: MagicMock) -> None:
    """Test that YAML contents are preserved correctly."""
    spec = create_mock_spec(
        rule_id="test.rule.1",
        enabled=True,
        severity="High",
        tags=["security"],
    )
    mock_load_specs.return_value = [spec]

    result = load_rules()
    assert len(result) == 1
    rule = result[0]
    assert rule.rule_id == "test.rule.1"
    assert rule.enabled
    assert rule.severity == "High"
    assert rule.tags == ["security"]


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_preserves_file_paths(mock_load_specs: MagicMock) -> None:
    """Test that file paths are preserved correctly."""
    spec = create_mock_spec(rule_id="test.rule.1", has_python_file=True)
    mock_load_specs.return_value = [spec]

    result = load_rules()
    assert len(result) == 1
    rule = result[0]
    assert rule._item.yaml_file_path == "/test/test.rule.1.yml"
    assert rule._item.python_file_path == "/test/test.rule.1.py"


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_status(mock_load_specs: MagicMock) -> None:
    """Test filtering by status."""
    spec1 = create_mock_spec(rule_id="test.rule.1", status="Active")
    spec2 = create_mock_spec(rule_id="test.rule.2", status="Inactive")
    mock_load_specs.return_value = [spec1, spec2]

    result = load_rules(status="Active")
    assert len(result) == 1
    assert result[0].rule_id == "test.rule.1"


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_status_list(mock_load_specs: MagicMock) -> None:
    """Test filtering by status with a list - uses OR logic (any value matches)."""
    spec1 = create_mock_spec(rule_id="test.rule.1", status="Active")
    spec2 = create_mock_spec(rule_id="test.rule.2", status="Inactive")
    spec3 = create_mock_spec(rule_id="test.rule.3", status="Deprecated")
    mock_load_specs.return_value = [spec1, spec2, spec3]

    # Filter uses OR logic - matches if status is "Active" OR "Deprecated"
    result = load_rules(status=["Active", "Deprecated"])
    assert len(result) == 2
    assert {r.rule_id for r in result} == {"test.rule.1", "test.rule.3"}


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_display_name(mock_load_specs: MagicMock) -> None:
    """Test filtering by display name."""
    spec1 = create_mock_spec(rule_id="test.rule.1", display_name="Test Rule One")
    spec2 = create_mock_spec(rule_id="test.rule.2", display_name="Test Rule Two")
    mock_load_specs.return_value = [spec1, spec2]

    result = load_rules(display_name="Test Rule One")
    assert len(result) == 1
    assert result[0].rule_id == "test.rule.1"


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_display_name_list(mock_load_specs: MagicMock) -> None:
    """Test filtering by display name with a list - uses OR logic (any value matches)."""
    spec1 = create_mock_spec(rule_id="test.rule.1", display_name="Test Rule One")
    spec2 = create_mock_spec(rule_id="test.rule.2", display_name="Test Rule Two")
    spec3 = create_mock_spec(rule_id="test.rule.3", display_name="Test Rule Three")
    mock_load_specs.return_value = [spec1, spec2, spec3]

    # Filter uses OR logic - matches if display_name is "Test Rule One" OR "Test Rule Three"
    result = load_rules(display_name=["Test Rule One", "Test Rule Three"])
    assert len(result) == 2
    assert {r.rule_id for r in result} == {"test.rule.1", "test.rule.3"}


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_description(mock_load_specs: MagicMock) -> None:
    """Test filtering by description."""
    spec1 = create_mock_spec(rule_id="test.rule.1", description="First test rule")
    spec2 = create_mock_spec(rule_id="test.rule.2", description="Second test rule")
    mock_load_specs.return_value = [spec1, spec2]

    result = load_rules(description="First test rule")
    assert len(result) == 1
    assert result[0].rule_id == "test.rule.1"


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_description_list(mock_load_specs: MagicMock) -> None:
    """Test filtering by description with a list - uses OR logic (any value matches)."""
    spec1 = create_mock_spec(rule_id="test.rule.1", description="First test rule")
    spec2 = create_mock_spec(rule_id="test.rule.2", description="Second test rule")
    spec3 = create_mock_spec(rule_id="test.rule.3", description="Third test rule")
    mock_load_specs.return_value = [spec1, spec2, spec3]

    # Filter uses OR logic - matches if description is "First test rule" OR "Third test rule"
    result = load_rules(description=["First test rule", "Third test rule"])
    assert len(result) == 2
    assert {r.rule_id for r in result} == {"test.rule.1", "test.rule.3"}


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_created_by(mock_load_specs: MagicMock) -> None:
    """Test filtering by created_by."""
    spec1 = create_mock_spec(rule_id="test.rule.1", created_by="user1@example.com")
    spec2 = create_mock_spec(rule_id="test.rule.2", created_by="user2@example.com")
    mock_load_specs.return_value = [spec1, spec2]

    result = load_rules(created_by="user1@example.com")
    assert len(result) == 1
    assert result[0].rule_id == "test.rule.1"


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_created_by_list(mock_load_specs: MagicMock) -> None:
    """Test filtering by created_by with a list - uses OR logic (any value matches)."""
    spec1 = create_mock_spec(rule_id="test.rule.1", created_by="user1@example.com")
    spec2 = create_mock_spec(rule_id="test.rule.2", created_by="user2@example.com")
    spec3 = create_mock_spec(rule_id="test.rule.3", created_by="user3@example.com")
    mock_load_specs.return_value = [spec1, spec2, spec3]

    # Filter uses OR logic - matches if created_by is "user1@example.com" OR "user3@example.com"
    result = load_rules(created_by=["user1@example.com", "user3@example.com"])
    assert len(result) == 2
    assert {r.rule_id for r in result} == {"test.rule.1", "test.rule.3"}


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_reference(mock_load_specs: MagicMock) -> None:
    """Test filtering by reference."""
    spec1 = create_mock_spec(rule_id="test.rule.1", reference="https://example.com/ref1")
    spec2 = create_mock_spec(rule_id="test.rule.2", reference="https://example.com/ref2")
    mock_load_specs.return_value = [spec1, spec2]

    result = load_rules(reference="https://example.com/ref1")
    assert len(result) == 1
    assert result[0].rule_id == "test.rule.1"


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_reference_list(mock_load_specs: MagicMock) -> None:
    """Test filtering by reference with a list - uses OR logic (any value matches)."""
    spec1 = create_mock_spec(rule_id="test.rule.1", reference="https://example.com/ref1")
    spec2 = create_mock_spec(rule_id="test.rule.2", reference="https://example.com/ref2")
    spec3 = create_mock_spec(rule_id="test.rule.3", reference="https://example.com/ref3")
    mock_load_specs.return_value = [spec1, spec2, spec3]

    # Filter uses OR logic - matches if reference is "https://example.com/ref1" OR "https://example.com/ref3"
    result = load_rules(reference=["https://example.com/ref1", "https://example.com/ref3"])
    assert len(result) == 2
    assert {r.rule_id for r in result} == {"test.rule.1", "test.rule.3"}


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_runbook(mock_load_specs: MagicMock) -> None:
    """Test filtering by runbook."""
    spec1 = create_mock_spec(rule_id="test.rule.1", runbook="https://example.com/runbook1")
    spec2 = create_mock_spec(rule_id="test.rule.2", runbook="https://example.com/runbook2")
    mock_load_specs.return_value = [spec1, spec2]

    result = load_rules(runbook="https://example.com/runbook1")
    assert len(result) == 1
    assert result[0].rule_id == "test.rule.1"


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_runbook_list(mock_load_specs: MagicMock) -> None:
    """Test filtering by runbook with a list - uses OR logic (any value matches)."""
    spec1 = create_mock_spec(rule_id="test.rule.1", runbook="https://example.com/runbook1")
    spec2 = create_mock_spec(rule_id="test.rule.2", runbook="https://example.com/runbook2")
    spec3 = create_mock_spec(rule_id="test.rule.3", runbook="https://example.com/runbook3")
    mock_load_specs.return_value = [spec1, spec2, spec3]

    # Filter uses OR logic - matches if runbook is "https://example.com/runbook1" OR "https://example.com/runbook3"
    result = load_rules(runbook=["https://example.com/runbook1", "https://example.com/runbook3"])
    assert len(result) == 2
    assert {r.rule_id for r in result} == {"test.rule.1", "test.rule.3"}


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_output_ids(mock_load_specs: MagicMock) -> None:
    """Test filtering by output_ids."""
    spec1 = create_mock_spec(rule_id="test.rule.1", output_ids=["output1", "output2"])
    spec2 = create_mock_spec(rule_id="test.rule.2", output_ids=["output3"])
    mock_load_specs.return_value = [spec1, spec2]

    result = load_rules(output_ids="output1")
    assert len(result) == 1
    assert result[0].rule_id == "test.rule.1"


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_output_ids_list(mock_load_specs: MagicMock) -> None:
    """Test filtering by output_ids with a list - uses OR logic (any value matches)."""
    spec1 = create_mock_spec(rule_id="test.rule.1", output_ids=["output1", "output2"])
    spec2 = create_mock_spec(rule_id="test.rule.2", output_ids=["output3"])
    spec3 = create_mock_spec(rule_id="test.rule.3", output_ids=["output4", "output5"])
    mock_load_specs.return_value = [spec1, spec2, spec3]

    # Filter uses OR logic - matches if item has "output1" OR "output4" in its output_ids
    result = load_rules(output_ids=["output1", "output4"])
    assert len(result) == 2
    assert {r.rule_id for r in result} == {"test.rule.1", "test.rule.3"}


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_threshold(mock_load_specs: MagicMock) -> None:
    """Test filtering by threshold."""
    spec1 = create_mock_spec(rule_id="test.rule.1", threshold=5)
    spec2 = create_mock_spec(rule_id="test.rule.2", threshold=10)
    mock_load_specs.return_value = [spec1, spec2]

    result = load_rules(threshold=5)
    assert len(result) == 1
    assert result[0].rule_id == "test.rule.1"


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_threshold_list(mock_load_specs: MagicMock) -> None:
    """Test filtering by threshold with a list - uses OR logic (any value matches)."""
    spec1 = create_mock_spec(rule_id="test.rule.1", threshold=5)
    spec2 = create_mock_spec(rule_id="test.rule.2", threshold=10)
    spec3 = create_mock_spec(rule_id="test.rule.3", threshold=15)
    mock_load_specs.return_value = [spec1, spec2, spec3]

    # Filter uses OR logic - matches if threshold is 5 OR 15
    result = load_rules(threshold=[5, 15])
    assert len(result) == 2
    assert {r.rule_id for r in result} == {"test.rule.1", "test.rule.3"}


@patch("panther_analysis_tool.api.loader.analysis_utils.load_analysis_specs_ex")
def test_load_rules_filters_by_create_alert(mock_load_specs: MagicMock) -> None:
    """Test filtering by create_alert."""
    spec1 = create_mock_spec(rule_id="test.rule.1", create_alert=True)
    spec2 = create_mock_spec(rule_id="test.rule.2", create_alert=False)
    mock_load_specs.return_value = [spec1, spec2]

    result = load_rules(create_alert=True)
    assert len(result) == 1
    assert result[0].rule_id == "test.rule.1"
    assert result[0].create_alert is True
