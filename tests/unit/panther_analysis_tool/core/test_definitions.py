"""Tests for panther_analysis_tool.core.definitions."""

import pytest

from panther_analysis_tool.constants import AnalysisTypes
from panther_analysis_tool.core.definitions import analysis_id_field_name


@pytest.mark.parametrize(
    ("analysis_type", "expected_field"),
    [
        (AnalysisTypes.RULE, "RuleID"),
        (AnalysisTypes.SCHEDULED_RULE, "RuleID"),
        (AnalysisTypes.CORRELATION_RULE, "RuleID"),
        (AnalysisTypes.DERIVED, "RuleID"),
        (AnalysisTypes.SIMPLE_DETECTION, "RuleID"),
        (AnalysisTypes.DATA_MODEL, "DataModelID"),
        (AnalysisTypes.POLICY, "PolicyID"),
        (AnalysisTypes.GLOBAL, "GlobalID"),
        (AnalysisTypes.SCHEDULED_QUERY, "QueryName"),
        (AnalysisTypes.SAVED_QUERY, "QueryName"),
        (AnalysisTypes.PACK, "PackID"),
        (AnalysisTypes.LOOKUP_TABLE, "LookupName"),
    ],
)
def test_analysis_id_field_name(analysis_type: str, expected_field: str) -> None:
    """analysis_id_field_name returns the correct ID field for each analysis type."""
    assert analysis_id_field_name(analysis_type) == expected_field


def test_analysis_id_field_name_unsupported_raises() -> None:
    """analysis_id_field_name raises ValueError for unsupported analysis types."""
    with pytest.raises(ValueError, match="Unsupported analysis type: unknown_type"):
        analysis_id_field_name("unknown_type")
