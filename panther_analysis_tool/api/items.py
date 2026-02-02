"""Type-specific wrapper classes for analysis items."""

from panther_analysis_tool.api.base import BaseAnalysisItem
from panther_analysis_tool.api.severity import Severity


class Rule(BaseAnalysisItem):
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
    def severity(self) -> str:
        """Get the Severity field."""
        return self._get_field("Severity")

    @severity.setter
    def severity(self, value: str | Severity) -> None:
        """Set the Severity field. Must be one of: Info, Low, Medium, High, Critical.

        Accepts either a string or a Severity enum value.
        """
        # Convert Severity enum to string if needed
        if isinstance(value, Severity):
            severity_str = value.value
        else:
            severity_str = str(value)

        # Validate the severity value
        if severity_str not in [s.value for s in Severity]:
            raise ValueError(f"Invalid severity: {severity_str}")

        # Remove severity function if Python file exists
        if self._item.python_file_contents is not None:
            self.remove_severity_function()
        self._set_field("Severity", severity_str)

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

    def append_to_rule_function(self, code: str) -> None:
        """Append code to the end of the rule() function body.

        Args:
            code: Code to append (will be indented appropriately)
        """
        self._append_to_function("rule", code)

    def prepend_to_rule_function(self, code: str) -> None:
        """Prepend code to the beginning of the rule() function body.

        Args:
            code: Code to prepend (will be indented appropriately)
        """
        self._prepend_to_function("rule", code)
