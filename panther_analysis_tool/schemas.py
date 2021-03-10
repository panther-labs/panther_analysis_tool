"""
Panther Analysis Tool is a command line interface for writing,
testing, and packaging policies/rules.
Copyright (C) 2020 Panther Labs Inc

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from schema import And, Optional, Or, Regex, Schema

NAME_ID_VALIDATION_REGEX = Regex(r"^[A-Za-z0-9_. ()-]+$")

TYPE_SCHEMA = Schema(
    {
        "AnalysisType": Or(
            "datamodel", "global", "pack", "policy", "rule", "scheduled_rule", "scheduled_query"
        ),
    },
    ignore_extra_keys=True,
)

DATA_MODEL_SCHEMA = Schema(
    {
        "AnalysisType": Or("datamodel"),
        "DataModelID": And(str, NAME_ID_VALIDATION_REGEX),
        "Enabled": bool,
        "LogTypes": [str],
        "Mappings": [
            {
                "Name": str,
                Or("Method", "Path"): str,
            }
        ],
        Optional("DisplayName"): And(str, NAME_ID_VALIDATION_REGEX),
        Optional("Filename"): str,
    },
    ignore_extra_keys=False,
)

GLOBAL_SCHEMA = Schema(
    {
        "AnalysisType": Or("global"),
        "Filename": str,
        "GlobalID": And(str, NAME_ID_VALIDATION_REGEX),
        Optional("Description"): str,
        Optional("Tags"): [str],
    },
    ignore_extra_keys=False,
)

PACK_SCHEMA = Schema(
    {
        "AnalysisType": Or("pack"),
        "PackID": And(str, NAME_ID_VALIDATION_REGEX),
        "PackDefinition": {
            "IDs": [str],
        },
        Optional("Description"): str,
        Optional("DisplayName"): And(str, NAME_ID_VALIDATION_REGEX),
    }
)

POLICY_SCHEMA = Schema(
    {
        "AnalysisType": Or("policy"),
        "Enabled": bool,
        "Filename": str,
        "PolicyID": And(str, NAME_ID_VALIDATION_REGEX),
        "ResourceTypes": [str],
        "Severity": Or("Info", "Low", "Medium", "High", "Critical"),
        Optional("ActionDelaySeconds"): int,
        Optional("AutoRemediationID"): str,
        Optional("AutoRemediationParameters"): object,
        Optional("Description"): str,
        Optional("DisplayName"): And(str, NAME_ID_VALIDATION_REGEX),
        Optional("OutputIds"): [str],
        Optional("Reference"): str,
        Optional("Runbook"): str,
        Optional("Suppressions"): [str],
        Optional("Tags"): [str],
        Optional("Reports"): {str: list},
        Optional("Tests"): [
            {
                "Name": str,
                Optional(
                    "ResourceType"
                ): str,  # Not needed anymore, optional for backwards compatibility
                "ExpectedResult": bool,
                "Resource": object,
            }
        ],
    },
    ignore_extra_keys=False,
)  # Prevent user typos on optional fields

RULE_SCHEMA = Schema(
    {
        "AnalysisType": Or("rule", "scheduled_rule"),
        "Enabled": bool,
        "Filename": str,
        "RuleID": And(str, NAME_ID_VALIDATION_REGEX),
        Or("LogTypes", "ScheduledQueries"): [str],
        "Severity": Or("Info", "Low", "Medium", "High", "Critical"),
        Optional("Description"): str,
        Optional("DedupPeriodMinutes"): int,
        Optional("DisplayName"): And(str, NAME_ID_VALIDATION_REGEX),
        Optional("OutputIds"): [str],
        Optional("Reference"): str,
        Optional("Runbook"): str,
        Optional("SummaryAttributes"): [str],
        Optional("Suppressions"): [str],
        Optional("Threshold"): int,
        Optional("Tags"): [str],
        Optional("Reports"): {str: list},
        Optional("Tests"): [
            {
                "Name": str,
                Optional(
                    "LogType"
                ): str,  # Not needed anymore, optional for backwards compatibility
                "ExpectedResult": bool,
                "Log": object,
            }
        ],
    },
    ignore_extra_keys=False,
)  # Prevent user typos on optional fields

SCHEDULED_QUERY_SCHEMA = Schema(
    {
        "AnalysisType": Or("scheduled_query"),
        "QueryName": And(str, NAME_ID_VALIDATION_REGEX),
        "Enabled": bool,
        Or("Query", "AthenaQuery", "SnowflakeQuery"): str,
        "Schedule": {
            Or("CronExpression", "RateMinutes"): Or(str, int),
            "TimeoutMinutes": int,
        },
        Optional("Description"): str,
        Optional("Tags"): [str],
    },
    ignore_extra_keys=False,
)  # Prevent user typos on optional fields
