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
import json
import pkgutil
from typing import Any, Dict

from schema import And, Optional, Or, Regex, Schema, SchemaError

from panther_analysis_tool.schema_regexs import LOG_TYPE_REGEX


class QueryScheduleSchema(Schema):
    # pylint: disable=arguments-differ
    def validate(
        self, data: Dict[str, Any], _is_query_schedule_schema: bool = True
    ) -> Dict[str, Any]:
        super().validate(data, _is_query_schedule_schema=False)
        if _is_query_schedule_schema:
            rate, timeout = data.get("RateMinutes"), data.get("TimeoutMinutes")
            if rate is not None:
                # validate rate minutes >1m
                if rate <= 1:
                    raise SchemaError("RateMinutes must be > 1")
                # validate rate minutes >= timeout
                if rate < timeout:
                    raise SchemaError("RateMinutes must be >= TimeoutMinutes")
        return data


NAME_ID_VALIDATION_REGEX = Regex(r"^[^<>&\"%]+$")
RESOURCE_TYPE_REGEX = Regex(
    r"^AWS\.(ACM\.Certificate|CloudFormation\.Stack|CloudTrail\.Meta|CloudTrail|CloudWatch"
    r"\.LogGroup|Config\.Recorder\.Meta|Config\.Recorder|DynamoDB\.Table|EC2\.AMI|EC2\.Instance"
    r"|EC2\.NetworkACL|EC2\.SecurityGroup|EC2\.Volume|EC2\.VPC|ECS\.Cluster|EKS\.Cluster|ELBV2"
    r"\.ApplicationLoadBalancer|GuardDuty\.Detector\.Meta|GuardDuty\.Detector|IAM\.Group|IAM"
    r"\.Policy|IAM\.Role|IAM\.RootUser|IAM\.User|KMS\.Key|Lambda\.Function|PasswordPolicy|RDS"
    r"\.Instance|Redshift\.Cluster|S3\.Bucket|WAF\.Regional\.WebACL|WAF\.WebACL)$"
)

TYPE_SCHEMA = Schema(
    {
        "AnalysisType": Or(
            "correlation_rule",
            "datamodel",
            "global",
            "pack",
            "policy",
            "rule",
            "saved_query",
            "scheduled_rule",
            "scheduled_query",
            "lookup_table",
        ),
    },
    ignore_extra_keys=True,
)

MOCK_SCHEMA = Schema(
    {
        "objectName": str,
        # best effort to detect str: because of the ruamel bool constructor, boolean strings are converted to bools
        "returnValue": Or(str, bool),
    }
)

DATA_MODEL_SCHEMA = Schema(
    {
        "AnalysisType": Or("datamodel"),
        "DataModelID": And(str, NAME_ID_VALIDATION_REGEX),
        "Enabled": bool,
        "LogTypes": And([str], [LOG_TYPE_REGEX]),
        "Mappings": [
            {
                "Name": str,
                Or("Method", "Path", only_one=True): str,
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
        Optional("ResourceTypes"): And([str], [RESOURCE_TYPE_REGEX]),
        "Severity": Or("Info", "Low", "Medium", "High", "Critical"),
        Optional("ActionDelaySeconds"): int,
        Optional("AutoRemediationID"): str,
        Optional("AutoRemediationParameters"): object,
        Optional("Description"): str,
        Optional("DisplayName"): And(str, NAME_ID_VALIDATION_REGEX),
        Optional("OnlyUseBaseRiskScore"): bool,
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
                Optional("Mocks"): [MOCK_SCHEMA],
            }
        ],
    },
    ignore_extra_keys=False,
)  # Prevent user typos on optional fields

RULE_SCHEMA = Schema(
    {
        "AnalysisType": Or("rule", "scheduled_rule"),
        "Enabled": bool,
        Or("Filename", "Detection", only_one=True): Or(str, object),
        "RuleID": And(str, NAME_ID_VALIDATION_REGEX),
        Or("LogTypes", "ScheduledQueries", only_one=True): And([str], [LOG_TYPE_REGEX]),
        "Severity": Or("Info", "Low", "Medium", "High", "Critical"),
        Optional("Description"): str,
        Optional("DedupPeriodMinutes"): int,
        Optional("InlineFilters"): object,
        Optional("DisplayName"): And(str, NAME_ID_VALIDATION_REGEX),
        Optional("OnlyUseBaseRiskScore"): bool,
        Optional("OutputIds"): [str],
        Optional("Reference"): str,
        Optional("Runbook"): str,
        Optional("SummaryAttributes"): [str],
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
                Optional("Mocks"): [MOCK_SCHEMA],
            }
        ],
        Optional("DynamicSeverities"): object,
        Optional("AlertTitle"): str,
        Optional("AlertContext"): object,
        Optional("GroupBy"): object,
        Optional("CreateAlert"): bool,
    },
    ignore_extra_keys=False,
)  # Prevent user typos on optional fields

DERIVED_SCHEMA = Schema(
    {
        "AnalysisType": "rule",
        "RuleID": And(str, NAME_ID_VALIDATION_REGEX),
        "BaseDetection": And(str, NAME_ID_VALIDATION_REGEX),
        Optional("Enabled"): bool,
        Optional("Severity"): Or("Info", "Low", "Medium", "High", "Critical"),
        Optional("Description"): str,
        Optional("DedupPeriodMinutes"): int,
        Optional("InlineFilters"): object,
        Optional("DisplayName"): And(str, NAME_ID_VALIDATION_REGEX),
        Optional("OnlyUseBaseRiskScore"): bool,
        Optional("OutputIds"): [str],
        Optional("Reference"): str,
        Optional("Runbook"): str,
        Optional("SummaryAttributes"): [str],
        Optional("Threshold"): int,
        Optional("Tags"): [str],
        Optional("Reports"): {str: list},
        Optional("DynamicSeverities"): object,
        Optional("AlertTitle"): str,
        Optional("AlertContext"): object,
        Optional("GroupBy"): object,
        Optional("Tests"): object,
        Optional("CreateAlert"): bool,
    },
    ignore_extra_keys=False,
)

CORRELATION_RULE_SCHEMA = Schema(
    {
        "AnalysisType": "correlation_rule",
        "RuleID": And(str, NAME_ID_VALIDATION_REGEX),
        "Enabled": bool,
        "Detection": object,
        "Severity": Or("Info", "Low", "Medium", "High", "Critical"),
        Optional("Description"): str,
        Optional("DisplayName"): And(str, NAME_ID_VALIDATION_REGEX),
        Optional("OnlyUseBaseRiskScore"): bool,
        Optional("OutputIds"): [str],
        Optional("Reference"): str,
        Optional("Runbook"): str,
        Optional("SummaryAttributes"): [str],
        Optional("Tags"): [str],
        Optional("Reports"): {str: list},
        Optional("CreateAlert"): bool,
    },
    ignore_extra_keys=False,
)

SAVED_QUERY_SCHEMA = Schema(
    {
        "AnalysisType": Or("saved_query"),
        "QueryName": And(str, NAME_ID_VALIDATION_REGEX),
        Or("Query", "AthenaQuery", "SnowflakeQuery"): str,
        Optional("Description"): str,
        Optional("Tags"): [str],
        Optional("Lookback"): bool,
        Optional("LookbackWindowSeconds"): int,
    },
    ignore_extra_keys=False,
)  # Prevent user typos on optional fields

SCHEDULED_QUERY_SCHEMA = Schema(
    {
        "AnalysisType": Or("scheduled_query"),
        "QueryName": And(str, NAME_ID_VALIDATION_REGEX),
        "Enabled": bool,
        Or("Query", "AthenaQuery", "SnowflakeQuery"): str,
        "Schedule": QueryScheduleSchema(
            {
                Or("CronExpression", "RateMinutes", only_one=True): Or(str, int),
                "TimeoutMinutes": int,
            }
        ),
        Optional("Description"): str,
        Optional("Tags"): [str],
        Optional("Lookback"): bool,
        Optional("LookbackWindowSeconds"): int,
    },
    ignore_extra_keys=False
    # Prevent user typos on optional fields
)

LOOKUP_TABLE_SCHEMA = Schema(
    {
        "AnalysisType": Or("lookup_table"),
        "LookupName": str,
        "Enabled": bool,
        Or("Filename", "Refresh"): Or(
            str,
            {
                "RoleARN": str,
                "ObjectPath": str,
                Optional("PeriodMinutes"): int,
                Optional("AlarmPeriodMinutes"): int,
                Optional("ObjectKMSKey"): str,
            },
        ),
        "Schema": str,
        "LogTypeMap": {
            "PrimaryKey": str,
            "AssociatedLogTypes": [{"LogType": str, Optional("Selectors"): [str]}],
        },
        Optional("Description"): str,
        Optional("Reference"): str,
    },
    ignore_extra_keys=False,
)  # Prevent user typos on optional fields

# load jsonschema files
raw_simple_detection_schema = pkgutil.get_data(
    __name__, "detection_schemas/analysis_config_schema.json"
)
ANALYSIS_CONFIG_SCHEMA = (
    json.loads(raw_simple_detection_schema) if raw_simple_detection_schema else {}
)
