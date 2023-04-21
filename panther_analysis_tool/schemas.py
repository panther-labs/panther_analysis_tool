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
from typing import Any, Dict

from schema import And, Optional, Or, Regex, Schema, SchemaError


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


NAME_ID_VALIDATION_REGEX = Regex(r"^[^<>&\"]+$")
RESOURCE_TYPE_REGEX = Regex(
    r"^AWS\.(ACM\.Certificate|CloudFormation\.Stack|CloudTrail\.Meta|CloudTrail|CloudWatch"
    r"\.LogGroup|Config\.Recorder\.Meta|Config\.Recorder|DynamoDB\.Table|EC2\.AMI|EC2\.Instance"
    r"|EC2\.NetworkACL|EC2\.SecurityGroup|EC2\.Volume|EC2\.VPC|ECS\.Cluster|EKS\.Cluster|ELBV2"
    r"\.ApplicationLoadBalancer|GuardDuty\.Detector\.Meta|GuardDuty\.Detector|IAM\.Group|IAM"
    r"\.Policy|IAM\.Role|IAM\.RootUser|IAM\.User|KMS\.Key|Lambda\.Function|PasswordPolicy|RDS"
    r"\.Instance|Redshift\.Cluster|S3\.Bucket|WAF\.Regional\.WebACL|WAF\.WebACL)$"
)
# pylint: disable=line-too-long
LOG_TYPE_REGEX = Regex(
    r"^(Apache\.AccessCombined|Amazon\.EKS\.Audit|Amazon\.EKS\.Authenticator|Apache\.AccessCommon"
    r"|Asana\.Audit|Atlassian\.Audit|AWS\.ALB|AWS\.AuroraMySQLAudit"
    r"|AWS\.CloudTrail|AWS\.CloudTrailDigest|AWS\.CloudTrailInsight|AWS\.CloudWatchEvents"
    r"|AWS\.GuardDuty|AWS\.S3ServerAccess|AWS\.VPCDns|AWS\.VPCFlow|AWS\.WAFWebACL|Box\.Event"
    r"|CiscoUmbrella\.CloudFirewall|CiscoUmbrella\.DNS|CiscoUmbrella\.IP|CiscoUmbrella\."
    r"Proxy|Cloudflare\.Audit|Cloudflare\.Firewall|Cloudflare\.HttpRequest|Cloudflare\.Spectrum|Crowdstrike\.FDREvent|"
    r"Crowdstrike\.ActivityAudit|Crowdstrike\.AIDMaster|Crowdstrike\.AppInfo|Crowdstrike\.CriticalFile"
    r"|Crowdstrike\.DNSRequest|Crowdstrike\.DetectionSummary|Crowdstrike\.GroupIdentity|"
    r"Crowdstrike\.ManagedAssets|Crowdstrike\.NetworkConnect|Crowdstrike\.NetworkListen|"
    r"Crowdstrike\.NotManagedAssets|Crowdstrike\.ProcessRollup2|Crowdstrike\.Process"
    r"Rollup2Stats|Crowdstrike\.SyntheticProcessRollup2|Crowdstrike\.Unknown|Crowdstrike"
    r"\.UserIdentity|Crowdstrike\.UserInfo|Crowdstrike\.UserLogonLogoff|Dropbox\.TeamEvent|Duo\.Administrator|Duo"
    r"\.Authentication|Duo\.OfflineEnrollment|Duo\.Telephony|Fastly\.Access|Fluentd\.Syslog3164"
    r"|Fluentd\.Syslog5424|GCP\.AuditLog|GCP\.HTTPLoadBalancer|GitHub\.Audit|GitLab\.API|GitLab\.Audit|GitLab\.Exceptions"
    r"|GitLab\.Git|GitLab\.Integrations|GitLab\.Production|Gravitational\.TeleportAudit|GSuite\."
    r"ActivityEvent|GSuite\.Reports|Juniper\.Access|Juniper\.Audit|Juniper\.Firewall|Juniper\.MWS"
    r"|Juniper\.Postgres|Juniper\.Security|Lacework\.AgentManagement|Lacework\.AlertDetails|Lacework\.AllFiles|"
    r"Lacework\.Applications|Lacework\.ChangeFiles|Lacework\.CloudCompliance|Lacework\.CloudConfiguration|"
    r"Lacework\.Cmdline|Lacework\.Connections|Lacework\.ContainerSummary|Lacework\.ContainerVulnDetails|"
    r"Lacework\.DNSQuery|Lacework\.Events|Lacework\.HostVulnDetails|Lacework\.Image|Lacework\.Interfaces|"
    r"Lacework\.InternalIPA|Lacework\.MachineDetails|Lacework\.MachineSummary|Lacework\.NewHashes|"
    r"Lacework\.Package|Lacework\.PodSummary|Lacework\.ProcessSummary|Lacework\.UserDetails|Lacework\.UserLogin"
    r"|Microsoft365\.Audit\.AzureActiveDirectory|Microsoft365\.Audit\.Exchange"
    r"|Microsoft365\.Audit\.General|Microsoft365\.Audit\.SharePoint|Microsoft365\.DLP\.All|"
    r"MicrosoftGraph\.SecurityAlert|"
    r"Nginx\.Access|Okta\.SystemLog|OneLogin\.Events|Osquery\.Batch|Osquery\.Differential|"
    r"Osquery\.Snapshot|Osquery\.Status|OSSEC\.EventInfo|OnePassword\.ItemUsage|OnePassword"
    r"\.SignInAttempt|Panther\.Audit|Salesforce\.Login|Salesforce\.LoginAs|Salesforce\.Logout|"
    r"Salesforce\.URI|Slack\.AccessLogs|Slack\.AuditLogs|Slack\.IntegrationLogs|Snyk\.OrgAudit|Snyk\.GroupAudit|Sophos\.Central|Suricata"
    r"\.Anomaly|Suricata\.DNS|Syslog\.RFC3164|Syslog\.RFC5424|Zeek\.DNS|Zendesk\.Audit|Zendesk"
    r"\.AuditLog|Zoom\.Activity|Zoom\.Operation"
    r"|SentinelOne\.Activity|SentinelOne\.DeepVisibility|SentinelOne\.DeepVisibilityV2"
    r"|Tines\.Audit"
    r"|Custom\.([A-Z][A-Za-z0-9]*)(\.[A-Z][A-Za-z0-9]*){0,5})$"
)

TYPE_SCHEMA = Schema(
    {
        "AnalysisType": Or(
            "datamodel",
            "global",
            "pack",
            "policy",
            "rule",
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
        "ResourceTypes": And([str], [RESOURCE_TYPE_REGEX]),
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
        "Filename": str,
        "RuleID": And(str, NAME_ID_VALIDATION_REGEX),
        Or("LogTypes", "ScheduledQueries", only_one=True): And([str], [LOG_TYPE_REGEX]),
        "Severity": Or("Info", "Low", "Medium", "High", "Critical"),
        Optional("Description"): str,
        Optional("DedupPeriodMinutes"): int,
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
    },
    ignore_extra_keys=False,
)  # Prevent user typos on optional fields

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
