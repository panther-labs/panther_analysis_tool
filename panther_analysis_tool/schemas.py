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
RESOURCE_TYPE_REGEX = Regex(
    r"^AWS\.(ACM\.Certificate|CloudFormation\.Stack|CloudTrail\.Meta|CloudTrail|CloudWatch"
    r"\.LogGroup|Config\.Recorder\.Meta|Config\.Recorder|DynamoDB\.Table|EC2\.AMI|EC2\.Instance"
    r"|EC2\.NetworkACL|EC2\.SecurityGroup|EC2\.Volume|EC2\.VPC|ECS\.Cluster|EKS\.Cluster|ELBV2"
    r"\.ApplicationLoadBalancer|GuardDuty\.Detector\.Meta|GuardDuty\.Detector|IAM\.Group|IAM"
    r"\.Policy|IAM\.Role|IAM\.RootUser|IAM\.User|KMS\.Key|Lambda\.Function|PasswordPolicy|RDS"
    r"\.Instance|Redshift\.Cluster|S3\.Bucket|WAF\.Regional\.WebACL|WAF\.WebACL)$"
)
LOG_TYPE_REGEX = Regex(
    r"^(Apache\.AccessCombined|Apache\.AccessCommon|AWS\.ALB|AWS\.AuroraMySQLAudit|AWS"
    r"\.CloudTrail|AWS\.CloudTrailDigest|AWS\.CloudTrailInsight|AWS\.CloudWatchEvents|AWS"
    r"\.GuardDuty|AWS\.S3ServerAccess|AWS\.VPCDns|AWS\.VPCFlow|Box\.Event|CiscoUmbrella"
    r"\.CloudFirewall|CiscoUmbrella\.DNS|CiscoUmbrella\.IP|CiscoUmbrella\.Proxy|Cloudflare"
    r"\.Firewall|Cloudflare\.HttpRequest|Cloudflare\.Spectrum|Crowdstrike\.AIDMaster|Crowdstrike"
    r"\.DNSRequest|Crowdstrike\.GroupIdentity|Crowdstrike\.ManagedAssets|Crowdstrike"
    r"\.NetworkConnect|Crowdstrike\.NetworkListen|Crowdstrike\.NotManagedAssets|Crowdstrike"
    r"\.ProcessRollup2|Crowdstrike\.UserIdentity|Crowdstrike\.UserInfo|Duo\.Administrator|Duo"
    r"\.Authentication|Duo\.OfflineEnrollment|Duo\.Telephony|Fastly\.Access|Fluentd\.Syslog3164"
    r"|Fluentd\.Syslog5424|GCP\.AuditLog|GitLab\.API|GitLab\.Audit|GitLab\.Exceptions|GitLab\.Git"
    r"|GitLab\.Integrations|GitLab\.Production|Gravitational\.TeleportAudit|GSuite\.Reports"
    r"|Juniper\.Access|Juniper\.Audit|Juniper\.Firewall|Juniper\.MWS|Juniper\.Postgres|Juniper"
    r"\.Security|Lacework\.Events|Microsoft365\.Audit\.AzureActiveDirectory|Microsoft365\.Audit"
    r"\.Exchange|Microsoft365\.Audit\.General|Microsoft365\.Audit\.SharePoint|Microsoft365\.DLP"
    r"\.All|Nginx\.Access|Okta\.SystemLog|OneLogin\.Events|Osquery\.Batch|Osquery\.Differential"
    r"|Osquery\.Snapshot|Osquery\.Status|OSSEC\.EventInfo|Salesforce\.Login|Salesforce\.LoginAs"
    r"|Salesforce\.Logout|Salesforce\.URI|Slack\.AccessLogs|Slack\.AuditLogs|Slack"
    r"\.IntegrationLogs|Sophos\.Central|Suricata\.Anomaly|Suricata\.DNS|Syslog\.RFC3164|Syslog"
    r"\.RFC5424|Zeek\.DNS)$"
)

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
        "LogTypes": And([str], [LOG_TYPE_REGEX]),
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
        "ResourceTypes": And([str], [RESOURCE_TYPE_REGEX]),
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
                Optional(
                    "Mocks"
                ): object,
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
        Or("LogTypes", "ScheduledQueries"): And([str], [LOG_TYPE_REGEX]),
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
                Optional(
                    "Mocks"
                ): object,
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
