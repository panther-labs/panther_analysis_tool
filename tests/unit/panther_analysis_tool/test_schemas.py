import unittest
from typing import Any, Dict

import jsonschema
from schema import SchemaError

from panther_analysis_tool.schemas import (
    ANALYSIS_CONFIG_SCHEMA,
    DATA_MODEL_SCHEMA,
    LOG_TYPE_REGEX,
    MOCK_SCHEMA,
    POLICY_SCHEMA,
    RULE_SCHEMA,
    SAVED_QUERY_SCHEMA,
    SCHEDULED_QUERY_SCHEMA,
)


class TestPATSchemas(unittest.TestCase):
    def test_known_log_types(selfs):
        arr = [
            "AWS.ALB",
            "AWS.AuroraMySQLAudit",
            "AWS.CloudTrail",
            "AWS.CloudTrailDigest",
            "AWS.CloudTrailInsight",
            "AWS.CloudWatchEvents",
            "AWS.Config",
            "AWS.GuardDuty",
            "AWS.S3ServerAccess",
            "AWS.TransitGatewayFlow",
            "AWS.VPCDns",
            "AWS.VPCFlow",
            "AWS.WAFWebACL",
            "AlphaSOC.Alert",
            "Amazon.EKS.Audit",
            "Amazon.EKS.Authenticator",
            "Apache.AccessCombined",
            "Apache.AccessCommon",
            "Asana.Audit",
            "Atlassian.Audit",
            "Auth0.Events",
            "Azure.Audit",
            "Bitwarden.Events",
            "Box.Event",
            "CarbonBlack.Audit",
            "CiscoUmbrella.CloudFirewall",
            "CiscoUmbrella.DNS",
            "CiscoUmbrella.IP",
            "CiscoUmbrella.Proxy",
            "Cloudflare.Audit",
            "Cloudflare.Firewall",
            "Cloudflare.HttpRequest",
            "Cloudflare.Spectrum",
            "Crowdstrike.AIDMaster",
            "Crowdstrike.ActivityAudit",
            "Crowdstrike.AppInfo",
            "Crowdstrike.CriticalFile",
            "Crowdstrike.DNSRequest",
            "Crowdstrike.DetectionSummary",
            "Crowdstrike.FDREvent",
            "Crowdstrike.GroupIdentity",
            "Crowdstrike.ManagedAssets",
            "Crowdstrike.NetworkConnect",
            "Crowdstrike.NetworkListen",
            "Crowdstrike.NotManagedAssets",
            "Crowdstrike.ProcessRollup2",
            "Crowdstrike.ProcessRollup2Stats",
            "Crowdstrike.SyntheticProcessRollup2",
            "Crowdstrike.Unknown",
            "Crowdstrike.UserIdentity",
            "Crowdstrike.UserInfo",
            "Crowdstrike.UserLogonLogoff",
            "Docker.Events",
            "Dropbox.TeamEvent",
            "Duo.Administrator",
            "Duo.Authentication",
            "Duo.OfflineEnrollment",
            "Duo.Telephony",
            "Fastly.Access",
            "Fluentd.Syslog3164",
            "Fluentd.Syslog5424",
            "GCP.AuditLog",
            "GCP.HTTPLoadBalancer",
            "GSuite.ActivityEvent",
            "GSuite.DirectoryUsers",
            "GSuite.Reports",
            "GitHub.Audit",
            "GitLab.API",
            "GitLab.Audit",
            "GitLab.Exceptions",
            "GitLab.Git",
            "GitLab.Integrations",
            "GitLab.Production",
            "Gravitational.TeleportAudit",
            "GreyNoise.Noise",
            "GreyNoise.RIOT",
            "Heroku.Runtime",
            "IPInfo.ASNCIDR",
            "IPInfo.ASNRanges",
            "IPInfo.LocationCIDR",
            "IPInfo.LocationRanges",
            "IPInfo.PrivacyCIDR",
            "IPInfo.PrivacyRanges",
            "Jamfpro.Login",
            "Juniper.Access",
            "Juniper.Audit",
            "Juniper.Firewall",
            "Juniper.MWS",
            "Juniper.Postgres",
            "Juniper.Security",
            "Lacework.AgentManagement",
            "Lacework.AlertDetails",
            "Lacework.AllFiles",
            "Lacework.Applications",
            "Lacework.ChangeFiles",
            "Lacework.CloudCompliance",
            "Lacework.CloudConfiguration",
            "Lacework.Cmdline",
            "Lacework.Connections",
            "Lacework.ContainerSummary",
            "Lacework.ContainerVulnDetails",
            "Lacework.DNSQuery",
            "Lacework.Events",
            "Lacework.HostVulnDetails",
            "Lacework.Image",
            "Lacework.Interfaces",
            "Lacework.InternalIPA",
            "Lacework.MachineDetails",
            "Lacework.MachineSummary",
            "Lacework.NewHashes",
            "Lacework.Package",
            "Lacework.PodSummary",
            "Lacework.ProcessSummary",
            "Lacework.UserDetails",
            "Lacework.UserLogin",
            "Linux.Auditd",
            "Microsoft365.Audit.AzureActiveDirectory",
            "Microsoft365.Audit.Exchange",
            "Microsoft365.Audit.General",
            "Microsoft365.Audit.SharePoint",
            "Microsoft365.DLP.All",
            "MicrosoftGraph.SecurityAlert",
            "MongoDB.OrganizationEvent",
            "MongoDB.ProjectEvent",
            "Netskope.Audit",
            "Nginx.Access",
            "Notion.AuditLogs",
            "OSSEC.EventInfo",
            "Okta.Devices",
            "Okta.SystemLog",
            "Okta.Users",
            "OneLogin.Events",
            "OnePassword.AuditEvent",
            "OnePassword.ItemUsage",
            "OnePassword.SignInAttempt",
            "Osquery.Batch",
            "Osquery.Differential",
            "Osquery.Snapshot",
            "Osquery.Status",
            "Panther.Audit",
            "Salesforce.Login",
            "Salesforce.LoginAs",
            "Salesforce.Logout",
            "Salesforce.URI",
            "SentinelOne.Activity",
            "SentinelOne.DeepVisibility",
            "SentinelOne.DeepVisibilityV2",
            "Slack.AccessLogs",
            "Slack.AuditLogs",
            "Slack.IntegrationLogs",
            "Snyk.GroupAudit",
            "Snyk.OrgAudit",
            "Sophos.Central",
            "Suricata.Alert",
            "Suricata.Anomaly",
            "Suricata.DHCP",
            "Suricata.DNS",
            "Suricata.FileInfo",
            "Suricata.Flow",
            "Suricata.HTTP",
            "Suricata.SSH",
            "Suricata.TLS",
            "Sysdig.Audit",
            "Syslog.RFC3164",
            "Syslog.RFC5424",
            "Tailscale.Audit",
            "Tailscale.Network",
            "Tenable.Vulnerability",
            "Tines.Audit",
            "Tor.ExitNode",
            "Windows.EventLogs",
            "Workday.Activity",
            "Workday.SignOnAttempt",
            "Zeek.CaptureLoss",
            "Zeek.Conn",
            "Zeek.DHCP",
            "Zeek.DNS",
            "Zeek.DPD",
            "Zeek.Files",
            "Zeek.HTTP",
            "Zeek.NTP",
            "Zeek.Notice",
            "Zeek.OCSP",
            "Zeek.Reporter",
            "Zeek.SIP",
            "Zeek.Software",
            "Zeek.Ssh",
            "Zeek.Ssl",
            "Zeek.Stats",
            "Zeek.Tunnel",
            "Zeek.Weird",
            "Zeek.X509",
            "Zendesk.Audit",
            "Zoom.Activity",
            "Zoom.Operation",
        ]
        for log_type in arr:
            LOG_TYPE_REGEX.validate(log_type)

    def test_logtypes_regex_amazon_eks(self):
        LOG_TYPE_REGEX.validate("Amazon.EKS.Audit")
        LOG_TYPE_REGEX.validate("Amazon.EKS.Authenticator")

        with self.assertRaises(SchemaError):
            LOG_TYPE_REGEX.validate("Amazon.EKS.Foo")

    def test_logtypes_regex_zeek(self):
        LOG_TYPE_REGEX.validate("Zeek.CaptureLoss")
        LOG_TYPE_REGEX.validate("Zeek.Conn")
        LOG_TYPE_REGEX.validate("Zeek.DHCP")
        LOG_TYPE_REGEX.validate("Zeek.DNS")
        LOG_TYPE_REGEX.validate("Zeek.DPD")
        LOG_TYPE_REGEX.validate("Zeek.Files")
        LOG_TYPE_REGEX.validate("Zeek.HTTP")
        LOG_TYPE_REGEX.validate("Zeek.Notice")
        LOG_TYPE_REGEX.validate("Zeek.NTP")
        LOG_TYPE_REGEX.validate("Zeek.OCSP")
        LOG_TYPE_REGEX.validate("Zeek.Reporter")
        LOG_TYPE_REGEX.validate("Zeek.SIP")
        LOG_TYPE_REGEX.validate("Zeek.Software")
        LOG_TYPE_REGEX.validate("Zeek.Ssh")
        LOG_TYPE_REGEX.validate("Zeek.Ssl")
        LOG_TYPE_REGEX.validate("Zeek.Stats")
        LOG_TYPE_REGEX.validate("Zeek.Tunnel")
        LOG_TYPE_REGEX.validate("Zeek.Weird")
        LOG_TYPE_REGEX.validate("Zeek.X509")

    def test_mocks_are_str(self):
        MOCK_SCHEMA.validate({"objectName": "hello", "returnValue": "Testing a string"})
        MOCK_SCHEMA.validate({"objectName": "hello", "returnValue": "False"})

        with self.assertRaises(SchemaError):
            LOG_TYPE_REGEX.validate(
                {"objectName": "hello", "returnValue": ["Testing a non-string"]}
            )

    def test_data_model_path(self):
        sample_datamodel = {
            "DataModelID": "my.datamodel.id",
            "AnalysisType": "datamodel",
            "LogTypes": ["Amazon.EKS.Audit"],
            "Enabled": False,
        }
        sample_datamodel["Mappings"] = [{"Name": "hello", "Path": "world"}]
        DATA_MODEL_SCHEMA.validate(sample_datamodel)
        sample_datamodel["Mappings"] = [{"Name": "hello", "Method": "world"}]
        DATA_MODEL_SCHEMA.validate(sample_datamodel)

        with self.assertRaises(SchemaError):
            sample_datamodel["Mappings"] = [{"Name": "hello", "Path": "world", "Method": "foo"}]
            DATA_MODEL_SCHEMA.validate(sample_datamodel)

    def test_scheduled_query_validate_schema(self):
        # has required fields
        SCHEDULED_QUERY_SCHEMA.validate(
            {
                "QueryName": "my.query.id",
                "AnalysisType": "scheduled_query",
                "Query": "select 1",
                "Enabled": False,
                "Schedule": {"RateMinutes": 10, "TimeoutMinutes": 5},
            }
        )
        # missing Enabled
        with self.assertRaises(SchemaError):
            SCHEDULED_QUERY_SCHEMA.validate(
                {
                    "QueryName": "my.query.id",
                    "AnalysisType": "scheduled_query",
                    "Query": "select 1",
                    "Schedule": {"RateMinutes": 10, "TimeoutMinutes": 5},
                }
            )
        # missing Schedule
        with self.assertRaises(SchemaError):
            SCHEDULED_QUERY_SCHEMA.validate(
                {
                    "QueryName": "my.query.id",
                    "AnalysisType": "scheduled_query",
                    "Query": "select 1",
                    "Enabled": False,
                }
            )
        #  unknown field
        with self.assertRaises(SchemaError):
            SCHEDULED_QUERY_SCHEMA.validate(
                {
                    "QueryName": "my.query.id",
                    "AnalysisType": "scheduled_query",
                    "Query": "select 1",
                    "Enabled": False,
                    "Schedule": {"RateMinutes": 10, "TimeoutMinutes": 5},
                    "Unknown field": 1,
                }
            )
        # Lookback and LookbackWindow
        SCHEDULED_QUERY_SCHEMA.validate(
            {
                "QueryName": "my.query.id",
                "AnalysisType": "scheduled_query",
                "Query": "select 1",
                "Enabled": False,
                "Schedule": {"RateMinutes": 10, "TimeoutMinutes": 5},
                "Lookback": True,
                "LookbackWindowSeconds": 60,
            }
        )

    def test_saved_query_validate_schema(self):
        # has required fields
        SAVED_QUERY_SCHEMA.validate(
            {
                "QueryName": "my.query.id",
                "AnalysisType": "saved_query",
                "Query": "select 1",
            }
        )
        # missing QueryName
        with self.assertRaises(SchemaError):
            SAVED_QUERY_SCHEMA.validate(
                {
                    "AnalysisType": "saved_query",
                    "Query": "select 1",
                    "Schedule": {"RateMinutes": 10, "TimeoutMinutes": 5},
                }
            )
        #  schedule query
        with self.assertRaises(SchemaError):
            SAVED_QUERY_SCHEMA.validate(
                {
                    "QueryName": "my.query.id",
                    "AnalysisType": "saved_query",
                    "Query": "select 1",
                    "Enabled": False,
                    "Schedule": {"RateMinutes": 10, "TimeoutMinutes": 5},
                }
            )
            #  unknown field
        with self.assertRaises(SchemaError):
            SAVED_QUERY_SCHEMA.validate(
                {
                    "QueryName": "my.query.id",
                    "AnalysisType": "saved_query",
                    "Query": "select 1",
                    "Enabled": False,
                    "Schedule": {"RateMinutes": 10, "TimeoutMinutes": 5},
                    "Unknown field": 1,
                }
            )

    def test_query_rateminutes(self):
        sample_query = {
            "QueryName": "my.query.id",
            "AnalysisType": "scheduled_query",
            "Query": "select 1",
            "Enabled": False,
        }
        sample_query["Schedule"] = {"RateMinutes": 10, "TimeoutMinutes": 10}
        SCHEDULED_QUERY_SCHEMA.validate(sample_query)
        sample_query["Schedule"] = {"RateMinutes": 10, "TimeoutMinutes": 5}
        SCHEDULED_QUERY_SCHEMA.validate(sample_query)
        with self.assertRaises(SchemaError):
            # timeout must be <= rate
            sample_query["Schedule"] = {"RateMinutes": 5, "TimeoutMinutes": 10}
            SCHEDULED_QUERY_SCHEMA.validate(sample_query)
        with self.assertRaises(SchemaError):
            # not a valid rate type
            sample_query["Schedule"] = {"RateMinutes": "not an int", "TimeoutMinutes": 10}
            SCHEDULED_QUERY_SCHEMA.validate(sample_query)
        with self.assertRaises(SchemaError):
            # not a valid timeout type
            sample_query["Schedule"] = {"RateMinutes": 10, "TimeoutMinutes": "not an int"}
            SCHEDULED_QUERY_SCHEMA.validate(sample_query)
        with self.assertRaises(SchemaError):
            # can't have both cron and rate
            sample_query["Schedule"] = {
                "RateMinutes": 10,
                "TimeoutMinutes": 10,
                "CronExpression": "* * * * *",
            }
            SCHEDULED_QUERY_SCHEMA.validate(sample_query)
        with self.assertRaises(SchemaError):
            # can't have rate <= 1
            sample_query["Schedule"] = {"RateMinutes": 1, "TimeoutMinutes": 1}
            SCHEDULED_QUERY_SCHEMA.validate(sample_query)
        with self.assertRaises(SchemaError):
            # TimeoutMinutes must be set
            sample_query["Schedule"] = {"RateMinutes": 1}
            SCHEDULED_QUERY_SCHEMA.validate(sample_query)

    def test_rba_flag(self):
        RULE_SCHEMA.validate(
            {
                "AnalysisType": "rule",
                "Enabled": False,
                "Filename": "hmm",
                "RuleID": "h",
                "Severity": "Info",
                "LogTypes": ["Custom.OhSnap"],
                "OnlyUseBaseRiskScore": True,
            }
        )
        RULE_SCHEMA.validate(
            {
                "AnalysisType": "scheduled_rule",
                "Enabled": False,
                "Filename": "hmm",
                "RuleID": "h",
                "Severity": "Info",
                "LogTypes": ["AWS.ALB"],
                "OnlyUseBaseRiskScore": False,
            }
        )
        POLICY_SCHEMA.validate(
            {
                "AnalysisType": "policy",
                "Enabled": False,
                "Filename": "hmm",
                "PolicyID": "h",
                "Severity": "Info",
                "ResourceTypes": ["AWS.DynamoDB.Table"],
                "OnlyUseBaseRiskScore": True,
            }
        )

    def test_missing_rba_flag(self):
        RULE_SCHEMA.validate(
            {
                "AnalysisType": "rule",
                "Enabled": False,
                "Filename": "hmm",
                "RuleID": "h",
                "Severity": "Info",
                "LogTypes": ["Custom.OhSnap"],
            }
        )
        RULE_SCHEMA.validate(
            {
                "AnalysisType": "scheduled_rule",
                "Enabled": False,
                "Filename": "hmm",
                "RuleID": "h",
                "Severity": "Info",
                "LogTypes": ["AWS.ALB"],
            }
        )
        POLICY_SCHEMA.validate(
            {
                "AnalysisType": "policy",
                "Enabled": False,
                "Filename": "hmm",
                "PolicyID": "h",
                "Severity": "Info",
                "ResourceTypes": ["AWS.DynamoDB.Table"],
            }
        )

    def test_policy_without_resource_types(self):
        POLICY_SCHEMA.validate(
            {
                "AnalysisType": "policy",
                "Enabled": False,
                "Filename": "hmm",
                "PolicyID": "h",
                "Severity": "Info",
                "ResourceTypes": [],
            }
        )
        POLICY_SCHEMA.validate(
            {
                "AnalysisType": "policy",
                "Enabled": False,
                "Filename": "hmm",
                "PolicyID": "h",
                "Severity": "Info",
            }
        )

    def test_percent_sign_banned(self):
        with self.assertRaises(SchemaError):
            RULE_SCHEMA.validate(
                {
                    "AnalysisType": "scheduled_rule",
                    "Enabled": False,
                    "Filename": "hmm",
                    "RuleID": "%s",
                    "Severity": "Info",
                    "LogTypes": ["AWS.ALB"],
                }
            )
        with self.assertRaises(SchemaError):
            POLICY_SCHEMA.validate(
                {
                    "AnalysisType": "policy",
                    "Enabled": False,
                    "Filename": "hmm",
                    "PolicyID": "%s",
                    "Severity": "Info",
                    "ResourceTypes": ["AWS.DynamoDB.Table"],
                }
            )


# This class was generated in whole or in part by GitHub Copilot
class TestSimpleDetectionSchemas(unittest.TestCase):
    def call_validate(self, detection: Dict[str, Any]) -> Any:
        RULE_SCHEMA.validate(detection)
        return jsonschema.validate(detection, ANALYSIS_CONFIG_SCHEMA)

    def get_test_case(self) -> Dict[str, Any]:
        return {
            "Detection": [],
            "InlineFilters": [],
            "AnalysisType": "rule",
            "Enabled": True,
            "RuleID": "my-test-id",
            "Severity": "Info",
            "LogTypes": ["Custom.Heylo"],
        }

    def test_top_level_keys(self):
        self.call_validate(self.get_test_case())

        with self.assertRaises(SchemaError):
            case = self.get_test_case()
            case["Filename"] = "uh-oh"
            RULE_SCHEMA.validate(case)

    def test_invalid_props(self):
        case = self.get_test_case()
        case["Detection"] = [{"someExtraProperty": "hello!!"}]
        # should pass regular rule schema validation
        RULE_SCHEMA.validate(case)
        # should raise exception for jsonschema validation
        with self.assertRaises(jsonschema.exceptions.ValidationError):
            self.call_validate(case)

    def test_valid_scalar_match_any_type_no_value(self):
        case = self.get_test_case()
        case["Detection"] = [
            {"Key": "event_type", "Condition": "Exists"},
            {"DeepKey": ["details", "new_value"], "Condition": "IsNotNull"},
        ]
        self.call_validate(case)

    def test_valid_scalar_match_boolean_type_value(self):
        case = self.get_test_case()
        case["Detection"] = [
            {"Key": "event_type", "Condition": "DoesNotEqual", "Value": True},
            {"DeepKey": ["details", 1], "Condition": "Equals", "Value": False},
        ]
        self.call_validate(case)

    def test_valid_scalar_match_string_type_value(self):
        case = self.get_test_case()
        case["Detection"] = [
            {"Key": "event_type", "Condition": "StartsWith", "Value": "team_"},
            {"DeepKey": ["details", "new_value"], "Condition": "IDoesNotEndWith", "Value": "_"},
        ]
        self.call_validate(case)

    def test_valid_scalar_match_int_type_value(self):
        case = self.get_test_case()
        case["Detection"] = [
            {"Key": "event_type", "Condition": "IsLessThan", "Value": 20},
            {"DeepKey": [1998, 11, 13], "Condition": "IsGreaterThanOrEqualTo", "Value": -25},
        ]
        self.call_validate(case)

    def test_valid_scalar_match_float_type_value(self):
        case = self.get_test_case()
        case["Detection"] = [
            {"Key": "event_type", "Condition": "IsLessThan", "Value": 20.1},
            {
                "DeepKey": ["details", "new_value"],
                "Condition": "IsGreaterThanOrEqualTo",
                "Value": -25.5,
            },
        ]
        self.call_validate(case)

    def test_valid_string_list_value_match(self):
        case = self.get_test_case()
        case["Detection"] = [
            {
                "Key": "event_type",
                "Condition": "IsNotIn",
                "Values": ["team_privacy_settings_changed", "team_profile_changed"],
            },
            {
                "DeepKey": ["details", "new_value"],
                "Condition": "IsIn",
                "Values": ["public", "package-private"],
            },
        ]
        self.call_validate(case)

    def test_valid_bool_list_value_match(self):
        case = self.get_test_case()
        case["Detection"] = [
            {"Key": "event_type", "Condition": "IsNotIn", "Values": [True, False]},
            {"DeepKey": ["details", "new_value"], "Condition": "IsIn", "Values": [True, False]},
        ]
        self.call_validate(case)

    def test_valid_int_list_value_match(self):
        case = self.get_test_case()
        case["Detection"] = [
            {"Key": "event_type", "Condition": "IsNotIn", "Values": [2, 3, 5, 7]},
            {"DeepKey": ["details", "new_value"], "Condition": "IsIn", "Values": [4, 6, 8, 9]},
        ]
        self.call_validate(case)

    def test_valid_float_list_value_match(self):
        case = self.get_test_case()
        case["Detection"] = [
            {"Key": "event_type", "Condition": "IsNotIn", "Values": [2.2, 3.7, 5.4, 7.9]},
            {
                "DeepKey": ["details", "new_value"],
                "Condition": "IsIn",
                "Values": [4.5, 6.6, 8.1, 9.0],
            },
        ]
        self.call_validate(case)

    def test_valid_multikey_match(self):
        case = self.get_test_case()
        case["Detection"] = [
            {
                "Condition": "DoesNotEqual",
                "Values": [{"Key": "leftKey"}, {"DeepKey": ["details", "new_value"]}],
            }
        ]
        self.call_validate(case)

    def test_valid_all(self):
        case = self.get_test_case()
        case["Detection"] = [
            {
                "All": [
                    {"Key": "event_type", "Condition": "Exists"},
                    {"DeepKey": ["details", "new_value"], "Condition": "IsNotNull"},
                ]
            }
        ]
        self.call_validate(case)

    def test_valid_any(self):
        case = self.get_test_case()
        case["Detection"] = [
            {
                "Any": [
                    {"Key": "event_type", "Condition": "Exists"},
                    {"DeepKey": ["details", "new_value"], "Condition": "IsNotNull"},
                ]
            }
        ]
        self.call_validate(case)

    def test_valid_only_one(self):
        case = self.get_test_case()
        case["Detection"] = [
            {
                "OnlyOne": [
                    {"Key": "event_type", "Condition": "Exists"},
                    {"DeepKey": ["details", "new_value"], "Condition": "IsNotNull"},
                ]
            }
        ]
        self.call_validate(case)

    def test_valid_absolute_match(self):
        case = self.get_test_case()
        case["Detection"] = [{"Condition": "AlwaysTrue"}]
        self.call_validate(case)

    def test_valid_list_comprehension(self):
        case = self.get_test_case()
        case["Detection"] = [
            {
                "Key": "event_type",
                "Condition": "AnyElement",
                "Expressions": [
                    {
                        "DeepKey": ["details", "new_value"],
                        "Condition": "IsIn",
                        "Values": [4.5, 6.6, 8.1, 9.0],
                    },
                    {"Key": "action", "Condition": "Equals", "Value": "team_profile_changed"},
                ],
            }
        ]
        self.call_validate(case)

    def test_valid_nested(self):
        case = self.get_test_case()
        case["Detection"] = [
            {
                "OnlyOne": [
                    {"Key": "event_type", "Condition": "Exists"},
                    {
                        "Any": [
                            {"DeepKey": ["details", "new_value"], "Condition": "IsNotNull"},
                            {
                                "Condition": "DoesNotEqual",
                                "Values": [
                                    {"Key": "leftKey"},
                                    {"DeepKey": ["details", "new_value"]},
                                ],
                            },
                        ]
                    },
                ]
            }
        ]
        self.call_validate(case)
