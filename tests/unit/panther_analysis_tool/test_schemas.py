import unittest
from typing import Any, Dict

import jsonschema
from schema import SchemaError

from panther_analysis_tool.schemas import (
    ANALYSIS_CONFIG_SCHEMA,
    CORRELATION_RULE_SCHEMA,
    DATA_MODEL_SCHEMA,
    DERIVED_SCHEMA,
    MOCK_SCHEMA,
    POLICY_SCHEMA,
    RULE_SCHEMA,
    SAVED_QUERY_SCHEMA,
    SCHEDULED_QUERY_SCHEMA,
    SKILL_SCHEMA,
)


class TestPATSchemas(unittest.TestCase):
    def test_mocks_are_str(self):
        MOCK_SCHEMA.validate({"objectName": "hello", "returnValue": "Testing a string"})
        MOCK_SCHEMA.validate({"objectName": "hello", "returnValue": "False"})

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
        # Email Config
        SCHEDULED_QUERY_SCHEMA.validate(
            {
                "QueryName": "my.query.id2",
                "AnalysisType": "scheduled_query",
                "Query": "select 1",
                "Enabled": False,
                "Schedule": {"RateMinutes": 10, "TimeoutMinutes": 5},
                "Lookback": True,
                "LookbackWindowSeconds": 60,
                "EmailConfig": {
                    "Recipients": ["email@example.com"],
                    "SendEmpty": True,
                    "PreferAttachment": False,
                },
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

    def test_created_by(self):
        RULE_SCHEMA.validate(
            {
                "AnalysisType": "rule",
                "Description": "SomeRule",
                "DisplayName": "Some Rule",
                "Enabled": True,
                "Filename": "rule.py",
                "Severity": "Low",
                "LogTypes": ["Panther.Audit"],
                "RuleID": "'Some.Rule1.CreatedBy'",
                "CreatedBy": "eee",
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
                "CreatedBy": "hello",
            }
        )
        CORRELATION_RULE_SCHEMA.validate(
            {
                "AnalysisType": "correlation_rule",
                "DisplayName": "Example Correlation Rule",
                "Enabled": True,
                "RuleID": "My.Correlation.Rule",
                "Severity": "High",
                "CreatedBy": "some@email.com",
                "Detection": [
                    {
                        "Sequence": [
                            {
                                "ID": "First",
                                "RuleID": "Okta.Global.MFA.Disabled",
                                "MinMatchCount": 7,
                            },
                            {
                                "ID": "Second",
                                "RuleID": "Okta.Support.Access",
                                "MinMatchCount": 1,
                            },
                        ],
                        "LookbackWindowMinutes": 15,
                        "Schedule": {
                            "RateMinutes": 5,
                            "TimeoutMinutes": 3,
                        },
                    }
                ],
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
                "CreatedBy": "yes!",
            }
        )
        # test validation works that it must be a string
        with self.assertRaises(SchemaError):
            RULE_SCHEMA.validate(
                {
                    "AnalysisType": "scheduled_rule",
                    "Enabled": False,
                    "Filename": "hmm",
                    "RuleID": "h",
                    "Severity": "Info",
                    "LogTypes": ["AWS.ALB"],
                    "CreatedBy": 123,
                }
            )

    def test_status_field(self):
        RULE_SCHEMA.validate(
            {
                "AnalysisType": "rule",
                "Description": "SomeRule",
                "DisplayName": "Some Rule",
                "Enabled": True,
                "Filename": "rule.py",
                "Severity": "Low",
                "LogTypes": ["Panther.Audit"],
                "RuleID": "'Some.Rule1.CreatedBy'",
                "Status": "Experimental",
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
                "Status": "Experimental",
            }
        )
        CORRELATION_RULE_SCHEMA.validate(
            {
                "AnalysisType": "correlation_rule",
                "DisplayName": "Example Correlation Rule",
                "Enabled": True,
                "RuleID": "My.Correlation.Rule",
                "Severity": "High",
                "Status": "Experimental",
                "Detection": [
                    {
                        "Sequence": [
                            {
                                "ID": "First",
                                "RuleID": "Okta.Global.MFA.Disabled",
                                "MinMatchCount": 7,
                            },
                            {
                                "ID": "Second",
                                "RuleID": "Okta.Support.Access",
                                "MinMatchCount": 1,
                            },
                        ],
                        "LookbackWindowMinutes": 15,
                        "Schedule": {
                            "RateMinutes": 5,
                            "TimeoutMinutes": 3,
                        },
                    }
                ],
            }
        )
        # test validation works that it must be a string
        with self.assertRaises(SchemaError):
            RULE_SCHEMA.validate(
                {
                    "AnalysisType": "scheduled_rule",
                    "Enabled": False,
                    "Filename": "hmm",
                    "RuleID": "h",
                    "Severity": "Info",
                    "LogTypes": ["AWS.ALB"],
                    "Status": 123,
                }
            )

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

    def test_policy_route53_resource_types(self):
        sample_policy = {
            "AnalysisType": "policy",
            "Enabled": False,
            "Filename": "hmm",
            "PolicyID": "h",
            "Severity": "Info",
        }
        POLICY_SCHEMA.validate({**sample_policy, "ResourceTypes": ["AWS.Route53.HostedZone"]})
        POLICY_SCHEMA.validate({**sample_policy, "ResourceTypes": ["AWS.Route53Domains"]})

    def test_correlation_rule_unit_tests(self):
        # works without unit tests
        CORRELATION_RULE_SCHEMA.validate(
            {
                "AnalysisType": "correlation_rule",
                "DisplayName": "Example Correlation Rule",
                "Enabled": True,
                "RuleID": "My.Correlation.Rule",
                "Severity": "High",
                "Detection": [
                    {
                        "Sequence": [
                            {
                                "ID": "First",
                                "RuleID": "Okta.Global.MFA.Disabled",
                                "MinMatchCount": 7,
                            },
                            {
                                "ID": "Second",
                                "RuleID": "Okta.Support.Access",
                                "MinMatchCount": 1,
                            },
                        ],
                        "LookbackWindowMinutes": 15,
                        "Schedule": {
                            "RateMinutes": 5,
                            "TimeoutMinutes": 3,
                        },
                    }
                ],
            }
        )

        # works with unit tests
        CORRELATION_RULE_SCHEMA.validate(
            {
                "AnalysisType": "correlation_rule",
                "DisplayName": "Example Correlation Rule",
                "Enabled": True,
                "RuleID": "My.Correlation.Rule",
                "Severity": "High",
                "Detection": [
                    {
                        "Sequence": [
                            {
                                "ID": "First",
                                "RuleID": "Okta.Global.MFA.Disabled",
                                "MinMatchCount": 7,
                            },
                            {
                                "ID": "Second",
                                "RuleID": "Okta.Support.Access",
                                "MinMatchCount": 1,
                            },
                        ],
                        "LookbackWindowMinutes": 15,
                        "Schedule": {
                            "RateMinutes": 5,
                            "TimeoutMinutes": 3,
                        },
                    }
                ],
                "Tests": [
                    {
                        "Name": "alert because the other fields are absent",
                        "ExpectedResult": True,
                        "RuleOutputs": [
                            {
                                "ID": "First",
                                "Matches": {
                                    "p_actor": {
                                        "jane.smith": [1, 2, 3, 4],
                                    },
                                },
                            },
                            {
                                "ID": "Second",
                                "Matches": {
                                    "p_enrichment.endpoint_mapping.aid.assigned_user": {
                                        "jane.smith": [6],
                                    },
                                },
                            },
                        ],
                    },
                ],
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


class TestSkillSchema(unittest.TestCase):
    def _valid_skill(self) -> Dict[str, Any]:
        return {
            "AnalysisType": "skill",
            "SkillName": "test_skill",
            "Description": "A test skill",
            "Prompt": "Do something useful",
        }

    def test_valid_minimal_skill(self):
        SKILL_SCHEMA.validate(self._valid_skill())

    def test_valid_skill_all_optional_fields(self):
        skill = self._valid_skill()
        skill.update(
            {
                "DisplayName": "Test Skill",
                "ToolMessage": "Processing your request...",
                "Enabled": True,
                "Tags": ["security", "test"],
                "DependsOn": ["other_skill"],
                "RequiredTools": ["panther_ai_alerts_list"],
                "Namespace": "panther_ai",
            }
        )
        SKILL_SCHEMA.validate(skill)

    def test_reference_field_rejected(self):
        skill = self._valid_skill()
        skill["Reference"] = "https://docs.example.com"
        with self.assertRaises(SchemaError):
            SKILL_SCHEMA.validate(skill)

    def test_required_tools_must_be_list_of_strings(self):
        skill = self._valid_skill()
        skill["RequiredTools"] = "not_a_list"
        with self.assertRaises(SchemaError):
            SKILL_SCHEMA.validate(skill)

    def test_invalid_namespace_uppercase(self):
        skill = self._valid_skill()
        skill["Namespace"] = "BadNamespace"
        with self.assertRaises(SchemaError):
            SKILL_SCHEMA.validate(skill)

    def test_missing_skill_name(self):
        skill = self._valid_skill()
        del skill["SkillName"]
        with self.assertRaises(SchemaError):
            SKILL_SCHEMA.validate(skill)

    def test_missing_description(self):
        skill = self._valid_skill()
        del skill["Description"]
        with self.assertRaises(SchemaError):
            SKILL_SCHEMA.validate(skill)

    def test_missing_prompt(self):
        skill = self._valid_skill()
        del skill["Prompt"]
        with self.assertRaises(SchemaError):
            SKILL_SCHEMA.validate(skill)

    def test_invalid_skill_name_uppercase(self):
        skill = self._valid_skill()
        skill["SkillName"] = "BadName"
        with self.assertRaises(SchemaError):
            SKILL_SCHEMA.validate(skill)

    def test_invalid_skill_name_starts_with_number(self):
        skill = self._valid_skill()
        skill["SkillName"] = "1bad_name"
        with self.assertRaises(SchemaError):
            SKILL_SCHEMA.validate(skill)

    def test_extra_keys_rejected(self):
        skill = self._valid_skill()
        skill["UnknownField"] = "should fail"
        with self.assertRaises(SchemaError):
            SKILL_SCHEMA.validate(skill)

    def test_enabled_must_be_bool(self):
        skill = self._valid_skill()
        skill["Enabled"] = "yes"
        with self.assertRaises(SchemaError):
            SKILL_SCHEMA.validate(skill)

    def test_tags_must_be_list_of_strings(self):
        skill = self._valid_skill()
        skill["Tags"] = [123]
        with self.assertRaises(SchemaError):
            SKILL_SCHEMA.validate(skill)

    def test_depends_on_must_be_list_of_strings(self):
        skill = self._valid_skill()
        skill["DependsOn"] = "not_a_list"
        with self.assertRaises(SchemaError):
            SKILL_SCHEMA.validate(skill)
