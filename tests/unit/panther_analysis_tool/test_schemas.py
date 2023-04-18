import unittest

from schema import SchemaError

from panther_analysis_tool.schemas import (
    DATA_MODEL_SCHEMA,
    POLICY_SCHEMA,
    RULE_SCHEMA,
    LOG_TYPE_REGEX,
    MOCK_SCHEMA,
    SCHEDULED_QUERY_SCHEMA
)


class TestPATSchemas(unittest.TestCase):
    def test_logtypes_regex_amazon_eks(self):
        LOG_TYPE_REGEX.validate("Amazon.EKS.Audit")
        LOG_TYPE_REGEX.validate("Amazon.EKS.Authenticator")

        with self.assertRaises(SchemaError):
            LOG_TYPE_REGEX.validate("Amazon.EKS.Foo")

    def test_mocks_are_str(self):
        MOCK_SCHEMA.validate({"objectName": "hello", "returnValue": "Testing a string"})
        MOCK_SCHEMA.validate({"objectName": "hello", "returnValue": "False"})

        with self.assertRaises(SchemaError):
            LOG_TYPE_REGEX.validate({"objectName": "hello", "returnValue": ["Testing a non-string"]})

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
            sample_query["Schedule"] = {"RateMinutes": 10, "TimeoutMinutes": 10, "CronExpression": "* * * * *"}
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
        RULE_SCHEMA.validate({
            "AnalysisType": "rule", "Enabled": False, "Filename": "hmm", "RuleID": "h", "Severity": "Info",
            "LogTypes": ["Custom.OhSnap"], "OnlyUseBaseRiskScore": True
        })
        RULE_SCHEMA.validate({
            "AnalysisType": "scheduled_rule", "Enabled": False, "Filename": "hmm", "RuleID": "h", "Severity": "Info",
            "LogTypes": ["AWS.ALB"], "OnlyUseBaseRiskScore": False
        })
        POLICY_SCHEMA.validate({
            "AnalysisType": "policy", "Enabled": False, "Filename": "hmm", "PolicyID": "h", "Severity": "Info",
            "ResourceTypes": ["AWS.DynamoDB.Table"], "OnlyUseBaseRiskScore": True
        })

    def test_missing_rba_flag(self):
        RULE_SCHEMA.validate({
            "AnalysisType": "rule", "Enabled": False, "Filename": "hmm", "RuleID": "h", "Severity": "Info",
            "LogTypes": ["Custom.OhSnap"]
        })
        RULE_SCHEMA.validate({
            "AnalysisType": "scheduled_rule", "Enabled": False, "Filename": "hmm", "RuleID": "h", "Severity": "Info",
            "LogTypes": ["AWS.ALB"]
        })
        POLICY_SCHEMA.validate({
            "AnalysisType": "policy", "Enabled": False, "Filename": "hmm", "PolicyID": "h", "Severity": "Info",
            "ResourceTypes": ["AWS.DynamoDB.Table"]
        })
