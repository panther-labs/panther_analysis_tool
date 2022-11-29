import unittest

from schema import SchemaError

from panther_analysis_tool.schemas import LOG_TYPE_REGEX


class TestPATSchemas(unittest.TestCase):
    def test_logtypes_regex_amazon_eks(self):
        LOG_TYPE_REGEX.validate("Amazon.EKS.Audit")
        LOG_TYPE_REGEX.validate("Amazon.EKS.Authenticator")

        with self.assertRaises(SchemaError):
            LOG_TYPE_REGEX.validate("Amazon.EKS.Foo")
