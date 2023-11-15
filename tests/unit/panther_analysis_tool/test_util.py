import unittest
from unittest import mock

import responses

import panther_analysis_tool.constants
from panther_analysis_tool import util as pat_utils
from panther_analysis_tool.util import convert_unicode


class TestToList(unittest.TestCase):
    def test_single_becomes_list(self):
        tests = [
            [1, [1]],
            ["fe", ["fe"]],
            [{"hi": 6}, [{"hi": 6}]],
            [{"hi", "bye"}, [{"hi", "bye"}]],
            [("tu", "ple"), [("tu", "ple")]],
        ]

        for test in tests:
            inp, exp = test
            res = pat_utils.to_list(inp)
            self.assertEqual(exp, res)

    def test_list_stays_list(self):
        tests = [
            [[1], [1]],
            [["fe"], ["fe"]],
            [[{"hi": 6}], [{"hi": 6}]],
            [[1, "hi"], [1, "hi"]],
            [[{"hi", "bye"}], [{"hi", "bye"}]],
            [[("tu", "ple")], [("tu", "ple")]],
        ]

        for test in tests:
            inp, exp = test
            res = pat_utils.to_list(inp)
            self.assertEqual(exp, res)


class Version(unittest.TestCase):
    @responses.activate
    def test_get_version_success(self) -> None:
        sample_response = {
            "info": {
                "version": "0.1.1",
            },
        }
        responses.get(
            "https://pypi.org/pypi/panther_analysis_tool/json", json=sample_response, status=200
        )

        version = pat_utils.get_latest_version()
        self.assertTrue(len(responses.calls) == 1)
        self.assertTrue(
            responses.calls[0].request.url == "https://pypi.org/pypi/panther_analysis_tool/json"
        )
        self.assertEqual(version, "0.1.1")

    @responses.activate
    def test_get_version_empty(self) -> None:
        responses.get(
            "https://pypi.org/pypi/panther_analysis_tool/json", json={"info": {}}, status=200
        )

        version = pat_utils.get_latest_version()
        self.assertTrue(len(responses.calls) == 1)
        self.assertTrue(
            responses.calls[0].request.url == "https://pypi.org/pypi/panther_analysis_tool/json"
        )
        self.assertEqual(version, pat_utils.UNKNOWN_VERSION)

    @responses.activate
    def test_get_version_not_success(self) -> None:
        sample_response = {
            "info": {
                "version": "0.1.1",
            },
        }
        responses.get(
            "https://pypi.org/pypi/panther_analysis_tool/json", json=sample_response, status=400
        )

        version = pat_utils.get_latest_version()
        self.assertTrue(len(responses.calls) == 1)
        self.assertTrue(
            responses.calls[0].request.url == "https://pypi.org/pypi/panther_analysis_tool/json"
        )
        self.assertEqual(version, pat_utils.UNKNOWN_VERSION)

    @responses.activate
    def test_get_version_exception(self) -> None:
        responses.get("https://pypi.org/pypi/panther_analysis_tool/json", body=Exception("uh-ohs"))
        version = pat_utils.get_latest_version()
        self.assertEqual(version, pat_utils.UNKNOWN_VERSION)

    @mock.patch("panther_analysis_tool.util.VERSION_STRING", "0.1.1")
    def test_is_latest(
        self,
    ) -> None:
        self.assertTrue(pat_utils.is_latest("0.1.1"))

    @mock.patch("panther_analysis_tool.util.VERSION_STRING", "0.1.1")
    def test_is_not_latest(self) -> None:
        self.assertFalse(pat_utils.is_latest("0.2.0"))

    @mock.patch("panther_analysis_tool.util.VERSION_STRING", "0.1.1")
    def test_latest_unknown_version(self) -> None:
        self.assertTrue(pat_utils.is_latest(pat_utils.UNKNOWN_VERSION))

    def test_version_does_not_parse(self) -> None:
        self.assertTrue(pat_utils.is_latest("invalid-version"))


class TestConvertUnicode(unittest.TestCase):
    def test_typical_error_response(self):
        error_str = """
        {'statusCode': 400,
         'headers': {},
          'multiValueHeaders': {},
           'body': '{"issues":[{
           "path":"ipinfo_asn.yml",
           "errorMessage":"failed to save lut \\\\"too_many-minutes\\\\": alarm period minutes must be \\\\u003c= 1440"
           }]}'}
        """
        expected_str = """
        {'statusCode': 400,
         'headers': {},
          'multiValueHeaders': {},
           'body': '{"issues":[{
           "path":"ipinfo_asn.yml",
           "errorMessage":"failed to save lut \\\\"too_many-minutes\\\\": alarm period minutes must be <= 1440"
           }]}'}
        """
        self.assertEqual(convert_unicode(error_str), expected_str)


class TestAnalysisTypePredicates(unittest.TestCase):
    def test_is_simple_detection(self):
        test_cases = [
            {
                "analysis_type": {"AnalysisType": "rule", "Detection": "something"},
                "expected": True,
            },
            {
                "analysis_type": {"AnalysisType": "rule", "Filename": "foo.py"},
                "expected": False,
            },
            {
                "analysis_type": {"AnalysisType": "correlation_rule", "Detection": "hurgledurgle"},
                "expected": False,
            },
            {
                "analysis_type": {"AnalysisType": "policy", "Filename": "foo.py"},
                "expected": False,
            },
        ]

        for case in test_cases:
            res = pat_utils.is_simple_detection(case["analysis_type"])
            self.assertEqual(case["expected"], res)

    def test_is_correlation_rule(self):
        test_cases = [
            {
                "analysis_type": {"AnalysisType": "correlation_rule", "Detection": "something"},
                "expected": True,
            },
            {
                "analysis_type": {"AnalysisType": "rule", "Filename": "foo.py"},
                "expected": False,
            },
            {
                "analysis_type": {"AnalysisType": "policy", "Filename": "foo.py"},
                "expected": False,
            },
        ]

        for case in test_cases:
            res = pat_utils.is_correlation_rule(case["analysis_type"])
            self.assertEqual(case["expected"], res)

    def test_is_policy(self):
        test_cases = [
            {
                "analysis_type": {"AnalysisType": "policy", "Filename": "something.py"},
                "expected": True,
            },
            {
                "analysis_type": {"AnalysisType": "rule", "Filename": "foo.py"},
                "expected": False,
            },
            {
                "analysis_type": {"AnalysisType": "correlation_rule", "Filename": "foo.py"},
                "expected": False,
            },
        ]

        for case in test_cases:
            res = pat_utils.is_policy(case["analysis_type"])
            self.assertEqual(case["expected"], res)
