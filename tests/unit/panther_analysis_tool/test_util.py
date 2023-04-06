import unittest
import responses
from unittest import mock

import panther_analysis_tool.constants
from panther_analysis_tool import util as pat_utils


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
        responses.get('https://pypi.org/pypi/panther_analysis_tool/json',
                      json=sample_response, status=200)

        version = pat_utils.get_latest_version()
        self.assertTrue(len(responses.calls) == 1)
        self.assertTrue(responses.calls[0].request.url == 'https://pypi.org/pypi/panther_analysis_tool/json')
        self.assertEqual(version, "0.1.1")

    @responses.activate
    def test_get_version_empty(self) -> None:
        responses.get('https://pypi.org/pypi/panther_analysis_tool/json',
                      json={"info": {}}, status=200)

        version = pat_utils.get_latest_version()
        self.assertTrue(len(responses.calls) == 1)
        self.assertTrue(responses.calls[0].request.url == 'https://pypi.org/pypi/panther_analysis_tool/json')
        self.assertEqual(version, pat_utils.UNKNOWN_VERSION)

    @responses.activate
    def test_get_version_not_success(self) -> None:
        sample_response = {
            "info": {
                "version": "0.1.1",
            },
        }
        responses.get('https://pypi.org/pypi/panther_analysis_tool/json',
                      json=sample_response, status=400)

        version = pat_utils.get_latest_version()
        self.assertTrue(len(responses.calls) == 1)
        self.assertTrue(responses.calls[0].request.url == 'https://pypi.org/pypi/panther_analysis_tool/json')
        self.assertEqual(version, pat_utils.UNKNOWN_VERSION)


    @responses.activate
    def test_get_version_exception(self) -> None:
        responses.get('https://pypi.org/pypi/panther_analysis_tool/json', body=Exception("uh-ohs"))
        version = pat_utils.get_latest_version()
        self.assertEqual(version, pat_utils.UNKNOWN_VERSION)

    @mock.patch("panther_analysis_tool.util.VERSION_STRING", "0.1.1")
    @mock.patch("panther_analysis_tool.util.get_latest_version")
    def test_is_latest(self, mock_get_version) -> None:
        mock_get_version.return_value = "0.1.1"
        self.assertTrue(pat_utils.is_latest())

    @mock.patch("panther_analysis_tool.util.VERSION_STRING", "0.0.1")
    @mock.patch("panther_analysis_tool.util.get_latest_version")
    def test_is_not_latest(self, mock_get_version) -> None:
        mock_get_version.return_value = "0.1.1"
        self.assertFalse(pat_utils.is_latest())

    @mock.patch("panther_analysis_tool.util.VERSION_STRING", "0.1.1")
    @mock.patch("panther_analysis_tool.util.get_latest_version")
    def test_latest_unknown_version(self, mock_get_version) -> None:
        mock_get_version.return_value = pat_utils.UNKNOWN_VERSION
        self.assertTrue(pat_utils.is_latest())

    @mock.patch("panther_analysis_tool.util.get_latest_version")
    def test_version_does_not_parse(self, mock_get_version) -> None:
        mock_get_version.return_value = "invalid-version"
        self.assertTrue(pat_utils.is_latest())
