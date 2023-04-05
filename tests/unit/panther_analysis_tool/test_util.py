import unittest
import responses

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
    def test_version_success(self) -> None:
        sample_response = {
            "info": {
                "version": "0.1.1",
            },
        }
        responses.add(responses.GET, 'https://pypi.org/pypi/panther_analysis_tool/json',
                      json=sample_response, status=200)

        latest = pat_utils.is_latest()
        self.assertTrue(len(responses.calls) == 1)
        self.assertTrue(responses.calls[0].request.url == 'https://pypi.org/pypi/panther_analysis_tool/json')
        self.assertTrue(latest)

    @responses.activate
    def test_version_non_200(self) -> None:
        responses.get('https://pypi.org/pypi/panther_analysis_tool/json',
                      json={"doesn't": "matter"}, status=400)
        self.assertTrue(pat_utils.is_latest())

    @responses.activate
    def test_version_does_not_parse(self) -> None:
        sample_response = {
            "info": {
                "version": "not_a_valid_version",
            },
        }
        responses.get('https://pypi.org/pypi/panther_analysis_tool/json',
                      json=sample_response, status=200)
        self.assertTrue(pat_utils.is_latest())

    @responses.activate
    def test_connection_exception(self) -> None:
        responses.get('https://pypi.org/pypi/panther_analysis_tool/json', body=Exception("uh-ohs"))
        self.assertTrue(pat_utils.is_latest())
