import unittest

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
