from panther_analysis_tool import main as pat
from panther_analysis_tool.core import parse
import os
from unittest import TestCase


FIXTURES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../", "fixtures"))
DETECTIONS_FIXTURES_PATH = os.path.join(FIXTURES_PATH, "detections")


class TestParser(TestCase):
    def test_parse_filters(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --filter AnalysisType=policy,global Severity=Critical Enabled=true".split()
        )
        args.filter, args.filter_inverted = parse.parse_filter(args.filter)
        self.assertTrue("AnalysisType" in args.filter.keys())
        self.assertTrue("policy" in args.filter["AnalysisType"])
        self.assertTrue("global" in args.filter["AnalysisType"])
        self.assertTrue("Severity" in args.filter.keys())
        self.assertTrue("Critical" in args.filter["Severity"])
        self.assertTrue("Enabled" in args.filter.keys())
        self.assertTrue(True in args.filter["Enabled"])