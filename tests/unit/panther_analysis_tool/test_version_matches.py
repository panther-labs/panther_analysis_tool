import unittest
from pathlib import Path

import panther_analysis_tool


class Version(unittest.TestCase):
    def test_version_matches(self) -> None:
        root = Path(__file__).parent.parent.parent.parent
        v1 = (root / "VERSION").read_text().strip()
        v2 = panther_analysis_tool.constants.VERSION_STRING

        self.assertEqual(v1, v2)
