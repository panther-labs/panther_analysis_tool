import os
import tempfile
import unittest
from pathlib import Path

from panther_analysis_tool.command import fmt


VALID_RULE_YAML = """AnalysisType: rule
RuleID: Test.Rule
LogTypes:
  - AWS.CloudTrail
Severity: Info
Enabled: true
Description: a test rule
Filename: rule.py
"""

# An unclosed quote produces a YAML scanner error.
INVALID_RULE_YAML = """AnalysisType: rule
RuleID: "Broken.Rule
LogTypes:
  - AWS.CloudTrail
"""


class TestFmt(unittest.TestCase):
    def _run_fmt_in(self, dirpath: str) -> tuple[int, str]:
        cwd = os.getcwd()
        os.chdir(dirpath)
        try:
            return fmt.run()
        finally:
            os.chdir(cwd)

    def test_invalid_yaml_is_left_intact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = Path(tmp) / "rules"
            rules_dir.mkdir()
            bad = rules_dir / "broken.yml"
            bad.write_text(INVALID_RULE_YAML, encoding="utf-8")
            original = bad.read_bytes()

            code, msg = self._run_fmt_in(tmp)

            self.assertEqual(bad.read_bytes(), original)
            self.assertNotEqual(code, 0)
            self.assertIn("broken.yml", msg)

    def test_valid_yaml_is_formatted_and_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = Path(tmp) / "rules"
            rules_dir.mkdir()
            good = rules_dir / "ok.yml"
            good.write_text(VALID_RULE_YAML, encoding="utf-8")

            code, msg = self._run_fmt_in(tmp)

            self.assertEqual(code, 0)
            self.assertEqual(msg, "")
            self.assertIn("AnalysisType: rule", good.read_text(encoding="utf-8"))
