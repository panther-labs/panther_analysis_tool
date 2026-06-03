from pathlib import Path

import pytest

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


def test_invalid_yaml_is_left_intact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    bad = rules_dir / "broken.yml"
    bad.write_text(INVALID_RULE_YAML, encoding="utf-8")
    original = bad.read_bytes()

    monkeypatch.chdir(tmp_path)
    code, msg = fmt.run()

    assert bad.read_bytes() == original
    assert code == 1
    expected = (
        "fmt failed to parse the following files; they were left unchanged:\n"
        f"  {bad}: while scanning a quoted scalar\n"
        '  in "<file>", line 2, column 9\n'
        "found unexpected end of stream\n"
        '  in "<file>", line 5, column 1'
    )
    assert msg == expected


def test_valid_yaml_is_formatted_and_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    good = rules_dir / "ok.yml"
    good.write_text(VALID_RULE_YAML, encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    code, msg = fmt.run()

    assert code == 0
    assert msg == ""
    assert "AnalysisType: rule" in good.read_text(encoding="utf-8")


VALID_SKILL_YAML = """AnalysisType: skill
SkillName: fmt_test_skill
Description: A test skill
Prompt: |
  Do something useful.
"""


def test_valid_skill_yaml_is_formatted_and_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    skills_dir = tmp_path / "skills"
    skills_dir.mkdir()
    good = skills_dir / "ok.yml"
    good.write_text(VALID_SKILL_YAML, encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    code, msg = fmt.run()

    assert code == 0
    assert msg == ""
    assert "AnalysisType: skill" in good.read_text(encoding="utf-8")


def test_invalid_skill_yaml_is_left_intact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    skills_dir = tmp_path / "skills"
    skills_dir.mkdir()
    bad = skills_dir / "broken.yml"
    # Unclosed quoted scalar — same shape as the rule case, applied to a skill.
    bad.write_text(
        'AnalysisType: skill\nSkillName: "broken\nDescription: x\nPrompt: y\n',
        encoding="utf-8",
    )
    original = bad.read_bytes()

    monkeypatch.chdir(tmp_path)
    code, msg = fmt.run()

    assert bad.read_bytes() == original
    assert code == 1
    assert "broken.yml" in msg
