"""Audit tests for skill YAML fixtures.

We previously shipped a fixture with a duplicate SkillName, which caused
classify_analysis to flag one spec as invalid. This file guards against that
class of bug by asserting global uniqueness across every skill fixture in
tests/fixtures/.
"""

import os
import unittest
from glob import glob

import yaml

FIXTURES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../..", "fixtures"))


def _load_skill_fixtures() -> list[tuple[str, dict]]:
    paths: list[str] = []
    for pattern in ("**/skills/*.yml", "**/skills/*.yaml"):
        paths.extend(glob(os.path.join(FIXTURES_PATH, pattern), recursive=True))

    skills: list[tuple[str, dict]] = []
    for path in paths:
        with open(path, encoding="utf-8") as f:
            spec = yaml.safe_load(f)
        if isinstance(spec, dict) and spec.get("AnalysisType") == "skill":
            skills.append((path, spec))
    return skills


class TestSkillFixtures(unittest.TestCase):
    def test_skill_fixtures_have_unique_skill_names(self) -> None:
        skills = _load_skill_fixtures()
        # Sanity check: we expect to find at least the two checked-in fixtures.
        self.assertGreaterEqual(len(skills), 2, msg="expected skill fixtures to exist")

        seen: dict[str, str] = {}
        duplicates: list[str] = []
        for path, spec in skills:
            name = spec.get("SkillName")
            self.assertIsNotNone(name, msg=f"{path} is missing SkillName")
            if name in seen:
                duplicates.append(f"{name}: {seen[name]} vs {path}")
            else:
                seen[name] = path

        self.assertEqual(
            duplicates,
            [],
            msg="duplicate SkillName values across fixtures will cause "
            "AnalysisIDConflictException when both are loaded together",
        )
