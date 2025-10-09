import os
import pathlib
import tempfile
import unittest
from unittest import mock

import yaml

from panther_analysis_tool.command import fetch
from panther_analysis_tool.constants import CACHE_DIR, PANTHER_ANALYSIS_SQLITE_FILE
from panther_analysis_tool.core import analysis_cache

_FAKE_PY = """
def rule(event):
    return True
"""

_FAKE_RULE_1_V1 = yaml.dump({
    "AnalysisType": "rule",
    "Filename": "fake_rule_1.py",
    "RuleID": "fake.rule.1",
    "Enabled": True,
    "Description": "Fake rule 1 v1",
})

_FAKE_RULE_2_V1 = yaml.dump({
    "AnalysisType": "rule",
    "Filename": "fake_rule_2.py",
    "RuleID": "fake.rule.2",
    "Enabled": True,
    "Description": "Fake rule 2 v1",
})

_FAKE_RULE_2_V2 = yaml.dump({
    "AnalysisType": "rule",
    "Filename": "fake_rule_2.py",
    "RuleID": "fake.rule.2",
    "Enabled": True,
    "Description": "Fake rule 2 v2",
})

_FAKE_VERSIONS_FILE = yaml.dump({
    "versions": {
        "fake.rule.1": {
            "version": 1,
            "type": "rule",
            "sha256": "fake_sha256_1",
            "history": {
                "1": {
                    "version": 1,
                    "commit_hash": "fake_commit_hash_1",
                    "yaml_file_path": "fake_rule_1.yaml",
                    "py_file_path": "fake_rule_1.py",
                },
            },
        },
        "fake.rule.2": {
            "version": 2,
            "type": "rule",
            "sha256": "fake_sha256_2",
            "history": {
                "1": {
                    "version": 1,
                    "commit_hash": "fake_commit_hash_2_1",
                    "yaml_file_path": "fake_rule_2.yaml",
                    "py_file_path": "fake_rule_2.py",
                },
                "2": {
                    "version": 2,
                    "commit_hash": "fake_commit_hash_2_2",
                    "yaml_file_path": "fake_rule_2.yaml",
                    "py_file_path": "fake_rule_2.py",
                },
            }
        }
    },
})


class TestFetchCommand(unittest.TestCase):
    def set_up_cache(self, temp_dir: str) -> None:
        os.chdir(temp_dir)
        pa_clone_path = pathlib.Path(CACHE_DIR) / "panther-analysis"
        os.makedirs(pa_clone_path, exist_ok=True)
        
        sqlite_file = pathlib.Path(CACHE_DIR) / PANTHER_ANALYSIS_SQLITE_FILE
        sqlite_file.touch()

        # fake cloning panther-analysis repository
        self.create_file_with_text(pa_clone_path / "rules" / "fake_rule_1.yaml", _FAKE_RULE_1_V1)
        self.create_file_with_text(pa_clone_path / "rules" / "fake_rule_1.py", _FAKE_PY)
        self.create_file_with_text(pa_clone_path / "rules" / "fake_rule_2.yaml", _FAKE_RULE_2_V2)
        self.create_file_with_text(pa_clone_path / "rules" / "fake_rule_2.py", _FAKE_PY)

        self.create_file_with_text(pa_clone_path / ".versions.yml", _FAKE_VERSIONS_FILE)

        # fake user's analysis items
        os.makedirs(pathlib.Path("rules"), exist_ok=True)
        self.create_file_with_text(pathlib.Path("rules") / "fake_rule_2.yaml", _FAKE_RULE_2_V1)
        self.create_file_with_text(pathlib.Path("rules") / "fake_rule_2.py", _FAKE_PY)

        for root, dirs, files in os.walk("."):
            for file in files:
                print(f"{root}/{file}")

    def create_file_with_text(self, path: pathlib.Path, text: str) -> None:
        path.touch()
        path.write_text(text)

        

    def test_populate_works_with_latest_versions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self.set_up_cache(temp_dir)
            fetch.populate_sqlite()
            cache = analysis_cache.AnalysisCache()

            latest_spec = cache.get_latest_spec("fake.rule.1")
            assert latest_spec is not None
            self.assertEqual(latest_spec.spec.decode("utf-8"), _FAKE_RULE_1_V1)
            self.assertEqual(latest_spec.version, 1)
            self.assertEqual(latest_spec.id_field, "RuleID")
            self.assertEqual(latest_spec.id_value, "fake.rule.1")

            py_file = cache.get_file_for_spec(latest_spec.id or -1)
            assert py_file is not None
            self.assertEqual(py_file.decode("utf-8"), _FAKE_PY)

            latest_spec = cache.get_latest_spec("fake.rule.2")
            assert latest_spec is not None
            self.assertEqual(latest_spec.spec.decode("utf-8"), _FAKE_RULE_2_V2)
            self.assertEqual(latest_spec.version, 2)
            self.assertEqual(latest_spec.id_field, "RuleID")
            self.assertEqual(latest_spec.id_value, "fake.rule.2")

            py_file = cache.get_file_for_spec(latest_spec.id or -1)
            assert py_file is not None
            self.assertEqual(py_file.decode("utf-8"), _FAKE_PY)

    @mock.patch("panther_analysis_tool.command.fetch.git_helpers.get_panther_analysis_file_contents")
    def test_populate_works_when_user_has_old_version(self, mock_get_panther_analysis_file_contents: mock.MagicMock) -> None:
        mock_get_panther_analysis_file_contents.side_effect = [_FAKE_RULE_2_V1, _FAKE_PY]
        with tempfile.TemporaryDirectory() as temp_dir:
            self.set_up_cache(temp_dir)
            fetch.populate_sqlite()
            cache = analysis_cache.AnalysisCache()

            latest_spec = cache.get_latest_spec("fake.rule.2")
            assert latest_spec is not None
            self.assertEqual(latest_spec.spec.decode("utf-8"), _FAKE_RULE_2_V2)
            self.assertEqual(latest_spec.version, 2)
            self.assertEqual(latest_spec.id_field, "RuleID")
            self.assertEqual(latest_spec.id_value, "fake.rule.2")

            py_file = cache.get_file_for_spec(latest_spec.id or -1)
            assert py_file is not None
            self.assertEqual(py_file.decode("utf-8"), _FAKE_PY)

            old_spec = cache.get_spec_for_version("fake.rule.2", 1)
            assert old_spec is not None
            self.assertEqual(old_spec.spec.decode("utf-8"), _FAKE_RULE_2_V1)
            self.assertEqual(old_spec.version, 1)
            self.assertEqual(old_spec.id_field, "RuleID")
            self.assertEqual(old_spec.id_value, "fake.rule.2")

            py_file = cache.get_file_for_spec(old_spec.id or -1)
            assert py_file is not None
            self.assertEqual(py_file.decode("utf-8"), _FAKE_PY)
