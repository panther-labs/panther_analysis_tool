import os
import pathlib
import tempfile
import unittest

from ruamel import yaml

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.command import enable
from panther_analysis_tool.constants import (
    CACHE_DIR,
    PANTHER_ANALYSIS_SQLITE_FILE,
    AnalysisTypes,
)
from panther_analysis_tool.core import analysis_cache

_FAKE_PY = """
def rule(event):
    return True
"""

_FAKE_RULE_1_V1 = yaml.dump(
    {
        "AnalysisType": "rule",
        "Filename": "fake_rule_1.py",
        "RuleID": "fake.rule.1",
        "Enabled": True,
        "Description": "Fake rule 1 v1",
    }
)

_FAKE_RULE_2_V1 = yaml.dump(
    {
        "AnalysisType": "rule",
        "Filename": "fake_rule_2.py",
        "RuleID": "fake.rule.2",
        "Enabled": True,
        "Description": "Fake rule 2 v1",
    }
)

_FAKE_RULE_2_V2 = yaml.dump(
    {
        "AnalysisType": "rule",
        "Filename": "fake_rule_2.py",
        "RuleID": "fake.rule.2",
        "Enabled": True,
        "Description": "Fake rule 2 v2",
    }
)

_FAKE_POLICY_1_V1 = yaml.dump(
    {
        "AnalysisType": "policy",
        "PolicyID": "fake.policy.1",
        "Enabled": True,
        "Description": "Fake policy 1 v1",
        "Filename": "fake_policy_1.py",
    }
)

_FAKE_VERSIONS_FILE = yaml.dump(
    {
        "versions": {
            "fake.rule.1": {
                "version": 1,
                "type": "rule",
                "sha256": "fake_sha256_1",
                "history": {
                    "1": {
                        "version": 1,
                        "commit_hash": "fake_commit_hash_1",
                        "yaml_file_path": "rules/fake_rule_1.yaml",
                        "py_file_path": "rules/fake_rule_1.py",
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
                        "yaml_file_path": "rules/fake_rule_2.yaml",
                        "py_file_path": "rules/fake_rule_2.py",
                    },
                    "2": {
                        "version": 2,
                        "commit_hash": "fake_commit_hash_2_2",
                        "yaml_file_path": "rules/fake_rule_2.yaml",
                        "py_file_path": "rules/fake_rule_2.py",
                    },
                },
            },
            "fake.policy.1": {
                "version": 1,
                "type": "policy",
                "sha256": "fake_sha256_policy_1",
                "history": {
                    "1": {
                        "version": 1,
                        "commit_hash": "fake_commit_hash_policy_1",
                        "yaml_file_path": "policies/fake_policy_1.yaml",
                        "py_file_path": "policies/fake_policy_1.py",
                    },
                },
            },
        },
    }
)


class TestEnable(unittest.TestCase):
    def set_up_cache(self, temp_dir: str) -> analysis_cache.AnalysisCache:
        os.chdir(temp_dir)
        os.makedirs(CACHE_DIR, exist_ok=True)

        sqlite_file = pathlib.Path(CACHE_DIR) / PANTHER_ANALYSIS_SQLITE_FILE
        sqlite_file.touch()

        pa_clone_path = pathlib.Path(CACHE_DIR) / "panther-analysis"
        os.makedirs(pa_clone_path, exist_ok=True)

        versions_file = pa_clone_path / ".versions.yml"
        versions_file.write_text(_FAKE_VERSIONS_FILE)

        cache = analysis_cache.AnalysisCache()
        cache.create_tables()
        cache.insert_analysis_spec(
            analysis_cache.AnalysisSpec(
                id=None,
                spec=bytes(_FAKE_RULE_1_V1, "utf-8"),
                version=1,
                id_field="RuleID",
                id_value="fake.rule.1",
            ),
            bytes(_FAKE_PY, "utf-8"),
        )
        cache.insert_analysis_spec(
            analysis_cache.AnalysisSpec(
                id=None,
                spec=bytes(_FAKE_RULE_2_V1, "utf-8"),
                version=1,
                id_field="RuleID",
                id_value="fake.rule.2",
            ),
            bytes(_FAKE_PY, "utf-8"),
        )
        cache.insert_analysis_spec(
            analysis_cache.AnalysisSpec(
                id=None,
                spec=bytes(_FAKE_RULE_2_V2, "utf-8"),
                version=2,
                id_field="RuleID",
                id_value="fake.rule.2",
            ),
            bytes(_FAKE_PY, "utf-8"),
        )
        cache.insert_analysis_spec(
            analysis_cache.AnalysisSpec(
                id=None,
                spec=bytes(_FAKE_POLICY_1_V1, "utf-8"),
                version=1,
                id_field="PolicyID",
                id_value="fake.policy.1",
            ),
            bytes(_FAKE_PY, "utf-8"),
        )
        return cache

    def test_set_enabled_field(self) -> None:
        for analysis_type in [
            AnalysisTypes.RULE,
            AnalysisTypes.SCHEDULED_RULE,
            AnalysisTypes.CORRELATION_RULE,
            AnalysisTypes.POLICY,
            AnalysisTypes.DATA_MODEL,
            AnalysisTypes.LOOKUP_TABLE,
            AnalysisTypes.SAVED_QUERY,
            AnalysisTypes.SCHEDULED_QUERY,
        ]:
            spec = {
                "AnalysisType": analysis_type,
            }
            enable.set_enabled_field(spec)
            self.assertIn("Enabled", spec)
            self.assertEqual(spec["Enabled"], True)

    def test_set_enabled_field_for_other_types(self) -> None:
        for analysis_type in [
            AnalysisTypes.PACK,
            AnalysisTypes.GLOBAL,
        ]:
            spec = {
                "AnalysisType": analysis_type,
            }
            enable.set_enabled_field(spec)
            self.assertNotIn("Enabled", spec)

    def test_get_analysis_items_no_cache(self) -> None:
        with self.assertRaises(analysis_cache.NoCacheException):
            enable.get_analysis_items(analysis_id="fake.rule.1", filter_args=[])

    def test_get_analysis_items_bad_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self.set_up_cache(temp_dir)
            items = enable.get_analysis_items(analysis_id="bad_id", filter_args=[])
            self.assertEqual(items, [])

    def test_get_analysis_items_no_filters_and_no_id(self) -> None:
        yaml = analysis_utils.get_yaml_loader(roundtrip=True)
        with tempfile.TemporaryDirectory() as temp_dir:
            self.set_up_cache(temp_dir)
            items = enable.get_analysis_items(analysis_id=None, filter_args=[])
            self.assertEqual(len(items), 3)
            self.assertEqual(
                items,
                [
                    enable.AnalysisItem(
                        analysis_spec=yaml.load(_FAKE_POLICY_1_V1),
                        yaml_file_path="policies/fake_policy_1.yaml",
                        python_file_path="policies/fake_policy_1.py",
                        python_file_bytes=bytes(_FAKE_PY, "utf-8"),
                    ),
                    enable.AnalysisItem(
                        analysis_spec=yaml.load(_FAKE_RULE_1_V1),
                        yaml_file_path="rules/fake_rule_1.yaml",
                        python_file_path="rules/fake_rule_1.py",
                        python_file_bytes=bytes(_FAKE_PY, "utf-8"),
                    ),
                    enable.AnalysisItem(
                        analysis_spec=yaml.load(_FAKE_RULE_2_V2),
                        yaml_file_path="rules/fake_rule_2.yaml",
                        python_file_path="rules/fake_rule_2.py",
                        python_file_bytes=bytes(_FAKE_PY, "utf-8"),
                    ),
                ],
            )

    def test_get_analysis_items_filters_and_no_id(self) -> None:
        yaml = analysis_utils.get_yaml_loader(roundtrip=True)
        with tempfile.TemporaryDirectory() as temp_dir:
            self.set_up_cache(temp_dir)
            items = enable.get_analysis_items(analysis_id=None, filter_args=["AnalysisType=rule"])
            self.assertEqual(len(items), 2)
            self.assertEqual(
                items,
                [
                    enable.AnalysisItem(
                        analysis_spec=yaml.load(_FAKE_RULE_1_V1),
                        yaml_file_path="rules/fake_rule_1.yaml",
                        python_file_path="rules/fake_rule_1.py",
                        python_file_bytes=bytes(_FAKE_PY, "utf-8"),
                    ),
                    enable.AnalysisItem(
                        analysis_spec=yaml.load(_FAKE_RULE_2_V2),
                        yaml_file_path="rules/fake_rule_2.yaml",
                        python_file_path="rules/fake_rule_2.py",
                        python_file_bytes=bytes(_FAKE_PY, "utf-8"),
                    ),
                ],
            )

    def test_get_analysis_items_no_filters_and_id(self) -> None:
        yaml = analysis_utils.get_yaml_loader(roundtrip=True)
        with tempfile.TemporaryDirectory() as temp_dir:
            self.set_up_cache(temp_dir)
            items = enable.get_analysis_items(analysis_id="fake.rule.1", filter_args=[])
            self.assertEqual(len(items), 1)
            self.assertEqual(
                items,
                [
                    enable.AnalysisItem(
                        analysis_spec=yaml.load(_FAKE_RULE_1_V1),
                        yaml_file_path="rules/fake_rule_1.yaml",
                        python_file_path="rules/fake_rule_1.py",
                        python_file_bytes=bytes(_FAKE_PY, "utf-8"),
                    ),
                ],
            )

    def test_clone_analysis_items(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self.set_up_cache(temp_dir)
            items = enable.get_analysis_items(analysis_id=None, filter_args=[])
            self.assertEqual(len(items), 3)
            enable.clone_analysis_items(items)

            self.assertTrue((pathlib.Path(temp_dir) / "rules" / "fake_rule_1.yaml").exists())
            self.assertTrue((pathlib.Path(temp_dir) / "rules" / "fake_rule_1.py").exists())
            self.assertTrue((pathlib.Path(temp_dir) / "rules" / "fake_rule_2.yaml").exists())
            self.assertTrue((pathlib.Path(temp_dir) / "rules" / "fake_rule_2.py").exists())
            self.assertTrue((pathlib.Path(temp_dir) / "policies" / "fake_policy_1.yaml").exists())
            self.assertTrue((pathlib.Path(temp_dir) / "policies" / "fake_policy_1.py").exists())
