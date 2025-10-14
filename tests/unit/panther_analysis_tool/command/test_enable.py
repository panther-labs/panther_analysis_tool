import os
import pathlib
import tempfile
import unittest
from typing import Optional

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
        "Enabled": False,
        "Description": "Fake rule 1 v1",
    }
)

_FAKE_RULE_2_V1 = yaml.dump(
    {
        "AnalysisType": "rule",
        "Filename": "fake_rule_2.py",
        "RuleID": "fake.rule.2",
        "Enabled": False,
        "Description": "Fake rule 2 v1",
    }
)

_FAKE_RULE_2_V2 = yaml.dump(
    {
        "AnalysisType": "rule",
        "Filename": "fake_rule_2.py",
        "RuleID": "fake.rule.2",
        "Enabled": False,
        "Description": "Fake rule 2 v2",
    }
)

_FAKE_POLICY_1_V1 = yaml.dump(
    {
        "AnalysisType": "policy",
        "PolicyID": "fake.policy.1",
        "Enabled": False,
        "Description": "Fake policy 1 v1",
        "Filename": "fake_policy_1.py",
    }
)

_FAKE_DATAMODEL_1_V1 = yaml.dump(
    {
        "AnalysisType": "datamodel",
        "Filename": "fake_datamodel_1.py",
        "DataModelID": "fake.datamodel.1",
        "Description": "Fake datamodel 1 v1",
        "Enabled": False,
    }
)

_FAKE_LOOKUP_TABLE_1_V1 = yaml.dump(
    {
        "AnalysisType": "lookup_table",
        "LookupName": "fake.lookup_table.1",
        "Enabled": False,
        "Description": "Fake lookup table 1 v1",
    }
)

_FAKE_GLOBAL_HELPER_1_V1 = yaml.dump(
    {
        "AnalysisType": "global",
        "GlobalID": "fake.global_helper.1",
        "Enabled": False,
        "Description": "Fake global helper 1 v1",
        "Filename": "fake_global_helper_1.py",
    }
)

_FAKE_CORRELATION_RULE_1_V1 = yaml.dump(
    {
        "AnalysisType": "correlation_rule",
        "RuleID": "fake.correlation_rule.1",
        "Enabled": False,
        "Description": "Fake correlation rule 1 v1",
    }
)

_FAKE_SCHEDULED_RULE_1_V1 = yaml.dump(
    {
        "AnalysisType": "scheduled_rule",
        "RuleID": "fake.scheduled_rule.1",
        "Enabled": False,
        "Description": "Fake scheduled rule 1 v1",
        "Filename": "fake_scheduled_rule_1.py",
    }
)

_FAKE_SAVED_QUERY_1_V1 = yaml.dump(
    {
        "AnalysisType": "saved_query",
        "QueryName": "fake.saved_query.1",
        "Enabled": False,
        "Description": "Fake saved query 1 v1",
    }
)

_FAKE_SCHEDULED_QUERY_1_V1 = yaml.dump(
    {
        "AnalysisType": "scheduled_query",
        "QueryName": "fake.scheduled_query.1",
        "Enabled": False,
        "Description": "Fake scheduled query 1 v1",
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
            "fake.datamodel.1": {
                "version": 1,
                "type": "datamodel",
                "sha256": "fake_sha256_datamodel_1",
                "history": {
                    "1": {
                        "version": 1,
                        "commit_hash": "fake_commit_hash_datamodel_1",
                        "yaml_file_path": "data_models/fake_datamodel_1.yaml",
                        "py_file_path": "data_models/fake_datamodel_1.py",
                    },
                },
            },
            "fake.lookup_table.1": {
                "version": 1,
                "type": "lookup_table",
                "sha256": "fake_sha256_lookup_table_1",
                "history": {
                    "1": {
                        "version": 1,
                        "commit_hash": "fake_commit_hash_lookup_table_1",
                        "yaml_file_path": "lookup_tables/fake_lookup_table_1.yaml",
                    },
                },
            },
            "fake.global_helper.1": {
                "version": 1,
                "type": "global",
                "sha256": "fake_sha256_global_helper_1",
                "history": {
                    "1": {
                        "version": 1,
                        "commit_hash": "fake_commit_hash_global_helper_1",
                        "yaml_file_path": "global_helpers/fake_global_helper_1.yaml",
                        "py_file_path": "global_helpers/fake_global_helper_1.py",
                    },
                },
            },
            "fake.correlation_rule.1": {
                "version": 1,
                "type": "correlation_rule",
                "sha256": "fake_sha256_correlation_rule_1",
                "history": {
                    "1": {
                        "version": 1,
                        "commit_hash": "fake_commit_hash_correlation_rule_1",
                        "yaml_file_path": "correlation_rules/fake_correlation_rule_1.yaml",
                    },
                },
            },
            "fake.scheduled_rule.1": {
                "version": 1,
                "type": "scheduled_rule",
                "sha256": "fake_sha256_scheduled_rule_1",
                "history": {
                    "1": {
                        "version": 1,
                        "commit_hash": "fake_commit_hash_scheduled_rule_1",
                        "yaml_file_path": "scheduled_rules/fake_scheduled_rule_1.yaml",
                        "py_file_path": "scheduled_rules/fake_scheduled_rule_1.py",
                    },
                },
            },
            "fake.saved_query.1": {
                "version": 1,
                "type": "saved_query",
                "sha256": "fake_sha256_saved_query_1",
                "history": {
                    "1": {
                        "version": 1,
                        "commit_hash": "fake_commit_hash_saved_query_1",
                        "yaml_file_path": "queries/fake_saved_query_1.yaml",
                    },
                },
            },
            "fake.scheduled_query.1": {
                "version": 1,
                "type": "scheduled_query",
                "sha256": "fake_sha256_scheduled_query_1",
                "history": {
                    "1": {
                        "version": 1,
                        "commit_hash": "fake_commit_hash_scheduled_query_1",
                        "yaml_file_path": "queries/fake_scheduled_query_1.yaml",
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
        self.insert_spec(cache, _FAKE_RULE_1_V1, 1, "RuleID", "fake.rule.1", _FAKE_PY)
        self.insert_spec(cache, _FAKE_RULE_2_V1, 1, "RuleID", "fake.rule.2", _FAKE_PY)
        self.insert_spec(cache, _FAKE_RULE_2_V2, 2, "RuleID", "fake.rule.2", _FAKE_PY)
        self.insert_spec(cache, _FAKE_POLICY_1_V1, 1, "PolicyID", "fake.policy.1", _FAKE_PY)
        self.insert_spec(
            cache, _FAKE_DATAMODEL_1_V1, 1, "DataModelID", "fake.datamodel.1", _FAKE_PY
        )
        self.insert_spec(
            cache, _FAKE_LOOKUP_TABLE_1_V1, 1, "LookupName", "fake.lookup_table.1", _FAKE_PY
        )
        self.insert_spec(
            cache, _FAKE_GLOBAL_HELPER_1_V1, 1, "GlobalID", "fake.global_helper.1", _FAKE_PY
        )
        self.insert_spec(
            cache, _FAKE_CORRELATION_RULE_1_V1, 1, "RuleID", "fake.correlation_rule.1", _FAKE_PY
        )
        self.insert_spec(
            cache, _FAKE_SCHEDULED_RULE_1_V1, 1, "RuleID", "fake.scheduled_rule.1", _FAKE_PY
        )
        self.insert_spec(
            cache, _FAKE_SAVED_QUERY_1_V1, 1, "QueryName", "fake.saved_query.1", _FAKE_PY
        )
        self.insert_spec(
            cache, _FAKE_SCHEDULED_QUERY_1_V1, 1, "QueryName", "fake.scheduled_query.1", _FAKE_PY
        )

        return cache

    def insert_spec(
        self,
        cache: analysis_cache.AnalysisCache,
        spec: str,
        version: int,
        id_field: str,
        id_value: str,
        py_contents: Optional[str] = None,
    ) -> None:
        cache.insert_analysis_spec(
            analysis_cache.AnalysisSpec(
                id=None,
                spec=bytes(spec, "utf-8"),
                version=version,
                id_field=id_field,
                id_value=id_value,
            ),
            bytes(py_contents, "utf-8") if py_contents is not None else None,
        )

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
        with tempfile.TemporaryDirectory() as temp_dir:
            self.set_up_cache(temp_dir)
            items = enable.get_analysis_items(analysis_id=None, filter_args=[])
            self.assertEqual(len(items), 10)

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
            self.assertEqual(len(items), 10)
            enable.clone_analysis_items(items)

            _dir = pathlib.Path(temp_dir)
            self.assertTrue((_dir / "rules" / "fake_rule_1.yaml").exists())
            self.assertTrue((_dir / "rules" / "fake_rule_1.py").exists())
            self.assertTrue((_dir / "rules" / "fake_rule_2.yaml").exists())
            self.assertTrue((_dir / "rules" / "fake_rule_2.py").exists())
            self.assertTrue((_dir / "policies" / "fake_policy_1.yaml").exists())
            self.assertTrue((_dir / "policies" / "fake_policy_1.py").exists())
            self.assertTrue((_dir / "data_models" / "fake_datamodel_1.yaml").exists())
            self.assertTrue((_dir / "data_models" / "fake_datamodel_1.py").exists())
            self.assertTrue((_dir / "lookup_tables" / "fake_lookup_table_1.yaml").exists())
            self.assertTrue((_dir / "global_helpers" / "fake_global_helper_1.yaml").exists())
            self.assertTrue((_dir / "global_helpers" / "fake_global_helper_1.py").exists())
            self.assertTrue((_dir / "correlation_rules" / "fake_correlation_rule_1.yaml").exists())
            self.assertTrue((_dir / "scheduled_rules" / "fake_scheduled_rule_1.yaml").exists())
            self.assertTrue((_dir / "scheduled_rules" / "fake_scheduled_rule_1.py").exists())
            self.assertTrue((_dir / "queries" / "fake_saved_query_1.yaml").exists())
            self.assertTrue((_dir / "queries" / "fake_scheduled_query_1.yaml").exists())

    def test_enable_works_with_all_types(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self.set_up_cache(temp_dir)

            for _id in [
                "fake.rule.1",
                "fake.rule.2",
                "fake.policy.1",
                "fake.datamodel.1",
                "fake.lookup_table.1",
                "fake.global_helper.1",
                "fake.correlation_rule.1",
                "fake.scheduled_rule.1",
                "fake.saved_query.1",
                "fake.scheduled_query.1",
            ]:
                code, err_str = enable.run(analysis_id=_id, filter_args=[])
                self.assertEqual(code, 0, f"{_id} {err_str}")
                self.assertEqual(err_str, "", f"{_id} {err_str}")

    def test_enable_sets_base_version_field(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self.set_up_cache(temp_dir)
            code, err_str = enable.run(analysis_id=None, filter_args=["AnalysisType=rule"])
            self.assertEqual(code, 0, f"{err_str}")
            self.assertEqual(err_str, "", f"{err_str}")

            rule_path = pathlib.Path(temp_dir) / "rules"
            self.assertTrue((rule_path / "fake_rule_1.yaml").exists())
            self.assertTrue((rule_path / "fake_rule_1.py").exists())
            self.assertTrue((rule_path / "fake_rule_2.yaml").exists())
            self.assertTrue((rule_path / "fake_rule_2.py").exists())
            self.assertEqual(
                analysis_utils.get_yaml_loader(True).load(
                    (rule_path / "fake_rule_1.yaml").read_text()
                )["BaseVersion"],
                1,
            )
            self.assertEqual(
                analysis_utils.get_yaml_loader(True).load(
                    (rule_path / "fake_rule_2.yaml").read_text()
                )["BaseVersion"],
                2,
            )

    def test_enable_messaging(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self.set_up_cache(temp_dir)

            code, err_str = enable.run(analysis_id="bad", filter_args=[])
            self.assertEqual(code, 1)
            self.assertEqual(
                err_str, "No items matched the analysis ID. Nothing to clone and enable."
            )

            code, err_str = enable.run(analysis_id=None, filter_args=["AnalysisType=bad"])
            self.assertEqual(code, 1)
            self.assertEqual(err_str, "No items matched the filters. Nothing to clone and enable.")

            code, err_str = enable.run(analysis_id="bad", filter_args=["AnalysisType=bad"])
            self.assertEqual(code, 1)
            self.assertEqual(
                err_str,
                "No items matched the analysis ID and filters. Nothing to clone and enable.",
            )
