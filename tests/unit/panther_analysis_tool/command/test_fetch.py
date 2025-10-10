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

_FAKE_USER_RULE_2_V1 = yaml.dump(
    {
        "AnalysisType": "rule",
        "Filename": "fake_user_rule_2.py",
        "RuleID": "fake.rule.2",
        "Enabled": True,
        "Description": "Fake user rule 2 v1",
        "BaseVersion": 1,
    }
)

_FAKE_DATAMODEL_1_V1 = yaml.dump(
    {
        "AnalysisType": "datamodel",
        "Filename": "fake_datamodel_1.py",
        "DataModelID": "fake.datamodel.1",
        "Description": "Fake datamodel 1 v1",
        "Enabled": True,
    }
)

_FAKE_LOOKUP_TABLE_1_V1 = yaml.dump(
    {
        "AnalysisType": "lookup_table",
        "LookupName": "fake.lookup_table.1",
        "Enabled": True,
        "Description": "Fake lookup table 1 v1",
    }
)

_FAKE_GLOBAL_HELPER_1_V1 = yaml.dump(
    {
        "AnalysisType": "global",
        "GlobalID": "fake.global_helper.1",
        "Enabled": True,
        "Description": "Fake global helper 1 v1",
        "Filename": "fake_global_helper_1.py",
    }
)

_FAKE_CORRELATION_RULE_1_V1 = yaml.dump(
    {
        "AnalysisType": "correlation_rule",
        "RuleID": "fake.correlation_rule.1",
        "Enabled": True,
        "Description": "Fake correlation rule 1 v1",
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

_FAKE_SCHEDULED_RULE_1_V1 = yaml.dump(
    {
        "AnalysisType": "scheduled_rule",
        "RuleID": "fake.scheduled_rule.1",
        "Enabled": True,
        "Description": "Fake scheduled rule 1 v1",
        "Filename": "fake_scheduled_rule_1.py",
    }
)

_FAKE_SAVED_QUERY_1_V1 = yaml.dump(
    {
        "AnalysisType": "saved_query",
        "QueryName": "fake.saved_query.1",
        "Enabled": True,
        "Description": "Fake saved query 1 v1",
    }
)

_FAKE_SCHEDULED_QUERY_1_V1 = yaml.dump(
    {
        "AnalysisType": "scheduled_query",
        "QueryName": "fake.scheduled_query.1",
        "Enabled": True,
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
                        "yaml_file_path": "fake_datamodel_1.yaml",
                        "py_file_path": "fake_datamodel_1.py",
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
                        "yaml_file_path": "fake_lookup_table_1.yaml",
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
                        "yaml_file_path": "fake_global_helper_1.yaml",
                        "py_file_path": "fake_global_helper_1.py",
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
                        "yaml_file_path": "fake_correlation_rule_1.yaml",
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
                        "yaml_file_path": "fake_policy_1.yaml",
                        "py_file_path": "fake_policy_1.py",
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
                        "yaml_file_path": "fake_scheduled_rule_1.yaml",
                        "py_file_path": "fake_scheduled_rule_1.py",
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
                        "yaml_file_path": "fake_saved_query_1.yaml",
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
                        "yaml_file_path": "fake_scheduled_query_1.yaml",
                    },
                },
            },
        },
    }
)


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
        self.create_file_with_text(
            pa_clone_path / "data_models" / "fake_datamodel_1.yaml", _FAKE_DATAMODEL_1_V1
        )
        self.create_file_with_text(pa_clone_path / "data_models" / "fake_datamodel_1.py", _FAKE_PY)
        self.create_file_with_text(
            pa_clone_path / "lookup_tables" / "fake_lookup_table_1.yaml", _FAKE_LOOKUP_TABLE_1_V1
        )
        self.create_file_with_text(
            pa_clone_path / "global_helpers" / "fake_global_helper_1.yaml", _FAKE_GLOBAL_HELPER_1_V1
        )
        self.create_file_with_text(
            pa_clone_path / "global_helpers" / "fake_global_helper_1.py", _FAKE_PY
        )
        self.create_file_with_text(
            pa_clone_path / "correlation_rules" / "fake_correlation_rule_1.yaml",
            _FAKE_CORRELATION_RULE_1_V1,
        )
        self.create_file_with_text(
            pa_clone_path / "policies" / "fake_policy_1.yaml", _FAKE_POLICY_1_V1
        )
        self.create_file_with_text(pa_clone_path / "policies" / "fake_policy_1.py", _FAKE_PY)
        self.create_file_with_text(
            pa_clone_path / "scheduled_rules" / "fake_scheduled_rule_1.yaml",
            _FAKE_SCHEDULED_RULE_1_V1,
        )
        self.create_file_with_text(
            pa_clone_path / "scheduled_rules" / "fake_scheduled_rule_1.py", _FAKE_PY
        )
        self.create_file_with_text(
            pa_clone_path / "saved_queries" / "fake_saved_query_1.yaml", _FAKE_SAVED_QUERY_1_V1
        )
        self.create_file_with_text(
            pa_clone_path / "scheduled_queries" / "fake_scheduled_query_1.yaml",
            _FAKE_SCHEDULED_QUERY_1_V1,
        )

        self.create_file_with_text(pa_clone_path / ".versions.yml", _FAKE_VERSIONS_FILE)

        # fake user's analysis items
        os.makedirs(pathlib.Path("rules"), exist_ok=True)
        self.create_file_with_text(pathlib.Path("rules") / "fake_rule_2.yaml", _FAKE_USER_RULE_2_V1)
        self.create_file_with_text(pathlib.Path("rules") / "fake_rule_2.py", _FAKE_PY)

    def create_file_with_text(self, path: pathlib.Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
        path.write_text(text)

    def dump_sqlite(self, cache: analysis_cache.AnalysisCache) -> None:
        cursor = cache.cursor
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()

        # Dump each table
        for table in tables:
            table_name = table[0]
            print(f"\n=== {table_name} ===")
            cursor.execute(f"SELECT * FROM {table_name}")
            rows = cursor.fetchall()
            for row in rows:
                print(row)

    @mock.patch(
        "panther_analysis_tool.command.fetch.git_helpers.get_panther_analysis_file_contents"
    )
    def test_populate_works_with_latest_versions(
        self, mock_get_panther_analysis_file_contents: mock.MagicMock
    ) -> None:
        mock_get_panther_analysis_file_contents.side_effect = [_FAKE_RULE_1_V1, _FAKE_PY]
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

            latest_spec_2 = cache.get_latest_spec("fake.rule.2")
            assert latest_spec_2 is not None
            self.assertEqual(latest_spec_2.spec.decode("utf-8"), _FAKE_RULE_2_V2)
            self.assertEqual(latest_spec_2.version, 2)
            self.assertEqual(latest_spec_2.id_field, "RuleID")
            self.assertEqual(latest_spec_2.id_value, "fake.rule.2")

            py_file = cache.get_file_for_spec(latest_spec.id or -1)
            assert py_file is not None
            self.assertEqual(py_file.decode("utf-8"), _FAKE_PY)

    @mock.patch(
        "panther_analysis_tool.command.fetch.git_helpers.get_panther_analysis_file_contents"
    )
    def test_populate_works_when_user_has_old_version(
        self, mock_get_panther_analysis_file_contents: mock.MagicMock
    ) -> None:
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

    def test_populate_works_with_datamodel(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self.set_up_cache(temp_dir)
            fetch.populate_sqlite()
            cache = analysis_cache.AnalysisCache()

            latest_spec = cache.get_latest_spec("fake.datamodel.1")
            assert latest_spec is not None
            self.assertEqual(latest_spec.spec.decode("utf-8"), _FAKE_DATAMODEL_1_V1)
            self.assertEqual(latest_spec.version, 1)
            self.assertEqual(latest_spec.id_field, "DataModelID")
            self.assertEqual(latest_spec.id_value, "fake.datamodel.1")

            py_file = cache.get_file_for_spec(latest_spec.id or -1)
            assert py_file is not None
            self.assertEqual(py_file.decode("utf-8"), _FAKE_PY)

    def test_populate_works_with_lookup_table(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self.set_up_cache(temp_dir)
            fetch.populate_sqlite()
            cache = analysis_cache.AnalysisCache()

            latest_spec = cache.get_latest_spec("fake.lookup_table.1")
            assert latest_spec is not None
            self.assertEqual(latest_spec.spec.decode("utf-8"), _FAKE_LOOKUP_TABLE_1_V1)
            self.assertEqual(latest_spec.version, 1)
            self.assertEqual(latest_spec.id_field, "LookupName")
            self.assertEqual(latest_spec.id_value, "fake.lookup_table.1")

    def test_populate_works_with_global_helper(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self.set_up_cache(temp_dir)
            fetch.populate_sqlite()
            cache = analysis_cache.AnalysisCache()

            latest_spec = cache.get_latest_spec("fake.global_helper.1")
            assert latest_spec is not None
            self.assertEqual(latest_spec.spec.decode("utf-8"), _FAKE_GLOBAL_HELPER_1_V1)
            self.assertEqual(latest_spec.version, 1)
            self.assertEqual(latest_spec.id_field, "GlobalID")
            self.assertEqual(latest_spec.id_value, "fake.global_helper.1")

            py_file = cache.get_file_for_spec(latest_spec.id or -1)
            assert py_file is not None
            self.assertEqual(py_file.decode("utf-8"), _FAKE_PY)

    def test_populate_works_with_correlation_rule(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self.set_up_cache(temp_dir)
            fetch.populate_sqlite()
            cache = analysis_cache.AnalysisCache()

            latest_spec = cache.get_latest_spec("fake.correlation_rule.1")
            assert latest_spec is not None
            self.assertEqual(latest_spec.spec.decode("utf-8"), _FAKE_CORRELATION_RULE_1_V1)
            self.assertEqual(latest_spec.version, 1)
            self.assertEqual(latest_spec.id_field, "RuleID")
            self.assertEqual(latest_spec.id_value, "fake.correlation_rule.1")

    def test_populate_works_with_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self.set_up_cache(temp_dir)
            fetch.populate_sqlite()
            cache = analysis_cache.AnalysisCache()

            latest_spec = cache.get_latest_spec("fake.policy.1")
            assert latest_spec is not None
            self.assertEqual(latest_spec.spec.decode("utf-8"), _FAKE_POLICY_1_V1)
            self.assertEqual(latest_spec.version, 1)
            self.assertEqual(latest_spec.id_field, "PolicyID")
            self.assertEqual(latest_spec.id_value, "fake.policy.1")

            py_file = cache.get_file_for_spec(latest_spec.id or -1)
            assert py_file is not None
            self.assertEqual(py_file.decode("utf-8"), _FAKE_PY)

    def test_populate_works_with_scheduled_rule(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self.set_up_cache(temp_dir)
            fetch.populate_sqlite()
            cache = analysis_cache.AnalysisCache()

            latest_spec = cache.get_latest_spec("fake.scheduled_rule.1")
            assert latest_spec is not None
            self.assertEqual(latest_spec.spec.decode("utf-8"), _FAKE_SCHEDULED_RULE_1_V1)
            self.assertEqual(latest_spec.version, 1)
            self.assertEqual(latest_spec.id_field, "RuleID")
            self.assertEqual(latest_spec.id_value, "fake.scheduled_rule.1")

            py_file = cache.get_file_for_spec(latest_spec.id or -1)
            assert py_file is not None
            self.assertEqual(py_file.decode("utf-8"), _FAKE_PY)

    def test_populate_works_with_saved_query(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self.set_up_cache(temp_dir)
            fetch.populate_sqlite()
            cache = analysis_cache.AnalysisCache()

            latest_spec = cache.get_latest_spec("fake.saved_query.1")
            assert latest_spec is not None
            self.assertEqual(latest_spec.spec.decode("utf-8"), _FAKE_SAVED_QUERY_1_V1)
            self.assertEqual(latest_spec.version, 1)
            self.assertEqual(latest_spec.id_field, "QueryName")
            self.assertEqual(latest_spec.id_value, "fake.saved_query.1")

    def test_populate_works_with_scheduled_query(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self.set_up_cache(temp_dir)
            fetch.populate_sqlite()
            cache = analysis_cache.AnalysisCache()

            latest_spec = cache.get_latest_spec("fake.scheduled_query.1")
            assert latest_spec is not None
            self.assertEqual(latest_spec.spec.decode("utf-8"), _FAKE_SCHEDULED_QUERY_1_V1)
            self.assertEqual(latest_spec.version, 1)
            self.assertEqual(latest_spec.id_field, "QueryName")
            self.assertEqual(latest_spec.id_value, "fake.scheduled_query.1")
