import os
import pathlib
from typing import Optional

from _pytest.monkeypatch import MonkeyPatch

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.constants import (
    CACHE_DIR,
    CACHED_VERSIONS_FILE_PATH,
    PANTHER_ANALYSIS_SQLITE_FILE_PATH,
    AnalysisTypes,
)
from panther_analysis_tool.core import analysis_cache, install_item, versions_file, yaml

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
        "LogTypes": ["fake.datamodel.1.log.type"],
    }
)

_FAKE_DATAMODEL_2_V1 = yaml.dump(
    {
        "AnalysisType": "datamodel",
        "Filename": "fake_datamodel_2.py",
        "DataModelID": "fake.datamodel.2",
        "Description": "Fake datamodel 2 v1",
        "Enabled": False,
        "LogTypes": ["fake.datamodel.2.log.type"],
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
        "Description": "Fake global helper 1 v1",
        "Filename": "fake_global_helper_1.py",
    }
)

_FAKE_GLOBAL_HELPER_2_V1 = yaml.dump(
    {
        "AnalysisType": "global",
        "GlobalID": "fake.global_helper.2",
        "Description": "Fake global helper 2 v1",
        "Filename": "fake_global_helper_2.py",
    }
)

_FAKE_GLOBAL_HELPER_3_V1 = yaml.dump(
    {
        "AnalysisType": "global",
        "GlobalID": "fake.global_helper.3",
        "Description": "Fake global helper 3 v1",
        "Filename": "fake_global_helper_3.py",
    }
)

_FAKE_GLOBAL_HELPER_4_V1 = yaml.dump(
    {
        "AnalysisType": "global",
        "GlobalID": "fake.global_helper.4",
        "Description": "Fake global helper 4 v1",
        "Filename": "fake_global_helper_4.py",
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

_FAKE_SCHEDULED_QUERY_2_V1 = yaml.dump(
    {
        "AnalysisType": "scheduled_query",
        "QueryName": "fake.scheduled_query.2",
        "Enabled": False,
        "Description": "Fake scheduled query 2 v1",
    }
)

_FAKE_SCHEDULED_RULE_WITH_QUERIES = yaml.dump(
    {
        "AnalysisType": "scheduled_rule",
        "Filename": "fake_scheduled_rule_with_queries.py",
        "RuleID": "fake.scheduled_rule.with.queries",
        "Enabled": False,
        "Description": "Fake scheduled rule with queries",
        "ScheduledQueries": ["fake.scheduled_query.1"],
    }
)

_FAKE_SCHEDULED_RULE_WITH_MULTIPLE_QUERIES = yaml.dump(
    {
        "AnalysisType": "scheduled_rule",
        "Filename": "fake_scheduled_rule_with_multiple_queries.py",
        "RuleID": "fake.scheduled_rule.with.multiple.queries",
        "Enabled": False,
        "Description": "Fake scheduled rule with multiple queries",
        "ScheduledQueries": ["fake.scheduled_query.1", "fake.scheduled_query.2"],
    }
)

_FAKE_SCHEDULED_RULE_WITH_MISSING_QUERY = yaml.dump(
    {
        "AnalysisType": "scheduled_rule",
        "Filename": "fake_scheduled_rule_with_missing_query.py",
        "RuleID": "fake.scheduled_rule.with.missing.query",
        "Enabled": False,
        "Description": "Fake scheduled rule depending on query not in cache",
        "ScheduledQueries": ["fake.scheduled_query.missing"],
    }
)

_FAKE_RULE_WITH_DEPS = yaml.dump(
    {
        "AnalysisType": "rule",
        "Filename": "fake_rule_with_deps.py",
        "RuleID": "fake.rule.with.deps",
        "Enabled": False,
        "Description": "Fake rule with deps",
        "LogTypes": ["fake.datamodel.1.log.type", "fake.datamodel.2.log.type"],
    }
)

_FAKE_PY_WITH_HELPERS = """
from fake_global_helper_1 import test_helper
import fake_global_helper_2

def rule(event):
    return True
"""

_FAKE_PY_GLOBAL_HELPER_1_V1 = """
from fake_global_helper_2 import something

def test_helper():
    return True
"""

_FAKE_PY_GLOBAL_HELPER_2_V1 = """
from fake_global_helper_3 import test_helper

something = "in the water"
"""

_FAKE_PY_GLOBAL_HELPER_3_V1 = """
def test_helper():
    return True
"""

_FAKE_PY_DATA_MODEL_1_V1 = """
from fake_global_helper_4 import test_helper
"""

_FAKE_PY_GLOBAL_HELPER_4_V1 = """
def test_helper():
    return True
"""

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
            "fake.datamodel.2": {
                "version": 1,
                "type": "datamodel",
                "sha256": "fake_sha256_datamodel_2",
                "history": {
                    "1": {
                        "version": 1,
                        "commit_hash": "fake_commit_hash_datamodel_2",
                        "yaml_file_path": "data_models/fake_datamodel_2.yaml",
                        "py_file_path": "data_models/fake_datamodel_2.py",
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
            "fake.global_helper.2": {
                "version": 1,
                "type": "global",
                "sha256": "fake_sha256_global_helper_2",
                "history": {
                    "1": {
                        "version": 1,
                        "commit_hash": "fake_commit_hash_global_helper_2",
                        "yaml_file_path": "global_helpers/fake_global_helper_2.yaml",
                        "py_file_path": "global_helpers/fake_global_helper_2.py",
                    },
                },
            },
            "fake.global_helper.3": {
                "version": 1,
                "type": "global",
                "sha256": "fake_sha256_global_helper_3",
                "history": {
                    "1": {
                        "version": 1,
                        "commit_hash": "fake_commit_hash_global_helper_3",
                        "yaml_file_path": "global_helpers/fake_global_helper_3.yaml",
                        "py_file_path": "global_helpers/fake_global_helper_3.py",
                    },
                },
            },
            "fake.global_helper.4": {
                "version": 1,
                "type": "global",
                "sha256": "fake_sha256_global_helper_4",
                "history": {
                    "1": {
                        "version": 1,
                        "commit_hash": "fake_commit_hash_global_helper_4",
                        "yaml_file_path": "global_helpers/fake_global_helper_4.yaml",
                        "py_file_path": "global_helpers/fake_global_helper_4.py",
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
            "fake.scheduled_query.2": {
                "version": 1,
                "type": "scheduled_query",
                "sha256": "fake_sha256_scheduled_query_2",
                "history": {
                    "1": {
                        "version": 1,
                        "commit_hash": "fake_commit_hash_scheduled_query_2",
                        "yaml_file_path": "queries/fake_scheduled_query_2.yaml",
                    },
                },
            },
            "fake.scheduled_rule.with.queries": {
                "version": 1,
                "type": "scheduled_rule",
                "sha256": "fake_sha256_scheduled_rule_with_queries",
                "history": {
                    "1": {
                        "version": 1,
                        "commit_hash": "fake_commit_hash_scheduled_rule_with_queries",
                        "yaml_file_path": "scheduled_rules/fake_scheduled_rule_with_queries.yaml",
                        "py_file_path": "scheduled_rules/fake_scheduled_rule_with_queries.py",
                    },
                },
            },
            "fake.scheduled_rule.with.multiple.queries": {
                "version": 1,
                "type": "scheduled_rule",
                "sha256": "fake_sha256_scheduled_rule_with_multiple_queries",
                "history": {
                    "1": {
                        "version": 1,
                        "commit_hash": "fake_commit_hash_scheduled_rule_with_multiple_queries",
                        "yaml_file_path": "scheduled_rules/fake_scheduled_rule_with_multiple_queries.yaml",
                        "py_file_path": "scheduled_rules/fake_scheduled_rule_with_multiple_queries.py",
                    },
                },
            },
            "fake.rule.with.deps": {
                "version": 1,
                "type": "rule",
                "sha256": "fake_sha256_rule_with_deps",
                "history": {
                    "1": {
                        "version": 1,
                        "commit_hash": "fake_commit_hash_rule_with_deps",
                        "yaml_file_path": "rules/fake_rule_with_deps.yaml",
                        "py_file_path": "rules/fake_rule_with_deps.py",
                    },
                },
            },
        },
    }
)


def set_up_cache(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> analysis_cache.AnalysisCache:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(versions_file, "_VERSIONS", None)

    PANTHER_ANALYSIS_SQLITE_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    PANTHER_ANALYSIS_SQLITE_FILE_PATH.touch()

    pa_clone_path = CACHE_DIR / "panther-analysis"
    os.makedirs(pa_clone_path, exist_ok=True)

    CACHED_VERSIONS_FILE_PATH.write_text(_FAKE_VERSIONS_FILE)

    cache = analysis_cache.AnalysisCache()
    cache.create_tables()
    insert_spec(cache, _FAKE_RULE_1_V1, 1, "RuleID", "fake.rule.1", _FAKE_PY)
    insert_spec(cache, _FAKE_RULE_2_V1, 1, "RuleID", "fake.rule.2", _FAKE_PY)
    insert_spec(cache, _FAKE_RULE_2_V2, 2, "RuleID", "fake.rule.2", _FAKE_PY)
    insert_spec(
        cache, _FAKE_RULE_WITH_DEPS, 1, "RuleID", "fake.rule.with.deps", _FAKE_PY_WITH_HELPERS
    )
    insert_spec(cache, _FAKE_POLICY_1_V1, 1, "PolicyID", "fake.policy.1", _FAKE_PY)
    insert_spec(
        cache, _FAKE_DATAMODEL_1_V1, 1, "DataModelID", "fake.datamodel.1", _FAKE_PY_DATA_MODEL_1_V1
    )
    insert_spec(cache, _FAKE_DATAMODEL_2_V1, 1, "DataModelID", "fake.datamodel.2", _FAKE_PY)
    insert_spec(cache, _FAKE_LOOKUP_TABLE_1_V1, 1, "LookupName", "fake.lookup_table.1", _FAKE_PY)
    insert_spec(
        cache,
        _FAKE_GLOBAL_HELPER_1_V1,
        1,
        "GlobalID",
        "fake.global_helper.1",
        _FAKE_PY_GLOBAL_HELPER_1_V1,
    )
    insert_spec(
        cache,
        _FAKE_GLOBAL_HELPER_2_V1,
        1,
        "GlobalID",
        "fake.global_helper.2",
        _FAKE_PY_GLOBAL_HELPER_2_V1,
    )
    insert_spec(
        cache,
        _FAKE_GLOBAL_HELPER_3_V1,
        1,
        "GlobalID",
        "fake.global_helper.3",
        _FAKE_PY_GLOBAL_HELPER_3_V1,
    )
    insert_spec(
        cache,
        _FAKE_GLOBAL_HELPER_4_V1,
        1,
        "GlobalID",
        "fake.global_helper.4",
        _FAKE_PY_GLOBAL_HELPER_4_V1,
    )
    insert_spec(
        cache, _FAKE_CORRELATION_RULE_1_V1, 1, "RuleID", "fake.correlation_rule.1", _FAKE_PY
    )
    insert_spec(cache, _FAKE_SCHEDULED_RULE_1_V1, 1, "RuleID", "fake.scheduled_rule.1", _FAKE_PY)
    insert_spec(
        cache,
        _FAKE_SCHEDULED_RULE_WITH_QUERIES,
        1,
        "RuleID",
        "fake.scheduled_rule.with.queries",
        _FAKE_PY,
    )
    insert_spec(
        cache,
        _FAKE_SCHEDULED_RULE_WITH_MULTIPLE_QUERIES,
        1,
        "RuleID",
        "fake.scheduled_rule.with.multiple.queries",
        _FAKE_PY,
    )
    insert_spec(cache, _FAKE_SAVED_QUERY_1_V1, 1, "QueryName", "fake.saved_query.1")
    insert_spec(cache, _FAKE_SCHEDULED_QUERY_1_V1, 1, "QueryName", "fake.scheduled_query.1")
    insert_spec(cache, _FAKE_SCHEDULED_QUERY_2_V1, 1, "QueryName", "fake.scheduled_query.2")

    return cache


def insert_spec(
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


def test_set_enabled_field() -> None:
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
        install_item.set_enabled_field(spec)
        assert "Enabled" in spec
        assert spec["Enabled"]


def test_set_enabled_field_for_other_types() -> None:
    for analysis_type in [
        AnalysisTypes.PACK,
        AnalysisTypes.GLOBAL,
    ]:
        spec = {
            "AnalysisType": analysis_type,
        }
        install_item.set_enabled_field(spec)
        assert "Enabled" not in spec


def test_cached_analysis_spec_to_analysis_item_with_python(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    cache = set_up_cache(tmp_path, monkeypatch)
    spec = cache.get_latest_spec("fake.rule.1")
    assert spec is not None

    versions = versions_file.get_versions().versions
    item = install_item.cached_analysis_spec_to_analysis_item(spec, cache, versions)
    assert item.python_file_contents == bytes(_FAKE_PY, "utf-8")
    assert item.python_file_path == "rules/fake_rule_1.py"
    assert item.yaml_file_contents == yaml.load(_FAKE_RULE_1_V1)
    assert item.yaml_file_path == "rules/fake_rule_1.yaml"
    assert item.raw_yaml_file_contents == spec.spec


def test_cached_analysis_spec_to_analysis_item_without_python(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    cache = set_up_cache(tmp_path, monkeypatch)
    spec = cache.get_latest_spec("fake.saved_query.1")
    assert spec is not None

    versions = versions_file.get_versions().versions
    item = install_item.cached_analysis_spec_to_analysis_item(spec, cache, versions)
    assert item.yaml_file_contents == yaml.load(_FAKE_SAVED_QUERY_1_V1)
    assert item.yaml_file_path == "queries/fake_saved_query_1.yaml"
    assert item.raw_yaml_file_contents == spec.spec
    assert item.python_file_contents is None
    assert item.python_file_path is None


def test_install_analysis_items_no_deps(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    set_up_cache(tmp_path, monkeypatch)
    items = [
        analysis_utils.AnalysisItem(
            yaml_file_contents=yaml.load(_FAKE_RULE_1_V1),
            yaml_file_path="rules/fake_rule_1.yaml",
            python_file_path="rules/fake_rule_1.py",
            python_file_contents=bytes(_FAKE_PY, "utf-8"),
        )
    ]
    install_item.install_deps(items)

    assert not (tmp_path / "global_helpers" / "fake_global_helper_1.yaml").exists()
    assert not (tmp_path / "global_helpers" / "fake_global_helper_1.py").exists()
    assert not (tmp_path / "data_models" / "fake_datamodel_1.yaml").exists()
    assert not (tmp_path / "data_models" / "fake_datamodel_1.py").exists()
    assert not (tmp_path / "global_helpers" / "fake_global_helper_2.yaml").exists()
    assert not (tmp_path / "global_helpers" / "fake_global_helper_2.py").exists()
    assert not (tmp_path / "data_models" / "fake_datamodel_2.yaml").exists()
    assert not (tmp_path / "data_models" / "fake_datamodel_2.py").exists()


def test_install_analysis_items_with_deps(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    set_up_cache(tmp_path, monkeypatch)

    items = [
        analysis_utils.AnalysisItem(
            yaml_file_contents=yaml.load(_FAKE_RULE_WITH_DEPS),
            yaml_file_path="rules/fake_rule_with_deps.yaml",
            python_file_path="rules/fake_rule_with_deps.py",
            python_file_contents=bytes(_FAKE_PY_WITH_HELPERS, "utf-8"),
        )
    ]
    install_item.install_deps(items)

    assert (tmp_path / "global_helpers" / "fake_global_helper_1.yaml").exists()
    assert (tmp_path / "global_helpers" / "fake_global_helper_1.py").exists()
    assert (tmp_path / "global_helpers" / "fake_global_helper_2.yaml").exists()
    assert (tmp_path / "global_helpers" / "fake_global_helper_2.py").exists()
    assert (tmp_path / "global_helpers" / "fake_global_helper_3.yaml").exists()
    assert (tmp_path / "global_helpers" / "fake_global_helper_3.py").exists()
    assert (tmp_path / "global_helpers" / "fake_global_helper_4.yaml").exists()
    assert (tmp_path / "global_helpers" / "fake_global_helper_4.py").exists()

    assert (tmp_path / "data_models" / "fake_datamodel_1.yaml").exists()
    assert (tmp_path / "data_models" / "fake_datamodel_1.py").exists()
    assert (tmp_path / "data_models" / "fake_datamodel_2.yaml").exists()
    assert (tmp_path / "data_models" / "fake_datamodel_2.py").exists()

    assert "Enabled: true" in (tmp_path / "data_models" / "fake_datamodel_1.yaml").read_text()
    assert "BaseVersion: 1" in (tmp_path / "data_models" / "fake_datamodel_1.yaml").read_text()
    assert "Enabled: true" in (tmp_path / "data_models" / "fake_datamodel_2.yaml").read_text()
    assert "BaseVersion: 1" in (tmp_path / "data_models" / "fake_datamodel_2.yaml").read_text()
    global_path = tmp_path / "global_helpers"
    assert "BaseVersion: 1" in (global_path / "fake_global_helper_1.yaml").read_text()
    assert "BaseVersion: 1" in (global_path / "fake_global_helper_2.yaml").read_text()
    assert "BaseVersion: 1" in (global_path / "fake_global_helper_3.yaml").read_text()
    assert "BaseVersion: 1" in (global_path / "fake_global_helper_4.yaml").read_text()


def test_install_analysis_item(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    CACHED_VERSIONS_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHED_VERSIONS_FILE_PATH.write_text(_FAKE_VERSIONS_FILE)
    item = analysis_utils.AnalysisItem(
        yaml_file_contents=yaml.load(_FAKE_RULE_1_V1),
        yaml_file_path="rules/fake_rule_1.yaml",
        python_file_path="rules/fake_rule_1.py",
        python_file_contents=bytes(_FAKE_PY, "utf-8"),
    )
    install_item.install_analysis_item(item, show_installed_items=True)

    assert (tmp_path / "rules" / "fake_rule_1.yaml").exists()
    assert (tmp_path / "rules" / "fake_rule_1.py").exists()

    assert "Enabled: true" in (tmp_path / "rules" / "fake_rule_1.yaml").read_text()
    assert "BaseVersion: 1" in (tmp_path / "rules" / "fake_rule_1.yaml").read_text()


def test_install_deps_with_scheduled_queries(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    set_up_cache(tmp_path, monkeypatch)

    items = [
        analysis_utils.AnalysisItem(
            yaml_file_contents=yaml.load(_FAKE_SCHEDULED_RULE_WITH_QUERIES),
            yaml_file_path="scheduled_rules/fake_scheduled_rule_with_queries.yaml",
            python_file_path="scheduled_rules/fake_scheduled_rule_with_queries.py",
            python_file_contents=bytes(_FAKE_PY, "utf-8"),
        )
    ]
    install_item.install_deps(items)

    assert (tmp_path / "queries" / "fake_scheduled_query_1.yaml").exists()
    assert "Enabled: true" in (tmp_path / "queries" / "fake_scheduled_query_1.yaml").read_text()
    assert "BaseVersion: 1" in (tmp_path / "queries" / "fake_scheduled_query_1.yaml").read_text()


def test_install_deps_with_multiple_scheduled_queries(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    set_up_cache(tmp_path, monkeypatch)

    items = [
        analysis_utils.AnalysisItem(
            yaml_file_contents=yaml.load(_FAKE_SCHEDULED_RULE_WITH_MULTIPLE_QUERIES),
            yaml_file_path="scheduled_rules/fake_scheduled_rule_with_multiple_queries.yaml",
            python_file_path="scheduled_rules/fake_scheduled_rule_with_multiple_queries.py",
            python_file_contents=bytes(_FAKE_PY, "utf-8"),
        )
    ]
    install_item.install_deps(items)

    assert (tmp_path / "queries" / "fake_scheduled_query_1.yaml").exists()
    assert "Enabled: true" in (tmp_path / "queries" / "fake_scheduled_query_1.yaml").read_text()
    assert "BaseVersion: 1" in (tmp_path / "queries" / "fake_scheduled_query_1.yaml").read_text()

    assert (tmp_path / "queries" / "fake_scheduled_query_2.yaml").exists()
    assert "Enabled: true" in (tmp_path / "queries" / "fake_scheduled_query_2.yaml").read_text()
    assert "BaseVersion: 1" in (tmp_path / "queries" / "fake_scheduled_query_2.yaml").read_text()


def test_install_deps_does_not_reinstall_existing_scheduled_query(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    set_up_cache(tmp_path, monkeypatch)

    # Pre-install the scheduled query
    query_dir = tmp_path / "queries"
    query_dir.mkdir(parents=True, exist_ok=True)
    existing_content = "existing content"
    (query_dir / "fake_scheduled_query_1.yaml").write_text(existing_content)

    items = [
        analysis_utils.AnalysisItem(
            yaml_file_contents=yaml.load(_FAKE_SCHEDULED_RULE_WITH_QUERIES),
            yaml_file_path="scheduled_rules/fake_scheduled_rule_with_queries.yaml",
            python_file_path="scheduled_rules/fake_scheduled_rule_with_queries.py",
            python_file_contents=bytes(_FAKE_PY, "utf-8"),
        )
    ]
    install_item.install_deps(items)

    # The file should not have been overwritten
    assert (query_dir / "fake_scheduled_query_1.yaml").read_text() == existing_content


def test_install_deps_when_scheduled_query_not_in_cache(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    """When a scheduled rule depends on a scheduled query that is not in the cache, install_deps skips it and does not install any file for that query."""
    set_up_cache(tmp_path, monkeypatch)

    items = [
        analysis_utils.AnalysisItem(
            yaml_file_contents=yaml.load(_FAKE_SCHEDULED_RULE_WITH_MISSING_QUERY),
            yaml_file_path="scheduled_rules/fake_scheduled_rule_with_missing_query.yaml",
            python_file_path="scheduled_rules/fake_scheduled_rule_with_missing_query.py",
            python_file_contents=bytes(_FAKE_PY, "utf-8"),
        )
    ]
    install_item.install_deps(items)

    # The missing query is not in the cache, so no file should be created for it
    assert not (tmp_path / "queries" / "fake_scheduled_query_missing.yaml").exists()
