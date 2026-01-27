import os
import pathlib
from typing import Optional

import pytest
from _pytest.monkeypatch import MonkeyPatch
from pytest_mock import MockerFixture

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.command import clone
from panther_analysis_tool.constants import (
    CACHE_DIR,
    CACHED_VERSIONS_FILE_PATH,
    PANTHER_ANALYSIS_SQLITE_FILE_PATH,
)
from panther_analysis_tool.core import analysis_cache, yaml

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
        "Enabled": False,
        "Description": "Fake global helper 1 v1",
        "Filename": "fake_global_helper_1.py",
    }
)

_FAKE_GLOBAL_HELPER_2_V1 = yaml.dump(
    {
        "AnalysisType": "global",
        "GlobalID": "fake.global_helper.2",
        "Enabled": False,
        "Description": "Fake global helper 2 v1",
        "Filename": "fake_global_helper_2.py",
    }
)

_FAKE_GLOBAL_HELPER_3_V1 = yaml.dump(
    {
        "AnalysisType": "global",
        "GlobalID": "fake.global_helper.3",
        "Enabled": False,
        "Description": "Fake global helper 3 v1",
        "Filename": "fake_global_helper_3.py",
    }
)

_FAKE_GLOBAL_HELPER_4_V1 = yaml.dump(
    {
        "AnalysisType": "global",
        "GlobalID": "fake.global_helper.4",
        "Enabled": False,
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
    insert_spec(cache, _FAKE_SAVED_QUERY_1_V1, 1, "QueryName", "fake.saved_query.1")
    insert_spec(cache, _FAKE_SCHEDULED_QUERY_1_V1, 1, "QueryName", "fake.scheduled_query.1")

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


def test_get_analysis_items_no_cache(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(analysis_cache.NoCacheException):
        clone.get_analysis_items(analysis_id="fake.rule.1", filter_args=[])


def test_get_analysis_items_bad_id(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    set_up_cache(tmp_path, monkeypatch)
    items = clone.get_analysis_items(analysis_id="bad_id", filter_args=[])
    assert items == []


def test_get_analysis_items_no_filters_and_no_id(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    set_up_cache(tmp_path, monkeypatch)
    items = clone.get_analysis_items(analysis_id=None, filter_args=[])
    assert len(items) == 15


def test_get_analysis_items_filters_and_no_id(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    set_up_cache(tmp_path, monkeypatch)
    items = clone.get_analysis_items(analysis_id=None, filter_args=["AnalysisType=rule"])
    assert len(items) == 3
    assert items == [
        analysis_utils.AnalysisItem(
            yaml_file_contents=yaml.load(_FAKE_RULE_1_V1),
            yaml_file_path="rules/fake_rule_1.yaml",
            python_file_path="rules/fake_rule_1.py",
            python_file_contents=bytes(_FAKE_PY, "utf-8"),
        ),
        analysis_utils.AnalysisItem(
            yaml_file_contents=yaml.load(_FAKE_RULE_2_V2),
            yaml_file_path="rules/fake_rule_2.yaml",
            python_file_path="rules/fake_rule_2.py",
            python_file_contents=bytes(_FAKE_PY, "utf-8"),
        ),
        analysis_utils.AnalysisItem(
            yaml_file_contents=yaml.load(_FAKE_RULE_WITH_DEPS),
            yaml_file_path="rules/fake_rule_with_deps.yaml",
            python_file_path="rules/fake_rule_with_deps.py",
            python_file_contents=bytes(_FAKE_PY_WITH_HELPERS, "utf-8"),
        ),
    ]


def test_get_analysis_items_no_filters_and_id(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    set_up_cache(tmp_path, monkeypatch)
    items = clone.get_analysis_items(analysis_id="fake.rule.1", filter_args=[])
    assert len(items) == 1
    assert items == [
        analysis_utils.AnalysisItem(
            yaml_file_contents=yaml.load(_FAKE_RULE_1_V1),
            yaml_file_path="rules/fake_rule_1.yaml",
            python_file_path="rules/fake_rule_1.py",
            python_file_contents=bytes(_FAKE_PY, "utf-8"),
        ),
    ]


def test_clone_analysis_items(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    set_up_cache(tmp_path, monkeypatch)
    items = clone.get_analysis_items(analysis_id=None, filter_args=[])
    assert len(items) == 15
    clone.clone_analysis_items(items)
    _dir = tmp_path
    assert (_dir / "rules" / "fake_rule_1.yaml").exists()
    assert (_dir / "rules" / "fake_rule_1.py").exists()
    assert (_dir / "rules" / "fake_rule_2.yaml").exists()
    assert (_dir / "rules" / "fake_rule_2.py").exists()
    assert (_dir / "policies" / "fake_policy_1.yaml").exists()
    assert (_dir / "policies" / "fake_policy_1.py").exists()
    assert (_dir / "data_models" / "fake_datamodel_1.yaml").exists()
    assert (_dir / "data_models" / "fake_datamodel_1.py").exists()
    assert (_dir / "lookup_tables" / "fake_lookup_table_1.yaml").exists()
    assert (_dir / "global_helpers" / "fake_global_helper_1.yaml").exists()
    assert (_dir / "global_helpers" / "fake_global_helper_1.py").exists()
    assert (_dir / "correlation_rules" / "fake_correlation_rule_1.yaml").exists()
    assert (_dir / "scheduled_rules" / "fake_scheduled_rule_1.yaml").exists()
    assert (_dir / "scheduled_rules" / "fake_scheduled_rule_1.py").exists()
    assert (_dir / "queries" / "fake_saved_query_1.yaml").exists()
    assert (_dir / "queries" / "fake_scheduled_query_1.yaml").exists()


def test_clone_analysis_items_already_exists(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    set_up_cache(tmp_path, monkeypatch)
    items = clone.get_analysis_items(analysis_id="fake.rule.1", filter_args=[])
    assert len(items) == 1
    clone.clone_analysis_items(items)

    rule_yaml = tmp_path / "rules" / "fake_rule_1.yaml"
    rule_py = tmp_path / "rules" / "fake_rule_1.py"
    assert rule_yaml.exists()
    assert rule_py.exists()
    assert rule_yaml.read_text() != "new yaml"
    assert rule_py.read_text() != "new py"

    rule_yaml.write_text("new yaml")
    rule_py.write_text("new py")
    assert rule_yaml.read_text() == "new yaml"
    assert rule_py.read_text() == "new py"

    # do it again and verify it did not change anything since it already existed
    items = clone.get_analysis_items(analysis_id="fake.rule.1", filter_args=[])
    assert len(items) == 1
    clone.clone_analysis_items(items)

    assert rule_yaml.read_text() == "new yaml"
    assert rule_py.read_text() == "new py"


def test_enable_works_with_all_types(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    mocker.patch(
        "panther_analysis_tool.command.clone.analysis_cache.update_with_latest_panther_analysis",
        return_value=None,
    )
    mocker.patch("panther_analysis_tool.command.clone.root.chdir_to_project_root")
    set_up_cache(tmp_path, monkeypatch)

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
        code, err_str = clone.run(analysis_id=_id, filter_args=[])
        assert code == 0
        assert err_str == ""


def test_enable_sets_base_version_field(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    mocker.patch(
        "panther_analysis_tool.command.clone.analysis_cache.update_with_latest_panther_analysis",
        return_value=None,
    )
    mocker.patch("panther_analysis_tool.command.clone.root.chdir_to_project_root")
    set_up_cache(tmp_path, monkeypatch)
    code, err_str = clone.run(analysis_id=None, filter_args=["AnalysisType=rule"])
    assert code == 0
    assert err_str == ""

    rule_path = tmp_path / "rules"
    assert (rule_path / "fake_rule_1.yaml").exists()
    assert (rule_path / "fake_rule_1.py").exists()
    assert (rule_path / "fake_rule_2.yaml").exists()
    assert (rule_path / "fake_rule_2.py").exists()
    assert (yaml.load((rule_path / "fake_rule_1.yaml").read_text())["BaseVersion"]) == 1
    assert (yaml.load((rule_path / "fake_rule_2.yaml").read_text())["BaseVersion"]) == 2


def test_enable_messaging(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    mocker.patch(
        "panther_analysis_tool.command.clone.analysis_cache.update_with_latest_panther_analysis",
        return_value=None,
    )
    mocker.patch("panther_analysis_tool.command.clone.root.chdir_to_project_root")
    set_up_cache(tmp_path, monkeypatch)
    code, err_str = clone.run(analysis_id="bad", filter_args=[])
    assert code == 1
    assert err_str == "No items matched the analysis ID. Nothing to clone."

    code, err_str = clone.run(analysis_id=None, filter_args=["AnalysisType=bad"])
    assert code == 1
    assert err_str == "No items matched the filters. Nothing to clone."

    code, err_str = clone.run(analysis_id="bad", filter_args=["AnalysisType=bad"])
    assert code == 1
    assert err_str == "No items matched the analysis ID and filters. Nothing to clone."


def test_clone_analysis_items_no_deps(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    set_up_cache(tmp_path, monkeypatch)
    items = clone.get_analysis_items(analysis_id="fake.rule.1", filter_args=[])
    assert len(items) == 1
    clone.clone_analysis_items(items)

    assert (tmp_path / "rules" / "fake_rule_1.yaml").exists()
    assert (tmp_path / "rules" / "fake_rule_1.py").exists()
    assert not (tmp_path / "global_helpers" / "fake_global_helper_1.yaml").exists()
    assert not (tmp_path / "global_helpers" / "fake_global_helper_1.py").exists()
    assert not (tmp_path / "data_models" / "fake_datamodel_1.yaml").exists()
    assert not (tmp_path / "data_models" / "fake_datamodel_1.py").exists()
    assert not (tmp_path / "global_helpers" / "fake_global_helper_2.yaml").exists()
    assert not (tmp_path / "global_helpers" / "fake_global_helper_2.py").exists()
    assert not (tmp_path / "data_models" / "fake_datamodel_2.yaml").exists()
    assert not (tmp_path / "data_models" / "fake_datamodel_2.py").exists()


def test_clone_analysis_items_with_deps(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    set_up_cache(tmp_path, monkeypatch)
    items = clone.get_analysis_items(analysis_id="fake.rule.with.deps", filter_args=[])
    assert len(items) == 1
    clone.clone_analysis_items(items)

    assert (tmp_path / "rules" / "fake_rule_with_deps.yaml").exists()
    assert (tmp_path / "rules" / "fake_rule_with_deps.py").exists()

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


def test_clone_from_subdirectory_creates_files_at_project_root_monorepo(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    """
    Test that cloning from a subdirectory in a monorepo creates files at project root,
    not in the subdirectory where the command was run.
    """
    import os

    from panther_analysis_tool.constants import (
        CACHE_DIR,
        CACHED_VERSIONS_FILE_PATH,
        PANTHER_ANALYSIS_SQLITE_FILE_PATH,
        PAT_ROOT_FILE_NAME,
    )

    git_root = tmp_path
    project_root = git_root / "pa"
    subdir = project_root / "some" / "nested" / "directory"

    project_root.mkdir(parents=True, exist_ok=True)
    subdir.mkdir(parents=True, exist_ok=True)
    (project_root / PAT_ROOT_FILE_NAME).touch()

    monkeypatch.chdir(subdir)

    # Mock git_root to return the actual git root
    mocker.patch("panther_analysis_tool.core.git_helpers.git_root", return_value=git_root)

    # Mock the actual chdir to track where we chdir to
    actual_chdirs = []
    original_chdir = os.chdir

    def track_chdir(path):
        actual_chdirs.append(pathlib.Path(path).resolve())
        return original_chdir(path)

    mocker.patch("os.chdir", side_effect=track_chdir)

    # Set up cache at project root
    monkeypatch.chdir(project_root)
    PANTHER_ANALYSIS_SQLITE_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    PANTHER_ANALYSIS_SQLITE_FILE_PATH.touch()
    pa_clone_path = CACHE_DIR / "panther-analysis"
    pa_clone_path.mkdir(parents=True, exist_ok=True)
    _FAKE_VERSIONS_FILE_SIMPLE = yaml.dump(
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
                        }
                    },
                }
            }
        }
    )
    CACHED_VERSIONS_FILE_PATH.write_text(_FAKE_VERSIONS_FILE_SIMPLE)
    cache = analysis_cache.AnalysisCache()
    cache.create_tables()
    insert_spec(cache, _FAKE_RULE_1_V1, 1, "RuleID", "fake.rule.1", _FAKE_PY)

    # Mock cache operations
    mocker.patch(
        "panther_analysis_tool.command.clone.analysis_cache.update_with_latest_panther_analysis",
        return_value=None,
    )

    # Mock AnalysisCache to return our pre-populated cache
    def mock_analysis_cache(*args, **kwargs):
        return cache

    mocker.patch(
        "panther_analysis_tool.command.clone.analysis_cache.AnalysisCache",
        side_effect=mock_analysis_cache,
    )

    # Reset versions_file cache to ensure it reads from the file we just created
    mocker.patch(
        "panther_analysis_tool.core.versions_file._VERSIONS",
        None,
    )

    # Run clone command
    clone.run(analysis_id="fake.rule.1", filter_args=[])

    # Verify we chdir'd to project root
    assert len(actual_chdirs) >= 1
    assert actual_chdirs[0] == project_root.resolve()

    # Verify files were created at project root, not in subdirectory
    assert (project_root / "rules" / "fake_rule_1.yaml").exists()
    assert (project_root / "rules" / "fake_rule_1.py").exists()
    assert not (subdir / "rules" / "fake_rule_1.yaml").exists()

    # Verify cache is at project root
    assert (project_root / CACHE_DIR).exists()
    assert not (subdir / CACHE_DIR).exists()


def test_clone_from_subdirectory_creates_files_at_git_root_normal_repo(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    """
    Test that cloning from a subdirectory in a normal repo (no .pat-root)
    creates files at git root.
    """
    import os

    from panther_analysis_tool.constants import (
        CACHE_DIR,
        CACHED_VERSIONS_FILE_PATH,
        PANTHER_ANALYSIS_SQLITE_FILE_PATH,
    )

    git_root = tmp_path
    subdir = git_root / "some" / "nested" / "directory"
    subdir.mkdir(parents=True, exist_ok=True)

    monkeypatch.chdir(subdir)

    mocker.patch("panther_analysis_tool.core.git_helpers.git_root", return_value=git_root)

    # Track chdir calls
    actual_chdirs = []
    original_chdir = os.chdir

    def track_chdir(path):
        actual_chdirs.append(pathlib.Path(path).resolve())
        return original_chdir(path)

    mocker.patch("os.chdir", side_effect=track_chdir)

    # Set up cache at git root
    monkeypatch.chdir(git_root)
    PANTHER_ANALYSIS_SQLITE_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    PANTHER_ANALYSIS_SQLITE_FILE_PATH.touch()
    pa_clone_path = CACHE_DIR / "panther-analysis"
    pa_clone_path.mkdir(parents=True, exist_ok=True)
    _FAKE_VERSIONS_FILE_SIMPLE = yaml.dump(
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
                        }
                    },
                }
            }
        }
    )
    CACHED_VERSIONS_FILE_PATH.write_text(_FAKE_VERSIONS_FILE_SIMPLE)
    cache = analysis_cache.AnalysisCache()
    cache.create_tables()
    insert_spec(cache, _FAKE_RULE_1_V1, 1, "RuleID", "fake.rule.1", _FAKE_PY)

    mocker.patch(
        "panther_analysis_tool.command.clone.analysis_cache.update_with_latest_panther_analysis",
        return_value=None,
    )

    # Mock AnalysisCache to return our pre-populated cache
    def mock_analysis_cache(*args, **kwargs):
        return cache

    mocker.patch(
        "panther_analysis_tool.command.clone.analysis_cache.AnalysisCache",
        side_effect=mock_analysis_cache,
    )

    # Reset versions_file cache to ensure it reads from the file we just created
    mocker.patch(
        "panther_analysis_tool.core.versions_file._VERSIONS",
        None,
    )

    # Run clone command
    clone.run(analysis_id="fake.rule.1", filter_args=[])

    # Verify we chdir'd to git root
    assert len(actual_chdirs) >= 1
    assert actual_chdirs[0] == git_root.resolve()

    # Verify files were created at git root, not in subdirectory
    assert (git_root / "rules" / "fake_rule_1.yaml").exists()
    assert (git_root / "rules" / "fake_rule_1.py").exists()
    assert not (subdir / "rules" / "fake_rule_1.yaml").exists()

    # Verify cache is at git root
    assert (git_root / CACHE_DIR).exists()
    assert not (subdir / CACHE_DIR).exists()
