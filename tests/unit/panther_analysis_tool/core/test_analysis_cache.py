import json
import pathlib
from datetime import datetime, timedelta

from _pytest.monkeypatch import MonkeyPatch
from pytest_mock import MockerFixture

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.constants import (
    CACHE_DIR,
    CACHED_VERSIONS_FILE_PATH,
    LATEST_CACHED_PANTHER_ANALYSIS_FILE_PATH,
    PANTHER_ANALYSIS_SQLITE_FILE_PATH,
)
from panther_analysis_tool.core import analysis_cache, versions_file, yaml

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
        "NewField": "fake_rule_2_v2",
    }
)

_FAKE_USER_RULE_2_V1 = yaml.dump(
    {
        "AnalysisType": "rule",
        "Filename": "fake_user_rule_2.py",
        "RuleID": "fake.rule.2",  # matches _FAKE_RULE_2_V2
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


def set_up_cache(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> analysis_cache.AnalysisCache:
    monkeypatch.chdir(tmp_path)
    pa_clone_path = CACHE_DIR / "panther-analysis"
    pa_clone_path.mkdir(parents=True, exist_ok=True)

    PANTHER_ANALYSIS_SQLITE_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    PANTHER_ANALYSIS_SQLITE_FILE_PATH.touch()

    # fake cloning panther-analysis repository
    create_file_with_text(pa_clone_path / "rules" / "fake_rule_1.yaml", _FAKE_RULE_1_V1)
    create_file_with_text(pa_clone_path / "rules" / "fake_rule_1.py", _FAKE_PY)
    create_file_with_text(pa_clone_path / "rules" / "fake_rule_2.yaml", _FAKE_RULE_2_V2)
    create_file_with_text(pa_clone_path / "rules" / "fake_rule_2.py", _FAKE_PY)
    create_file_with_text(
        pa_clone_path / "data_models" / "fake_datamodel_1.yaml", _FAKE_DATAMODEL_1_V1
    )
    create_file_with_text(pa_clone_path / "data_models" / "fake_datamodel_1.py", _FAKE_PY)
    create_file_with_text(
        pa_clone_path / "lookup_tables" / "fake_lookup_table_1.yaml", _FAKE_LOOKUP_TABLE_1_V1
    )
    create_file_with_text(
        pa_clone_path / "global_helpers" / "fake_global_helper_1.yaml", _FAKE_GLOBAL_HELPER_1_V1
    )
    create_file_with_text(pa_clone_path / "global_helpers" / "fake_global_helper_1.py", _FAKE_PY)
    create_file_with_text(
        pa_clone_path / "correlation_rules" / "fake_correlation_rule_1.yaml",
        _FAKE_CORRELATION_RULE_1_V1,
    )
    create_file_with_text(pa_clone_path / "policies" / "fake_policy_1.yaml", _FAKE_POLICY_1_V1)
    create_file_with_text(pa_clone_path / "policies" / "fake_policy_1.py", _FAKE_PY)
    create_file_with_text(
        pa_clone_path / "scheduled_rules" / "fake_scheduled_rule_1.yaml",
        _FAKE_SCHEDULED_RULE_1_V1,
    )
    create_file_with_text(pa_clone_path / "scheduled_rules" / "fake_scheduled_rule_1.py", _FAKE_PY)
    create_file_with_text(
        pa_clone_path / "saved_queries" / "fake_saved_query_1.yaml", _FAKE_SAVED_QUERY_1_V1
    )
    create_file_with_text(
        pa_clone_path / "scheduled_queries" / "fake_scheduled_query_1.yaml",
        _FAKE_SCHEDULED_QUERY_1_V1,
    )

    create_file_with_text(CACHED_VERSIONS_FILE_PATH, _FAKE_VERSIONS_FILE)

    # fake user's analysis items
    pathlib.Path("rules").mkdir(parents=True, exist_ok=True)
    create_file_with_text(pathlib.Path("rules") / "fake_user_rule_2.yaml", _FAKE_USER_RULE_2_V1)
    create_file_with_text(pathlib.Path("rules") / "fake_user_rule_2.py", _FAKE_PY)

    cache = analysis_cache.AnalysisCache()
    cache.create_tables()
    return cache


def create_file_with_text(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()
    path.write_text(text)


def dump_sqlite(cache: analysis_cache.AnalysisCache) -> None:
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


def populate_sqlite_with_test_data(cache: analysis_cache.AnalysisCache) -> None:
    user_analysis_specs = {
        spec.analysis_id(): spec for spec in analysis_utils.load_analysis_specs_ex(["."], [], True)
    }
    versions = versions_file.get_versions().versions

    for spec in analysis_utils.load_analysis_specs_ex([str(CACHE_DIR)], [], True):
        analysis_cache._populate_sqlite(spec, cache, user_analysis_specs, versions)


def get_analysis_cache(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> analysis_cache.AnalysisCache:
    monkeypatch.chdir(tmp_path)
    PANTHER_ANALYSIS_SQLITE_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    PANTHER_ANALYSIS_SQLITE_FILE_PATH.touch()
    return analysis_cache.AnalysisCache()


def test_create_tables(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    analysis_cache = get_analysis_cache(tmp_path, monkeypatch)
    analysis_cache.create_tables()

    tables = analysis_cache.cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    tables = [table[0] for table in tables]
    assert "analysis_specs" in tables
    assert "files" in tables
    assert "file_mappings" in tables

    indexes = analysis_cache.cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='index'"
    ).fetchall()
    indexes = [index[0] for index in indexes]
    assert "idx_analysis_specs_unique" in indexes
    assert "idx_file_mappings_unique" in indexes


def test_insert_spec(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    analysis_cache = get_analysis_cache(tmp_path, monkeypatch)
    analysis_cache.create_tables()
    analysis_cache._insert_spec("id_field1", "id_value1", b"test", 1)
    assert analysis_cache.cursor.execute("SELECT COUNT(*) FROM analysis_specs").fetchone()[0] == 1
    assert analysis_cache.cursor.execute("SELECT COUNT(*) FROM analysis_specs").fetchone()[0] == 1
    assert analysis_cache.cursor.execute(
        "SELECT id_field, id_value, spec, version FROM analysis_specs WHERE id = 1"
    ).fetchone() == ("id_field1", "id_value1", b"test", 1)


def test_insert_file(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    analysis_cache = get_analysis_cache(tmp_path, monkeypatch)
    analysis_cache.create_tables()
    file_id = analysis_cache._insert_file(b"test")
    assert file_id == 1
    assert analysis_cache.cursor.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 1
    assert (
        analysis_cache.cursor.execute("SELECT content FROM files WHERE id = 1").fetchone()[0]
        == b"test"
    )


def test_insert_file_mapping(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    analysis_cache = get_analysis_cache(tmp_path, monkeypatch)
    analysis_cache.create_tables()
    analysis_cache._insert_file_mapping(spec_id=1, version=1, file_id=1)
    assert analysis_cache.cursor.execute("SELECT COUNT(*) FROM file_mappings").fetchone()[0] == 1
    assert analysis_cache.cursor.execute(
        "SELECT spec_id, version, file_id FROM file_mappings WHERE id = 1"
    ).fetchone() == (1, 1, 1)


def test_list_spec_ids(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    analysis_cache = get_analysis_cache(tmp_path, monkeypatch)
    analysis_cache.create_tables()
    analysis_cache._insert_spec("id_field1", "id_value1", b"test", 1)
    analysis_cache._insert_spec("id_field2", "id_value2", b"test", 1)
    assert analysis_cache.list_spec_ids() == ["id_value1", "id_value2"]


def test_insert_analysis_spec(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    cache = get_analysis_cache(tmp_path, monkeypatch)
    cache.create_tables()
    cache.insert_analysis_spec(
        analysis_cache.AnalysisSpec(
            id=1, spec=b"test", version=1, id_field="id_field", id_value="id_value"
        ),
        b"test",
    )
    assert cache.cursor.execute("SELECT COUNT(*) FROM analysis_specs").fetchone()[0] == 1
    assert cache.cursor.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 1
    assert cache.cursor.execute("SELECT COUNT(*) FROM file_mappings").fetchone()[0] == 1
    assert cache.cursor.execute(
        "SELECT id_field, id_value, spec, version FROM analysis_specs WHERE id = 1"
    ).fetchone() == ("id_field", "id_value", b"test", 1)
    assert cache.cursor.execute(
        "SELECT spec_id, file_id FROM file_mappings WHERE id = 1"
    ).fetchone() == (1, 1)
    assert cache.cursor.execute("SELECT content FROM files WHERE id = 1").fetchone()[0] == b"test"


def test_insert_analysis_spec_with_none_py_file_contents(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    cache = get_analysis_cache(tmp_path, monkeypatch)
    cache.create_tables()
    cache.insert_analysis_spec(
        analysis_cache.AnalysisSpec(
            id=1, spec=b"test", version=1, id_field="id_field", id_value="id_value"
        ),
        None,
    )
    assert cache.cursor.execute("SELECT COUNT(*) FROM analysis_specs").fetchone()[0] == 1
    assert cache.cursor.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0
    assert cache.cursor.execute("SELECT COUNT(*) FROM file_mappings").fetchone()[0] == 0
    assert cache.cursor.execute(
        "SELECT id_field, id_value, spec, version FROM analysis_specs WHERE id = 1"
    ).fetchone() == ("id_field", "id_value", b"test", 1)
    assert (
        cache.cursor.execute("SELECT spec_id, file_id FROM file_mappings WHERE id = 1").fetchone()
        is None
    )
    assert cache.cursor.execute("SELECT content FROM files WHERE id = 1").fetchone() is None


def test_insert_analysis_spec_duplicate(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    cache = get_analysis_cache(tmp_path, monkeypatch)
    cache.create_tables()
    cache.insert_analysis_spec(
        analysis_cache.AnalysisSpec(
            id=1, spec=b"test", version=1, id_field="id_field", id_value="id_value"
        ),
        b"test",
    )
    cache.insert_analysis_spec(
        analysis_cache.AnalysisSpec(
            id=1, spec=b"test", version=1, id_field="id_field", id_value="id_value"
        ),
        b"test",
    )
    assert cache.cursor.execute("SELECT COUNT(*) FROM analysis_specs").fetchone()[0] == 1
    assert cache.cursor.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 1
    assert cache.cursor.execute("SELECT COUNT(*) FROM file_mappings").fetchone()[0] == 1


def test_get_file_for_spec(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    cache = get_analysis_cache(tmp_path, monkeypatch)
    cache.create_tables()
    spec_id = cache._insert_spec("id_field1", "id_value1", b"test", 1)
    file_id = cache._insert_file(b"test") or -1
    cache._insert_file_mapping(spec_id=spec_id, version=1, file_id=file_id)
    assert cache.get_file_for_spec(analysis_spec_id=spec_id, version=1) == b"test"


def test_get_file_by_id(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    cache = get_analysis_cache(tmp_path, monkeypatch)
    cache.create_tables()
    file_id = cache._insert_file(b"test") or -1
    assert cache.get_file_by_id(file_id) == b"test"


def test_get_spec_for_version(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    cache = get_analysis_cache(tmp_path, monkeypatch)
    cache.create_tables()
    cache._insert_spec("id_field", "id_value", b"test1", 1)
    cache._insert_spec("id_field", "id_value", b"test2", 2)
    assert cache.get_spec_for_version("id_value", 2) == analysis_cache.AnalysisSpec(
        id=2, spec=b"test2", version=2, id_field="id_field", id_value="id_value"
    )
    assert cache.get_spec_for_version("id_value", 3) is None


def test_get_latest_spec(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    cache = get_analysis_cache(tmp_path, monkeypatch)
    cache.create_tables()
    cache._insert_spec("id_field", "id_value", b"test1", 1)
    cache._insert_spec("id_field", "id_value", b"test2", 2)
    assert cache.get_latest_spec("id_value") == analysis_cache.AnalysisSpec(
        id=2, spec=b"test2", version=2, id_field="id_field", id_value="id_value"
    )
    assert cache.get_latest_spec("id_value3") is None


def test_insert_different_spec_versions(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    cache = get_analysis_cache(tmp_path, monkeypatch)
    cache.create_tables()
    cache.insert_analysis_spec(
        analysis_cache.AnalysisSpec(
            id=1, spec=b"test1", version=1, id_field="id_field", id_value="id_value"
        ),
        b"test1",
    )
    cache.insert_analysis_spec(
        analysis_cache.AnalysisSpec(
            id=2, spec=b"test2", version=2, id_field="id_field", id_value="id_value"
        ),
        b"test2",
    )
    assert cache.cursor.execute("SELECT COUNT(*) FROM analysis_specs").fetchone()[0] == 2
    assert cache.cursor.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 2
    assert cache.cursor.execute("SELECT COUNT(*) FROM file_mappings").fetchone()[0] == 2

    spec1 = cache.get_spec_for_version("id_value", 1)
    spec2 = cache.get_spec_for_version("id_value", 2)
    assert spec1 == analysis_cache.AnalysisSpec(
        id=1, spec=b"test1", version=1, id_field="id_field", id_value="id_value"
    )
    assert spec2 == analysis_cache.AnalysisSpec(
        id=2, spec=b"test2", version=2, id_field="id_field", id_value="id_value"
    )
    assert cache.get_file_for_spec(spec1.id or -1, spec1.version) == b"test1"
    assert cache.get_file_for_spec(spec2.id or -1, spec2.version) == b"test2"


########################################################
# Tests for _populate_sqlite
########################################################


def test_populate_works_with_latest_versions(
    tmp_path: pathlib.Path,
    monkeypatch: MonkeyPatch,
    mocker: MockerFixture,
) -> None:
    mocker.patch(
        "panther_analysis_tool.core.analysis_cache.git_helpers.get_panther_analysis_file_contents",
        side_effect=[_FAKE_RULE_1_V1, _FAKE_PY],
    )
    cache = set_up_cache(tmp_path, monkeypatch)
    populate_sqlite_with_test_data(cache)

    latest_spec = cache.get_latest_spec("fake.rule.1")
    assert latest_spec is not None
    assert latest_spec.spec.decode("utf-8") == _FAKE_RULE_1_V1
    assert latest_spec.version == 1
    assert latest_spec.id_field == "RuleID"
    assert latest_spec.id_value == "fake.rule.1"

    py_file = cache.get_file_for_spec(latest_spec.id or -1, latest_spec.version)
    assert py_file is not None
    assert py_file.decode("utf-8") == _FAKE_PY

    latest_spec_2 = cache.get_latest_spec("fake.rule.2")
    assert latest_spec_2 is not None
    assert latest_spec_2.spec.decode("utf-8") == _FAKE_RULE_2_V2
    assert latest_spec_2.version == 2
    assert latest_spec_2.id_field == "RuleID"
    assert latest_spec_2.id_value == "fake.rule.2"

    py_file = cache.get_file_for_spec(latest_spec.id or -1, latest_spec.version)
    assert py_file is not None
    assert py_file.decode("utf-8") == _FAKE_PY


def test_populate_works_when_user_has_old_version(
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    monkeypatch: MonkeyPatch,
) -> None:
    mocker.patch(
        "panther_analysis_tool.core.analysis_cache.git_helpers.get_panther_analysis_file_contents",
        side_effect=[_FAKE_RULE_2_V1, _FAKE_PY + "old"],
    )
    cache = set_up_cache(tmp_path, monkeypatch)
    populate_sqlite_with_test_data(cache)

    latest_spec = cache.get_latest_spec("fake.rule.2")
    assert latest_spec is not None
    assert latest_spec.spec.decode("utf-8") == _FAKE_RULE_2_V2
    assert latest_spec.version == 2
    assert latest_spec.id_field == "RuleID"
    assert latest_spec.id_value == "fake.rule.2"

    py_file = cache.get_file_for_spec(latest_spec.id or -1, latest_spec.version)
    assert py_file is not None
    assert py_file.decode("utf-8") == _FAKE_PY

    old_spec = cache.get_spec_for_version("fake.rule.2", 1)
    assert old_spec is not None
    assert old_spec.spec.decode("utf-8") == _FAKE_RULE_2_V1
    assert old_spec.version == 1
    assert old_spec.id_field == "RuleID"
    assert old_spec.id_value == "fake.rule.2"

    py_file = cache.get_file_for_spec(old_spec.id or -1, old_spec.version)
    assert py_file is not None
    assert py_file.decode("utf-8") == _FAKE_PY + "old"


def test_populate_works_with_datamodel(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    cache = set_up_cache(tmp_path, monkeypatch)
    populate_sqlite_with_test_data(cache)

    latest_spec = cache.get_latest_spec("fake.datamodel.1")
    assert latest_spec is not None
    assert latest_spec.spec.decode("utf-8") == _FAKE_DATAMODEL_1_V1
    assert latest_spec.version == 1
    assert latest_spec.id_field == "DataModelID"
    assert latest_spec.id_value == "fake.datamodel.1"

    py_file = cache.get_file_for_spec(latest_spec.id or -1, latest_spec.version)
    assert py_file is not None
    assert py_file.decode("utf-8") == _FAKE_PY


def test_populate_works_with_lookup_table(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    cache = set_up_cache(tmp_path, monkeypatch)
    populate_sqlite_with_test_data(cache)

    latest_spec = cache.get_latest_spec("fake.lookup_table.1")
    assert latest_spec is not None
    assert latest_spec.spec.decode("utf-8") == _FAKE_LOOKUP_TABLE_1_V1
    assert latest_spec.version == 1
    assert latest_spec.id_field == "LookupName"
    assert latest_spec.id_value == "fake.lookup_table.1"


def test_populate_works_with_global_helper(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    cache = set_up_cache(tmp_path, monkeypatch)
    populate_sqlite_with_test_data(cache)

    latest_spec = cache.get_latest_spec("fake.global_helper.1")
    assert latest_spec is not None
    assert latest_spec.spec.decode("utf-8") == _FAKE_GLOBAL_HELPER_1_V1
    assert latest_spec.version == 1
    assert latest_spec.id_field == "GlobalID"
    assert latest_spec.id_value == "fake.global_helper.1"

    py_file = cache.get_file_for_spec(latest_spec.id or -1, latest_spec.version)
    assert py_file is not None
    assert py_file.decode("utf-8") == _FAKE_PY


def test_populate_works_with_correlation_rule(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    cache = set_up_cache(tmp_path, monkeypatch)
    populate_sqlite_with_test_data(cache)

    latest_spec = cache.get_latest_spec("fake.correlation_rule.1")
    assert latest_spec is not None
    assert latest_spec.spec.decode("utf-8") == _FAKE_CORRELATION_RULE_1_V1
    assert latest_spec.version == 1
    assert latest_spec.id_field == "RuleID"
    assert latest_spec.id_value == "fake.correlation_rule.1"


def test_populate_works_with_policy(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    cache = set_up_cache(tmp_path, monkeypatch)
    populate_sqlite_with_test_data(cache)

    latest_spec = cache.get_latest_spec("fake.policy.1")
    assert latest_spec is not None
    assert latest_spec.spec.decode("utf-8") == _FAKE_POLICY_1_V1
    assert latest_spec.version == 1
    assert latest_spec.id_field == "PolicyID"
    assert latest_spec.id_value == "fake.policy.1"

    py_file = cache.get_file_for_spec(latest_spec.id or -1, latest_spec.version)
    assert py_file is not None
    assert py_file.decode("utf-8") == _FAKE_PY


def test_populate_works_with_scheduled_rule(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    cache = set_up_cache(tmp_path, monkeypatch)
    populate_sqlite_with_test_data(cache)

    latest_spec = cache.get_latest_spec("fake.scheduled_rule.1")
    assert latest_spec is not None
    assert latest_spec.spec.decode("utf-8") == _FAKE_SCHEDULED_RULE_1_V1
    assert latest_spec.version == 1
    assert latest_spec.id_field == "RuleID"
    assert latest_spec.id_value == "fake.scheduled_rule.1"

    py_file = cache.get_file_for_spec(latest_spec.id or -1, latest_spec.version)
    assert py_file is not None
    assert py_file.decode("utf-8") == _FAKE_PY


def test_populate_works_with_saved_query(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    cache = set_up_cache(tmp_path, monkeypatch)
    populate_sqlite_with_test_data(cache)

    latest_spec = cache.get_latest_spec("fake.saved_query.1")
    assert latest_spec is not None
    assert latest_spec.spec.decode("utf-8") == _FAKE_SAVED_QUERY_1_V1
    assert latest_spec.version == 1
    assert latest_spec.id_field == "QueryName"
    assert latest_spec.id_value == "fake.saved_query.1"


def test_populate_works_with_scheduled_query(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    cache = set_up_cache(tmp_path, monkeypatch)
    populate_sqlite_with_test_data(cache)

    latest_spec = cache.get_latest_spec("fake.scheduled_query.1")
    assert latest_spec is not None
    assert latest_spec.spec.decode("utf-8") == _FAKE_SCHEDULED_QUERY_1_V1
    assert latest_spec.version == 1
    assert latest_spec.id_field == "QueryName"
    assert latest_spec.id_value == "fake.scheduled_query.1"


def test_cache_is_latest(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert not LATEST_CACHED_PANTHER_ANALYSIS_FILE_PATH.exists()

    # First call with empty cache should return False and create cache
    assert not analysis_cache._cache_is_latest("main", "fake_commit_hash_1")
    cached = analysis_cache.LatestCachedCommit.load()
    assert cached.commit == "fake_commit_hash_1"
    assert not cached.is_expired()

    # Same commit should return True (commit matches)
    assert analysis_cache._cache_is_latest("main", "fake_commit_hash_1")
    # Expiration should be refreshed
    cached = analysis_cache.LatestCachedCommit.load()
    assert cached.commit == "fake_commit_hash_1"
    assert not cached.is_expired()

    # Different commit should return False and update cache
    assert not analysis_cache._cache_is_latest("main", "fake_commit_hash_2")
    cached = analysis_cache.LatestCachedCommit.load()
    assert cached.commit == "fake_commit_hash_2"
    assert not cached.is_expired()

    # Same commit should return True again
    assert analysis_cache._cache_is_latest("main", "fake_commit_hash_2")
    # Expiration should be refreshed again
    cached = analysis_cache.LatestCachedCommit.load()
    assert cached.commit == "fake_commit_hash_2"
    assert not cached.is_expired()

    # Empty commit should return False and not update cache
    assert not analysis_cache._cache_is_latest("main", "")
    cached = analysis_cache.LatestCachedCommit.load()
    assert cached.commit == "fake_commit_hash_2"  # Should remain unchanged


def test_update_with_latest_panther_analysis_skips_if_cache_is_latest(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    mock_get_commit = mocker.patch(
        "panther_analysis_tool.core.analysis_cache.git_helpers.panther_analysis_latest_release_commit",
        return_value="fake_commit_hash_1",
    )
    monkeypatch.chdir(tmp_path)
    LATEST_CACHED_PANTHER_ANALYSIS_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    LATEST_CACHED_PANTHER_ANALYSIS_FILE_PATH.touch()
    # Set expiration in the past (cache is expired, but commit will match)
    expiration = datetime.now() - timedelta(hours=2)
    LATEST_CACHED_PANTHER_ANALYSIS_FILE_PATH.write_text(
        analysis_cache.LatestCachedCommit(
            commit="fake_commit_hash_1", expiration=expiration
        ).model_dump_json()
    )

    analysis_cache.update_with_latest_panther_analysis()
    result = analysis_cache.LatestCachedCommit(
        **json.loads(LATEST_CACHED_PANTHER_ANALYSIS_FILE_PATH.read_text())
    )
    # Cache commit should match, and expiration should be refreshed
    assert result.commit == "fake_commit_hash_1"
    assert not result.is_expired()  # Expiration should be refreshed to 1 hour from now
    assert not PANTHER_ANALYSIS_SQLITE_FILE_PATH.exists()
    # Verify that panther_analysis_latest_release_commit() was called (cache was expired)
    mock_get_commit.assert_called_once()


def test_update_with_latest_panther_analysis_calls_git_when_cache_expired(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    """
    Test that panther_analysis_latest_release_commit() is called when cache is expired.
    """
    mock_get_commit = mocker.patch(
        "panther_analysis_tool.core.analysis_cache.git_helpers.panther_analysis_latest_release_commit",
        return_value="fake_commit_hash_2",
    )
    mocker.patch("panther_analysis_tool.core.analysis_cache._clone_panther_analysis")
    mocker.patch(
        "panther_analysis_tool.core.analysis_cache.git_helpers.delete_cloned_panther_analysis"
    )
    mocker.patch(
        "panther_analysis_tool.core.analysis_cache.analysis_utils.load_analysis_specs_ex",
        return_value=[],
    )
    monkeypatch.chdir(tmp_path)
    LATEST_CACHED_PANTHER_ANALYSIS_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Create versions file (required by update_with_latest_panther_analysis)
    CACHED_VERSIONS_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    create_file_with_text(CACHED_VERSIONS_FILE_PATH, _FAKE_VERSIONS_FILE)
    # Set expiration in the past (cache is expired)
    expiration = datetime.now() - timedelta(hours=2)
    LATEST_CACHED_PANTHER_ANALYSIS_FILE_PATH.write_text(
        analysis_cache.LatestCachedCommit(
            commit="fake_commit_hash_1", expiration=expiration
        ).model_dump_json()
    )

    analysis_cache.update_with_latest_panther_analysis()
    # Verify that panther_analysis_latest_release_commit() WAS called since cache is expired
    mock_get_commit.assert_called_once()


def test_cache_expiration_logic(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    """
    Test that the cache logic works correctly - expiration is always refreshed, only commit matching matters.
    """
    mocker.patch(
        "panther_analysis_tool.core.analysis_cache.git_helpers.panther_analysis_latest_release_commit",
        return_value="fake_commit_hash_1",
    )
    monkeypatch.chdir(tmp_path)
    LATEST_CACHED_PANTHER_ANALYSIS_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Create a cache that's expired (2 hours ago)
    expiration = datetime.now() - timedelta(hours=2)
    analysis_cache.LatestCachedCommit(commit="fake_commit_hash_1", expiration=expiration).save()

    # Cache should be considered latest (commit matches, expiration doesn't matter)
    assert analysis_cache._cache_is_latest("main", "fake_commit_hash_1")

    # Verify that the expiration was refreshed to 1 hour from now
    result = analysis_cache.LatestCachedCommit.load()
    assert result.commit == "fake_commit_hash_1"
    # Expiration should be approximately 1 hour from now (allow 1 second tolerance)
    expected_expiration = datetime.now() + timedelta(hours=1)
    assert abs((result.expiration - expected_expiration).total_seconds()) < 1

    # Cache should still be considered latest (commit still matches)
    assert analysis_cache._cache_is_latest("main", "fake_commit_hash_1")

    # Test with different commit - should not be latest
    # Different commit should not be latest
    assert not analysis_cache._cache_is_latest("main", "fake_commit_hash_2")

    # Verify commit was updated and expiration was refreshed
    result = analysis_cache.LatestCachedCommit.load()
    assert result.commit == "fake_commit_hash_2"
    assert not result.is_expired()
    # Expiration should be approximately 1 hour from now
    expected_expiration = datetime.now() + timedelta(hours=1)
    assert abs((result.expiration - expected_expiration).total_seconds()) < 1


def test_cache_is_latest_non_main_branch(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    """
    Test that _cache_is_latest returns False for non-main branches.
    """
    monkeypatch.chdir(tmp_path)
    LATEST_CACHED_PANTHER_ANALYSIS_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Create a valid cache
    analysis_cache.LatestCachedCommit(
        commit="fake_commit_hash_1", expiration=datetime.now() + timedelta(hours=1)
    ).save()

    # Non-main branch should return False regardless of commit
    assert not analysis_cache._cache_is_latest("develop", "fake_commit_hash_1")
    assert not analysis_cache._cache_is_latest("feature-branch", "any_commit")


def test_cache_is_expired_non_main_branch(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    """
    Test that _cache_is_expired returns True for non-main branches.
    """
    monkeypatch.chdir(tmp_path)
    LATEST_CACHED_PANTHER_ANALYSIS_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Create a valid cache
    analysis_cache.LatestCachedCommit(
        commit="fake_commit_hash_1", expiration=datetime.now() + timedelta(hours=1)
    ).save()

    # Non-main branch should return True (expired) regardless of actual expiration
    assert analysis_cache._cache_is_expired("develop")
    assert analysis_cache._cache_is_expired("feature-branch")


def test_cache_is_latest_invalid_json(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    """
    Test that _cache_is_latest handles invalid JSON in cache file.
    """
    monkeypatch.chdir(tmp_path)
    LATEST_CACHED_PANTHER_ANALYSIS_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Write invalid JSON to cache file
    LATEST_CACHED_PANTHER_ANALYSIS_FILE_PATH.write_text("invalid json content")

    # Should return False and create new cache
    assert not analysis_cache._cache_is_latest("main", "fake_commit_hash_1")

    # Verify new cache was created
    cached = analysis_cache.LatestCachedCommit.load()
    assert cached.commit == "fake_commit_hash_1"
    assert not cached.is_expired()


def test_cache_is_expired_invalid_json(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    """
    Test that _cache_is_expired handles invalid JSON in cache file.
    """
    monkeypatch.chdir(tmp_path)
    LATEST_CACHED_PANTHER_ANALYSIS_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Write invalid JSON to cache file
    LATEST_CACHED_PANTHER_ANALYSIS_FILE_PATH.write_text("invalid json content")

    # Should return True (expired) for invalid cache
    assert analysis_cache._cache_is_expired("main")


def test_cache_is_latest_missing_keys_in_json(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    """
    Test that _cache_is_latest handles JSON missing required keys (commit or expiration).
    """
    monkeypatch.chdir(tmp_path)
    LATEST_CACHED_PANTHER_ANALYSIS_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Write JSON missing required keys
    LATEST_CACHED_PANTHER_ANALYSIS_FILE_PATH.write_text('{"some_other_key": "value"}')

    # Should return False and create new cache
    assert not analysis_cache._cache_is_latest("main", "fake_commit_hash_1")

    # Verify new cache was created
    cached = analysis_cache.LatestCachedCommit.load()
    assert cached.commit == "fake_commit_hash_1"
    assert not cached.is_expired()


def test_cache_is_expired_missing_keys_in_json(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    """
    Test that _cache_is_expired handles JSON missing required keys (commit or expiration).
    """
    monkeypatch.chdir(tmp_path)
    LATEST_CACHED_PANTHER_ANALYSIS_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Write JSON missing required keys
    LATEST_CACHED_PANTHER_ANALYSIS_FILE_PATH.write_text('{"some_other_key": "value"}')

    # Should return True (expired) for invalid cache
    assert analysis_cache._cache_is_expired("main")


def test_cache_is_latest_empty_commit_with_existing_cache(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    """
    Test that _cache_is_latest handles empty commit string with existing cache.
    """
    monkeypatch.chdir(tmp_path)
    LATEST_CACHED_PANTHER_ANALYSIS_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Create existing cache
    original_commit = "fake_commit_hash_1"
    original_expiration = datetime.now() + timedelta(hours=1)
    analysis_cache.LatestCachedCommit(commit=original_commit, expiration=original_expiration).save()

    # Call with empty commit - should return False and not update cache
    assert not analysis_cache._cache_is_latest("main", "")

    # Verify cache was not modified
    cached = analysis_cache.LatestCachedCommit.load()
    assert cached.commit == original_commit
    assert cached.expiration == original_expiration


def test_cache_is_expired_with_valid_cache(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    """
    Test that _cache_is_expired correctly identifies expired and non-expired caches.
    """
    monkeypatch.chdir(tmp_path)
    LATEST_CACHED_PANTHER_ANALYSIS_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Test with non-expired cache
    expiration = datetime.now() + timedelta(hours=1)
    analysis_cache.LatestCachedCommit(commit="fake_commit_hash_1", expiration=expiration).save()
    assert not analysis_cache._cache_is_expired("main")

    # Test with expired cache
    expiration = datetime.now() - timedelta(hours=2)
    analysis_cache.LatestCachedCommit(commit="fake_commit_hash_1", expiration=expiration).save()
    assert analysis_cache._cache_is_expired("main")

    # Test with empty cache file
    LATEST_CACHED_PANTHER_ANALYSIS_FILE_PATH.write_text("")
    assert analysis_cache._cache_is_expired("main")


def test_populate_skips_packs(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    PANTHER_ANALYSIS_SQLITE_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    PANTHER_ANALYSIS_SQLITE_FILE_PATH.touch()
    cache = analysis_cache.AnalysisCache()
    cache.create_tables()
    assert cache.list_spec_ids() == []

    spec = analysis_utils.LoadAnalysisSpecsResult(
        spec_filename="fake.pack.1.yaml",
        relative_path="fake.pack.1.yaml",
        analysis_spec={"AnalysisType": "pack", "PackID": "fake.pack.1"},
        yaml_ctx=yaml.BlockStyleYAML(),
        error=None,
        raw_spec_file_content=b"",
    )
    versions = {
        "fake.pack.1": versions_file.AnalysisVersionItem(
            version=1,
            sha256="fake.pack.1.sha256",
            type="pack",
            history={
                1: versions_file.AnalysisVersionHistoryItem(
                    commit_hash="fake.pack.1.commit.hash",
                    yaml_file_path="fake.pack.1.yaml",
                    py_file_path="fake.pack.1.py",
                ),
            },
        )
    }
    analysis_cache._populate_sqlite(spec, cache, {}, versions)
    assert cache.list_spec_ids() == []


def test_populate_skips_experimental_detections(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    PANTHER_ANALYSIS_SQLITE_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    PANTHER_ANALYSIS_SQLITE_FILE_PATH.touch()
    cache = analysis_cache.AnalysisCache()
    cache.create_tables()
    assert cache.list_spec_ids() == []

    spec = analysis_utils.LoadAnalysisSpecsResult(
        spec_filename="fake_rule_1.yaml",
        relative_path=str(tmp_path / "fake_rule_1.yaml"),
        analysis_spec={"AnalysisType": "rule", "RuleID": "fake_rule_1", "Status": "experimental"},
        yaml_ctx=yaml.BlockStyleYAML(),
        error=None,
        raw_spec_file_content=b"",
    )
    analysis_cache._populate_sqlite(spec, cache, {}, {})
    assert cache.list_spec_ids() == []
