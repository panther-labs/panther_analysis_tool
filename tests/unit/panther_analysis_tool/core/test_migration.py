import pathlib
from typing import Callable

import pytest
from _pytest.monkeypatch import MonkeyPatch

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.constants import PANTHER_ANALYSIS_SQLITE_FILE_PATH
from panther_analysis_tool.core import analysis_cache, migration, yaml


def _type_to_id_field(analysis_type: str) -> str:
    return {
        "rule": "RuleID",
        "policy": "PolicyID",
        "datamodel": "DataModelID",
    }[analysis_type]


make_load_spec_type = Callable[
    [pathlib.Path, str, str, int | None, str | None], analysis_utils.LoadAnalysisSpecsResult
]


@pytest.fixture
def make_load_spec() -> make_load_spec_type:
    def _make_load_spec(
        tmp_path: pathlib.Path,
        analysis_type: str,
        analysis_id: str,
        base_version: int | None,
        python_contents: str | None = None,
    ) -> analysis_utils.LoadAnalysisSpecsResult:
        python_file = f"{analysis_id}.py" if python_contents is not None else None
        spec = {
            "AnalysisType": analysis_type,
            _type_to_id_field(analysis_type): analysis_id,
            **({"BaseVersion": base_version} if base_version is not None else {}),
            **({"Filename": python_file} if python_file is not None else {}),
        }
        spec_path = tmp_path / f"{analysis_id}.yml"
        raw_spec = yaml.dump(spec).encode("utf-8")
        spec_path.write_bytes(raw_spec)
        if python_contents is not None and python_file is not None:
            pathlib.Path(tmp_path / python_file).write_text(python_contents)

        return analysis_utils.LoadAnalysisSpecsResult(
            spec_filename=str(spec_path),
            relative_path=".",
            analysis_spec=spec,
            yaml_ctx=yaml.BlockStyleYAML(),
            error=None,
            raw_spec_file_content=raw_spec,
        )

    return _make_load_spec


make_analysis_spec_type = Callable[[str, str, int, dict], analysis_cache.AnalysisSpec]


@pytest.fixture
def make_analysis_spec() -> make_analysis_spec_type:
    def _make_analysis_spec(
        analysis_type: str, analysis_id: str, version: int, spec: dict
    ) -> analysis_cache.AnalysisSpec:
        return analysis_cache.AnalysisSpec(
            id=123534891243894,
            spec=yaml.dump(spec).encode("utf-8"),
            version=version,
            id_field=_type_to_id_field(analysis_type),
            id_value=analysis_id,
        )

    return _make_analysis_spec


_FAKE_PY = b"""
def rule(event):
    return True
"""


def setup(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> analysis_cache.AnalysisCache:
    monkeypatch.chdir(tmp_path)
    PANTHER_ANALYSIS_SQLITE_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    PANTHER_ANALYSIS_SQLITE_FILE_PATH.touch()
    cache = analysis_cache.AnalysisCache()
    cache.create_tables()
    return cache


def test_migrate_analysis_item_no_conflict(
    tmp_path: pathlib.Path,
    monkeypatch: MonkeyPatch,
    make_load_spec: make_load_spec_type,
    make_analysis_spec: make_analysis_spec_type,
) -> None:
    cache = setup(tmp_path, monkeypatch)

    user_spec = make_load_spec(tmp_path, "rule", "rule_1", None, _FAKE_PY.decode("utf-8"))
    cache.insert_analysis_spec(
        # pretend PA added a new field that should not cause a conflict
        make_analysis_spec("rule", "rule_1", 1, user_spec.analysis_spec | {"new": "field"}),
        _FAKE_PY,
    )

    has_conflict = migration.migrate_analysis_item(user_spec, cache)
    assert not has_conflict

    spec_path = pathlib.Path(user_spec.spec_filename)
    py_path = user_spec.python_file_path()

    assert user_spec.analysis_spec["BaseVersion"] == 1
    assert spec_path.exists()
    assert py_path is not None
    assert py_path.exists()
    assert dict(yaml.load(spec_path.read_text())) == {
        "AnalysisType": "rule",
        "RuleID": "rule_1",
        "BaseVersion": 1,
        "new": "field",
        "Filename": "rule_1.py",
    }
    assert py_path.read_text() == _FAKE_PY.decode("utf-8")


def test_migrate_analysis_item_no_conflict_no_python(
    tmp_path: pathlib.Path,
    monkeypatch: MonkeyPatch,
    make_load_spec: make_load_spec_type,
    make_analysis_spec: make_analysis_spec_type,
) -> None:
    cache = setup(tmp_path, monkeypatch)

    user_spec = make_load_spec(tmp_path, "rule", "rule_1", None, None)
    cache.insert_analysis_spec(
        # pretend PA added a new field that should not cause a conflict
        make_analysis_spec("rule", "rule_1", 1, user_spec.analysis_spec | {"new": "field"}),
        None,
    )

    has_conflict = migration.migrate_analysis_item(user_spec, cache)
    assert not has_conflict

    spec_path = pathlib.Path(user_spec.spec_filename)
    py_path = user_spec.python_file_path()

    assert user_spec.analysis_spec["BaseVersion"] == 1
    assert spec_path.exists()
    assert py_path is None
    assert dict(yaml.load(spec_path.read_text())) == {
        "AnalysisType": "rule",
        "RuleID": "rule_1",
        "BaseVersion": 1,
        "new": "field",
    }
