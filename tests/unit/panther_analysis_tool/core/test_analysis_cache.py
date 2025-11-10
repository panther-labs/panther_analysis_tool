import pathlib

from _pytest.monkeypatch import MonkeyPatch

from panther_analysis_tool.constants import PANTHER_ANALYSIS_SQLITE_FILE_PATH
from panther_analysis_tool.core.analysis_cache import AnalysisCache, AnalysisSpec


def get_analysis_cache(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> AnalysisCache:
    monkeypatch.chdir(tmp_path)
    PANTHER_ANALYSIS_SQLITE_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    PANTHER_ANALYSIS_SQLITE_FILE_PATH.touch()
    return AnalysisCache()


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
    analysis_cache = get_analysis_cache(tmp_path, monkeypatch)
    analysis_cache.create_tables()
    analysis_cache.insert_analysis_spec(
        AnalysisSpec(id=1, spec=b"test", version=1, id_field="id_field", id_value="id_value"),
        b"test",
    )
    assert analysis_cache.cursor.execute("SELECT COUNT(*) FROM analysis_specs").fetchone()[0] == 1
    assert analysis_cache.cursor.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 1
    assert analysis_cache.cursor.execute("SELECT COUNT(*) FROM file_mappings").fetchone()[0] == 1
    assert analysis_cache.cursor.execute(
        "SELECT id_field, id_value, spec, version FROM analysis_specs WHERE id = 1"
    ).fetchone() == ("id_field", "id_value", b"test", 1)
    assert analysis_cache.cursor.execute(
        "SELECT spec_id, file_id FROM file_mappings WHERE id = 1"
    ).fetchone() == (1, 1)
    assert (
        analysis_cache.cursor.execute("SELECT content FROM files WHERE id = 1").fetchone()[0]
        == b"test"
    )


def test_insert_analysis_spec_with_none_py_file_contents(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    analysis_cache = get_analysis_cache(tmp_path, monkeypatch)
    analysis_cache.create_tables()
    analysis_cache.insert_analysis_spec(
        AnalysisSpec(id=1, spec=b"test", version=1, id_field="id_field", id_value="id_value"), None
    )
    assert analysis_cache.cursor.execute("SELECT COUNT(*) FROM analysis_specs").fetchone()[0] == 1
    assert analysis_cache.cursor.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0
    assert analysis_cache.cursor.execute("SELECT COUNT(*) FROM file_mappings").fetchone()[0] == 0
    assert analysis_cache.cursor.execute(
        "SELECT id_field, id_value, spec, version FROM analysis_specs WHERE id = 1"
    ).fetchone() == ("id_field", "id_value", b"test", 1)
    assert (
        analysis_cache.cursor.execute(
            "SELECT spec_id, file_id FROM file_mappings WHERE id = 1"
        ).fetchone()
        is None
    )
    assert (
        analysis_cache.cursor.execute("SELECT content FROM files WHERE id = 1").fetchone() is None
    )


def test_insert_analysis_spec_duplicate(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    analysis_cache = get_analysis_cache(tmp_path, monkeypatch)
    analysis_cache.create_tables()
    analysis_cache.insert_analysis_spec(
        AnalysisSpec(id=1, spec=b"test", version=1, id_field="id_field", id_value="id_value"),
        b"test",
    )
    analysis_cache.insert_analysis_spec(
        AnalysisSpec(id=1, spec=b"test", version=1, id_field="id_field", id_value="id_value"),
        b"test",
    )
    assert analysis_cache.cursor.execute("SELECT COUNT(*) FROM analysis_specs").fetchone()[0] == 1
    assert analysis_cache.cursor.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 1
    assert analysis_cache.cursor.execute("SELECT COUNT(*) FROM file_mappings").fetchone()[0] == 1


def test_get_file_for_spec(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    analysis_cache = get_analysis_cache(tmp_path, monkeypatch)
    analysis_cache.create_tables()
    spec_id = analysis_cache._insert_spec("id_field1", "id_value1", b"test", 1)
    file_id = analysis_cache._insert_file(b"test") or -1
    analysis_cache._insert_file_mapping(spec_id=spec_id, version=1, file_id=file_id)
    assert analysis_cache.get_file_for_spec(analysis_spec_id=spec_id, version=1) == b"test"


def test_get_file_by_id(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    analysis_cache = get_analysis_cache(tmp_path, monkeypatch)
    analysis_cache.create_tables()
    file_id = analysis_cache._insert_file(b"test") or -1
    assert analysis_cache.get_file_by_id(file_id) == b"test"


def test_get_spec_for_version(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    analysis_cache = get_analysis_cache(tmp_path, monkeypatch)
    analysis_cache.create_tables()
    analysis_cache._insert_spec("id_field", "id_value", b"test1", 1)
    analysis_cache._insert_spec("id_field", "id_value", b"test2", 2)
    assert analysis_cache.get_spec_for_version("id_value", 2) == AnalysisSpec(
        id=2, spec=b"test2", version=2, id_field="id_field", id_value="id_value"
    )
    assert analysis_cache.get_spec_for_version("id_value", 3) is None


def test_get_latest_spec(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    analysis_cache = get_analysis_cache(tmp_path, monkeypatch)
    analysis_cache.create_tables()
    analysis_cache._insert_spec("id_field", "id_value", b"test1", 1)
    analysis_cache._insert_spec("id_field", "id_value", b"test2", 2)
    assert analysis_cache.get_latest_spec("id_value") == AnalysisSpec(
        id=2, spec=b"test2", version=2, id_field="id_field", id_value="id_value"
    )
    assert analysis_cache.get_latest_spec("id_value3") is None


def test_insert_different_spec_versions(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    analysis_cache = get_analysis_cache(tmp_path, monkeypatch)
    analysis_cache.create_tables()
    analysis_cache.insert_analysis_spec(
        AnalysisSpec(id=1, spec=b"test1", version=1, id_field="id_field", id_value="id_value"),
        b"test1",
    )
    analysis_cache.insert_analysis_spec(
        AnalysisSpec(id=2, spec=b"test2", version=2, id_field="id_field", id_value="id_value"),
        b"test2",
    )
    assert analysis_cache.cursor.execute("SELECT COUNT(*) FROM analysis_specs").fetchone()[0] == 2
    assert analysis_cache.cursor.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 2
    assert analysis_cache.cursor.execute("SELECT COUNT(*) FROM file_mappings").fetchone()[0] == 2

    spec1 = analysis_cache.get_spec_for_version("id_value", 1)
    spec2 = analysis_cache.get_spec_for_version("id_value", 2)
    assert spec1 == AnalysisSpec(
        id=1, spec=b"test1", version=1, id_field="id_field", id_value="id_value"
    )
    assert spec2 == AnalysisSpec(
        id=2, spec=b"test2", version=2, id_field="id_field", id_value="id_value"
    )
    assert analysis_cache.get_file_for_spec(spec1.id or -1, spec1.version) == b"test1"
    assert analysis_cache.get_file_for_spec(spec2.id or -1, spec2.version) == b"test2"
