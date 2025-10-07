import os
import pathlib
import tempfile
import unittest

from panther_analysis_tool.constants import CACHE_DIR, PANTHER_ANALYSIS_SQLITE_FILE
from panther_analysis_tool.core.analysis_cache import AnalysisCache, AnalysisSpec


class TestAnalysisCache(unittest.TestCase):
    def get_analysis_cache(self, temp_dir: str) -> AnalysisCache:
        os.chdir(temp_dir)
        os.makedirs(CACHE_DIR, exist_ok=True)
        file = pathlib.Path(CACHE_DIR) / PANTHER_ANALYSIS_SQLITE_FILE
        file.touch()
        return AnalysisCache()

    def test_create_tables(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            analysis_cache = self.get_analysis_cache(temp_dir)
            analysis_cache.create_tables()
            # get number of tables in sqlite database
            tables = analysis_cache.cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            tables = [table[0] for table in tables]
            self.assertIn("analysis_specs", tables)
            self.assertIn("files", tables)
            self.assertIn("file_mappings", tables)

            indexes = analysis_cache.cursor.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()
            indexes = [index[0] for index in indexes]
            self.assertIn("idx_analysis_specs_unique", indexes)
            self.assertIn("idx_file_mappings_unique", indexes)

    def test_insert_spec(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            analysis_cache = self.get_analysis_cache(temp_dir)
            analysis_cache.create_tables()
            analysis_cache.insert_spec("id_field1", "id_value1", b"test", "test.py", 1)
            self.assertEqual(analysis_cache.cursor.execute("SELECT COUNT(*) FROM analysis_specs").fetchone()[0], 1)
            self.assertEqual(
                analysis_cache.cursor.execute("SELECT id_field, id_value, spec, file_path, version FROM analysis_specs WHERE id = 1").fetchone(), 
                ("id_field1", "id_value1", b"test", "test.py", 1),
            )

    def test_insert_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            analysis_cache = self.get_analysis_cache(temp_dir)
            analysis_cache.create_tables()
            file_id = analysis_cache.insert_file(b"test")
            self.assertEqual(file_id, 1)
            self.assertEqual(analysis_cache.cursor.execute("SELECT COUNT(*) FROM files").fetchone()[0], 1)
            self.assertEqual(analysis_cache.cursor.execute("SELECT content FROM files WHERE id = 1").fetchone()[0], b"test")

    def test_insert_file_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            analysis_cache = self.get_analysis_cache(temp_dir)
            analysis_cache.create_tables()
            analysis_cache.insert_file_mapping(1, 1)
            self.assertEqual(analysis_cache.cursor.execute("SELECT COUNT(*) FROM file_mappings").fetchone()[0], 1)
            self.assertEqual(analysis_cache.cursor.execute("SELECT spec_id, file_id FROM file_mappings WHERE id = 1").fetchone(), (1, 1))


    def test_list_spec_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            analysis_cache = self.get_analysis_cache(temp_dir)
            analysis_cache.create_tables()
            analysis_cache.insert_spec("id_field1", "id_value1", b"test", "test.py", 1)
            analysis_cache.insert_spec("id_field2", "id_value2", b"test", "test.py", 1)
            self.assertEqual(analysis_cache.list_spec_ids(), ["id_value1", "id_value2"])

    def test_get_file_for_spec(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            analysis_cache = self.get_analysis_cache(temp_dir)
            analysis_cache.create_tables()
            spec_id = analysis_cache.insert_spec("id_field1", "id_value1", b"test", "test.py", 1)
            file_id = analysis_cache.insert_file(b"test") or -1
            analysis_cache.insert_file_mapping(spec_id, file_id)
            self.assertEqual(analysis_cache.get_file_for_spec(spec_id), b"test")

    def test_get_file_by_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            analysis_cache = self.get_analysis_cache(temp_dir)
            analysis_cache.create_tables()
            file_id = analysis_cache.insert_file(b"test") or -1
            self.assertEqual(analysis_cache.get_file_by_id(file_id), b"test")

    def test_get_spec_for_version(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            analysis_cache = self.get_analysis_cache(temp_dir)
            analysis_cache.create_tables()
            analysis_cache.insert_spec("id_field", "id_value", b"test1", "test.py", 1)
            analysis_cache.insert_spec("id_field", "id_value", b"test2", "test.py", 2)
            self.assertEqual(
                analysis_cache.get_spec_for_version("id_value", 2), 
                AnalysisSpec(id=2, spec=b"test2", version=2, file_path="test.py", id_field="id_field", id_value="id_value"),
            )
            self.assertEqual(
                analysis_cache.get_spec_for_version("id_value", 3), None)

    def test_get_latest_spec(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            analysis_cache = self.get_analysis_cache(temp_dir)
            analysis_cache.create_tables()
            analysis_cache.insert_spec("id_field", "id_value", b"test1", "test.py", 1)
            analysis_cache.insert_spec("id_field", "id_value", b"test2", "test.py", 2)
            self.assertEqual(
                analysis_cache.get_latest_spec("id_value"), 
                AnalysisSpec(id=2, spec=b"test2", version=2, file_path="test.py", id_field="id_field", id_value="id_value"),
            )
            self.assertEqual(analysis_cache.get_latest_spec("id_value3"), None)

    def test_relative_path_to_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            analysis_cache = self.get_analysis_cache(temp_dir)
            analysis_cache.create_tables()
            
            test_path = pathlib.Path.cwd() / CACHE_DIR / "panther-analysis" / "stuff" / "test.py"
            expected_path = pathlib.Path("stuff") / "test.py"
            actual_path = analysis_cache.relative_path_to_file(test_path.as_posix())
            
            self.assertEqual(
                actual_path, 
                expected_path,
                f"Expected '{expected_path}' but got '{actual_path}'"
            )