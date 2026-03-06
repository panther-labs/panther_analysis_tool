import os
from unittest import TestCase

from panther_analysis_tool import main as pat

FIXTURES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../", "fixtures"))
LUTS_FIXTURES_PATH = os.path.join(FIXTURES_PATH, "lookup-tables")


class TestLookupTable(TestCase):  # pylint: disable=too-many-public-methods
    def test_load_invalid_specs_from_folder(self) -> None:
        path = f"{LUTS_FIXTURES_PATH}/invalid/lookup-table-1.yml"
        rc, file_path = pat.test_lookup_table(path)
        self.assertEqual(1, rc)
        self.assertEqual(file_path, "")

    def test_load_valid_specs_from_folder(self) -> None:
        path = f"{LUTS_FIXTURES_PATH}/valid/lookup-table-1.yml"
        rc, file_path = pat.test_lookup_table(path)
        self.assertEqual(0, rc)
        self.assertEqual(file_path, "")

        path = f"{LUTS_FIXTURES_PATH}/valid/lookup-table-2.yml"
        rc, file_path = pat.test_lookup_table(path)
        self.assertEqual(0, rc)
        self.assertEqual(file_path, "")

    def test_valid_sql_lookup_table_full(self):
        path = f"{LUTS_FIXTURES_PATH}/valid/lookup-table-sql-1.yml"
        rc, file_path = pat.test_lookup_table(path)
        self.assertEqual(0, rc)
        self.assertEqual(file_path, "")

    def test_valid_sql_lookup_table_minimal(self):
        path = f"{LUTS_FIXTURES_PATH}/valid/lookup-table-sql-2.yml"
        rc, file_path = pat.test_lookup_table(path)
        self.assertEqual(0, rc)
        self.assertEqual(file_path, "")

    def test_valid_sql_lookup_table_query_minimal(self):
        path = f"{LUTS_FIXTURES_PATH}/valid/lookup-table-sql-3.yml"
        rc, file_path = pat.test_lookup_table(path)
        self.assertEqual(0, rc)
        self.assertEqual(file_path, "")

    def test_valid_sql_lookup_table_query_full(self):
        path = f"{LUTS_FIXTURES_PATH}/valid/lookup-table-sql-4.yml"
        rc, file_path = pat.test_lookup_table(path)
        self.assertEqual(0, rc)
        self.assertEqual(file_path, "")

    def test_invalid_sql_lookup_table_with_schema_field(self):
        path = f"{LUTS_FIXTURES_PATH}/invalid/lookup-table-sql-invalid-1.yml"
        rc, file_path = pat.test_lookup_table(path)
        self.assertEqual(1, rc)
        self.assertEqual(file_path, "")

    def test_invalid_sql_lookup_table_period_minutes_string(self):
        path = f"{LUTS_FIXTURES_PATH}/invalid/lookup-table-sql-invalid-3.yml"
        rc, file_path = pat.test_lookup_table(path)
        self.assertEqual(1, rc)
        self.assertEqual(file_path, "")

    def test_invalid_sql_lookup_table_cron_expression_int(self):
        path = f"{LUTS_FIXTURES_PATH}/invalid/lookup-table-sql-invalid-4.yml"
        rc, file_path = pat.test_lookup_table(path)
        self.assertEqual(1, rc)
        self.assertEqual(file_path, "")
