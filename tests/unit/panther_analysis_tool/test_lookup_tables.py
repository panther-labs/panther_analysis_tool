import os
from unittest import TestCase

from panther_analysis_tool import main as pat

FIXTURES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../", "fixtures"))
LUTS_FIXTURES_PATH = os.path.join(FIXTURES_PATH, "lookup-tables")


class TestLookupTable(TestCase):  # pylint: disable=too-many-public-methods
    def test_load_invalid_specs_from_folder(self):
        path = f"{LUTS_FIXTURES_PATH}/invalid/lookup-table-1.yml"
        rc, file_path = pat.test_lookup_table(path)
        self.assertEqual(1, rc)
        self.assertEqual(file_path, "")

    def test_load_invalid_specs_from_folder(self):
        path = f"{LUTS_FIXTURES_PATH}/valid/lookup-table-1.yml"
        rc, file_path = pat.test_lookup_table(path)
        self.assertEqual(0, rc)
        self.assertEqual(file_path, "")

        path = f"{LUTS_FIXTURES_PATH}/valid/lookup-table-2.yml"
        rc, file_path = pat.test_lookup_table(path)
        self.assertEqual(0, rc)
        self.assertEqual(file_path, "")
