"""
Panther Analysis Tool is a command line interface for writing,
testing, and packaging policies/rules.
Copyright (C) 2020 Panther Labs Inc

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import argparse
import os
from unittest import TestCase

from panther_analysis_tool import main as pat

FIXTURES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../", "fixtures"))
LUTS_FIXTURES_PATH = os.path.join(FIXTURES_PATH, "lookup-tables")


class TestLookupTable(TestCase):  # pylint: disable=too-many-public-methods
    def test_load_invalid_specs_from_folder(self):
        args = argparse.Namespace()
        args.path = f"{LUTS_FIXTURES_PATH}/invalid/lookup-table-1.yml"
        rc, file_path = pat.test_lookup_table(args)
        self.assertEqual(1, rc)
        self.assertEqual(file_path, "")

    def test_load_invalid_specs_from_folder(self):
        args = argparse.Namespace()
        args.path = f"{LUTS_FIXTURES_PATH}/valid/lookup-table-1.yml"
        rc, file_path = pat.test_lookup_table(args)
        self.assertEqual(0, rc)
        self.assertEqual(file_path, "")

        args.path = f"{LUTS_FIXTURES_PATH}/valid/lookup-table-2.yml"
        rc, file_path = pat.test_lookup_table(args)
        self.assertEqual(0, rc)
        self.assertEqual(file_path, "")
