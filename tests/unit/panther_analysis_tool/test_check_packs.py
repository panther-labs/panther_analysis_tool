"""
Panther Analysis Tool is a command line interface for writing,
testing, and packaging policies/rules.
Copyright (C) 2023 Panther Labs Inc

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
import os
import unittest
from argparse import Namespace

from panther_analysis_tool.main import check_packs

FIXTURES_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../", "fixtures", "check-packs")
)


class TestCheckPacks(unittest.TestCase):
    def test_fixtures(self) -> None:
        args = Namespace(path=FIXTURES_PATH)
        exit_code, res = check_packs(args)

        assert exit_code == 1
        expected = (
            "There are packs that are potentially missing detections:\ntest.yml: Test.Missing\n\n"
        )
        assert res == expected

    def test_empty_dir(self) -> None:
        current_dir = os.path.dirname(os.path.realpath(__file__))
        print(current_dir)
        args = Namespace(path=current_dir)
        exit_code, res = check_packs(args)

        assert exit_code == 0
        assert res == "Looks like packs are up to date"
