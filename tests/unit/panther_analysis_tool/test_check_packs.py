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
import re
import unittest
from argparse import Namespace
from pathlib import Path

from panther_analysis_tool.main import check_packs

FIXTURES_PATH = Path(__file__).parents[2] / "fixtures/check-packs"


class TestCheckPacks(unittest.TestCase):
    _bad_packs: dict = None

    def get_bad_packs(self) -> dict:
        if self._bad_packs is not None:
            return self._bad_packs

        args = Namespace(path=FIXTURES_PATH / "missing-dependencies")
        exit_code, res = check_packs(args)

        assert exit_code == 1
        res = res.split("\n")
        self._bad_packs = {}
        current_key = ""
        for line in res[1:]:
            if line.startswith(" ") or not line:
                continue
            if line.startswith("\t"):
                self._bad_packs[current_key].append(line.strip())
                continue
            current_key = Path(line.strip()).name
            self._bad_packs[current_key] = []

        return self._bad_packs

    def test_fixtures(self) -> None:
        args = Namespace(path=FIXTURES_PATH / "packless-rule")
        exit_code, res = check_packs(args)

        assert exit_code == 1
        assert "Test.Missing" in res

    def test_missing_global(self) -> None:
        bad_packs = self.get_bad_packs()
        assert "missing_global.yml" in bad_packs
        missing_items = bad_packs["missing_global.yml"]
        assert "a_helper" in missing_items

    def test_missing_data_model(self) -> None:
        bad_packs = self.get_bad_packs()
        assert "missing_datamodel.yml" in bad_packs
        missing_items = bad_packs["missing_datamodel.yml"]
        assert "panther" in missing_items
        assert "Standard.AWS.CloudTrail" in missing_items

    def test_missing_query(self) -> None:
        bad_packs = self.get_bad_packs()
        assert "missing_query.yml" in bad_packs
        missing_items = bad_packs["missing_query.yml"]
        assert "A Test Query" in missing_items

    def test_missing_subrules(self) -> None:
        bad_packs = self.get_bad_packs()
        assert "missing_subrules.yml" in bad_packs
        missing_items = bad_packs["missing_subrules.yml"]
        assert "AWS.CloudTrail.IaaS" in missing_items
        assert "GitHub.CICD" in missing_items

    def test_empty_dir(self) -> None:
        current_dir = os.path.dirname(os.path.realpath(__file__))
        print(current_dir)
        args = Namespace(path=current_dir)
        exit_code, res = check_packs(args)

        assert exit_code == 0
        assert res == "Looks like packs are up to date"
