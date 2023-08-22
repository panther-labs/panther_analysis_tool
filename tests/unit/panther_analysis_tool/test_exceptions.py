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

import unittest
from typing import Any, Dict, List

from panther_core.exceptions import PantherError


class TestPantherError(unittest.TestCase):
    def test_equals(self) -> None:
        cases: List[Dict[str, Any]] = [
            {"args": (("a", "b"), ("a", "b")), "expected": True},
            {"args": (("a",), ("a",)), "expected": True},
            {"args": (("a", "b", "c"), ("a", "b")), "expected": False},
        ]
        for case in cases:
            instance_args, other_args = case["args"]
            instance = PantherError(*instance_args)
            other = PantherError(*other_args)
            self.assertIs(instance.equals(other), case["expected"])
            # Test symmetry
            self.assertIs(other.equals(instance), case["expected"])

    def test_has_message_prefix(self) -> None:
        exc = PantherError("something", "went wrong")
        self.assertTrue(exc.has_message_prefix("something"))
        self.assertFalse(exc.has_message_prefix("something went"))

    def test_to_string(self) -> None:
        exc = PantherError("generic error", "went wrong")
        self.assertEqual(str(exc), "generic error: went wrong")
        exc = PantherError("generic error")
        self.assertEqual(str(exc), "generic error")
