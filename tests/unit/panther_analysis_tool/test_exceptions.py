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
