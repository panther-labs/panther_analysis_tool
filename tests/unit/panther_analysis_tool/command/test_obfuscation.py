import json
import os
import sys
import unittest

import yaml

# Adjust the sys.path to include the directory containing panther_analysis_tool
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "panther_analysis_tool")
)

from panther_analysis_tool.command.obfuscate import (
    Base62,
    deobfuscate_recursive,
    obfuscate_recursive,
    validate_patterns,
)

# Relative path from test_obfuscation.py to default_PATTERNS.json
PATTERNS_FILE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "..",
    "..",
    "..",
    "panther_analysis_tool",
    "patterns",
    "default_PATTERNS.json",
)


class TestObfuscation(unittest.TestCase):
    """Test cases for obfuscation and deobfuscation functions."""

    def setUp(self):
        """Set up test data."""
        self.valid_patterns = {"name": "John", "address": "123 Main St"}
        self.invalid_patterns = {"name": 123, "address": "123 Main St"}
        with open(PATTERNS_FILE_PATH, "r") as f:
            self.default_patterns = json.load(f)

    def test_validate_patterns_valid(self):
        """Test validate_patterns with valid patterns."""
        with open("test_patterns.json", "w") as f:
            json.dump(self.valid_patterns, f)
        self.assertEqual(validate_patterns("test_patterns.json"), self.valid_patterns)

    def test_validate_patterns_invalid(self):
        """Test validate_patterns with invalid patterns."""
        with open("invalid_patterns.json", "w") as f:
            json.dump(self.invalid_patterns, f)
        self.assertEqual(validate_patterns("invalid_patterns.json"), self.default_patterns)

    def test_base62_deobfuscation_invalid_input(self):
        """Test Base62 deobfuscation with invalid input."""
        with self.assertRaises(ValueError):
            Base62.deobfuscate("Invalid$tring")

    def test_validate_patterns_empty(self):
        """Test validate_patterns with an empty patterns file."""
        with open("empty_patterns.json", "w") as f:
            json.dump({}, f)
        self.assertEqual(validate_patterns("empty_patterns.json"), {})

    def tearDown(self):
        """Clean up test data."""
        if os.path.exists("test_patterns.json"):
            os.remove("test_patterns.json")
        if os.path.exists("invalid_patterns.json"):
            os.remove("invalid_patterns.json")
        if os.path.exists("empty_patterns.json"):
            os.remove("empty_patterns.json")


if __name__ == "__main__":
    unittest.main()
