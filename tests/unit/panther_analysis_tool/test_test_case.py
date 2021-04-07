import unittest
from panther_analysis_tool.test_case import TestCase as PantherTestCase


class TestPantherTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.data = {"username": "someone@company.com", "ip": "10.0.0.1"}
        self.data_model = None
        self.test_case = PantherTestCase(self.data, self.data_model)

    def test_get(self) -> None:
        self.assertEqual(self.test_case.get('username'), self.data['username'])

    def test_missing_key_lookup(self) -> None:
        with self.assertRaises(KeyError):
            _ = self.test_case['unknown']

    def test_case_insensitive_lookup(self):
        self.assertEqual(self.test_case['Username'], self.data['username'])

