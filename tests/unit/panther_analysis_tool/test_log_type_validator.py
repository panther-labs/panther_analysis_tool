"""Unit tests for log_type_validator module."""

import unittest
from unittest.mock import Mock

from panther_analysis_tool.backend.client import ListSchemasResponse, Schema
from panther_analysis_tool.log_type_validator import (
    CUSTOM_LOG_TYPE_REGEX,
    LogTypeCache,
    _fetch_log_types,
    filter_rules_by_log_type_support,
    get_unsupported_log_types,
    init_log_type_cache,
    is_log_type_supported,
    is_valid_custom_log_type,
)


class TestCustomFormatValidation(unittest.TestCase):
    """Tests for Custom.* format validation."""

    def test_valid_custom_log_types(self):
        """Test that valid Custom.* log types pass validation."""
        valid_log_types = [
            "Custom.MyApp",
            "Custom.MyOrg.Events",
            "Custom.App.Logs.Important",
            "Custom.A.B.C.D.E",  # 6 segments total (max)
            "Custom.ABC123",  # Alphanumeric
            "Custom.MyApp2.Events3",
        ]

        for log_type in valid_log_types:
            with self.subTest(log_type=log_type):
                self.assertTrue(
                    is_valid_custom_log_type(log_type),
                    f"Expected {log_type} to be valid",
                )

    def test_invalid_custom_log_types(self):
        """Test that invalid Custom.* log types fail validation."""
        invalid_log_types = [
            "custom.MyApp",  # lowercase "custom"
            "Custom.myapp",  # lowercase after dot
            "Custom.My-App",  # hyphen not allowed
            "Custom.My_App",  # underscore not allowed
            "Custom.A.B.C.D.E.F.G",  # 7 segments after Custom (too many)
            "Custom.",  # no segment after dot
            "Custom",  # no dot
            "MyApp.Custom",  # wrong order
            "Custom.123App",  # starts with number
        ]

        for log_type in invalid_log_types:
            with self.subTest(log_type=log_type):
                self.assertFalse(
                    is_valid_custom_log_type(log_type),
                    f"Expected {log_type} to be invalid",
                )

    def test_custom_regex_pattern(self):
        """Test the Custom log type regex pattern directly."""
        # Valid
        self.assertIsNotNone(CUSTOM_LOG_TYPE_REGEX.match("Custom.MyApp"))
        self.assertIsNotNone(CUSTOM_LOG_TYPE_REGEX.match("Custom.A.B.C.D.E"))

        # Invalid
        self.assertIsNone(CUSTOM_LOG_TYPE_REGEX.match("custom.MyApp"))
        self.assertIsNone(CUSTOM_LOG_TYPE_REGEX.match("Custom.myapp"))


class TestFetchLogTypes(unittest.TestCase):
    """Tests for fetching log types from backend."""

    def setUp(self):
        """Clear cache before each test."""
        LogTypeCache.clear()

    def test_fetch_log_types_success(self):
        """Test successful fetching of log types."""
        mock_backend = Mock()
        mock_response = Mock()
        mock_response.data = ListSchemasResponse(
            schemas=[
                Schema(
                    name="AWS.CloudTrail",
                    created_at="",
                    description="",
                    is_managed=True,
                    reference_url="",
                    revision="",
                    spec="",
                    updated_at="",
                    field_discovery_enabled=False,
                ),
                Schema(
                    name="Okta.SystemLog",
                    created_at="",
                    description="",
                    is_managed=True,
                    reference_url="",
                    revision="",
                    spec="",
                    updated_at="",
                    field_discovery_enabled=False,
                ),
            ]
        )
        mock_backend.list_schemas.return_value = mock_response

        log_types = _fetch_log_types(mock_backend)

        self.assertIsNotNone(log_types)
        self.assertEqual(log_types, {"AWS.CloudTrail", "Okta.SystemLog"})

    def test_fetch_log_types_empty_response(self):
        """Test handling of empty response from backend."""
        mock_backend = Mock()
        mock_response = Mock()
        mock_response.data = None
        mock_backend.list_schemas.return_value = mock_response

        log_types = _fetch_log_types(mock_backend)

        self.assertIsNone(log_types)

    def test_fetch_log_types_exception(self):
        """Test handling of exceptions during fetch."""
        mock_backend = Mock()
        mock_backend.list_schemas.side_effect = Exception("Network error")

        log_types = _fetch_log_types(mock_backend)

        self.assertIsNone(log_types)


class TestInitLogTypeCache(unittest.TestCase):
    """Tests for init_log_type_cache function."""

    def setUp(self):
        """Clear cache before each test."""
        LogTypeCache.clear()

    def test_init_with_no_backend(self):
        """Test initialization with no backend returns False."""
        result = init_log_type_cache(None)
        self.assertFalse(result)

    def test_init_with_backend_success(self):
        """Test successful initialization with backend."""
        mock_backend = Mock()
        mock_response = Mock()
        mock_response.data = ListSchemasResponse(
            schemas=[
                Schema(
                    name="AWS.CloudTrail",
                    created_at="",
                    description="",
                    is_managed=True,
                    reference_url="",
                    revision="",
                    spec="",
                    updated_at="",
                    field_discovery_enabled=False,
                ),
            ]
        )
        mock_backend.list_schemas.return_value = mock_response

        result = init_log_type_cache(mock_backend)

        self.assertTrue(result)
        self.assertEqual(LogTypeCache.get_log_types(), {"AWS.CloudTrail"})

    def test_init_uses_cache(self):
        """Test that subsequent calls use cached results."""
        mock_backend = Mock()
        mock_response = Mock()
        mock_response.data = ListSchemasResponse(
            schemas=[
                Schema(
                    name="AWS.CloudTrail",
                    created_at="",
                    description="",
                    is_managed=True,
                    reference_url="",
                    revision="",
                    spec="",
                    updated_at="",
                    field_discovery_enabled=False,
                ),
            ]
        )
        mock_backend.list_schemas.return_value = mock_response

        # First call
        init_log_type_cache(mock_backend)
        # Second call
        init_log_type_cache(mock_backend)

        # Backend should only be called once
        self.assertEqual(mock_backend.list_schemas.call_count, 1)


class TestIsLogTypeSupported(unittest.TestCase):
    """Tests for is_log_type_supported function."""

    def setUp(self):
        """Clear cache before each test."""
        LogTypeCache.clear()

    def test_no_cache_allows_all(self):
        """Test that without cache, all log types are allowed."""
        self.assertTrue(is_log_type_supported("AWS.CloudTrail"))
        self.assertTrue(is_log_type_supported("FakeVendor.FakeLog"))
        self.assertTrue(is_log_type_supported("Custom.MyApp"))

    def test_with_cache_checks_instance(self):
        """Test that with cache, log types are checked against instance."""
        LogTypeCache.set_log_types({"AWS.CloudTrail", "Okta.SystemLog"})

        # In instance
        self.assertTrue(is_log_type_supported("AWS.CloudTrail"))
        self.assertTrue(is_log_type_supported("Okta.SystemLog"))

        # Not in instance but valid Custom.*
        self.assertTrue(is_log_type_supported("Custom.MyApp.Events"))

        # Not in instance and not Custom.*
        self.assertFalse(is_log_type_supported("FakeVendor.FakeLog"))
        self.assertFalse(is_log_type_supported("AWS.NewService"))


class TestGetUnsupportedLogTypes(unittest.TestCase):
    """Tests for get_unsupported_log_types function."""

    def setUp(self):
        """Clear cache before each test."""
        LogTypeCache.clear()

    def test_no_cache_returns_empty(self):
        """Test that without cache, no log types are marked unsupported."""
        result = get_unsupported_log_types(["AWS.CloudTrail", "FakeVendor.FakeLog"])
        self.assertEqual(result, [])

    def test_with_cache_returns_unsupported(self):
        """Test that with cache, unsupported log types are returned."""
        LogTypeCache.set_log_types({"AWS.CloudTrail"})

        result = get_unsupported_log_types(
            ["AWS.CloudTrail", "Okta.SystemLog", "Custom.MyApp"]
        )

        # Only Okta.SystemLog is unsupported (AWS.CloudTrail is in instance, Custom.MyApp is valid format)
        self.assertEqual(result, ["Okta.SystemLog"])


class TestFilterRulesByLogTypeSupport(unittest.TestCase):
    """Tests for filter_rules_by_log_type_support function."""

    def setUp(self):
        """Clear cache before each test."""
        LogTypeCache.clear()

    def test_no_cache_allows_all(self):
        """Test that without cache, all rules pass."""
        rules = [
            ("rule1.yml", {"RuleID": "Rule1", "LogTypes": ["AWS.CloudTrail"]}),
            ("rule2.yml", {"RuleID": "Rule2", "LogTypes": ["FakeVendor.FakeLog"]}),
        ]

        supported, skipped = filter_rules_by_log_type_support(rules)

        self.assertEqual(len(supported), 2)
        self.assertEqual(len(skipped), 0)

    def test_with_cache_filters_unsupported(self):
        """Test that with cache, unsupported rules are filtered."""
        LogTypeCache.set_log_types({"AWS.CloudTrail"})

        rules = [
            ("rule1.yml", {"RuleID": "Rule1", "LogTypes": ["AWS.CloudTrail"]}),
            ("rule2.yml", {"RuleID": "Rule2", "LogTypes": ["Okta.SystemLog"]}),
            ("rule3.yml", {"RuleID": "Rule3", "LogTypes": ["Custom.MyApp"]}),
        ]

        supported, skipped = filter_rules_by_log_type_support(rules)

        self.assertEqual(len(supported), 2)  # Rule1 and Rule3
        self.assertEqual(len(skipped), 1)  # Rule2

        # Check skipped rule details
        self.assertEqual(skipped[0][0], "rule2.yml")
        self.assertEqual(skipped[0][2], ["Okta.SystemLog"])

    def test_rules_without_log_types_pass(self):
        """Test that rules without LogTypes field pass."""
        LogTypeCache.set_log_types({"AWS.CloudTrail"})

        rules = [
            ("global.yml", {"GlobalID": "MyGlobal"}),  # No LogTypes
            ("rule1.yml", {"RuleID": "Rule1", "LogTypes": ["AWS.CloudTrail"]}),
        ]

        supported, skipped = filter_rules_by_log_type_support(rules)

        self.assertEqual(len(supported), 2)
        self.assertEqual(len(skipped), 0)

    def test_scheduled_queries_validated(self):
        """Test that ScheduledQueries field is also validated."""
        LogTypeCache.set_log_types({"AWS.CloudTrail"})

        rules = [
            (
                "scheduled.yml",
                {"RuleID": "Scheduled1", "ScheduledQueries": ["Okta.SystemLog"]},
            ),
        ]

        supported, skipped = filter_rules_by_log_type_support(rules)

        self.assertEqual(len(supported), 0)
        self.assertEqual(len(skipped), 1)


class TestLogTypeCache(unittest.TestCase):
    """Tests for LogTypeCache singleton."""

    def setUp(self):
        """Clear cache before each test."""
        LogTypeCache.clear()

    def test_cache_singleton(self):
        """Test that LogTypeCache is a singleton."""
        cache1 = LogTypeCache()
        cache2 = LogTypeCache()

        self.assertIs(cache1, cache2)

    def test_cache_set_and_get(self):
        """Test setting and getting cached log types."""
        log_types = {"AWS.CloudTrail", "Okta.SystemLog"}

        LogTypeCache.set_log_types(log_types)
        cached = LogTypeCache.get_log_types()

        self.assertEqual(cached, log_types)

    def test_cache_clear(self):
        """Test clearing the cache."""
        log_types = {"AWS.CloudTrail"}
        LogTypeCache.set_log_types(log_types)

        LogTypeCache.clear()

        self.assertIsNone(LogTypeCache.get_log_types())


if __name__ == "__main__":
    unittest.main()
