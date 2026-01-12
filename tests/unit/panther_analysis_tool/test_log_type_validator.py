"""Unit tests for log_type_validator module."""

import unittest
from unittest.mock import MagicMock, Mock, patch

from schema import SchemaError

from panther_analysis_tool.backend.client import ListSchemasResponse, Schema
from panther_analysis_tool.log_type_validator import (
    CUSTOM_LOG_TYPE_REGEX,
    LogTypeCache,
    _fetch_log_types,
    _validate_custom_format,
    create_log_type_validator,
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
                    _validate_custom_format(log_type),
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
                    _validate_custom_format(log_type),
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
                Schema(
                    name="Custom.MyApp.Events",
                    created_at="",
                    description="",
                    is_managed=False,
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
        self.assertEqual(log_types, {"AWS.CloudTrail", "Okta.SystemLog", "Custom.MyApp.Events"})

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


class TestValidatorWithBackend(unittest.TestCase):
    """Tests for validator with backend client."""

    def setUp(self):
        """Clear cache before each test."""
        LogTypeCache.clear()

    def test_validator_with_backend_valid_log_type(self):
        """Test validator accepts log types from backend."""
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

        validator = create_log_type_validator(mock_backend)

        # Should accept AWS.CloudTrail (from backend)
        result = validator("AWS.CloudTrail")
        self.assertEqual(result, "AWS.CloudTrail")

    def test_validator_with_backend_invalid_log_type(self):
        """Test validator rejects log types not in backend."""
        mock_backend = Mock()
        mock_response = Mock()
        mock_response.data = ListSchemasResponse(schemas=[])
        mock_backend.list_schemas.return_value = mock_response

        validator = create_log_type_validator(mock_backend)

        # Should reject invalid log type
        with self.assertRaises(SchemaError) as context:
            validator("AWS.InvalidService")

        self.assertIn("Invalid log type", str(context.exception))
        self.assertIn("AWS.InvalidService", str(context.exception))

    def test_validator_with_backend_accepts_custom_format(self):
        """Test validator accepts Custom.* format even with backend."""
        mock_backend = Mock()
        mock_response = Mock()
        mock_response.data = ListSchemasResponse(schemas=[])
        mock_backend.list_schemas.return_value = mock_response

        validator = create_log_type_validator(mock_backend)

        # Should accept Custom.* format
        result = validator("Custom.MyApp.Events")
        self.assertEqual(result, "Custom.MyApp.Events")

    def test_validator_caches_results(self):
        """Test that validator caches log types from backend."""
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

        # First validator should fetch from backend
        validator1 = create_log_type_validator(mock_backend)
        validator1("AWS.CloudTrail")

        # Second validator should use cached results
        validator2 = create_log_type_validator(mock_backend)
        validator2("AWS.CloudTrail")

        # Backend should only be called once
        self.assertEqual(mock_backend.list_schemas.call_count, 1)


class TestValidatorWithoutBackend(unittest.TestCase):
    """Tests for validator without backend client."""

    def setUp(self):
        """Clear cache before each test."""
        LogTypeCache.clear()

    def test_validator_without_backend_valid_custom(self):
        """Test validator accepts valid Custom.* format without backend."""
        validator = create_log_type_validator(None)

        result = validator("Custom.MyApp.Events")
        self.assertEqual(result, "Custom.MyApp.Events")

    def test_validator_without_backend_invalid_custom(self):
        """Test validator rejects invalid Custom.* format without backend."""
        validator = create_log_type_validator(None)

        with self.assertRaises(SchemaError) as context:
            validator("Custom.invalid")

        self.assertIn("Invalid log type", str(context.exception))
        self.assertIn("Custom.*", str(context.exception))

    def test_validator_without_backend_rejects_standard_log_types(self):
        """Test validator rejects standard log types without backend."""
        validator = create_log_type_validator(None)

        with self.assertRaises(SchemaError) as context:
            validator("AWS.CloudTrail")

        self.assertIn("Invalid log type", str(context.exception))
        self.assertIn("Custom.*", str(context.exception))

    @patch("panther_analysis_tool.log_type_validator.logging")
    def test_validator_shows_warning_once(self, mock_logging):
        """Test that warning is only shown once without backend."""
        validator = create_log_type_validator(None)

        # First invalid log type should trigger warning
        with self.assertRaises(SchemaError):
            validator("AWS.CloudTrail")

        # Second invalid log type should not trigger warning again
        with self.assertRaises(SchemaError):
            validator("AWS.S3")

        # Warning should only be called once
        warning_calls = [
            call
            for call in mock_logging.warning.call_args_list
            if "API credentials not configured" in str(call)
        ]
        self.assertEqual(len(warning_calls), 1)


class TestValidatorFallback(unittest.TestCase):
    """Tests for validator fallback behavior on API errors."""

    def setUp(self):
        """Clear cache before each test."""
        LogTypeCache.clear()

    def test_validator_falls_back_on_api_error(self):
        """Test validator falls back to Custom.* validation on API error."""
        mock_backend = Mock()
        mock_backend.list_schemas.side_effect = Exception("Network error")

        validator = create_log_type_validator(mock_backend)

        # Should fall back to Custom.* validation
        result = validator("Custom.MyApp.Events")
        self.assertEqual(result, "Custom.MyApp.Events")

        # Should reject standard log types
        with self.assertRaises(SchemaError):
            validator("AWS.CloudTrail")

    @patch("panther_analysis_tool.log_type_validator.logging")
    def test_validator_logs_api_error(self, mock_logging):
        """Test that API errors are logged."""
        mock_backend = Mock()
        mock_backend.list_schemas.side_effect = Exception("Network error")

        validator = create_log_type_validator(mock_backend)

        # Trigger fetch
        try:
            validator("Custom.MyApp.Events")
        except SchemaError:
            pass

        # Should log the error
        warning_calls = [
            call
            for call in mock_logging.warning.call_args_list
            if "Failed to fetch log types" in str(call)
        ]
        self.assertGreaterEqual(len(warning_calls), 1)


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
        LogTypeCache.mark_warning_shown()

        LogTypeCache.clear()

        self.assertIsNone(LogTypeCache.get_log_types())
        self.assertFalse(LogTypeCache.has_shown_warning())

    def test_warning_flag(self):
        """Test warning flag tracking."""
        self.assertFalse(LogTypeCache.has_shown_warning())

        LogTypeCache.mark_warning_shown()

        self.assertTrue(LogTypeCache.has_shown_warning())


if __name__ == "__main__":
    unittest.main()
