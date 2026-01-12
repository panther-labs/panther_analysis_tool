"""
Dynamic log type validator module.

This module provides dynamic log type validation that queries supported log types
from a Panther instance when API credentials are available, or falls back to
validating Custom.* format only when credentials are not provided.
"""

import logging
import re
from typing import TYPE_CHECKING, Callable, Optional, Set

from schema import SchemaError

if TYPE_CHECKING:
    from panther_analysis_tool.backend.client import Client as BackendClient

# Custom log type format: Custom.SegmentName.SegmentName...
# - Must start with "Custom."
# - Each segment after the dot must start with an uppercase letter
# - Segments can contain alphanumeric characters
# - Maximum 6 segments total (Custom + 5 additional segments)
CUSTOM_LOG_TYPE_REGEX = re.compile(r"^Custom\.([A-Z][A-Za-z0-9]*)(\.[A-Z][A-Za-z0-9]*){0,5}$")


class LogTypeCache:
    """
    Singleton cache for log types fetched from the Panther instance.
    Caches log types in-memory for the session (per command invocation).

    Note: Resource types are not cached as there's no API endpoint to fetch them.
    """

    _instance: Optional["LogTypeCache"] = None
    _log_types: Optional[Set[str]] = None
    _warning_shown: bool = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def get_log_types(cls) -> Optional[Set[str]]:
        """Returns cached log types, or None if not yet fetched."""
        instance = cls()
        return instance._log_types

    @classmethod
    def set_log_types(cls, log_types: Set[str]) -> None:
        """Caches the provided log types."""
        instance = cls()
        instance._log_types = log_types

    @classmethod
    def has_shown_warning(cls) -> bool:
        """Returns whether the 'no credentials' warning has been shown."""
        instance = cls()
        return instance._warning_shown

    @classmethod
    def mark_warning_shown(cls) -> None:
        """Marks that the 'no credentials' warning has been shown."""
        instance = cls()
        instance._warning_shown = True

    @classmethod
    def clear(cls) -> None:
        """Clears the cache (useful for testing)."""
        instance = cls()
        instance._log_types = None
        instance._warning_shown = False


def _validate_custom_format(log_type: str) -> bool:
    """
    Validates that a log type matches the Custom.* format.

    Args:
        log_type: The log type string to validate

    Returns:
        True if valid Custom.* format, False otherwise

    Examples:
        Valid: Custom.MyOrg.Events, Custom.App.Logs.Important
        Invalid: custom.invalid (lowercase), Custom.invalid (lowercase segment)
    """
    return CUSTOM_LOG_TYPE_REGEX.match(log_type) is not None


def _fetch_log_types(backend) -> Optional[Set[str]]:
    """
    Fetches supported log types from the Panther instance.

    Args:
        backend: The backend client (PublicAPIClient or LambdaClient)

    Returns:
        Set of log type names, or None if fetch fails

    Side Effects:
        Logs errors if the API call fails
    """
    try:
        # Import here to avoid circular dependencies
        from panther_analysis_tool.backend.client import ListSchemasParams

        # Fetch both managed and custom schemas (is_managed=None means all)
        response = backend.list_schemas(ListSchemasParams(is_managed=None))

        if response.data and response.data.schemas:
            log_types = {schema.name for schema in response.data.schemas}
            logging.debug(f"Fetched {len(log_types)} log types from Panther instance")
            return log_types
        else:
            logging.warning("No schemas returned from Panther instance")
            return None

    except Exception as e:  # pylint: disable=broad-except
        logging.warning(
            f"Failed to fetch log types from Panther instance: {e}. "
            "Falling back to Custom.* format validation only."
        )
        return None


def create_log_type_validator(backend: Optional["BackendClient"]) -> Callable[[str], str]:
    """
    Factory function that creates a log type validator callable.

    The returned validator has different behavior based on whether a backend client
    is provided:

    - With backend: Fetches log types from the Panther instance API, caches them,
      and validates log types against the fetched list. Falls back to Custom.*
      validation if the API call fails.

    - Without backend: Only validates Custom.* format and shows a warning once
      that API credentials are not configured.

    Args:
        backend: Optional backend client (PublicAPIClient or LambdaClient)

    Returns:
        A callable that validates log type strings and raises SchemaError if invalid

    Examples:
        >>> validator = create_log_type_validator(None)
        >>> validator("Custom.MyApp.Events")  # Returns the log type
        >>> validator("AWS.CloudTrail")  # Raises SchemaError (no API credentials)

        >>> validator = create_log_type_validator(backend_client)
        >>> validator("AWS.CloudTrail")  # Returns if CloudTrail is in fetched types
    """
    cache = LogTypeCache()

    # Determine whether to fetch from API
    should_fetch = backend is not None
    log_types: Optional[Set[str]] = None

    if should_fetch:
        # Check cache first
        log_types = cache.get_log_types()

        if log_types is None:
            # Not cached, fetch from API
            log_types = _fetch_log_types(backend)

            if log_types is not None:
                # Cache the fetched log types
                cache.set_log_types(log_types)
            else:
                # API call failed, will fall back to Custom.* validation
                logging.info("Using Custom.* format validation only due to API error")

    def validator(log_type: str) -> str:
        """
        Validates a single log type string.

        Args:
            log_type: The log type string to validate

        Returns:
            The log type string if valid

        Raises:
            SchemaError: If the log type is invalid
        """
        # If we have fetched log types, validate against them
        if log_types is not None:
            if log_type in log_types or _validate_custom_format(log_type):
                return log_type
            else:
                raise SchemaError(
                    f"Invalid log type '{log_type}'. "
                    f"Not found in Panther instance and does not match Custom.* format."
                )

        # No API credentials or API call failed - validate Custom.* format only
        if _validate_custom_format(log_type):
            return log_type

        # Show warning once
        if not cache.has_shown_warning():
            logging.warning(
                "API credentials not configured (PANTHER_API_TOKEN, PANTHER_API_HOST). "
                "Only Custom.* log type format will be validated. "
                "To validate against your Panther instance, set the PANTHER_API_TOKEN "
                "and PANTHER_API_HOST environment variables."
            )
            cache.mark_warning_shown()

        raise SchemaError(
            f"Invalid log type '{log_type}'. "
            f"Only Custom.* format is allowed without API credentials. "
            f"Example: Custom.MyOrg.MyApp.Events"
        )

    return validator
