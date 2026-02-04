"""
Dynamic log type validation module.

This module provides log type validation against a Panther instance's supported
log types. It fetches the list of supported log types from the API and caches
them for the session duration.

Log type validation is performed at upload time (not during schema validation)
to allow tests to run for all rules while skipping unsupported rules during upload.
"""

import logging
import re
import threading
from typing import TYPE_CHECKING, List, Optional, Set, Tuple

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

    Thread-safe implementation using a lock for singleton creation and state access.
    """

    _instance: Optional["LogTypeCache"] = None
    _lock: threading.Lock = threading.Lock()
    _log_types: Optional[Set[str]] = None

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                # Double-check locking pattern
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def get_log_types(cls) -> Optional[Set[str]]:
        """Returns cached log types, or None if not yet fetched."""
        with cls._lock:
            instance = cls()
            return instance._log_types

    @classmethod
    def set_log_types(cls, log_types: Set[str]) -> None:
        """Caches the provided log types."""
        with cls._lock:
            instance = cls()
            instance._log_types = log_types

    @classmethod
    def clear(cls) -> None:
        """Clears the cache (useful for testing)."""
        with cls._lock:
            instance = cls()
            instance._log_types = None


def is_valid_custom_log_type(log_type: str) -> bool:
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


def _fetch_log_types(backend: "BackendClient") -> Optional[Set[str]]:
    """
    Fetches supported log types from the Panther instance.

    Args:
        backend: The backend client (PublicAPIClient or LambdaClient)

    Returns:
        Set of log type names, or None if fetch fails
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
        logging.warning(f"Failed to fetch log types from Panther instance: {e}")
        return None


def init_log_type_cache(backend: Optional["BackendClient"]) -> bool:
    """
    Initializes the log type cache by fetching log types from the Panther instance.

    Should be called once at the start of an upload operation.

    Args:
        backend: Optional backend client. If None, no log type validation will occur.

    Returns:
        True if log types were successfully fetched and cached, False otherwise.
    """
    if backend is None:
        logging.info(
            "No backend client provided. Log type validation will be skipped. "
            "To validate log types, set PANTHER_API_TOKEN and PANTHER_API_HOST."
        )
        return False

    cache = LogTypeCache()

    # Check if already cached
    if cache.get_log_types() is not None:
        return True

    # Fetch from API
    log_types = _fetch_log_types(backend)
    if log_types is not None:
        cache.set_log_types(log_types)
        return True

    return False


def is_log_type_supported(log_type: str) -> bool:
    """
    Checks if a log type is supported by the Panther instance.

    Must call init_log_type_cache() first to populate the cache.

    Args:
        log_type: The log type to check

    Returns:
        True if the log type is supported (in instance or valid Custom.* format),
        False otherwise. Returns True if cache is not initialized (no validation).
    """
    cache = LogTypeCache()
    cached_log_types = cache.get_log_types()

    # If no cached log types, skip validation (allow all)
    if cached_log_types is None:
        return True

    # Check if in instance or valid Custom.* format
    return log_type in cached_log_types or is_valid_custom_log_type(log_type)


def get_unsupported_log_types(log_types: List[str]) -> List[str]:
    """
    Returns log types that are not supported by the Panther instance.

    Must call init_log_type_cache() first to populate the cache.

    Args:
        log_types: List of log types to check

    Returns:
        List of unsupported log types. Empty if all are supported or if
        cache is not initialized (no validation).
    """
    return [lt for lt in log_types if not is_log_type_supported(lt)]


def filter_rules_by_log_type_support(
    rules: List[Tuple[str, dict]],
) -> Tuple[List[Tuple[str, dict]], List[Tuple[str, dict, List[str]]]]:
    """
    Filters rules based on log type support.

    Args:
        rules: List of (filename, rule_spec) tuples

    Returns:
        Tuple of:
        - supported_rules: List of (filename, rule_spec) tuples with supported log types
        - skipped_rules: List of (filename, rule_spec, unsupported_log_types) tuples
    """
    supported_rules = []
    skipped_rules = []

    for filename, rule_spec in rules:
        # Get log types from the rule (could be LogTypes or ScheduledQueries)
        log_types = rule_spec.get("LogTypes", rule_spec.get("ScheduledQueries", []))

        if not log_types:
            # No log types to validate, include the rule
            supported_rules.append((filename, rule_spec))
            continue

        unsupported = get_unsupported_log_types(log_types)

        if unsupported:
            skipped_rules.append((filename, rule_spec, unsupported))
        else:
            supported_rules.append((filename, rule_spec))

    return supported_rules, skipped_rules
