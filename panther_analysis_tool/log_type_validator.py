"""
Dynamic log type validation module.

This module provides log type validation against a Panther instance's supported
log types. It fetches the list of supported log types from the API and caches
them for the session duration.

Log type validation is performed at test/upload time (not during schema validation)
to provide dynamic validation when API credentials are available.
"""

import logging
import re
import threading
from typing import TYPE_CHECKING, Callable, FrozenSet, List, Optional, Set, Tuple

from schema import SchemaError

if TYPE_CHECKING:
    from panther_analysis_tool.backend.client import Client as BackendClient
    from panther_analysis_tool.core.definitions import ClassifiedAnalysis

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

    Thread-safe implementation using a lock for state access.
    """

    _lock: threading.Lock = threading.Lock()
    _log_types: Optional[FrozenSet[str]] = None
    _initialized: bool = False

    @classmethod
    def get_log_types(cls) -> Optional[FrozenSet[str]]:
        """Returns cached log types, or None if not yet fetched."""
        with cls._lock:
            return cls._log_types

    @classmethod
    def set_log_types(cls, log_types: Set[str]) -> None:
        """Caches the provided log types as a frozenset."""
        with cls._lock:
            cls._log_types = frozenset(log_types)
            cls._initialized = True

    @classmethod
    def is_initialized(cls) -> bool:
        """Returns True if cache initialization has been attempted (success or failure)."""
        with cls._lock:
            return cls._initialized

    @classmethod
    def initialize_once(cls, fetcher: Callable[[], Optional[Set[str]]]) -> bool:
        """Atomically initialize the cache using the provided fetcher function.

        Thread-safe: only the first caller runs the fetcher; subsequent calls
        return immediately. Failed fetches are negatively cached to avoid
        repeated API calls.

        Returns:
            True if log types are cached (now or previously), False otherwise.
        """
        if cls.is_initialized():
            return cls.get_log_types() is not None

        with cls._lock:
            # Double-check after acquiring lock
            if cls._initialized:
                return cls._log_types is not None

            log_types = fetcher()
            if log_types is not None:
                cls._log_types = frozenset(log_types)
            cls._initialized = True
            return log_types is not None

    @classmethod
    def clear(cls) -> None:
        """Clears the cache (useful for testing)."""
        with cls._lock:
            cls._log_types = None
            cls._initialized = False


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
        # pylint: disable=import-outside-toplevel
        from panther_analysis_tool.backend.client import ListSchemasParams

        # Fetch managed schemas (built-in log types). Custom.* log types are
        # validated locally via regex, so we only need the managed set here.
        response = backend.list_schemas(ListSchemasParams(is_managed=True))

        if response.data and response.data.schemas is not None:
            log_types = {schema.name for schema in response.data.schemas}
            logging.debug("Fetched %d log types from Panther instance", len(log_types))
            if not log_types:
                logging.warning(
                    "Panther instance returned 0 managed schemas. This may indicate a "
                    "permissions issue or misconfiguration. Skipping log type validation."
                )
                return None
            return log_types

        logging.warning("No schemas returned from Panther instance")
        return None

    except Exception as e:  # pylint: disable=broad-except
        logging.warning("Failed to fetch log types from Panther instance: %s", e)
        return None


def init_log_type_cache(backend: Optional["BackendClient"]) -> bool:
    """
    Initializes the log type cache by fetching log types from the Panther instance.

    Should be called once at the start of a test/upload operation. Thread-safe:
    the entire check-fetch-set sequence is protected by the cache lock to prevent
    duplicate API calls. Failed fetches are negatively cached to avoid repeated
    API calls when the backend is unreachable.

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

    return LogTypeCache.initialize_once(lambda: _fetch_log_types(backend))


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
    # Custom.* log types are validated locally and always allowed by PAT.
    if is_valid_custom_log_type(log_type):
        return True

    cached_log_types = LogTypeCache.get_log_types()

    # If no cached log types, skip validation (allow all)
    if cached_log_types is None:
        return True

    return log_type in cached_log_types  # pylint: disable=unsupported-membership-test


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


def split_analysis_by_log_type_support(
    analysis: List["ClassifiedAnalysis"],
    backend: "BackendClient",
) -> Tuple[List["ClassifiedAnalysis"], List[Tuple[str, Exception]]]:
    """
    Split analysis items into supported and unsupported based on log types.

    Initializes the log type cache if needed. Items whose log types are not
    supported by the Panther instance are returned as (filename, error) pairs.

    Args:
        analysis: List of ClassifiedAnalysis to validate
        backend: Backend client for fetching supported log types

    Returns:
        Tuple of:
        - supported: items whose log types are all supported (or unvalidated)
        - errors: (filename, Exception) pairs for items with unsupported log types,
                  suitable for appending to invalid_specs
    """
    if not init_log_type_cache(backend):
        return analysis, []

    supported = []
    errors: List[Tuple[str, Exception]] = []

    for item in analysis:
        spec = item.analysis_spec
        if spec is None:
            supported.append(item)
            continue

        log_types = spec.get("LogTypes", [])

        if not log_types:
            supported.append(item)
            continue

        unsupported = get_unsupported_log_types(log_types)

        if unsupported:
            errors.append(
                (
                    item.file_name,
                    SchemaError(
                        f"LogTypes not supported by Panther instance: {', '.join(unsupported)}"
                    ),
                )
            )
        else:
            supported.append(item)

    return supported, errors


def filter_analysis_by_log_type_support(
    analysis: List["ClassifiedAnalysis"],
    backend: "BackendClient",
) -> List["ClassifiedAnalysis"]:
    """
    Filter out analysis items with unsupported log types (with warnings logged).

    Used by zip/upload paths where unsupported items should be silently skipped.
    For test paths where errors should be surfaced, use split_analysis_by_log_type_support.

    Args:
        analysis: List of ClassifiedAnalysis to filter
        backend: Backend client for fetching supported log types

    Returns:
        Filtered list with unsupported items removed
    """
    supported, errors = split_analysis_by_log_type_support(analysis, backend)

    for filename, err in errors:
        logging.warning("Skipping %s: %s", filename, err)

    if errors:
        logging.warning(
            "Skipped %d item(s) due to unsupported log types. "
            "These log types may not be available in your Panther instance.",
            len(errors),
        )

    return supported
