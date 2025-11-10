"""
Delete an analysis item from the cache at `.cache/panther-analysis.sqlite`.

This script is used for testing purposes.
It will allow you to delete an analysis item from the cache by its ID and version.

Usage:
    python ./tests/scripts/delete_cached_analysis_item.py <analysis_id> <version>
"""

import sys

from panther_analysis_tool.core.analysis_cache import AnalysisCache


def main() -> None:
    analysis_id = sys.argv[1]
    if not analysis_id:
        print_usage()
        sys.exit(1)

    version = sys.argv[2]
    if not version:
        print_usage()
        sys.exit(1)

    cache = AnalysisCache()
    cache.delete_analysis_spec(analysis_id, int(version))


def print_usage() -> None:
    print("Usage: python ./tests/scripts/delete_cached_analysis_item.py <analysis_id> <version>")


if __name__ == "__main__":
    main()
