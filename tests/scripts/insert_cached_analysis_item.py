"""
Insert a new version of an analysis item into the cache at `.cache`. 

This script is used for testing purposes.
It will allow you to edit the analysis item in an editor to make an update to it.
Then it will insert that updated version into the cache with a version one greater
than the previous version.
This is primarily useful for testing the merge command.

Usage:
    python ./tests/scripts/insert_cached_analysis_item.py <analysis_id>
"""

import subprocess
import sys
import tempfile

import yaml

import panther_analysis_tool.core.analysis_cache as analysis_cache


def main() -> None:
    analysis_id = sys.argv[1]
    if not analysis_id:
        print_usage()
        sys.exit(1)


    cache = analysis_cache.AnalysisCache()
    cache.create_tables()

    latest_spec = cache.get_latest_spec(analysis_id)
    if latest_spec is None:
        print(f"Analysis ID {analysis_id} not found in cache")
        sys.exit(1)


    spec_yaml = yaml.safe_load(latest_spec.spec)

    new_version_id = -1

    with tempfile.NamedTemporaryFile(delete=False) as temp_file_yaml:
        temp_file_yaml.write(latest_spec.spec)
        temp_file_yaml.flush()

        subprocess.run(["vim", temp_file_yaml.name])

        new_py_content: bytes | None = None
        if "Filename" in spec_yaml:
            spec_py = cache.get_file_for_spec(latest_spec.id or -1)
            if spec_py is not None:
                with tempfile.NamedTemporaryFile(delete=False) as temp_file_py:
                    temp_file_py.write(spec_py)
                    temp_file_py.flush()

                    subprocess.run(["vim", temp_file_py.name])

                    new_py_content = temp_file_py.read()

        cache.insert_analysis_spec(
            analysis_cache.AnalysisSpec(
                id=None,
                spec=temp_file_yaml.read(),
                version=latest_spec.version + 1,
                id_field=latest_spec.id_field,
                id_value=latest_spec.id_value,
            ),
            new_py_content,
        )


def print_usage() -> None:
    print("Usage: python ./tests/scripts/insert_cached_analysis_item.py <analysis_id>")

if __name__ == "__main__":
    main()