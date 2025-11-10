"""
Insert a new version of an analysis item into the cache at `.cache`.

This script is used for testing purposes.
It will allow you to edit the analysis item in an editor to make an update to it.
Then it will insert that updated version into the cache with a version one greater
than the previous version.
This is primarily useful for testing the merge command.

Usage:
    python ./tests/scripts/revise_cached_analysis_item.py <analysis_id>
"""

import pathlib
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

    revise_item(cache, analysis_id)


def revise_item(cache: analysis_cache.AnalysisCache, analysis_id: str) -> None:
    latest_spec = cache.get_latest_spec(analysis_id)
    if latest_spec is None:
        print(f"Analysis ID {analysis_id} not found in cache")
        sys.exit(1)

    if latest_spec.spec == b"":
        print(f"Analysis ID {analysis_id} has no spec")
        sys.exit(1)

    spec_yaml = yaml.safe_load(latest_spec.spec)

    with tempfile.NamedTemporaryFile(delete=False) as temp_file_yaml:
        temp_file_yaml.write(latest_spec.spec)
        temp_file_yaml.flush()

        subprocess.run(["vim", temp_file_yaml.name])

        new_yaml_content = pathlib.Path(temp_file_yaml.name).read_bytes()
        if new_yaml_content == b"":
            print("Revised yaml was empty, exiting")
            sys.exit(1)

        new_py_content: bytes | None = None
        if "Filename" in spec_yaml:
            spec_py = cache.get_file_for_spec(latest_spec.id or -1, latest_spec.version)
            if spec_py is not None:
                with tempfile.NamedTemporaryFile(delete=False) as temp_file_py:
                    temp_file_py.write(spec_py)
                    temp_file_py.flush()

                    subprocess.run(["vim", temp_file_py.name])

                    new_py_content = pathlib.Path(temp_file_py.name).read_bytes()
                    if new_py_content == b"":
                        print("Revised python was empty, exiting")
                        sys.exit(1)

        cache.insert_analysis_spec(
            analysis_cache.AnalysisSpec(
                id=None,
                spec=new_yaml_content,
                version=latest_spec.version + 1,
                id_field=latest_spec.id_field,
                id_value=latest_spec.id_value,
            ),
            new_py_content,
        )

        print("Inserted revised spec with version", latest_spec.version + 1)


def print_usage() -> None:
    print("Usage: python ./tests/scripts/revise_cached_analysis_item.py <analysis_id>")


if __name__ == "__main__":
    main()
