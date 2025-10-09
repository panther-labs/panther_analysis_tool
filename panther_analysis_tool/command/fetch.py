import os
import pathlib
from typing import Dict, Tuple

from panther_analysis_tool.analysis_utils import (
    LoadAnalysisSpecsResult,
    load_analysis_specs_ex,
)
from panther_analysis_tool.constants import CACHE_DIR
from panther_analysis_tool.core import analysis_cache, git_helpers, versions_file


def run() -> Tuple[int, str]:
    fetch()
    return 0, "Fetched"


def fetch() -> None:
    # allows for testing against a different branch or manual override
    release_branch = os.environ.get("PANTHER_ANALYSIS_RELEASE_BRANCH") or ""
    commit = ""

    if release_branch == "":
        release_branch = "main"
        commit = git_helpers.panther_analysis_latest_release_commit()

    git_helpers.clone_panther_analysis(release_branch, commit)
    populate_sqlite()


def populate_sqlite() -> None:
    cache = analysis_cache.AnalysisCache()
    cache.create_tables()
    versions = versions_file.get_versions().versions

    user_analysis_specs: Dict[str, LoadAnalysisSpecsResult] = {}
    for user_specs in load_analysis_specs_ex(["."], [], False):
        user_analysis_specs[user_specs.analysis_id()] = user_specs


    # load all analysis specs
    for spec in load_analysis_specs_ex([CACHE_DIR], [], False):
        if spec.error is not None:
            continue

        if "AnalysisType" not in spec.analysis_spec:
            raise ValueError(f"Analysis type not found in spec: {spec.analysis_spec}")

        id_value = spec.analysis_id()
        if id_value in user_analysis_specs:
            user_spec_version = user_analysis_specs[id_value].analysis_spec.get("BaseVersion", None)

            # if the user spec is older than the latest version, we need to insert the old spec too.
            # We know where to find the old spec because we have the version history in the versions file
            # and we can use the commit hash and file path to get the content from the panther-analysis repository.
            if user_spec_version is not None and user_spec_version < versions[id_value].version:
                spec_history_item = versions[id_value].history[user_spec_version]

                yaml_content =git_helpers.get_panther_analysis_file_contents(spec_history_item.commit_hash, spec_history_item.yaml_file_path)
                py_content = None
                if spec_history_item.py_file_path is not None:
                    py_content = bytes(git_helpers.get_panther_analysis_file_contents(spec_history_item.commit_hash, spec_history_item.py_file_path), "utf-8")

                cache.insert_analysis_spec(analysis_cache.AnalysisSpec(
                    id=None,
                    id_field=spec.analysis_id_field_name(),
                    id_value=id_value,
                    spec=bytes(yaml_content, "utf-8"),
                    version=versions[id_value].version,
                ), py_content)
                

        content = None
        filename = spec.analysis_spec.get("Filename")
        if spec.analysis_spec.get("Filename") is not None:
            file_path = pathlib.Path(spec.spec_filename).parent / filename
            with open(file_path, "rb") as spec_file:
                content = spec_file.read()

        

        cache.insert_analysis_spec(analysis_cache.AnalysisSpec(
            id=None,
            id_field=spec.analysis_id_field_name(),
            id_value=id_value,
            spec=spec.raw_spec_file_content or bytes(), # is only none if error which is handled above
            version=versions[id_value].version,
        ), content)

