import logging
import os
import pathlib
import shutil
from typing import Dict, Tuple

from panther_analysis_tool.analysis_utils import (
    LoadAnalysisSpecsResult,
    load_analysis_specs_ex,
)
from panther_analysis_tool.command.merge import merge_analysis
from panther_analysis_tool.constants import (
    CACHE_DIR,
    CACHED_VERSIONS_FILE_PATH,
    PANTHER_ANALYSIS_SQLITE_FILE_PATH,
)
from panther_analysis_tool.core import analysis_cache, git_helpers, versions_file


def run() -> Tuple[int, str]:
    pull()
    merge_analysis(None, None)
    return 0, ""


def pull() -> None:
    sqlite_file = PANTHER_ANALYSIS_SQLITE_FILE_PATH
    sqlite_file.parent.mkdir(parents=True, exist_ok=True)
    sqlite_file.touch(exist_ok=True)

    # allows for testing against a different branch or manual override
    release_branch = os.environ.get("PANTHER_ANALYSIS_RELEASE_BRANCH") or ""
    commit = ""

    if release_branch == "":
        release_branch = "main"
        commit = git_helpers.panther_analysis_latest_release_commit()
        logging.debug("Using Panther Analysis release: %s", commit)

    git_helpers.clone_panther_analysis(release_branch, commit)
    shutil.move(
        git_helpers.CLONED_VERSIONS_FILE_PATH,
        CACHED_VERSIONS_FILE_PATH,
    )  # move versions file so PA can be deleted
    populate_sqlite()
    git_helpers.delete_cloned_panther_analysis()


def populate_sqlite() -> None:
    cache = analysis_cache.AnalysisCache()
    cache.create_tables()
    versions = versions_file.get_versions().versions

    user_analysis_specs: Dict[str, LoadAnalysisSpecsResult] = {}
    for user_specs in load_analysis_specs_ex(["."], [], True):
        user_analysis_specs[user_specs.analysis_id()] = user_specs

    # load all analysis specs
    for spec in load_analysis_specs_ex([str(CACHE_DIR)], [], True):
        if spec.error is not None:
            continue

        id_value = spec.analysis_id()
        if id_value in user_analysis_specs:
            check_if_old_version_is_needed(cache, user_analysis_specs[id_value], versions[id_value])

        content = None
        filename = spec.analysis_spec.get("Filename")
        if spec.analysis_spec.get("Filename") is not None:
            file_path = pathlib.Path(spec.spec_filename).parent / filename
            with open(file_path, "rb") as spec_file:
                content = spec_file.read()

        cache.insert_analysis_spec(
            analysis_cache.AnalysisSpec(
                id=None,
                id_field=spec.analysis_id_field_name(),
                id_value=id_value,
                spec=spec.raw_spec_file_content
                or bytes(),  # is only none if error which is handled above
                version=versions[id_value].version,
            ),
            content,
        )


def check_if_old_version_is_needed(
    cache: analysis_cache.AnalysisCache,
    user_spec: LoadAnalysisSpecsResult,
    version_item: versions_file.AnalysisVersionItem,
) -> None:
    """
    Check if the user spec is older than the latest version, and if so, insert the old spec into the cache.
    Having the old version will allows us to perform a 3-way merge between the user spec, the old spec, and the latest spec.

    Returns:
        None

    Args:
        cache (analysis_cache.AnalysisCache): The cache to insert the old spec into.
        user_spec (LoadAnalysisSpecsResult): The user spec to check.
        version_item (versions_file.AnalysisVersionItem): The version item to check.
    """
    user_spec_version = user_spec.analysis_spec.get("BaseVersion", None)

    # if the user spec is older than the latest version, we need to insert the old spec too.
    # We know where to find the old spec because we have the version history in the versions file
    # and we can use the commit hash and file path to get the content from the panther-analysis repository.
    if user_spec_version is not None and user_spec_version < version_item.version:
        spec_history_item = version_item.history[user_spec_version]

        yaml_content = git_helpers.get_panther_analysis_file_contents(
            spec_history_item.commit_hash, spec_history_item.yaml_file_path
        )
        py_content = None
        if spec_history_item.py_file_path is not None:
            py_content = bytes(
                git_helpers.get_panther_analysis_file_contents(
                    spec_history_item.commit_hash, spec_history_item.py_file_path
                ),
                "utf-8",
            )

        cache.insert_analysis_spec(
            analysis_cache.AnalysisSpec(
                id=None,
                id_field=user_spec.analysis_id_field_name(),
                id_value=user_spec.analysis_id(),
                spec=bytes(yaml_content, "utf-8"),
                version=user_spec_version,
            ),
            py_content,
        )
