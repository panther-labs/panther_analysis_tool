import logging
import os
import pathlib
import shutil
from typing import Dict, Tuple

from rich.progress import BarColumn, Progress, TextColumn, track

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.analysis_utils import (
    LoadAnalysisSpecsResult,
    load_analysis_specs_ex,
)
from panther_analysis_tool.command import merge
from panther_analysis_tool.constants import (
    CACHE_DIR,
    CACHED_VERSIONS_FILE_PATH,
    PANTHER_ANALYSIS_SQLITE_FILE_PATH,
    AnalysisTypes,
    AutoAcceptOption,
)
from panther_analysis_tool.core import (
    analysis_cache,
    clone_item,
    git_helpers,
    versions_file,
)


def run() -> Tuple[int, str]:
    pull(show_progress_bar=True)
    return 0, ""


def pull(show_progress_bar: bool = False, auto_accept: AutoAcceptOption | None = None) -> None:
    sqlite_file = PANTHER_ANALYSIS_SQLITE_FILE_PATH
    sqlite_file.parent.mkdir(parents=True, exist_ok=True)
    sqlite_file.touch(exist_ok=True)

    # clone panther analysis
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        transient=True,
        disable=not show_progress_bar,
    ) as progress:
        task = progress.add_task("Pulling latest from Panther Analysis:", total=None)
        clone_panther_analysis()
        progress.update(task, completed=True)

    # load specs
    user_analysis_specs: Dict[str, LoadAnalysisSpecsResult] = {}
    for spec in track(
        # this does not load anything from the .cache dir
        load_analysis_specs_ex(["."], [], True),
        description="Loading user analysis items:",
        disable=not show_progress_bar,
        transient=True,
    ):
        user_analysis_specs[spec.analysis_id()] = spec

    # populate cache
    cache = analysis_cache.AnalysisCache()
    cache.create_tables()
    versions = versions_file.get_versions().versions

    for spec in track(
        load_analysis_specs_ex([str(CACHE_DIR)], [], True),
        description="Populating cache:",
        disable=not show_progress_bar,
        transient=True,
    ):
        populate_sqlite(spec, cache, user_analysis_specs, versions)

    # merge analysis items
    mergeable_items = merge.get_mergeable_items(None, list(user_analysis_specs.values()))
    if len(mergeable_items) > 0:
        merge.merge_items(mergeable_items, None, None, auto_accept, show_progress_bar)

    git_helpers.delete_cloned_panther_analysis()

    # we need to check if the new merged python includes any
    # new global helper imports and clone those so the new python works
    with Progress(
        TextColumn("Cloning dependencies:"),
        BarColumn(),
        transient=True,
        disable=not show_progress_bar,
    ) as progress:
        task = progress.add_task("cloning_dependencies", total=None)
        items = [item.merged_item for item in mergeable_items if item.merged_item is not None]
        clone_item.clone_deps(items)
        progress.update(task, completed=True)


def clone_panther_analysis() -> None:
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


def populate_sqlite(
    spec: analysis_utils.LoadAnalysisSpecsResult,
    cache: analysis_cache.AnalysisCache,
    user_analysis_specs: Dict[str, LoadAnalysisSpecsResult],
    versions: Dict[str, versions_file.AnalysisVersionItem],
) -> None:
    if spec.error is not None:
        return

    id_value = spec.analysis_id()

    if spec.analysis_type() == AnalysisTypes.PACK:
        return

    if id_value not in versions:
        logging.debug(
            "Analysis item %s not found in versions file, not loading it into cache", id_value
        )
        return

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
