import dataclasses
import logging
import pathlib
import tempfile
from typing import Tuple

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.analysis_utils import get_yaml_loader, load_analysis_specs_ex
from panther_analysis_tool.core import analysis_cache, editor, git_helpers
from panther_analysis_tool.gui import yaml_conflict_resolver_gui


class MergeError(Exception):
    pass


@dataclasses.dataclass
class MergeableItem:
    user_item: analysis_utils.AnalysisItem
    latest_panther_item: analysis_utils.AnalysisItem
    base_panther_item: analysis_utils.AnalysisItem


def run(analysis_id: str | None) -> Tuple[int, str]:
    return merge_analysis(analysis_id)


def merge_analysis(analysis_id: str | None) -> Tuple[int, str]:
    mergeable_items = get_mergeable_items(analysis_id)
    if not mergeable_items:
        print("Nothing to merge.")
        return 0, ""

    merge_items(mergeable_items, analysis_id)

    return 0, ""


def get_mergeable_items(analysis_id: str | None) -> list[MergeableItem]:
    """
    Get all mergeable items. An analysis item is mergeable if it has a BaseVersion and the BaseVersion is less than the latest version
    in the analysis cache. If an analysis_id is provided, only the item that matches the analysis_id is returned.

    Args:
        analysis_id: The analysis id to filter by. If None, all mergeable items are returned.

    Returns:
        A list of MergeableItem objects that contain the user's item, the latest Panther item, and the base Panther item.
    """
    yaml = get_yaml_loader(True)
    cache = analysis_cache.AnalysisCache()
    mergeable_items: list[MergeableItem] = []

    # load all analysis specs
    user_specs = list(load_analysis_specs_ex(["."], [], False))
    if not user_specs:
        return mergeable_items

    for user_spec in user_specs:
        user_spec_id = user_spec.analysis_id()
        if analysis_id is not None and analysis_id != user_spec_id:
            # user specified an analysis id, only merge that one
            continue

        # load the latest analysis item from the cache using the user spec's ID
        latest_spec = cache.get_latest_spec(user_spec_id)
        if latest_spec is None:
            # this happens with custom analysis items
            continue

        # check if the user spec's BaseVersion is less than the latest version, skip merge if it is not
        user_spec_base_version: int = user_spec.analysis_spec.get("BaseVersion") or -1
        if user_spec_base_version > latest_spec.version:
            logging.warning(
                "User spec %s has a base version greater than the latest version %s, skipping",
                user_spec_id,
                latest_spec.version,
            )
            continue
        if user_spec_base_version == latest_spec.version:
            continue

        # load the base analysis item from the cache using the user spec's BaseVersion
        base_spec = cache.get_spec_for_version(user_spec_id, user_spec_base_version)
        if base_spec is None:
            logging.warning(
                "Base version %s for %s not found, skipping", user_spec_base_version, user_spec_id
            )
            continue

        # load the python file for the user spec from the file system
        user_py: bytes | None = None
        py_path: str | None = None
        if user_spec.analysis_spec.get("Filename") is not None:
            py_path = str(
                pathlib.Path(user_spec.spec_filename).parent
                / user_spec.analysis_spec.get("Filename")
            )
            with open(py_path, "rb") as py_file:
                user_py = py_file.read()

        mergeable_items.append(
            MergeableItem(
                user_item=analysis_utils.AnalysisItem(
                    yaml_file_contents=user_spec.analysis_spec,
                    raw_yaml_file_contents=user_spec.raw_spec_file_content,
                    yaml_file_path=user_spec.spec_filename,
                    python_file_contents=user_py,
                    python_file_path=py_path,
                ),
                latest_panther_item=analysis_utils.AnalysisItem(
                    yaml_file_contents=yaml.load(latest_spec.spec),
                    raw_yaml_file_contents=latest_spec.spec,
                    python_file_contents=cache.get_file_for_spec(latest_spec.id or -1),
                ),
                base_panther_item=analysis_utils.AnalysisItem(
                    yaml_file_contents=yaml.load(base_spec.spec),
                    raw_yaml_file_contents=base_spec.spec,
                    python_file_contents=cache.get_file_for_spec(base_spec.id or -1),
                ),
            )
        )

    return mergeable_items


def merge_items(mergeable_items: list[MergeableItem], analysis_id: str | None) -> None:
    updated_item_ids: list[str] = []
    merge_conflict_item_ids: list[str] = []

    for mergeable_item in mergeable_items:
        if analysis_id is not None and analysis_id != mergeable_item.user_item.analysis_id():
            # user specified an analysis id, only merge that one
            continue

        user_item = mergeable_item.user_item
        latest_item = mergeable_item.latest_panther_item
        base_item = mergeable_item.base_panther_item
        user_item_id = user_item.analysis_id()

        # merge python
        if user_item.python_file_contents is not None:
            has_conflict = merge_file(
                solve_merge=analysis_id is not None,
                # or b"" makes typing happy but it should never be None
                user=user_item.python_file_contents or b"",
                base=base_item.python_file_contents or b"",
                latest=latest_item.python_file_contents or b"",
                user_python=user_item.python_file_contents or b"",
                output_path=str(user_item.python_file_path),
            )
            if has_conflict:
                merge_conflict_item_ids.append(user_item_id)
                # no need to merge yaml if python has a conflict because
                # we are just tracking what items have conflicts, not which files,
                # and has_conflict would be False if analysis_id provided
                continue

        # merge yaml
        has_conflict = merge_file(
            solve_merge=analysis_id is not None,
            # or b"" makes typing happy but it should never be None
            user=user_item.raw_yaml_file_contents or b"",
            base=base_item.raw_yaml_file_contents or b"",
            latest=latest_item.raw_yaml_file_contents or b"",
            user_python=b"",
            output_path=str(user_item.yaml_file_path),
        )
        if has_conflict:
            merge_conflict_item_ids.append(user_item_id)
            continue

        # consider updated if no conflict with both files
        updated_item_ids.append(user_item_id)

    if analysis_id is None:
        if len(updated_item_ids) > 0:
            print(f"Updated {len(updated_item_ids)} spec(s) with latest Panther version:")
            for item_id in updated_item_ids:
                print(f"  * {item_id}")
        if len(merge_conflict_item_ids) > 0:
            print(
                f"{len(merge_conflict_item_ids)} merge conflict(s) found, run `pat merge <id>` to resolve each conflict:"
            )
            for conflict in merge_conflict_item_ids:
                print(f"  * {conflict}")
        print(
            "Run `git diff` to see the changes. Run `pat test` to test the changes and `pat upload` to upload them."
        )


def merge_file(
    solve_merge: bool, user: bytes, base: bytes, latest: bytes, user_python: bytes, output_path: str
) -> bool:
    with (
        tempfile.NamedTemporaryFile(delete=False) as temp_file_user,
        tempfile.NamedTemporaryFile(delete=False) as temp_file_base,
        tempfile.NamedTemporaryFile(delete=False) as temp_file_latest,
    ):
        temp_file_user.write(user)
        temp_file_user.flush()
        temp_file_base.write(base)
        temp_file_base.flush()
        temp_file_latest.write(latest)
        temp_file_latest.flush()

        has_conflict, merged_yaml = git_helpers.merge_file(
            temp_file_user.name, temp_file_base.name, temp_file_latest.name
        )
        if has_conflict:
            if solve_merge:
                if pathlib.Path(output_path).suffix in [".yml", ".yaml"]:
                    with tempfile.NamedTemporaryFile(delete=False) as temp_file_user_python:
                        temp_file_user_python.write(user_python)
                        temp_file_user_python.flush()

                        yaml_conflict_resolver_gui.YAMLConflictResolverApp(
                            customer_python=user_python.decode("utf-8"),
                            raw_customer_yaml=user.decode("utf-8"),
                            raw_panther_yaml=latest.decode("utf-8"),
                            raw_base_yaml=base.decode("utf-8"),
                        )
                else:
                    with tempfile.NamedTemporaryFile(delete=False) as temp_merged_file:
                        temp_merged_file.write(merged_yaml)
                        temp_merged_file.flush()

                        editor.merge_files_in_editor(
                            editor.MergeableFiles(
                                users_file=temp_file_user.name,
                                base_file=temp_file_base.name,
                                panthers_file=temp_file_latest.name,
                                premerged_file=temp_merged_file.name,
                                output_file=output_path,
                            )
                        )
                return False  # merge was solved so no more conflict
            return True
        else:
            with open(output_path, "wb") as f:
                f.write(merged_yaml)
            return False
