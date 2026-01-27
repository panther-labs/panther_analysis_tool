import dataclasses
import logging
import pathlib
from typing import Tuple

from rich.progress import track

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.analysis_utils import load_analysis_specs_ex
from panther_analysis_tool.constants import AutoAcceptOption
from panther_analysis_tool.core import (
    analysis_cache,
    file_editor,
    merge_item,
    root,
    yaml,
)


@dataclasses.dataclass
class MergeArgs:
    analysis_id: str
    editor: str | None = None
    auto_accept: AutoAcceptOption | None = None
    write_merge_conflicts: bool = False


def run(args: MergeArgs) -> Tuple[int, str]:
    try:
        root.chdir_to_project_root()
        return merge_analysis(
            args.analysis_id, args.editor, args.auto_accept, args.write_merge_conflicts
        )
    except file_editor.EditorCommandNotFoundError as err:
        return 1, str(err)


def merge_analysis(
    analysis_id: str | None,
    editor: str | None,
    auto_accept: AutoAcceptOption | None = None,
    write_merge_conflicts: bool = False,
) -> Tuple[int, str]:
    # load all user analysis specs
    user_specs = list(load_analysis_specs_ex(["."], [], True))

    mergeable_items = get_mergeable_items(analysis_id, user_specs)
    if not mergeable_items and analysis_id is None:
        print("Nothing to merge.")
        return 0, ""

    if not mergeable_items and analysis_id is not None:
        spec_ids = [spec.analysis_id() for spec in user_specs]
        if analysis_id not in spec_ids:
            print(f"Analysis ID '{analysis_id}' not found in user analysis items.")
            return 0, ""
        print(f"Analysis ID '{analysis_id}' does not need merging.")
        return 0, ""

    merge_items(mergeable_items, analysis_id, editor, auto_accept, write_merge_conflicts)

    return 0, ""


def get_mergeable_items(
    analysis_id: str | None,
    user_specs: list[analysis_utils.LoadAnalysisSpecsResult],
) -> list[merge_item.MergeableItem]:
    """
    Get all mergeable items. An analysis item is mergeable if it has a BaseVersion and the BaseVersion is less than the latest version
    in the analysis cache. If an analysis_id is provided, only the item that matches the analysis_id is returned.

    Args:
        analysis_id: The analysis id to filter by. If None, all mergeable items are returned.

    Returns:
        A list of MergeableItem objects that contain the user's item, the latest Panther item, and the base Panther item.
    """
    yaml_loader = yaml.BlockStyleYAML()
    cache = analysis_cache.AnalysisCache()
    mergeable_items: list[merge_item.MergeableItem] = []

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

        # if the user spec does not have a BaseVersion, add one
        if "BaseVersion" not in user_spec.analysis_spec:
            user_spec.analysis_spec["BaseVersion"] = 1

        # check if the user spec's BaseVersion is less than the latest version, skip merge if it is not
        user_spec_base_version: int = user_spec.analysis_spec.get("BaseVersion")
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
                "%s at version %s not found, skipping", user_spec_id, user_spec_base_version
            )
            continue

        # load the python file for the user spec from the file system
        user_py: bytes | None = None
        py_path: pathlib.Path | None = None
        if user_spec.analysis_spec.get("Filename") is not None:
            py_path = user_spec.python_file_path()
            user_py = py_path.read_bytes() if py_path is not None else None

        mergeable_items.append(
            merge_item.MergeableItem(
                user_item=analysis_utils.AnalysisItem(
                    yaml_file_contents=user_spec.analysis_spec,
                    raw_yaml_file_contents=user_spec.raw_spec_file_content,
                    yaml_file_path=user_spec.spec_filename,
                    python_file_contents=user_py,
                    python_file_path=str(py_path) if py_path is not None else None,
                ),
                latest_panther_item=analysis_utils.AnalysisItem(
                    yaml_file_contents=yaml_loader.load(latest_spec.spec),
                    raw_yaml_file_contents=latest_spec.spec,
                    python_file_contents=cache.get_file_for_spec(
                        latest_spec.id or -1, latest_spec.version
                    ),
                ),
                base_panther_item=analysis_utils.AnalysisItem(
                    yaml_file_contents=yaml_loader.load(base_spec.spec),
                    raw_yaml_file_contents=base_spec.spec,
                    python_file_contents=cache.get_file_for_spec(
                        base_spec.id or -1, base_spec.version
                    ),
                ),
                latest_item_version=latest_spec.version,
            )
        )

    return mergeable_items


def merge_items(  # pylint: disable=too-many-arguments
    mergeable_items: list[merge_item.MergeableItem],
    analysis_id: str | None,
    editor: str | None,
    auto_accept: AutoAcceptOption | None = None,
    show_progress_bar: bool = False,
    write_merge_conflicts: bool = False,
) -> None:
    updated_item_ids: list[str] = []
    merge_conflict_item_ids: list[str] = []
    yaml_loader = yaml.BlockStyleYAML()

    for mergeable_item in track(
        mergeable_items,
        description="Merging analysis items:",
        disable=not show_progress_bar,
        transient=True,
    ):
        if analysis_id is not None and analysis_id != mergeable_item.user_item.analysis_id():
            # user specified an analysis id, only merge that one
            continue

        has_conflict = merge_item.merge_item(
            mergeable_item, analysis_id is not None, editor, auto_accept, write_merge_conflicts
        )
        if has_conflict:
            merge_conflict_item_ids.append(mergeable_item.user_item.analysis_id())
            continue

        # once we know there are no conflicts, we can update the BaseVersion to say merging is complete
        yaml_file_path = pathlib.Path(mergeable_item.user_item.yaml_file_path or "")
        user_spec: dict = yaml_loader.load(yaml_file_path)
        user_spec["BaseVersion"] = mergeable_item.latest_item_version
        yaml_loader.dump(user_spec, yaml_file_path)

        # consider updated if no conflict with both files
        updated_item_ids.append(mergeable_item.user_item.analysis_id())

    if analysis_id is None:
        if len(updated_item_ids) > 0:
            print(f"Updated {len(updated_item_ids)} analysis item(s) with latest Panther version:")
            for item_id in updated_item_ids:
                print(f"  * {item_id}")
        if len(merge_conflict_item_ids) > 0:
            print(
                f"{len(merge_conflict_item_ids)} merge conflict(s) found, run `EDITOR=<editor> pat merge <id>` to resolve each conflict:"
            )
            for conflict in merge_conflict_item_ids:
                print(f"  * {conflict}")
        if len(updated_item_ids) > 0:
            print(
                "Run `git diff` to see the changes. Run `pat test` to test the changes and `pat upload` to upload them."
            )
