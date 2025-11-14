import dataclasses
import logging
import pathlib
import shutil
import tempfile
from typing import Tuple

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.analysis_utils import load_analysis_specs_ex
from panther_analysis_tool.core import (
    analysis_cache,
    diff,
    file_editor,
    git_helpers,
    yaml,
)
from panther_analysis_tool.gui import yaml_conflict_resolver_gui


class MergeError(Exception):
    pass


@dataclasses.dataclass
class MergeableItem:
    user_item: analysis_utils.AnalysisItem
    latest_panther_item: analysis_utils.AnalysisItem
    base_panther_item: analysis_utils.AnalysisItem


def run(analysis_id: str | None, editor: str | None) -> Tuple[int, str]:
    return merge_analysis(analysis_id, editor)


def merge_analysis(analysis_id: str | None, editor: str | None) -> Tuple[int, str]:
    mergeable_items = get_mergeable_items(analysis_id)
    if not mergeable_items:
        print("Nothing to merge.")
        return 0, ""

    merge_items(mergeable_items, analysis_id, editor)

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
    yaml_loader = yaml.BlockStyleYAML()
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
            )
        )

    return mergeable_items


def merge_items(
    mergeable_items: list[MergeableItem], analysis_id: str | None, editor: str | None
) -> None:
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

        # merge yaml
        has_conflict = merge_file(
            solve_merge=analysis_id is not None,
            # or b"" makes typing happy but it should never be None
            user=user_item.raw_yaml_file_contents or b"",
            base=base_item.raw_yaml_file_contents or b"",
            latest=latest_item.raw_yaml_file_contents or b"",
            user_python=b"",
            output_path=pathlib.Path(user_item.yaml_file_path or ""),
            editor=editor,
        )
        if has_conflict and analysis_id is None:
            merge_conflict_item_ids.append(user_item_id)
            # no need to merge python if yaml has a conflict because
            # we are just tracking what items have conflicts, not which files,
            # and has_conflict would be False if analysis_id provided
            continue

        # merge python (do this second since IDE may return before merge happens)
        if user_item.python_file_contents is not None:
            has_conflict = merge_file(
                solve_merge=analysis_id is not None,
                # or b"" makes typing happy but it should never be None
                user=user_item.python_file_contents or b"",
                base=base_item.python_file_contents or b"",
                latest=latest_item.python_file_contents or b"",
                user_python=user_item.python_file_contents or b"",
                output_path=pathlib.Path(user_item.python_file_path or ""),
                editor=editor,
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
                f"{len(merge_conflict_item_ids)} merge conflict(s) found, run `EDITOR=<editor> pat merge <id>` to resolve each conflict:"
            )
            for conflict in merge_conflict_item_ids:
                print(f"  * {conflict}")
        if len(updated_item_ids) > 0:
            print(
                "Run `git diff` to see the changes. Run `pat test` to test the changes and `pat upload` to upload them."
            )


# pylint: disable=too-many-locals,too-many-arguments
def merge_file(
    solve_merge: bool,
    user: bytes,
    base: bytes,
    latest: bytes,
    user_python: bytes,
    output_path: pathlib.Path,
    editor: str | None,
) -> bool:
    """
    Merge a file with git and solve the merge conflict if requested.
    YAML conflicts are solved with the yaml_conflict_resolver_gui.
    Python conflicts are solved with an editor.

    Args:
        solve_merge: Whether to solve the merge conflict.
        user: The user file contents.
        base: The base file contents.
        latest: The latest Panther file contents.
        user_python: The user Python file contents.
        output_path: The path to the output file.

    Returns:
        True if there was a merge conflict, False otherwise or if the user soled the merge conflict.
    """
    ext = output_path.suffix
    yaml_loader = yaml.BlockStyleYAML()

    # this temp dir gets cleaned up automatically when it leaves the with block
    with tempfile.TemporaryDirectory(prefix="pat_merge_") as temp_dir_str:
        temp_dir = pathlib.Path(temp_dir_str)
        user_path = temp_dir / f"user{ext}"
        base_path = temp_dir / f"base{ext}"
        latest_path = temp_dir / f"latest{ext}"
        user_path.write_bytes(user)
        base_path.write_bytes(base)
        latest_path.write_bytes(latest)

        if ext in [".yml", ".yaml"]:
            user_python_path = temp_dir / "user_python.py"
            user_python_path.write_bytes(user_python)

            merge_dict = diff.Dict(yaml_loader.load(user_path))
            conflicts = merge_dict.merge_dict(
                yaml_loader.load(base_path), yaml_loader.load(latest_path)
            )

            if len(conflicts) == 0:
                with open(output_path, "w", encoding="utf-8") as file:
                    yaml_loader.dump(merge_dict.customer_dict, file)
                return False  # merge was solved so no more conflict

            if not solve_merge:
                return True

            app = yaml_conflict_resolver_gui.YAMLConflictResolverApp(
                customer_python=user_python.decode("utf-8"),
                raw_customer_yaml=user.decode("utf-8"),
                raw_panther_yaml=latest.decode("utf-8"),
                raw_base_yaml=base.decode("utf-8"),
                customer_dict=merge_dict.customer_dict,
                conflict_items=conflicts,
            )
            app.run()

            with open(output_path, "w", encoding="utf-8") as file:
                yaml_loader.dump(app.get_final_dict(), file)
            return False  # merge was solved so no more conflict

        # python merge
        has_conflict, merged_contents = git_helpers.merge_file(user_path, base_path, latest_path)
        if not has_conflict:
            with open(output_path, "wb") as file:
                file.write(merged_contents)
            return False

        if not solve_merge:
            return True

        # make a long-lived temp dir so that async editors can use the files in the directory.
        # IDE editing may outlive this function call because some IDEs are not blocking, like vscode and goland.
        # This dir will go in system temp and OS should eventually clean it up.
        long_lived_temp_dir = make_long_lived_temp_dir(temp_dir)

        merged_path = long_lived_temp_dir / f"merged{ext}"
        merged_path.write_bytes(merged_contents)

        async_edit = file_editor.merge_files_in_editor(
            file_editor.MergeableFiles(
                users_file=long_lived_temp_dir / user_path.name,
                base_file=long_lived_temp_dir / base_path.name,
                panthers_file=long_lived_temp_dir / latest_path.name,
                premerged_file=merged_path,
                output_file=output_path,
            ),
            editor=editor,
        )
        if not async_edit:
            # editing has finished so remove the long-lived temp dir
            shutil.rmtree(long_lived_temp_dir)

        return False  # merge was solved so no more conflict


def make_long_lived_temp_dir(copy_dir: pathlib.Path) -> pathlib.Path:
    """
    Creates a long-lived temporary directory that is not cleaned up at exit but by the OS.
    Copy all files contents from the copy_dir to this directory for use.
    """
    temp_dir = tempfile.mkdtemp(prefix="pat_merge_")
    logging.debug("Long lived temp dir: %s", temp_dir)

    for file_path in copy_dir.iterdir():
        (pathlib.Path(temp_dir) / file_path.name).write_bytes(file_path.read_bytes())

    return pathlib.Path(temp_dir)
