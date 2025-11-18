import dataclasses
import logging
import pathlib
import shutil
import tempfile

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.core import diff, file_editor, git_helpers, yaml
from panther_analysis_tool.gui import yaml_conflict_resolver_gui


class MergeError(Exception):
    pass


@dataclasses.dataclass
class MergeableItem:
    user_item: analysis_utils.AnalysisItem
    latest_panther_item: analysis_utils.AnalysisItem
    base_panther_item: analysis_utils.AnalysisItem


def merge_item(mergeable_item: MergeableItem, solve_merge: bool, editor: str | None) -> bool:
    user_item = mergeable_item.user_item
    latest_item = mergeable_item.latest_panther_item
    base_item = mergeable_item.base_panther_item

    # merge yaml
    has_conflict = merge_file(
        solve_merge=solve_merge,
        # or b"" makes typing happy but it should never be None
        user=user_item.raw_yaml_file_contents or b"",
        base=base_item.raw_yaml_file_contents or b"",
        latest=latest_item.raw_yaml_file_contents or b"",
        user_python=b"",
        output_path=pathlib.Path(user_item.yaml_file_path or ""),
        editor=editor,
    )
    if has_conflict and not solve_merge:
        # no need to merge python if yaml has a conflict because
        # we are just tracking what items have conflicts, not which files,
        # and has_conflict would be False if solve_merge is True
        return True

    # merge python (do this second since IDE may return before merge happens)
    if user_item.python_file_contents is not None:
        has_conflict = merge_file(
            solve_merge=solve_merge,
            # or b"" makes typing happy but it should never be None
            user=user_item.python_file_contents or b"",
            base=base_item.python_file_contents or b"",
            latest=latest_item.python_file_contents or b"",
            user_python=user_item.python_file_contents or b"",
            output_path=pathlib.Path(user_item.python_file_path or ""),
            editor=editor,
        )
        return has_conflict

    return False


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
