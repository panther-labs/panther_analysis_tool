"""
A module for migrating analysis items from v1 of Panther Analysis usage, where a user
forks the Panther Analysis repository, to v2 where a user uses the Panther Analysis tool to
manage their analysis items without a fork, taking over the merge process.
"""

import dataclasses
import io
import logging
import pathlib
from collections import defaultdict
from typing import Tuple

from rich.progress import BarColumn, Progress, TextColumn, track  # from tqdm

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.constants import AnalysisTypes, AutoAcceptOption
from panther_analysis_tool.core import (
    analysis_cache,
    clone_item,
    git_helpers,
    merge_item,
    versions_file,
    yaml,
)


@dataclasses.dataclass
class MigrationItem:
    """
    An item that was migrated or should be migrated.

    Attributes:
        analysis_id: The ID of the analysis item
        pretty_analysis_type: The type of the analysis item in a pretty format
        merged_item: The merged item that was migrated
        reason: More information about what happened to the item during migration
    """

    analysis_id: str
    "The ID of the analysis item"

    pretty_analysis_type: str
    "The type of the analysis item in a pretty format"

    merged_item: analysis_utils.AnalysisItem | None = None
    "The merged item that was migrated, or None if there was a merge conflict"

    reason: str | None = None
    "More information about what happened to the item during migration"


@dataclasses.dataclass
class MigrationResult:
    """
    Result of a migration operation.

    Attributes:
        items_with_conflicts: (analysis id, analysis type) of items not migrated due to merge conflicts
        items_migrated: (analysis id, analysis type) of items migrated
    """

    items_with_conflicts: list[MigrationItem] = dataclasses.field(default_factory=list)
    "Items not migrated due to merge conflicts"

    items_migrated: list[MigrationItem] = dataclasses.field(default_factory=list)
    "Items migrated"

    items_deleted: list[MigrationItem] = dataclasses.field(default_factory=list)
    "Items deleted"

    def empty(self) -> bool:
        return len(self.items_with_conflicts) == 0 and len(self.items_migrated) == 0

    def _by_analysis_type(self, items: list[MigrationItem]) -> dict[str, list[MigrationItem]]:
        result = defaultdict(list)
        for item in items:
            result[item.pretty_analysis_type].append(item)
        return dict(result)

    def migrated_items_by_analysis_type(self) -> dict[str, list[MigrationItem]]:
        return self._by_analysis_type(self.items_migrated)

    def items_with_conflicts_by_analysis_type(self) -> dict[str, list[MigrationItem]]:
        return self._by_analysis_type(self.items_with_conflicts)

    def has_conflicts(self) -> bool:
        return len(self.items_with_conflicts) > 0


def run(
    analysis_id: str | None, editor: str | None, auto_accept: AutoAcceptOption | None
) -> Tuple[int, str]:
    analysis_cache.update_with_latest_panther_analysis(show_progress_bar=True)

    migration_output = pathlib.Path("migration_output.md")
    migration_result = migrate(analysis_id, editor, migration_output, auto_accept)

    if analysis_id is not None:
        # skip the completion message if the user specified an analysis id
        return 0, ""

    if not migration_result.empty():
        completion_message = "Migration complete! Details can be found in: `migration_output.md`."
        if migration_result.has_conflicts():
            completion_message = (
                "Migration completed for analysis items without merge conflicts. "
                "Items with conflicts need to be resolved manually. \n"
                "  * Details can be found in: `migration_output.md`.\n"
                "  * Run `EDITOR=<editor> pat migrate <id>` to resolve each conflict.\n"
                "  * Run `pat migrate --auto-accept=<panthers|yours>` to automatically accept your changes or Panther's changes for merge conflicts."  # pylint: disable=line-too-long
            )
        print(completion_message)
        print()
        print("Run `git diff` to see any changes made.")
    else:
        print("All analysis items in your repo are already migrated! ")
        print("  * Run `pat pull` to pull in the latest Panther Analysis items.")
        print("  * Run `pat explore` to explore available analysis items.")
        print("  * Run `pat clone` to clone and enable analysis items you want to use.")
        print()
        print("Run `pat --help` for more information.")

    return 0, ""


def migrate(
    analysis_id: str | None,
    editor: str | None,
    migration_output: pathlib.Path,
    auto_accept: AutoAcceptOption | None = None,
) -> MigrationResult:
    result = MigrationResult()
    cache = analysis_cache.AnalysisCache()

    ancestor_commit: str | None = None
    try:
        ancestor_commit = git_helpers.get_forked_panther_analysis_common_ancestor()
    except RuntimeError as err:
        logging.debug("Failed to get forked panther analysis common ancestor: %s", err)

    # load all user analysis specs
    specs: list[analysis_utils.LoadAnalysisSpecsResult] = []
    for spec in track(
        analysis_utils.load_analysis_specs_ex(["."], [], True),
        description="Loading user analysis items:",
        disable=analysis_id is not None,
        transient=True,
    ):
        if spec.analysis_type() == AnalysisTypes.PACK:
            pathlib.Path(spec.spec_filename).unlink()
            result.items_deleted.append(
                MigrationItem(
                    analysis_id=spec.analysis_id(),
                    pretty_analysis_type=spec.pretty_analysis_type(),
                    reason="Packs are managed by Panther and not needed in your repo.",
                )
            )
            continue

        specs.append(spec)

    # migrate each user analysis spec
    for user_spec in track(
        specs, description="Migration progress:", disable=analysis_id is not None, transient=True
    ):
        item = get_migration_item(user_spec, analysis_id, cache, result, ancestor_commit)
        if item is None:
            continue

        migrate_item(item, analysis_id is not None, editor, result, auto_accept)
        ensure_python_file_exists(item)

    # we need to check if the new migrated python includes any
    # new global helper imports and clone those so the new python works
    with Progress(
        TextColumn("Cloning dependencies:"),
        BarColumn(),
        transient=True,
        disable=analysis_id is not None,
    ) as progress:
        task = progress.add_task("cloning_dependencies", total=None)
        items = [item.merged_item for item in result.items_migrated if item.merged_item is not None]
        clone_item.clone_deps(items)
        progress.update(task, completed=True)

    with Progress(
        TextColumn("Writing migration results:"),
        BarColumn(),
        transient=True,
        disable=analysis_id is not None,
    ) as progress:
        task = progress.add_task("writing_migration_results", total=None)
        write_migration_results(result, migration_output)
        progress.update(task, completed=True)

    return result


def write_migration_results(
    migration_result: MigrationResult, migration_output: pathlib.Path
) -> None:
    if migration_result.empty():
        return

    stream = io.StringIO()
    stream.write("# Migration Results\n\n")

    stream.write("## Migration Summary\n\n")
    stream.write(f"  * {len(migration_result.items_with_conflicts)} merge conflict(s) found.\n")
    stream.write(f"  * {len(migration_result.items_deleted)} analysis item(s) deleted.\n")
    stream.write(f"  * {len(migration_result.items_migrated)} analysis item(s) migrated.\n\n")

    if len(migration_result.items_with_conflicts) > 0:
        stream.write("## Analysis Items with Merge Conflicts\n\n")
        stream.write(
            f"{len(migration_result.items_with_conflicts)} merge conflict(s) found. Run `EDITOR=<editor> pat migrate <id>` to resolve each conflict.\n\n"  # pylint: disable=line-too-long
        )
        for conflict in migration_result.items_with_conflicts:
            stream.write(f"  * ({conflict.pretty_analysis_type}) {conflict.analysis_id}\n")
        stream.write("\n")

    if len(migration_result.items_deleted) > 0:
        stream.write("## Analysis Items Deleted\n\n")
        stream.write(f"{len(migration_result.items_deleted)} analysis item(s) deleted.\n\n")
        for item in migration_result.items_deleted:
            stream.write(
                f"  * ({item.pretty_analysis_type}) {item.analysis_id}{f' - {item.reason}' if item.reason is not None else ''}\n"
            )
        stream.write("\n")

    if len(migration_result.items_migrated) > 0:
        stream.write("## Analysis Items Migrated\n\n")
        stream.write(f"{len(migration_result.items_migrated)} analysis item(s) migrated.\n\n")
        for item in migration_result.items_migrated:
            stream.write(f"  * ({item.pretty_analysis_type}) {item.analysis_id}\n")
        stream.write("\n")

    migration_output.write_text(stream.getvalue())


def get_migration_item(
    user_spec: analysis_utils.LoadAnalysisSpecsResult,
    analysis_id: str | None,
    cache: analysis_cache.AnalysisCache,
    result: MigrationResult,
    ancestor_commit: str | None = None,
) -> merge_item.MergeableItem | None:
    yaml_loader = yaml.BlockStyleYAML()

    if analysis_id is not None and analysis_id != user_spec.analysis_id():
        # user specified an analysis id, only migrate that one
        return None

    if user_spec.analysis_type() == AnalysisTypes.PACK:
        # ignoring packs from migration
        return None

    user_spec_id = user_spec.analysis_id()

    # if the user spec does not have a BaseVersion, it needs to be migrated
    if "BaseVersion" in user_spec.analysis_spec:
        if analysis_id is not None:
            print(f"{user_spec_id} already migrated.")
        return None

    base_item = get_base_item(user_spec, ancestor_commit)

    # load the latest analysis item from the cache using the user spec's ID
    latest_spec = cache.get_latest_spec(user_spec_id)

    # was deleted by Panther, delete if the item was unused by the user
    if latest_spec is None and not base_item.empty() and not user_spec.enabled():
        user_spec.unlink()
        result.items_deleted.append(
            MigrationItem(
                analysis_id=user_spec_id,
                pretty_analysis_type=user_spec.pretty_analysis_type(),
                reason="Item was deleted by Panther since your last update and was disabled in your repo.",
            )
        )

    if latest_spec is None:
        # this happens with custom analysis items
        # or if the item was removed by Panther
        return None

    # load the python file for the user spec from the file system
    user_py: bytes | None = None
    py_path: pathlib.Path | None = None
    if user_spec.analysis_spec.get("Filename") is not None:
        py_path = user_spec.python_file_path()
        user_py = py_path.read_bytes() if py_path is not None else None

    return merge_item.MergeableItem(
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
            python_file_contents=cache.get_file_for_spec(latest_spec.id or -1, latest_spec.version),
        ),
        base_panther_item=base_item,
        latest_item_version=latest_spec.version,
    )


def migrate_item(
    item: merge_item.MergeableItem,
    solve_merge: bool,
    editor: str | None,
    migration_result: MigrationResult,
    auto_accept: AutoAcceptOption | None = None,
) -> None:
    yaml_loader = yaml.BlockStyleYAML()

    has_conflict = merge_item.merge_item(
        mergeable_item=item, solve_merge=solve_merge, editor=editor, auto_accept=auto_accept
    )
    if has_conflict:
        migration_result.items_with_conflicts.append(
            MigrationItem(
                analysis_id=item.user_item.analysis_id(),
                pretty_analysis_type=item.user_item.pretty_analysis_type(),
            )
        )
    else:
        migration_result.items_migrated.append(
            MigrationItem(
                analysis_id=item.user_item.analysis_id(),
                pretty_analysis_type=item.user_item.pretty_analysis_type(),
                merged_item=item.merged_item,
            )
        )

        # once we know there are no conflicts, we can add the BaseVersion to say migration is complete
        yaml_file_path = pathlib.Path(item.user_item.yaml_file_path or "")
        user_spec: dict = yaml_loader.load(yaml_file_path)
        user_spec["BaseVersion"] = item.latest_item_version
        yaml_loader.dump(user_spec, yaml_file_path)


def get_base_item(
    user_spec: analysis_utils.LoadAnalysisSpecsResult, ancestor_commit: str | None
) -> analysis_utils.AnalysisItem:
    """
    Get the base item for a user spec from Panther Analysis using the ancestor commit.
    If the ancestor commit is not provided, the base item will be an empty analysis item.

    Args:
        user_spec: The user spec to get the base item for
        ancestor_commit: The commit hash of the ancestor commit
    Returns:
        The base item for the user spec
    """
    base_item = analysis_utils.AnalysisItem({}, raw_yaml_file_contents=b"{}")
    if ancestor_commit is None or ancestor_commit == "":
        return base_item

    yaml_file_path = pathlib.Path(user_spec.spec_filename).relative_to(git_helpers.git_root())
    py_file_path = user_spec.python_file_path()
    if py_file_path is not None:
        py_file_path = pathlib.Path(py_file_path).relative_to(git_helpers.git_root())

    # use panther's file path if it exists
    if versions_file.get_versions().has_item(user_spec.analysis_id()):
        history_item = versions_file.get_versions().get_current_version_history_item(
            user_spec.analysis_id()
        )
        yaml_file_path = pathlib.Path(history_item.yaml_file_path)
        if py_file_path is not None:
            py_file_path = pathlib.Path(history_item.py_file_path or "")

    yaml_loader = yaml.BlockStyleYAML()
    base_yaml = git_helpers.get_file_at_commit(ancestor_commit, yaml_file_path)
    if base_yaml is not None:
        base_item.yaml_file_contents = yaml_loader.load(base_yaml)
        base_item.raw_yaml_file_contents = base_yaml

    if py_file_path is not None:
        base_item.python_file_contents = git_helpers.get_file_at_commit(
            ancestor_commit, py_file_path
        )

    return base_item


def ensure_python_file_exists(item: merge_item.MergeableItem) -> None:
    """
    Ensure the python file exists for the merged item.
    """
    if item.merged_item is None:
        return

    if "Filename" not in item.merged_item.yaml_file_contents:
        return

    if item.merged_item.yaml_file_path is None:
        return

    abs_python_file_path: pathlib.Path = (
        pathlib.Path(item.merged_item.yaml_file_path).parent
        / item.merged_item.yaml_file_contents["Filename"]
    )

    # when the item was updated during migration, the "Filename" value might have changed to
    # something not in the user's repo, so we need to check
    if abs_python_file_path.exists():
        return

    # turn absolute path into relative path
    git_python_file_path = abs_python_file_path.relative_to(git_helpers.git_root())

    # if the python file does not exist, try to grab it from PA
    python_file_contents = git_helpers.get_file_at_commit(
        git_helpers.REMOTE_UPSTREAM_NAME, git_python_file_path
    )

    # this is a best attempt effort so it is okay if it does not exist
    if python_file_contents is None or python_file_contents == b"":
        return

    # save the remote version of the python file if it does exist
    abs_python_file_path.parent.mkdir(parents=True, exist_ok=True)
    abs_python_file_path.write_bytes(python_file_contents)

    # update the merged item with the new stuff
    item.merged_item.python_file_contents = python_file_contents
    item.merged_item.python_file_path = str(abs_python_file_path)
