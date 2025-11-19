"""
A module for migrating analysis items from v1 of Panther Analysis usage, where a user
forks the Panther Analysis repository, to v2 where a user uses the Panther Analysis tool to
manage their analysis items without a fork, taking over the merge process.
"""

import dataclasses
import io
import pathlib
from collections import defaultdict
from typing import Tuple

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.constants import AutoAcceptOption
from panther_analysis_tool.core import analysis_cache, merge_item, yaml


@dataclasses.dataclass
class MigrationItem:
    """
    An item that was migrated or should be migrated.

    Attributes:
        analysis_id: The ID of the analysis item
        analysis_type: The type of the analysis item
    """

    analysis_id: str
    "The ID of the analysis item"

    analysis_type: str
    "The type of the analysis item"


@dataclasses.dataclass
class MigrationResult:
    """
    Result of a migration operation.

    Attributes:
        items_with_conflicts: (analysis id, analysis type) of items not migrated due to merge conflicts
        items_migrated: (analysis id, analysis type) of items migrated
    """

    items_with_conflicts: list[MigrationItem]
    "Items not migrated due to merge conflicts"

    items_migrated: list[MigrationItem]
    "Items migrated"

    def empty(self) -> bool:
        return len(self.items_with_conflicts) == 0 and len(self.items_migrated) == 0

    def _by_analysis_type(self, items: list[MigrationItem]) -> dict[str, list[MigrationItem]]:
        result = defaultdict(list)
        for item in items:
            result[item.analysis_type].append(item)
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
    migration_output = pathlib.Path("migration_output.md")
    migration_result = migrate(analysis_id, editor, migration_output, auto_accept)
    if not migration_result.empty():
        completion_message = "Migration complete! Details can be found in: `migration_output.md`."
        if migration_result.has_conflicts():
            completion_message = (
                "Migration completed for analysis items without merge conflicts. "
                "Items with conflicts need to be resolved manually. Details can be found in: `migration_output.md`.\n"
                "  * Run `EDITOR=<editor> pat migrate <id>` to resolve each conflict."
            )
        print(completion_message)
        print("Run `git diff` to see any changes made.")
    else:
        print("All analysis items in your repo are already migrated! ")
        print("  * Run `pat pull` to pull in the latest Panther Analysis items.")
        print("  * Run `pat explore` to explore available analysis items.")
        print("  * Run `pat enable` to clone and enable analysis items you want to use.")
        print("Run `pat --help` for more information.")

    return 0, ""


def migrate(
    analysis_id: str | None,
    editor: str | None,
    migration_output: pathlib.Path,
    auto_accept: AutoAcceptOption | None = None,
) -> MigrationResult:
    items_to_migrate = get_items_to_migrate(analysis_id)
    if len(items_to_migrate) == 0:
        return MigrationResult(items_with_conflicts=[], items_migrated=[])

    migration_result = migrate_items(items_to_migrate, analysis_id is not None, editor, auto_accept)
    write_migration_results(migration_result, migration_output)

    return migration_result


def write_migration_results(
    migration_result: MigrationResult, migration_output: pathlib.Path
) -> None:
    if migration_result.empty():
        return

    stream = io.StringIO()
    stream.write("# Migration Results\n\n")

    if len(migration_result.items_with_conflicts) > 0:
        stream.write("## Analysis Items with Merge Conflicts\n\n")
        stream.write(
            f"{len(migration_result.items_with_conflicts)} merge conflict(s) found. Run `EDITOR=<editor> pat migrate <id>` to resolve each conflict.\n\n"  # pylint: disable=line-too-long
        )
        for (
            analysis_type,
            conflicts,
        ) in migration_result.items_with_conflicts_by_analysis_type().items():
            stream.write(f"### Analysis Type: {analysis_type}\n\n")
            stream.write(f"{len(conflicts)} merge conflict(s).\n\n")
            for conflict in conflicts:
                stream.write(f"  * {conflict.analysis_id}\n")
            stream.write("\n")

    if len(migration_result.items_migrated) > 0:
        stream.write("## Analysis Items Migrated\n\n")
        stream.write(f"{len(migration_result.items_migrated)} analysis item(s) migrated.\n\n")
        for (
            analysis_type,
            items_migrated,
        ) in migration_result.migrated_items_by_analysis_type().items():
            stream.write(f"### Analysis Type: {analysis_type}\n\n")
            stream.write(f"{len(items_migrated)} analysis item(s) migrated.\n\n")
            for item in items_migrated:
                stream.write(f"  * {item.analysis_id}\n")
            stream.write("\n")

    migration_output.write_text(stream.getvalue())


def get_items_to_migrate(analysis_id: str | None) -> list[merge_item.MergeableItem]:
    cache = analysis_cache.AnalysisCache()
    yaml_loader = yaml.BlockStyleYAML()

    items_to_migrate: list[merge_item.MergeableItem] = []
    for user_spec in analysis_utils.load_analysis_specs_ex(["."], [], True):
        if analysis_id is not None and analysis_id != user_spec.analysis_id():
            # user specified an analysis id, only migrate that one
            continue

        user_spec_id = user_spec.analysis_id()

        # if the user spec does not have a BaseVersion, it needs to be migrated
        if "BaseVersion" in user_spec.analysis_spec:
            continue

        # load the latest analysis item from the cache using the user spec's ID
        latest_spec = cache.get_latest_spec(user_spec_id)
        if latest_spec is None:
            # this happens with custom analysis items
            continue

        user_spec.analysis_spec["BaseVersion"] = latest_spec.version
        stream = io.BytesIO()
        yaml_loader.dump(user_spec.analysis_spec, stream=stream)
        user_spec.raw_spec_file_content = stream.getvalue()

        # load the python file for the user spec from the file system
        user_py: bytes | None = None
        py_path: pathlib.Path | None = None
        if user_spec.analysis_spec.get("Filename") is not None:
            py_path = user_spec.python_file_path()
            user_py = py_path.read_bytes() if py_path is not None else None

        migration_item = merge_item.MergeableItem(
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
            # in the future this can be improved by using the last version fetched in the customer repo
            base_panther_item=analysis_utils.AnalysisItem({}, raw_yaml_file_contents=b"{}"),
        )

        items_to_migrate.append(migration_item)

    return items_to_migrate


def migrate_items(
    items_to_migrate: list[merge_item.MergeableItem],
    solve_merge: bool,
    editor: str | None,
    auto_accept: AutoAcceptOption | None = None,
) -> MigrationResult:
    items_with_conflicts: list[MigrationItem] = []
    items_migrated: list[MigrationItem] = []

    for item in items_to_migrate:
        has_conflict = merge_item.merge_item(
            mergeable_item=item, solve_merge=solve_merge, editor=editor, auto_accept=auto_accept
        )
        if has_conflict:
            items_with_conflicts.append(
                MigrationItem(
                    analysis_id=item.user_item.analysis_id(),
                    analysis_type=item.user_item.analysis_type(),
                )
            )
        else:
            items_migrated.append(
                MigrationItem(
                    analysis_id=item.user_item.analysis_id(),
                    analysis_type=item.user_item.analysis_type(),
                )
            )

    return MigrationResult(items_with_conflicts=items_with_conflicts, items_migrated=items_migrated)
