import dataclasses
from typing import Dict, Tuple

from rich.progress import BarColumn, Progress, TextColumn, track

from panther_analysis_tool.analysis_utils import (
    LoadAnalysisSpecsResult,
    load_analysis_specs_ex,
)
from panther_analysis_tool.command import merge
from panther_analysis_tool.constants import AutoAcceptOption
from panther_analysis_tool.core import analysis_cache, clone_item, root


@dataclasses.dataclass
class PullArgs:
    auto_accept: AutoAcceptOption | None = None
    write_merge_conflicts: bool = False
    preview: bool = False


def run(args: PullArgs) -> Tuple[int, str]:
    root.chdir_to_project_root()
    pull(
        show_progress_bar=True,
        auto_accept=args.auto_accept,
        write_merge_conflicts=args.write_merge_conflicts,
        preview=args.preview,
    )
    return 0, ""


def pull(
    show_progress_bar: bool = False,
    auto_accept: AutoAcceptOption | None = None,
    write_merge_conflicts: bool = False,
    preview: bool = False,
) -> None:
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
    analysis_cache.update_with_latest_panther_analysis(user_analysis_specs, show_progress_bar)

    # merge analysis items
    mergeable_items = merge.get_mergeable_items(None, list(user_analysis_specs.values()))
    if len(mergeable_items) > 0:
        merge.merge_items(
            mergeable_items=mergeable_items,
            analysis_id=None,
            editor=None,
            auto_accept=auto_accept,
            show_progress_bar=show_progress_bar,
            write_merge_conflicts=write_merge_conflicts,
            preview=preview,
        )

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
