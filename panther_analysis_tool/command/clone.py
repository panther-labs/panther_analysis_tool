import logging
from typing import Any, List, Optional, Tuple

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.core import (
    analysis_cache,
    clone_item,
    parse,
    versions_file,
    yaml,
)


def run(analysis_id: Optional[str], filter_args: List[str]) -> Tuple[int, str]:
    try:
        clone(analysis_id, filter_args)
    except (ValueError, analysis_cache.NoCacheException) as err:
        return 1, str(err)

    return 0, ""


def clone(analysis_id: Optional[str], filter_args: List[str]) -> None:
    items_to_clone = get_analysis_items(analysis_id, filter_args)

    if len(items_to_clone) == 0:
        label = "analysis ID and filters"
        if analysis_id is None and len(filter_args) > 0:
            label = "filters"
        elif analysis_id is not None and len(filter_args) == 0:
            label = "analysis ID"

        raise ValueError(f"No items matched the {label}. Nothing to clone.")

    for item in items_to_clone:
        clone_item.set_enabled_field(item.yaml_file_contents)
        clone_item.set_base_version_field(item.yaml_file_contents)

    clone_analysis_items(items_to_clone)


def get_analysis_items(
    analysis_id: Optional[str], filter_args: List[str]
) -> List[analysis_utils.AnalysisItem]:
    yaml_loader = yaml.BlockStyleYAML()
    cache = analysis_cache.AnalysisCache()
    versions = versions_file.get_versions().versions
    filters, filters_inverted = parse.parse_filter_args(filter_args)

    all_specs: List[analysis_utils.AnalysisItem] = []
    for _id in cache.list_spec_ids() if analysis_id is None else [analysis_id]:
        analysis_spec = cache.get_latest_spec(_id)
        if analysis_spec is None:
            continue

        loaded: dict[str, Any] = yaml_loader.load(analysis_spec.spec)

        if not analysis_utils.filter_analysis_spec(loaded, filters, filters_inverted):
            continue

        all_specs.append(
            analysis_utils.AnalysisItem(
                yaml_file_contents=loaded,
                yaml_file_path=versions[_id].history[versions[_id].version].yaml_file_path,
                python_file_path=versions[_id].history[versions[_id].version].py_file_path,
                python_file_contents=cache.get_file_for_spec(
                    analysis_spec.id or -1, analysis_spec.version
                ),
            )
        )

    return all_specs


def clone_analysis_items(items_to_clone: List[analysis_utils.AnalysisItem]) -> None:
    for item in items_to_clone:
        try:
            clone_item.clone_analysis_item(item)
        except FileExistsError:
            logging.info("%s already exists, skipping", item.analysis_id())

    clone_item.clone_deps(items_to_clone)
