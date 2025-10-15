import pathlib
from typing import Any, Dict, List, Optional, Tuple

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.constants import AnalysisTypes
from panther_analysis_tool.core import analysis_cache, parse, versions_file


def run(analysis_id: Optional[str], filter_args: List[str]) -> Tuple[int, str]:
    try:
        items_to_clone = get_analysis_items(analysis_id, filter_args)
    except analysis_cache.NoCacheException as err:
        return 1, str(err)

    if len(items_to_clone) == 0:
        label = "analysis ID and filters"
        if analysis_id is None and len(filter_args) > 0:
            label = "filters"
        elif analysis_id is not None and len(filter_args) == 0:
            label = "analysis ID"

        return 1, f"No items matched the {label}. Nothing to clone and enable."

    for item in items_to_clone:
        set_enabled_field(item.yaml_file_contents)
        set_base_version_field(item.yaml_file_contents)

    clone_analysis_items(items_to_clone)
    return 0, ""


def set_enabled_field(spec: Dict[str, Any]) -> None:
    if spec["AnalysisType"] in [
        AnalysisTypes.RULE,
        AnalysisTypes.SCHEDULED_RULE,
        AnalysisTypes.CORRELATION_RULE,
        AnalysisTypes.POLICY,
        AnalysisTypes.DATA_MODEL,
        AnalysisTypes.LOOKUP_TABLE,
        AnalysisTypes.SAVED_QUERY,
        AnalysisTypes.SCHEDULED_QUERY,
        AnalysisTypes.DERIVED,
        AnalysisTypes.SIMPLE_DETECTION,
    ]:
        spec["Enabled"] = True


def set_base_version_field(spec: Dict[str, Any]) -> None:
    versions = versions_file.get_versions().versions
    spec["BaseVersion"] = versions[analysis_utils.lookup_analysis_id(spec)].version


def get_analysis_items(
    analysis_id: Optional[str], filter_args: List[str]
) -> List[analysis_utils.AnalysisItem]:
    yaml = analysis_utils.get_yaml_loader(roundtrip=True)
    cache = analysis_cache.AnalysisCache()
    versions = versions_file.get_versions().versions
    filters, filters_inverted = parse.parse_filter_args(filter_args)

    all_specs: List[analysis_utils.AnalysisItem] = []
    for _id in cache.list_spec_ids() if analysis_id is None else [analysis_id]:
        analysis_spec = cache.get_latest_spec(_id)
        if analysis_spec is None:
            continue

        loaded: dict[str, Any] = yaml.load(analysis_spec.spec)

        if not analysis_utils.filter_analysis_spec(loaded, filters, filters_inverted):
            continue

        all_specs.append(
            analysis_utils.AnalysisItem(
                yaml_file_contents=loaded,
                yaml_file_path=versions[_id].history[versions[_id].version].yaml_file_path,
                python_file_path=versions[_id].history[versions[_id].version].py_file_path,
                python_file_contents=cache.get_file_for_spec(analysis_spec.id or -1),
            )
        )

    return all_specs


def clone_analysis_items(items_to_clone: List[analysis_utils.AnalysisItem]) -> None:
    yaml = analysis_utils.get_yaml_loader(roundtrip=True)

    for item in items_to_clone:
        yaml_path = pathlib.Path(item.yaml_file_path or "")
        yaml_path.parent.mkdir(parents=True, exist_ok=True)
        with open(yaml_path, "wb") as yaml_file:
            yaml.dump(item.yaml_file_contents, yaml_file)

        if item.python_file_path is not None and item.python_file_contents is not None:
            py_path = pathlib.Path(item.python_file_path)
            py_path.parent.mkdir(parents=True, exist_ok=True)
            with open(py_path, "wb") as py_file:
                py_file.write(item.python_file_contents)
