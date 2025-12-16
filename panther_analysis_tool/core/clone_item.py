import dataclasses
import pathlib
from typing import Any

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.constants import AnalysisTypes
from panther_analysis_tool.core import analysis_cache, parse, versions_file, yaml


@dataclasses.dataclass
class LoadedDataModelSpec:
    spec_item: analysis_cache.AnalysisSpec
    spec: dict[str, Any]
    log_types: list[str]


def clone_analysis_item(item: analysis_utils.AnalysisItem, show_cloned_items: bool = False) -> None:
    """
    Clones the analysis item.

    Args:
        item: The analysis item to clone.

    Raises:
        FileExistsError: If the analysis item already exists.
    """
    yaml_loader = yaml.BlockStyleYAML()

    yaml_path = pathlib.Path(item.yaml_file_path or "")
    if yaml_path.exists():
        raise FileExistsError(f"{item.analysis_id()} at {yaml_path} already exists")

    py_path = pathlib.Path(item.python_file_path or "")
    if item.python_file_path is not None and py_path.exists():
        raise FileExistsError(f"{item.analysis_id()} at {py_path} already exists")

    set_enabled_field(item.yaml_file_contents)
    set_base_version_field(item.yaml_file_contents)

    yaml_path.parent.mkdir(parents=True, exist_ok=True)
    with open(yaml_path, "wb") as yaml_file:
        yaml_loader.dump(item.yaml_file_contents, yaml_file)

    if item.python_file_path is not None and item.python_file_contents is not None:
        py_path.parent.mkdir(parents=True, exist_ok=True)
        with open(py_path, "wb") as py_file:
            py_file.write(item.python_file_contents)

    if show_cloned_items:
        print(f"{item.pretty_analysis_type()} {item.analysis_id()} cloned.")


def clone_deps(
    items_with_deps: list[analysis_utils.AnalysisItem],
    show_cloned_items: bool = False,
) -> None:
    """
    Clones the dependencies of the analysis item.

    Args:
        items_with_deps: The analysis items to clone the dependencies for.
    """
    if len(items_with_deps) == 0:
        return

    all_log_types: set[str] = set()
    all_top_level_imports: set[str] = set()
    checked_global_helpers: set[str] = set()  # global helpers whose imports have been checked
    cache = analysis_cache.AnalysisCache()
    versions = versions_file.get_versions().versions
    yaml_loader = yaml.BlockStyleYAML()
    global_helpers: dict[str, analysis_cache.AnalysisSpec] = {}  # filename -> spec
    data_models: list[LoadedDataModelSpec] = []

    for spec_id in cache.list_spec_ids():
        spec = cache.get_latest_spec(spec_id)
        if spec is None:
            continue

        loaded = yaml_loader.load(spec.spec)

        if loaded["AnalysisType"] == AnalysisTypes.GLOBAL:
            if "Filename" not in loaded:
                continue
            global_helpers[loaded["Filename"].split(".")[0]] = spec
        elif loaded["AnalysisType"] == AnalysisTypes.DATA_MODEL:
            data_models.append(
                LoadedDataModelSpec(
                    spec_item=spec,
                    spec=loaded,
                    log_types=loaded["LogTypes"] if "LogTypes" in loaded else [],
                )
            )

    # collect all imports from the items we are cloning
    for item in items_with_deps:
        imports = parse.collect_top_level_imports(item.python_file_contents or b"")
        all_top_level_imports.update(imports)
        all_log_types.update(
            item.yaml_file_contents["LogTypes"] if "LogTypes" in item.yaml_file_contents else []
        )

    # collect all imports from the data models we are cloning
    for log_type in all_log_types:
        for data_model in data_models:
            if log_type in data_model.log_types:
                python_file_content = cache.get_file_for_spec(
                    data_model.spec_item.id or -1, data_model.spec_item.version
                )
                if python_file_content is not None:
                    all_top_level_imports.update(
                        parse.collect_top_level_imports(python_file_content)
                    )

    # check all global helper imports
    check_global_helper_imports(
        all_top_level_imports, checked_global_helpers, global_helpers, cache
    )

    for import_ in all_top_level_imports:
        if import_ in global_helpers:
            try:
                item = cached_analysis_spec_to_analysis_item(
                    global_helpers[import_], cache, versions
                )
                clone_analysis_item(item, show_cloned_items=show_cloned_items)
            except FileExistsError:
                pass

    # just LogTypes in data models, no ResourceTypes support
    for log_type in all_log_types:
        for data_model in data_models:
            if log_type in data_model.log_types:
                item = cached_analysis_spec_to_analysis_item(data_model.spec_item, cache, versions)
                set_enabled_field(item.yaml_file_contents)
                try:
                    clone_analysis_item(item, show_cloned_items=show_cloned_items)
                except FileExistsError:
                    pass
                break


def check_global_helper_imports(
    all_top_level_imports: set[str],
    checked_global_helpers: set[str],
    global_helpers: dict[str, analysis_cache.AnalysisSpec],
    cache: analysis_cache.AnalysisCache,
) -> None:
    """
    Discovers transitive global helper dependencies by checking imports recursively.

    This function processes imports in needs_check and identifies which ones are global helpers.
    For each global helper found, it checks that helper's imports to discover additional
    transitive dependencies. All discovered global helper dependencies are added to needs_check.

    Args:
        all_top_level_imports: Set of import names to check. Modified in place to include all
            transitive global helper dependencies discovered during processing.
        checked_global_helpers: Set tracking which global helpers have already been
            processed. Modified in place to prevent duplicate processing.
        global_helpers: Dictionary mapping global helper filenames (without .py extension)
            to their AnalysisSpec objects.
        cache: AnalysisCache instance used to retrieve Python file contents for helpers.
    """
    # Use a queue-based approach to avoid recursion issues
    to_process = list(all_top_level_imports)

    while to_process:
        import_name = to_process.pop(0)

        # Skip if already checked or not a global helper
        if import_name in checked_global_helpers:
            continue
        if import_name not in global_helpers:
            continue

        # Get the helper's Python file
        helper = global_helpers[import_name]
        helper_py = cache.get_file_for_spec(helper.id or -1, helper.version)
        if helper_py is None:
            continue

        # Find imports in this helper
        helper_imports = parse.collect_top_level_imports(helper_py)

        # Mark this helper as checked
        checked_global_helpers.add(import_name)

        # Add any new global helper dependencies to the queue
        for helper_import in helper_imports:
            if helper_import in global_helpers and helper_import not in checked_global_helpers:
                all_top_level_imports.add(helper_import)
                if helper_import not in to_process:
                    to_process.append(helper_import)


def cached_analysis_spec_to_analysis_item(
    spec: analysis_cache.AnalysisSpec,
    cache: analysis_cache.AnalysisCache,
    versions: dict[str, versions_file.AnalysisVersionItem],
) -> analysis_utils.AnalysisItem:
    yaml_loader = yaml.BlockStyleYAML()
    loaded = yaml_loader.load(spec.spec)

    version_item = versions[spec.id_value]
    version_history_item = version_item.history[version_item.version]

    return analysis_utils.AnalysisItem(
        yaml_file_contents=loaded,
        yaml_file_path=version_history_item.yaml_file_path,
        raw_yaml_file_contents=spec.spec,
        python_file_path=version_history_item.py_file_path,
        python_file_contents=cache.get_file_for_spec(spec.id or -1, spec.version),
    )


def set_enabled_field(spec: dict[str, Any]) -> None:
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


def set_base_version_field(spec: dict[str, Any]) -> None:
    spec["BaseVersion"] = versions_file.get_versions().get_current_version(
        analysis_utils.lookup_analysis_id(spec)
    )
