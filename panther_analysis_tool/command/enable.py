import logging
import pathlib
import re
from typing import Any, Dict, List, Optional, Tuple

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.constants import AnalysisTypes
from panther_analysis_tool.core import analysis_cache, parse, versions_file


def run(analysis_id: Optional[str], filter_args: List[str]) -> Tuple[int, str]:
    try:
        enable(analysis_id, filter_args)
    except FileExistsError as err:
        logging.info(err)
        return 0, ""
    except (ValueError, analysis_cache.NoCacheException) as err:
        return 1, str(err)

    return 0, ""


def enable(analysis_id: Optional[str], filter_args: List[str]) -> None:
    items_to_clone = get_analysis_items(analysis_id, filter_args)

    if len(items_to_clone) == 0:
        label = "analysis ID and filters"
        if analysis_id is None and len(filter_args) > 0:
            label = "filters"
        elif analysis_id is not None and len(filter_args) == 0:
            label = "analysis ID"

        raise ValueError(f"No items matched the {label}. Nothing to clone and enable.")

    for item in items_to_clone:
        contents = item.raw_yaml_file_contents or b""

        needs_enabled = should_set_enabled_field(item.yaml_file_contents)
        base_version = get_base_version_value(item.yaml_file_contents)

        item.raw_yaml_file_contents = append_fields_to_yaml(contents, needs_enabled, base_version)

    clone_analysis_items(items_to_clone)


def should_set_enabled_field(spec: Dict[str, Any]) -> bool:
    """Returns True if Enabled field should be set to True, None otherwise."""
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
        return True
    return False


def get_base_version_value(spec: Dict[str, Any]) -> int:
    """Returns the BaseVersion value that should be set."""
    versions = versions_file.get_versions().versions
    return versions[analysis_utils.lookup_analysis_id(spec)].version


def append_fields_to_yaml(raw_yaml: bytes, needs_enabled: bool, base_version: int) -> bytes:
    """
    Appends or updates fields in raw YAML without reformatting.
    If fields already exist, they are replaced. Otherwise, they are appended.
    """
    yaml_str = raw_yaml.decode("utf-8")

    # Build the fields to add/update
    fields_to_add = [("BaseVersion", str(base_version))]
    if needs_enabled:
        fields_to_add.append(("Enabled", "true"))

    # For each field, check if it exists and replace it, or append if it doesn't
    for field_name, field_value in fields_to_add:
        # Pattern to match the field at the start of a line (with optional whitespace)
        # This handles various YAML formats: "Field: value", "Field:value", "  Field: value", etc.
        pattern = rf"^(\s*){re.escape(field_name)}\s*:\s*.*$"

        # Check if field exists
        if re.search(pattern, yaml_str, re.MULTILINE):
            # Replace existing field (only first occurrence to avoid issues with duplicates)
            yaml_str = re.sub(
                pattern,
                rf"\1{field_name}: {field_value}",
                yaml_str,
                count=1,
                flags=re.MULTILINE,
            )
        else:
            # Append field at the end
            # Ensure there's a newline before appending
            if yaml_str and not yaml_str.endswith("\n"):
                yaml_str += "\n"
            yaml_str += f"{field_name}: {field_value}\n"

    return yaml_str.encode("utf-8")


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
                raw_yaml_file_contents=analysis_spec.spec,
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
        yaml_path = pathlib.Path(item.yaml_file_path or "")
        if yaml_path.exists():
            raise FileExistsError(f"{item.analysis_id()} at {yaml_path} already exists")

        py_path = pathlib.Path(item.python_file_path or "")
        if item.python_file_path is not None and py_path.exists():
            raise FileExistsError(f"{item.analysis_id()} at {py_path} already exists")

        yaml_path.parent.mkdir(parents=True, exist_ok=True)

        # Write raw YAML contents (which already has fields appended/updated)
        if item.raw_yaml_file_contents is None:
            raise ValueError(f"No raw YAML contents for {item.analysis_id()}")

        with open(yaml_path, "wb") as yaml_file:
            yaml_file.write(item.raw_yaml_file_contents)

        if item.python_file_path is not None and item.python_file_contents is not None:
            py_path.parent.mkdir(parents=True, exist_ok=True)
            with open(py_path, "wb") as py_file:
                py_file.write(item.python_file_contents)
