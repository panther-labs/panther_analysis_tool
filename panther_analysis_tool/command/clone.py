import io
import logging
import pathlib
from dataclasses import dataclass
from typing import Any, Callable, Iterator, List, Optional, Tuple

from panther_analysis_tool.analysis_utils import (
    LoadAnalysisSpecsResult,
    filter_analysis_spec,
    get_yaml_loader,
    load_analysis_specs_ex,
    lookup_analysis_id,
)
from panther_analysis_tool.constants import AnalysisTypes
from panther_analysis_tool.core import analysis_cache
from panther_analysis_tool.core.formatter import analysis_spec_dump
from panther_analysis_tool.core.parse import parse_filter


def run(analysis_id: Optional[str], filters: List[str]) -> Tuple[int, str]:
    clone_analysis(analysis_id, filters, lambda x: x)
    return 0, ""


@dataclass
class CloneAnalysisResult:
    analysis_spec: dict[str, Any]
    file_bytes: Optional[bytes]
    relative_path: str


def clone_analysis(
    analysis_id: Optional[str], filters: List[str], mutator: Callable[[Any], Any]
) -> None:
    yaml = get_yaml_loader(roundtrip=False)
    cache = analysis_cache.AnalysisCache()
    all_specs = []
    for _id in cache.list_spec_ids():
        analysis_spec = cache.get_latest_spec(_id)
        if analysis_spec is None:
            raise ValueError(f"Analysis spec not found for id: {_id}")

        loaded = yaml.load(io.BytesIO(analysis_spec.spec))
        all_specs.append(
            CloneAnalysisResult(
                relative_path=analysis_spec.file_path,
                analysis_spec=loaded,
                file_bytes=cache.get_file_for_spec(analysis_spec.id),
            )
        )

    if not all_specs:
        logging.info("Nothing to clone")
        return None

    existing_specs = load_analysis_specs_ex(["."], [], False)

    if analysis_id is not None:
        return _clone_analysis_id(analysis_id, existing_specs, all_specs, mutator)

    return _clone_analysis_filters(filters, all_specs, mutator)


def _clone_analysis_filters(
    filters: List[str],
    all_specs: List[CloneAnalysisResult],
    mutator: Optional[Callable[[Any], Any]],
) -> None:
    _filters, _filters_inverted = parse_filter(filters)
    filtered_specs = [
        spec
        for spec in all_specs
        if filter_analysis_spec(spec.analysis_spec, _filters, _filters_inverted)
    ]

    if not filtered_specs:
        logging.info("Nothing to clone")

    # Apply the filters as needed
    for clone_spec in filtered_specs:
        match clone_spec.analysis_spec["AnalysisType"]:
            case (
                AnalysisTypes.RULE
                | AnalysisTypes.SCHEDULED_RULE
                | AnalysisTypes.SAVED_QUERY
                | AnalysisTypes.SCHEDULED_QUERY
                | AnalysisTypes.GLOBAL
                | AnalysisTypes.CORRELATION_RULE
                | AnalysisTypes.DATA_MODEL
                | AnalysisTypes.LOOKUP_TABLE
                | AnalysisTypes.POLICY
                | AnalysisTypes.DERIVED
                | AnalysisTypes.SIMPLE_DETECTION
            ):
                _create_clone(clone_spec, mutator, clone_spec.file_bytes)
            case AnalysisTypes.PACK:
                # ignore packs
                pass
            case _:
                raise ValueError(
                    f"Unsupported analysis type: {clone_spec.analysis_spec['AnalysisType']}"
                )


def _clone_analysis_id(
    analysis_id: str,
    existing_specs: Iterator[LoadAnalysisSpecsResult],
    all_specs: List[CloneAnalysisResult],
    mutator: Callable[[Any], Any],
) -> None:
    for existing_spec in existing_specs:
        if lookup_analysis_id(existing_spec.analysis_spec) == analysis_id:
            new_spec = mutator(existing_spec.analysis_spec)
            with open(existing_spec.spec_filename, "wb") as updated_spec:
                updated_spec.write(analysis_spec_dump(new_spec))
            logging.info("Updated existing %s in %s", analysis_id, existing_spec.spec_filename)
            return

    for clone_spec in all_specs:
        if lookup_analysis_id(clone_spec.analysis_spec) == analysis_id:
            _create_clone(clone_spec, mutator, clone_spec.file_bytes)
            return


def _create_clone(
    spec: CloneAnalysisResult,
    mutator: Optional[Callable[[Any], Any]],
    file_bytes: Optional[bytes],
) -> None:
    # create a copy of the spec, with the BaseVersion set to the current spec
    new_spec = spec.analysis_spec
    new_spec["BaseVersion"] = spec.analysis_spec.get("Version", 1)
    if mutator is not None:
        new_spec = mutator(new_spec)

    # create a new file
    new_file_path = pathlib.Path(spec.relative_path)

    new_file_path.parent.mkdir(parents=True, exist_ok=True)

    with open(new_file_path, "wb") as new_file:
        new_file.write(analysis_spec_dump(new_spec))

    match spec.analysis_spec["AnalysisType"]:
        case AnalysisTypes.SCHEDULED_RULE | AnalysisTypes.GLOBAL | AnalysisTypes.POLICY:
            if file_bytes is None:
                analysis_id = lookup_analysis_id(spec.analysis_spec)
                analysis_type = spec.analysis_spec["AnalysisType"]
                raise ValueError(f"File bytes are required for {analysis_type} {analysis_id}")

            spec_filename = spec.analysis_spec.get("Filename")
            if spec_filename is None:
                raise ValueError("Filename is required for rules")
            # clone the .py file
            filename = new_file_path.parent / spec_filename
            with open(filename, "wb") as new_file:
                new_file.write(file_bytes)
        case (
            AnalysisTypes.RULE
            | AnalysisTypes.SAVED_QUERY
            | AnalysisTypes.SCHEDULED_QUERY
            | AnalysisTypes.DATA_MODEL
        ):
            spec_filename = spec.analysis_spec.get("Filename")
            if spec_filename is None:
                return
            if file_bytes is None:
                raise ValueError("File bytes are required for rules")

            filename = new_file_path.parent / spec_filename
            with open(filename, "wb") as new_file:
                new_file.write(file_bytes)

        case _:
            pass
