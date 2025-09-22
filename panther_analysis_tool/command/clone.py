import logging
import pathlib
import shutil
from typing import Any, Callable, List, Optional, Tuple

from panther_analysis_tool.analysis_utils import (
    LoadAnalysisSpecsResult,
    load_analysis_specs_ex,
    lookup_analysis_id,
)
from panther_analysis_tool.constants import CACHE_DIR, AnalysisTypes
from panther_analysis_tool.core.formatter import analysis_spec_dump


def run(analysis_id: Optional[str], filters: List[str]) -> Tuple[int, str]:
    clone_analysis(analysis_id, filters, lambda x: None)
    return 0, ""


def clone_analysis(
    analysis_id: Optional[str], filters: List[str], mutator: Callable[[Any], None]
) -> None:
    all_specs = list(load_analysis_specs_ex([CACHE_DIR], [], False))
    if not all_specs:
        logging.info("Nothing to clone")
        return None

    existing = load_analysis_specs_ex(["."], [], False)

    if analysis_id is not None:
        for spec in existing:
            if lookup_analysis_id(spec.analysis_spec) == analysis_id:
                new_spec = mutator(spec.analysis_spec)
                with open(spec.spec_filename, "wb") as updated_spec:
                    updated_spec.write(analysis_spec_dump(new_spec))
                logging.info("Updated existing %s in %s", analysis_id, spec.spec_filename)
                return None

    # Apply the filters as needed
    for spec in all_specs:
        match spec.analysis_spec["AnalysisType"]:
            case AnalysisTypes.RULE | AnalysisTypes.SCHEDULED_RULE:
                if spec.analysis_spec["RuleID"] == analysis_id:
                    return create_clone(spec, mutator)
            case AnalysisTypes.SAVED_QUERY | AnalysisTypes.SCHEDULED_QUERY:
                if spec.analysis_spec["QueryName"] == analysis_id:
                    return create_clone(spec, mutator)
            case AnalysisTypes.CORRELATION_RULE:
                pass
            case AnalysisTypes.DATA_MODEL:
                pass
            case AnalysisTypes.GLOBAL:
                if spec.analysis_spec["GlobalID"] == analysis_id:
                    return create_clone(spec, mutator)
            case AnalysisTypes.LOOKUP_TABLE:
                pass
            case AnalysisTypes.PACK:
                # ignore packs
                pass
            case AnalysisTypes.POLICY:
                pass
            case AnalysisTypes.DERIVED:
                pass
            case AnalysisTypes.SIMPLE_DETECTION:
                pass
            case _:
                raise ValueError(f"Unsupported analysis type: {spec.analysis_spec['AnalysisType']}")
    logging.info("Nothing to clone")


def create_clone(spec: LoadAnalysisSpecsResult, mutator: Optional[Callable[[Any], Any]]) -> None:
    # create a copy of the spec, with the BaseVersion set to the current spec
    new_spec = spec.analysis_spec.copy()
    new_spec["BaseVersion"] = spec.analysis_spec.get("Version", 1)
    if mutator is not None:
        new_spec = mutator(new_spec)

    # create a new file
    cache_path = pathlib.Path(CACHE_DIR).absolute()
    new_file_path = pathlib.Path(spec.spec_filename).relative_to(cache_path / "panther-analysis")

    new_file_path.parent.mkdir(parents=True, exist_ok=True)

    with open(new_file_path, "wb") as new_file:
        new_file.write(analysis_spec_dump(new_spec))

    match spec.analysis_spec["AnalysisType"]:
        case AnalysisTypes.RULE | AnalysisTypes.SCHEDULED_RULE | AnalysisTypes.GLOBAL:
            # clone the .py file
            filename = pathlib.Path(spec.spec_filename).parent / spec.analysis_spec["Filename"]
            new_filename = filename.relative_to(cache_path / "panther-analysis")
            new_filename.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(filename, new_filename)
        case _:
            pass
