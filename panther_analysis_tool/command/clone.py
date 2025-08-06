import logging
import pathlib
from typing import Tuple
from panther_analysis_tool.analysis_utils import LoadAnalysisSpecsResult, load_analysis_specs_ex
from panther_analysis_tool.constants import CACHE_DIR, AnalysisTypes


def run(analysis_id: str) -> Tuple[int, str]:
    return clone_analysis(analysis_id)

def clone_analysis(analysis_id: str) -> None:
    all_specs = list(load_analysis_specs_ex(
        [CACHE_DIR], [], True
    ))
    if not all_specs:
        return 0, [f"Nothing to enable"]

    # Apply the filters as needed
    for spec in all_specs:
        match spec.analysis_spec["AnalysisType"]:
            case AnalysisTypes.RULE | AnalysisTypes.SCHEDULED_RULE:
                if spec.analysis_spec["RuleID"] == analysis_id:
                    return create_clone(spec)
            case AnalysisTypes.SAVED_QUERY | AnalysisTypes.SCHEDULED_QUERY:
                pass
            case AnalysisTypes.CORRELATION_RULE:
                pass
            case AnalysisTypes.DATA_MODEL:
                pass
            case AnalysisTypes.GLOBAL:
                pass
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
    return 0, logging.info(f"Nothing to clone")


def create_clone(spec: LoadAnalysisSpecsResult) -> None:
    # create a copy of the spec, with the BaseID and BaseVersion set to the current spec
    new_spec = spec.analysis_spec.copy()
    new_spec["BaseID"] = spec.analysis_spec["RuleID"]
    new_spec["BaseVersion"] = spec.analysis_spec.get("Version", 1)
    
    # create a new file 
    cache_path = pathlib.Path(CACHE_DIR).absolute()
    new_file_path = pathlib.Path(spec.spec_filename).relative_to(cache_path / "panther-analysis")
    
    new_file_path.parent.mkdir(parents=True, exist_ok=True)

    with open(new_file_path, "w") as f:
        spec.yaml_ctx.dump(new_spec, f)

    match spec.analysis_spec["AnalysisType"]:
        case AnalysisTypes.RULE | AnalysisTypes.SCHEDULED_RULE:
            # clone the .py file
            filename = pathlib.Path(spec.spec_filename).parent / spec.analysis_spec["Filename"]
            with open(filename, "r") as f:
                content = f.read()
            new_filename = filename.relative_to(cache_path / "panther-analysis")
            new_filename.parent.mkdir(parents=True, exist_ok=True)
            with open(new_filename, "w") as f:
                f.write(content)
        case _:
            pass
    return 0, ""