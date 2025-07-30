from typing import List, Optional, Tuple
import pathlib

import yaml

from panther_analysis_tool.libs.parse import parse_filter
from panther_analysis_tool.analysis_utils import load_analysis, filter_analysis, ClassifiedAnalysis
from panther_analysis_tool.constants import CACHE_DIR, AnalysisTypes
from panther_analysis_tool.util import get_spec_id

def run(id: Optional[str], **kwargs) -> Tuple[int, str]:
    if id is None:
        return enable_analysis_filter(kwargs["filter"])
    else:
        return enable_analysis_id(id)

def enable_analysis_id(id: str) -> Tuple[int, str]:
    # get all analysis specs
    # First classify each file, always include globals and data models location
    all_specs, _ = load_analysis(".", True, [], [])
    if all_specs.empty():
        return 0, f"Nothing to enable"

    # Apply the filters as needed
    managed_specs = all_specs.apply(lambda l: [x for x in l if CACHE_DIR in x.file_name])
    user_specs = all_specs.apply(lambda l: [x for x in l if CACHE_DIR not in x.file_name])

    user_specs_by_id = {get_spec_id(detection.analysis_spec): detection for detection in user_specs.detections}
    for spec in user_specs.data_models:
        user_specs_by_id[get_spec_id(spec.analysis_spec)] = spec
    for spec in user_specs.globals:
        user_specs_by_id[get_spec_id(spec.analysis_spec)] = spec
    for spec in user_specs.queries:
        user_specs_by_id[get_spec_id(spec.analysis_spec)] = spec
    for spec in user_specs.lookup_tables:
        user_specs_by_id[get_spec_id(spec.analysis_spec)] = spec

    # enable analysis specs
    for managed_spec in managed_specs.detections:
        if id == get_spec_id(managed_spec.analysis_spec):
            user_spec = user_specs_by_id.get(id)
            enable_analysis_spec(managed_spec, user_spec)

    return 0, "Enabled"


def enable_analysis_filter(filter: List[str]) -> Tuple[int, str]:
    # get all analysis specs
    # First classify each file, always include globals and data models location
    all_specs, _ = load_analysis(".", True, [], [])
    if all_specs.empty():
        return 0, [f"Nothing to enable"]

    # Apply the filters as needed
    parsed_filters, parsed_filters_inverted = parse_filter(filter)
    print(parsed_filters)
    all_specs = all_specs.apply(lambda l: filter_analysis(l, parsed_filters, parsed_filters_inverted))
    managed_specs = all_specs.apply(lambda l: [x for x in l if CACHE_DIR in x.file_name])
    user_specs = all_specs.apply(lambda l: [x for x in l if CACHE_DIR not in x.file_name])

    user_detections_by_id = {}
    for detection in user_specs.detections:
        if "RuleID" in detection.analysis_spec:
            user_detections_by_id[detection.analysis_spec["RuleID"]] = detection
        if "PolicyID" in detection.analysis_spec:
            user_detections_by_id[detection.analysis_spec["PolicyID"]] = detection
    user_data_models_by_id = {data_model.analysis_spec["DataModelID"]: data_model for data_model in user_specs.data_models}
    user_global_helpers_by_id = {global_helper.analysis_spec["GlobalID"]: global_helper for global_helper in user_specs.globals}
    user_queries_by_id = {query.analysis_spec["QueryName"]: query for query in user_specs.queries}
    user_lookup_tables_by_id = {lookup_table.analysis_spec["LookupName"]: lookup_table for lookup_table in user_specs.lookup_tables}
    # user_packs_by_id = {pack.analysis_spec["PackID"]: pack for pack in user_specs.packs}
    # user_simple_detections_by_id = {simple_detection.analysis_spec["RuleID"]: simple_detection for simple_detection in user_specs.simple_detections}

    # enable analysis specs
    for managed_spec in managed_specs.detections:
        if "RuleID" in managed_spec.analysis_spec:
            user_spec = user_detections_by_id.get(managed_spec.analysis_spec["RuleID"])
        else:
            user_spec = user_detections_by_id.get(managed_spec.analysis_spec["PolicyID"])
        enable_analysis_spec(managed_spec, user_spec)
    for managed_spec in managed_specs.data_models:
        user_spec = user_data_models_by_id.get(managed_spec.analysis_spec["DataModelID"])
        enable_analysis_spec(managed_spec, user_spec)
    for managed_spec in managed_specs.globals:
        user_spec = user_global_helpers_by_id.get(managed_spec.analysis_spec["GlobalID"])
        enable_analysis_spec(managed_spec, user_spec)
    for managed_spec in managed_specs.queries:
        user_spec = user_queries_by_id.get(managed_spec.analysis_spec["QueryName"])
        enable_analysis_spec(managed_spec, user_spec)
    for managed_spec in managed_specs.lookup_tables:
        user_spec = user_lookup_tables_by_id.get(managed_spec.analysis_spec["LookupName"])
        enable_analysis_spec(managed_spec, user_spec)

    return 0, "Enabled"


def enable_analysis_spec(managed_analysis_spec: ClassifiedAnalysis, user_analysis_spec: Optional[ClassifiedAnalysis]) -> None:
    if user_analysis_spec is None:
        # create new spec but as enabled
        # construct the new file path by removing the stem up to the cache dir
        cache_path = pathlib.Path(CACHE_DIR).absolute()
        new_file_path = pathlib.Path(managed_analysis_spec.file_name).relative_to(cache_path / "panther-analysis")

        new_spec = {
            "AnalysisType": f"managed_{managed_analysis_spec.analysis_spec['AnalysisType']}",
            "Enabled": True,
        }
        match managed_analysis_spec.analysis_spec["AnalysisType"]:
            case AnalysisTypes.SCHEDULED_QUERY:
                new_spec["QueryName"] = managed_analysis_spec.analysis_spec["QueryName"]
            case AnalysisTypes.SAVED_QUERY:
                new_spec["QueryName"] = managed_analysis_spec.analysis_spec["QueryName"]
            case AnalysisTypes.RULE:
                new_spec["RuleID"] = managed_analysis_spec.analysis_spec["RuleID"]
            case AnalysisTypes.POLICY:
                new_spec["PolicyID"] = managed_analysis_spec.analysis_spec["PolicyID"]
            case AnalysisTypes.CORRELATION_RULE:
                new_spec["RuleID"] = managed_analysis_spec.analysis_spec["RuleID"]
            case AnalysisTypes.SCHEDULED_RULE:
                new_spec["RuleID"] = managed_analysis_spec.analysis_spec["RuleID"]
            case AnalysisTypes.DATA_MODEL:
                new_spec["DataModelID"] = managed_analysis_spec.analysis_spec["DataModelID"]
            case AnalysisTypes.GLOBAL:
                new_spec["GlobalID"] = managed_analysis_spec.analysis_spec["GlobalID"]
            case AnalysisTypes.LOOKUP_TABLE:
                new_spec["LookupName"] = managed_analysis_spec.analysis_spec["LookupName"]
            case _:
                raise Exception(f"Unknown analysis type: {managed_analysis_spec.analysis_spec['AnalysisType']}")
        new_file_path.parent.mkdir(parents=True, exist_ok=True)
        yaml.dump(new_spec, open(new_file_path, "w"))
        print("created new spec", new_file_path)
    else:
        # update the existing spec
        print("updating existing spec", managed_analysis_spec.file_name)
