import argparse
import pathlib
from typing import Tuple

from panther_analysis_tool.analysis_utils import load_analysis
from panther_analysis_tool.constants import CACHE_DIR

def run(args: argparse.Namespace) -> Tuple[int, str]:
    return 0, "Merged"

def merge_analysis(args: argparse.Namespace) -> None:
    #load all analysis specs
    all_specs, _ = load_analysis(
        ".", True, [], []
    )
    if all_specs.empty():
        return 0, [f"Nothing to merge"]
    
    managed_specs = all_specs.apply(lambda l: [x for x in l if CACHE_DIR in x.file_name])
    user_specs = all_specs.apply(lambda l: [x for x in l if CACHE_DIR not in x.file_name])

    # merge managed specs with user specs
    for user_spec in user_specs.items():
        if 'BaseID' in user_spec.analysis_spec and 'BaseVersion' in user_spec.analysis_spec:
            # find the base spec
            base_spec = managed_specs.detections.get(user_spec.analysis_spec["BaseID"])
            if base_spec is not None:
                merge_analysis_spec(base_spec, user_spec)
            else:
                # create new spec but as enabled
                # construct the new file path by removing the stem up to the cache dir
                cache_path = pathlib.Path(CACHE_DIR).absolute()
                new_file_path = pathlib.Path(managed_analysis_spec.file_name).relative_to(cache_path / "panther-analysis")
        else:
            # create new spec but as enabled
            # construct the new file path by removing the stem up to the cache dir
            cache_path = pathlib.Path(CACHE_DIR).absolute()
            new_file_path = pathlib.Path(managed_analysis_spec.file_name).relative_to(cache_path / "panther-analysis")