""" This code is invoked when the --sync option is passed to 'pat upload'. """

import argparse
from collections import defaultdict
from typing import Dict, List, Set, Tuple

import panther_analysis_tool.util as pat_utils
from panther_analysis_tool.analysis_utils import load_analysis_specs
from panther_analysis_tool.backend.public_api_client import PublicAPIClient
from panther_analysis_tool.backend.rest_client import RestAPIClient


def _get_analysis_ids(args: argparse.Namespace) -> Set[str]:
    analysis_items = load_analysis_specs(args.path, args.ignore_files)
    return set(
        pat_utils.get_spec_id(item[2]) for item in analysis_items if "AnalysisType" in item[2]
    )


def get_remote_diff(
    backend: PublicAPIClient, args: argparse.Namespace
) -> Tuple[Set[str], Dict[str, List[str]]]:
    """Compares the analysis items that would be uploaded with the current PAT arguments, with the
    analysis items that are present on the remote Panther instance, and returns a record of any
    items on the remote that aren't included in the repo.

    Args:
        args (argparse.Namespace): The command-line arguments passed to upload or delete

    Returns:
        diff_ids (set): the full set of analysis IDs which are present remotely & absent locally
        diff_ids_by_type (dict[str, list]): a dict, grouping the analysis IDs by analysis type
    """
    # This function compares only the item IDs of analysis items locally and remote. It doesn't
    # perform any checks to determine if an item's content is different, only whether an item
    # exists or doesn't.

    # First, get all the analysis item IDs locally:
    local_ids = _get_analysis_ids(args)

    # Next, get the remote specs
    client = RestAPIClient(backend)
    remote_specs = client.get_analysis_items()

    diff_ids = set()
    diff_ids_by_type = defaultdict(list)
    for spec in remote_specs:
        spec_id = spec["_id"]
        if spec_id not in local_ids:
            diff_ids.add(spec_id)
            # The '_type' field is added by 'get_analysis_items' for this reason
            diff_ids_by_type[spec["_type"]].append(spec_id)

    return diff_ids, diff_ids_by_type
