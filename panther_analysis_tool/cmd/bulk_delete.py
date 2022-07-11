"""
 Analysis Tool is a command line interface for writing,
testing, and packaging policies/rules.
Copyright (C) 2020 Panther Labs Inc

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import argparse
import logging
from typing import Tuple
from panther_analysis_tool.backend.client import Client as BackendClient, BulkDeletePayload


def run(backend: BackendClient, args: argparse.Namespace) -> Tuple[int, str]:
    logging.info("preparing bulk delete...")

    # Get lists of analysis and queries from args
    analysis_id_list = args.analysis_id
    query_list = args.query_id

    if len(analysis_id_list) == 0 and len(query_list) == 0:
        logging.error("Must specify a list of analysis or queries to delete")
        logging.error("Run panther_analysis_tool -h for help statement")
        return 1, ""

    dry_run_res = backend.bulk_delete(BulkDeletePayload(dry_run=True, detection_ids=args.analysis_ids, saved_query_ids=args.query_ids))
    if dry_run_res.status_code != 200:
        logging.error("Error connecting to backend for delete.")
        return 1, ""

    dr_info = dry_run_res.data["dryRun"]

    for not_found_detection_id in dr_info["detectionIdsNotFound"]:
        logging.info(f"Detection '{not_found_detection_id}' was not found.")

    for not_found_query_id in dr_info["savedQueryIdsNotFound"]:
        logging.info(f"Saved Query '{not_found_query_id}' was not found.")

    # BE needs to:
    # - expand saved detection id list to include scheduled rules matching saved query ids.
    # - validate which detection ids actually exist (metadata.detectionIdsNotFound)

    # {
    #     "detectionIds": [],  // empty because it's a dry run
    #     "savedQueryIds": [], // empty because it's a dry run
    #     "dryRun": {
    #         "stats": {
    #           "totalDetectionsToDelete": 0,
    #           "totalSavedQueriesToDelete": 0,
    #         }
    #
    #         "detectionIdsToDelete":  [],
    #         "detectionIdsNotFound":  [],
    #         "savedQueryIdsToDelete": [],
    #         "savedQueryIdsNotFound": [],
    #
    #         "linkedDetectionsToDelete":   [],
    #         "linkedSavedQueriesToDelete": [],
    #     }
    # }

    # Unless explicitly bypassed, get user confirmation to delete
    if not args.confirm_bypass:
        dr_stats = dr_info["stats"]
        total_detections = dr_stats["totalDetectionsToDelete"]
        total_saved_queries = dr_stats["totalSavedQueriesToDelete"]

        if total_detections > 0:
            logging.warning("You are about to delete detections %s", total_detections)
        if total_saved_queries > 0:
            logging.warning("You are about to delete saved queries %s", total_saved_queries)

        confirm = input("Continue? (y/n) ")

        if confirm.lower() != "y":
            print("Cancelled")
            return 0, ""

    delete_res = backend.bulk_delete(BulkDeletePayload(dry_run=False, detection_ids=args.analysis_ids, saved_query_ids=args.query_ids))

    if delete_res.status_code != 200:
        logging.error("Error connecting to backend for delete.")
        return 1, ""

    return 0, ""
