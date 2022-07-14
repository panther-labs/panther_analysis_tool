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
from typing import Tuple, List
from panther_analysis_tool.backend.client import Client as BackendClient, DeleteDetectionsParams, DeleteSavedQueriesParams


def run(backend: BackendClient, args: argparse.Namespace) -> Tuple[int, str]:
    logging.info("preparing bulk delete...")

    # Get lists of analysis and queries from args
    analysis_id_list = args.analysis_id
    query_id_list = args.query_id

    if len(analysis_id_list) == 0 and len(query_id_list) == 0:
        logging.error("Must specify a list of analysis or queries to delete")
        logging.error("Run panther_analysis_tool -h for help statement")
        return 1, ""

    code, msg = _delete_detections_dry_run(backend, analysis_id_list)
    if code != 0:
        return code, msg

    code, msg = _delete_queries_dry_run(backend, query_id_list)
    if code != 0:
        return code, msg

    # Unless explicitly bypassed, get user confirmation to delete
    if not args.confirm_bypass:
        confirm = input("Continue? (y/n) ")

        if confirm.lower() != "y":
            print("Cancelled")
            return 0, ""

    delete_detections_res = backend.delete_detections(DeleteDetectionsParams(
        dry_run=False, ids=analysis_id_list, include_saved_queries=True))

    if delete_detections_res.status_code != 200:
        logging.error("Error deleting detections")
        return 1, ""

    logging.info(f"{len(delete_detections_res.data.ids)} detections and" +
                 f"{len(delete_detections_res.data.saved_query_names)} linked saved queries deleted")

    delete_queries_res = backend.delete_saved_queries(DeleteSavedQueriesParams(
        dry_run=False, names=args.query_id_list, include_detections=True))

    if delete_queries_res.status_code != 200:
        logging.error("Error deleting saved queries")
        return 1, ""

    logging.info(f"{len(delete_queries_res.data.names)} saved queries and" +
                 f"{len(delete_queries_res.data.detection_ids)} linked detections deleted")

    return 0, ""


def _delete_detections_dry_run(backend: BackendClient, ids: List[str]) -> Tuple[int, str]:
    res = backend.delete_detections(DeleteDetectionsParams(dry_run=True, ids=ids, include_saved_queries=True))

    if res.status_code != 200:
        logging.error("Error connecting to backend.")
        return 1, ""

    for detection_id in ids:
        if detection_id in res.data.ids:
            logging.info(f"Detection '{detection_id}' will be deleted")
        else:
            logging.info(f"Detection '{detection_id}' was not found.")

    for query_id in res.data.saved_query_names:
        logging.info(f"Linked saved query '{query_id}' will be deleted.")

    return 0, ""


def _delete_queries_dry_run(backend: BackendClient, names: List[str]) -> Tuple[int, str]:
    res = backend.delete_saved_queries(DeleteSavedQueriesParams(dry_run=True, names=names, include_detections=True))

    if res.status_code != 200:
        logging.error("Error connecting to backend.")
        return 1, ""

    for query_name in names:
        if query_name in res.data.names:
            logging.info(f"Saved query '{query_name}' will be deleted")
        else:
            logging.info(f"Saved query '{query_name}' was not found.")

    for detection_id in res.data.detection_ids:
        logging.info(f"Linked detection '{detection_id}' will be deleted.")

    return 0, ""
