import logging
from dataclasses import dataclass
from typing import List, Tuple

from panther_analysis_tool.backend.client import Client as BackendClient
from panther_analysis_tool.backend.client import (
    DeleteDetectionsParams,
    DeleteSavedQueriesParams,
)


@dataclass
class BulkDeleteArgs:
    query_id: List[str]
    analysis_id: List[str]
    confirm: bool


def run(backend: BackendClient, args: BulkDeleteArgs) -> Tuple[int, str]:
    # pylint: disable=too-many-return-statements

    logging.info("preparing bulk delete...")

    # Get lists of detection ids and query names from args
    query_name_list = args.query_id
    detection_id_list = args.analysis_id

    targets_detections = len(detection_id_list) != 0
    targets_saved_queries = len(query_name_list) != 0

    if not targets_detections and not targets_saved_queries:
        logging.error("Must specify a list of analysis or queries to delete")
        logging.error("Run panther_analysis_tool -h for help statement")
        return 1, ""

    # Dry Run: Detections
    if targets_detections:
        code, msg = _delete_detections_dry_run(backend, detection_id_list)
        if code != 0:
            return code, msg

    # Dry Run: Saved Queries
    if targets_saved_queries:
        code, msg = _delete_queries_dry_run(backend, query_name_list)
        if code != 0:
            return code, msg

    # Prompt for user confirmation (unless bypassed)
    if args.confirm:
        confirm = input("\nContinue? (y/n) ")

        if confirm.lower() != "y":
            print("Cancelled")
            return 0, ""

        print("")

    # Delete Detections
    if targets_detections:
        code, msg = _delete_detections(backend, detection_id_list)
        if code != 0:
            logging.warning("error deleting detections: %s", msg)
            return code, msg

        logging.info("successfully deleted detections.")

    # Delete Saved Queries
    if targets_saved_queries:
        code, msg = _delete_queries(backend, query_name_list)
        if code != 0:
            logging.warning("error deleting saved queries: %s", msg)
            return code, msg

        logging.info("successfully deleted saved queries.")

    logging.info("done")
    return 0, ""


def _delete_detections_dry_run(backend: BackendClient, ids: List[str]) -> Tuple[int, str]:
    if len(ids) == 0:
        return 0, ""

    res = backend.delete_detections(
        DeleteDetectionsParams(dry_run=True, ids=ids, include_saved_queries=True)
    )

    if res.status_code != 200:
        logging.error("Error connecting to backend.")
        return 1, ""

    found_ids = res.data.ids or []

    for detection_id in ids:
        if detection_id in found_ids:
            logging.info("Detection '%s' will be deleted", detection_id)
        else:
            logging.info("Detection '%s' was not found.", detection_id)

    linked_query_names = res.data.saved_query_names or []

    for query_id in linked_query_names:
        logging.info("Linked saved query '%s' will be deleted.", query_id)

    return 0, ""


def _delete_queries_dry_run(backend: BackendClient, names: List[str]) -> Tuple[int, str]:
    if len(names) == 0:
        return 0, ""

    res = backend.delete_saved_queries(
        DeleteSavedQueriesParams(dry_run=True, names=names, include_detections=True)
    )

    if res.status_code != 200:
        logging.error("Error connecting to backend.")
        return 1, ""

    found_names = res.data.names or []

    for query_name in names:
        if query_name in found_names:
            logging.info("Saved query '%s' will be deleted", query_name)
        else:
            logging.info("Saved query '%s' was not found.", query_name)

    linked_detection_ids = res.data.detection_ids or []

    for detection_id in linked_detection_ids:
        logging.info("Linked detection '%s' will be deleted.", detection_id)

    return 0, ""


def _delete_detections(backend: BackendClient, ids: List[str]) -> Tuple[int, str]:
    if len(ids) == 0:
        return 0, ""

    delete_detections_res = backend.delete_detections(
        DeleteDetectionsParams(
            ids=ids,
            dry_run=False,
            include_saved_queries=True,
        )
    )

    if delete_detections_res.status_code != 200:
        logging.error("Error deleting detections")
        return 1, ""

    logging.info(
        "%d detections and %d linked saved queries deleted",
        len(delete_detections_res.data.ids),
        len(delete_detections_res.data.saved_query_names),
    )

    return 0, ""


def _delete_queries(backend: BackendClient, names: List[str]) -> Tuple[int, str]:
    delete_queries_res = backend.delete_saved_queries(
        DeleteSavedQueriesParams(
            names=names,
            dry_run=False,
            include_detections=True,
        )
    )

    if delete_queries_res.status_code != 200:
        logging.error("Error deleting saved queries")
        return 1, ""

    logging.info(
        "%d saved queries and %d linked detections deleted",
        len(delete_queries_res.data.names),
        len(delete_queries_res.data.detection_ids),
    )

    return 0, ""
