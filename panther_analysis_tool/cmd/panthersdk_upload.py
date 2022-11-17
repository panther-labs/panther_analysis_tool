import argparse
import logging
from typing import Final, Tuple

from panther_analysis_tool.backend.client import BackendError
from panther_analysis_tool.backend.client import Client as BackendClient
from panther_analysis_tool.backend.client import PantherSDKBulkUploadParams
from panther_analysis_tool.cmd import panthersdk_utils


def run(
    backend: BackendClient,
    args: argparse.Namespace,  # pylint: disable=unused-argument
    indirect_invocation: bool = False,
) -> Tuple[int, str]:
    """Packages and uploads all policies and rules from the Panther SDK-based module at
    ./panther_content, if it exists, into a Panther deployment.

        Returns 1 if the packaging or upload fails.

        Args:
            backend: Backend API client.
            args: The populated Argparse namespace with parsed command-line arguments.
            indirect_invocation: True if this function is being invoked as part of
                                 another command (probably the legacy bulk upload command)

        Returns:
            Return code
    """

    panther_sdk_cache_path: Final = panthersdk_utils.get_sdk_cache_path()

    try:
        panthersdk_utils.run_sdk_module(panther_sdk_cache_path)
    except FileNotFoundError:
        err_message = "Did not find a Panther SDK based module at ./panther_content"
        if indirect_invocation:
            # If this is run automatically at the end of the standard upload command,
            # this isn't an error that should cause the invocation to return 1.
            logging.debug(err_message)
            return 0, ""
        logging.error(err_message)
        return 1, ""

    with open(panther_sdk_cache_path) as sdk_cache_file:
        try:
            result = backend.panthersdk_bulk_upload(
                params=PantherSDKBulkUploadParams(content=sdk_cache_file.read())
            )
        except BackendError as exc:
            logging.error(exc)
            return 1, ""

    logging.info("Panther SDK module upload succeeded")
    logging.info(
        "(Rules: %d new; %d modified; %d total)",
        result.data.rules.new,
        result.data.rules.modified,
        result.data.rules.total,
    )
    logging.info(
        "(Policies: %d new; %d modified; %d total)",
        result.data.policies.new,
        result.data.policies.modified,
        result.data.policies.total,
    )
    logging.info(
        "(Queries: %d new; %d modified; %d total)",
        result.data.queries.new,
        result.data.queries.modified,
        result.data.queries.total,
    )

    return 0, ""
