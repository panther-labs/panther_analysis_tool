import argparse
import logging
from typing import Final, Tuple

from panther_analysis_tool.backend.client import Client as BackendClient, \
    ConfigSDKBulkUploadParams, BackendError
from panther_analysis_tool.cmd import config_utils


def run(
        backend: BackendClient,
        args: argparse.Namespace,
        indirect_invocation: bool = False
) -> Tuple[int, str]:
    """Packages and uploads all policies and rules from the Config SDK-based module at
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
    if not args.api_token:
        logging.error("Config SDK based uploads are only possible using the public API")
        return 1, ""

    panther_config_cache_path: Final = config_utils.get_config_cache_path()

    try:
        config_utils.run_config_module(panther_config_cache_path)
    except FileNotFoundError as e:
        if indirect_invocation:
            # If this is run automatically at the end of the standard upload command,
            # this isn't an error that should cause the invocation to return 1.
            logging.debug(e)
            return 0, ""
        logging.error(e)
        return 1, ""

    with open(panther_config_cache_path) as config_cache_file:
        try:
            result = backend.configsdk_bulk_upload(params=ConfigSDKBulkUploadParams(
                content=config_cache_file.read()
            ))
        except BackendError as exc:
            logging.error(exc)
            return 1, ""

    logging.info("Config SDK module upload succeeded")
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
