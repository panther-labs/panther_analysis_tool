import argparse
import logging
import os
import runpy
import sys
from typing import Final, Tuple

from panther_analysis_tool.backend.client import Client as BackendClient, \
    ConfigSDKBulkUploadParams, BackendError


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

    if not os.path.exists(os.path.join("panther_content", "__main__.py")):
        err_message = "Did not find a Config SDK based module at ./panther_content"
        if indirect_invocation:
            # If this is run automatically at the end of the standard upload command,
            # this isn't an error that should cause the invocation to return 1.
            logging.debug(err_message)
            return 0, ""
        logging.error(err_message)
        return 1, ""

    if not args.api_token:
        logging.error("Config SDK based uploads are only possible using the public API")
        return 1, ""

    panther_config_cache_path: Final = os.path.join(".panther", "panther-config-cache")

    try:
        os.remove(panther_config_cache_path)
    except FileNotFoundError:
        pass

    path_had_cwd = os.getcwd() in sys.path
    if not path_had_cwd:
        sys.path.append(os.getcwd())
    runpy.run_module("panther_content")
    if not path_had_cwd:
        sys.path.remove(os.getcwd())

    if not os.path.exists(panther_config_cache_path):
        logging.error("panther_content did not generate %s", panther_config_cache_path)
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
