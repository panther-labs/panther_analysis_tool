import argparse
import json
import logging
import os
import tempfile
import time
import zipfile
from dataclasses import asdict
from fnmatch import fnmatch
from typing import Tuple

import yaml

from panther_analysis_tool import cli_output
from panther_analysis_tool.backend.client import (
    BackendError,
    BulkUploadMultipartError,
    BulkUploadParams,
)
from panther_analysis_tool.backend.client import Client as BackendClient
from panther_analysis_tool.backend.client import (
    FeatureFlagsParams,
    FeatureFlagWithDefault,
)
from panther_analysis_tool.constants import ENABLE_CORRELATION_RULES_FLAG
from panther_analysis_tool.util import convert_unicode


def run(backend: BackendClient, args: argparse.Namespace) -> Tuple[int, str]:
    with tempfile.NamedTemporaryFile() as tmp:
        with zipfile.ZipFile(tmp, "w") as zip_out:
            logging.info(f"Writing to temporary zip file at {tmp.name}")

            for root, dirs, files in os.walk("."):
                if any(True for bad in [".mypy_cache", "panther_analysis", ".git"] if bad in root):
                    continue

                for file in files:
                    filepath = os.path.join(root, file)

                    if fnmatch(file, "*.y*ml"):
                        with open(filepath) as yml:
                            item = yaml.safe_load(yml)
                        if "AnalysisType" in item:
                            zip_out.write(filename=filepath)
                            if "Filename" in item:
                                zip_out.write(os.path.join(root, item["Filename"]))

                    zip_out.write(
                        filepath,
                        arcname=os.path.join("customer_code_v2", filepath),
                    )

        return upload_zip(backend, args, archive=tmp.name, use_async=True)


def upload_zip(
    backend: BackendClient, args: argparse.Namespace, archive: str, use_async: bool
) -> Tuple[int, str]:
    # extract max retries we should handle
    max_retries = 10
    if args.max_retries > 10:
        logging.warning("max_retries cannot be greater than 10, defaulting to 10")
    elif args.max_retries < 0:
        logging.warning("max_retries cannot be negative, defaulting to 0")
        max_retries = 0

    with open(archive, "rb") as analysis_zip:
        logging.info("Uploading items to Panther")

        upload_params = BulkUploadParams(zip_bytes=analysis_zip.read())
        retry_count = 0

        while True:
            try:
                if use_async:
                    response = backend.async_bulk_upload(upload_params)
                else:
                    response = backend.bulk_upload(upload_params)

                resp_dict = asdict(response.data)
                flags_params = FeatureFlagsParams(
                    flags=[FeatureFlagWithDefault(flag=ENABLE_CORRELATION_RULES_FLAG)]
                )
                try:
                    if not backend.feature_flags(flags_params).data.flags[0].treatment:
                        del resp_dict["correlation_rules"]
                # pylint: disable=broad-except
                except BaseException:
                    del resp_dict["correlation_rules"]

                logging.info("API Response:\n%s", json.dumps(resp_dict, indent=4))
                return 0, cli_output.success("Upload succeeded")

            except BackendError as be_err:
                err = cli_output.multipart_error_msg(
                    BulkUploadMultipartError.from_jsons(convert_unicode(be_err)),
                    "Upload failed",
                )
                if be_err.permanent is True:
                    return 1, f"Failed to upload to Panther: {err}"

                if max_retries - retry_count > 0:
                    logging.debug("Failed to upload to Panther: %s.", err)
                    retry_count += 1

                    # typical bulk upload takes 30 seconds, allow any currently running one to complete
                    logging.debug(
                        "Will retry upload in 30 seconds. Retries remaining: %s",
                        max_retries - retry_count,
                    )
                    time.sleep(30)

                else:
                    logging.warning("Exhausted retries attempting to perform bulk upload.")
                    return 1, f"Failed to upload to Panther: {err}"

            # PEP8 guide states it is OK to catch BaseException if you log it.
            except BaseException as err:  # pylint: disable=broad-except
                return 1, f"Failed to upload to Panther: {err}"
