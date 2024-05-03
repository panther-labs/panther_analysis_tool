import argparse
import json
import logging
import os
import re
import tempfile
import time
import zipfile
from dataclasses import asdict
from datetime import datetime
from typing import Tuple, Optional, Dict, Any, List
from uuid import uuid4

import panther_analysis
import yaml

from panther_analysis_tool import cli_output
from panther_analysis_tool.backend.client import (
    Client as BackendClient,
    BackendError,
    BulkUploadMultipartError,
    FeatureFlagWithDefault,
    FeatureFlagsParams,
    BulkUploadParams,
)
from panther_analysis_tool.constants import ENABLE_CORRELATION_RULES_FLAG
from panther_analysis_tool.util import convert_unicode

BASE_DETECTION_FIELD = "BaseDetection"

if len(panther_analysis.__path__) < 1:
    raise Exception("Error: panther_analysis package had no __path__ members.")
PANTHER_ANALYSIS_PATH = panther_analysis.__path__[0]


def maxpoc_deploy(
    args: argparse.Namespace, backend: Optional[BackendClient] = None
) -> Tuple[int, str]:
    analysis_items = get_analysis_items()
    yaml_items, py_items = collect_analysis_items(analysis_items)

    with tempfile.TemporaryDirectory(dir=".") as tmp:
        for yaml_item in yaml_items:
            write_file(tmp, filename, yaml_item)
        for py_item in py_items:
            write_file(tmp, filename, py_item)
        #     for root, dirs, files in os.walk("."):
        #         for name in files:
        #             filename = str(os.path.join(root, name))
        #
        #             if fnmatch(filename, "*.y*ml"):
        #                 yaml_data = handle_yaml(filename)
        #                 write_file(tmp, filename, yaml.dump(yaml_data))
        #             elif fnmatch(filename, "*.py"):
        #                 if "rules" in filename:
        #                     py_data = handle_py(filename)
        #                     write_file(tmp, filename, py_data)
        #
        zip_name = zip_tmp_dir(tmp)
    #     upload_zip(backend, args, archive=zip_name, use_async=True)

    return 0, ""


def get_analysis_items() -> Dict[str, Any]:
    with open("./AnalysisItems.yml", "r") as f:
        return yaml.safe_load(f)


def camel_to_snake(name):
    name = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", name).lower()


def collect_analysis_items(analysis_items: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    yaml_items, py_items = [], []
    for k, v in analysis_items.items():
        if camel_to_snake(k) == "panther_analysis":
            collect_analysis_items_recursive(PANTHER_ANALYSIS_PATH, v, yaml_items, py_items)
        else:
            collect_analysis_items_recursive(
                os.path.join(".", camel_to_snake(k)), v, yaml_items, py_items
            )

    return yaml_items, py_items


def collect_analysis_items_recursive(
    dir: str, analysis_items: Dict[str, Any], yaml_items: List[str], py_items: List[str]
):
    print(dir, analysis_items)
    for k, v in analysis_items.items():
        k = camel_to_snake(k)
        new_dir = os.path.join(dir, k)

        if isinstance(v, dict):
            collect_analysis_items_recursive(new_dir, v, yaml_items, py_items)
        elif isinstance(v, list):
            for file in v:
                yaml_data = handle_yaml(os.path.join(new_dir, file))
                yaml_items.append(yaml.dump(yaml_data))

                py_data = handle_py(os.path.join(new_dir, yaml_data["Filename"]))
                py_items.append(py_data)


def write_file(tmp_dir: str, filepath: str, content: str):
    out_filename = os.path.join(tmp_dir, filepath.lstrip("." + os.path.sep))
    out_filepath = out_filename.rsplit(os.path.sep, 1)[0]
    os.makedirs(out_filepath, exist_ok=True)

    with open(out_filename, "w") as f:
        f.write(content)


def zip_tmp_dir(tmp: str) -> str:
    current_time = datetime.now().isoformat(timespec="seconds").replace(":", "-")
    filename = f"panther-analysis-{current_time}-{uuid4()}.zip"

    with zipfile.ZipFile(filename, "w", zipfile.ZIP_DEFLATED) as zip_out:
        for root, dirs, files in os.walk(tmp):
            for name in files:
                zip_out.write(str(os.path.join(root, name)))

    return filename


def add_path_to_filename(output_path: str, filename: str) -> str:
    if output_path:
        if not os.path.isdir(output_path):
            logging.info(
                "Creating directory: %s",
                output_path,
            )
            os.makedirs(output_path)
        filename = f"{output_path.rstrip('/')}/{filename}"

    return filename


def handle_py(filename: str) -> str:
    with open(filename, "r") as f:
        return f.read()


def handle_yaml(filename: str) -> Dict[str, Any]:
    data = load_yaml(filename)

    if BASE_DETECTION_FIELD in data and isinstance(data[BASE_DETECTION_FIELD], str):
        base_detection_file = full_base_detection_path(data[BASE_DETECTION_FIELD])
        base_detection = load_yaml(base_detection_file)

        base_detection.update(data)
        del base_detection[BASE_DETECTION_FIELD]
        return base_detection

    return data


def full_base_detection_path(base_detection_path: str) -> str:
    base_detection_split = base_detection_path.split("/")
    return str(os.path.join(PANTHER_ANALYSIS_PATH, *base_detection_split))


def load_yaml(filepath: str) -> dict:
    with open(filepath, "r") as f:
        return yaml.safe_load(f)


def upload_zip(
    backend: BackendClient, args: argparse.Namespace, archive: str, use_async: bool
) -> Tuple[int, str]:
    # extract max retries we should handle
    max_retries = 10
    # if args.max_retries > 10:
    #     logging.warning("max_retries cannot be greater than 10, defaulting to 10")
    # elif args.max_retries < 0:
    #     logging.warning("max_retries cannot be negative, defaulting to 0")
    #     max_retries = 0

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
