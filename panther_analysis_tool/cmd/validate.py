import argparse
import io
import logging
import zipfile
from typing import Tuple

from panther_analysis_tool.backend.client import BulkUploadParams
from panther_analysis_tool.backend.client import Client as BackendClient
from panther_analysis_tool.backend.client import UnsupportedEndpointError
from panther_analysis_tool.zip_chunker import ZipArgs, analysis_chunks


class BColors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

    @classmethod
    def bold(cls, text: str) -> str:
        return cls.wrap(cls.BOLD, text)

    @classmethod
    def header(cls, text: str) -> str:
        return cls.wrap(cls.HEADER, text)

    @classmethod
    def blue(cls, text: str) -> str:
        return cls.wrap(cls.OKBLUE, text)

    @classmethod
    def cyan(cls, text: str) -> str:
        return cls.wrap(cls.OKCYAN, text)

    @classmethod
    def green(cls, text: str) -> str:
        return cls.wrap(cls.OKGREEN, text)

    @classmethod
    def warning(cls, text: str) -> str:
        return cls.wrap(cls.WARNING, text)

    @classmethod
    def underline(cls, text: str) -> str:
        return cls.wrap(cls.UNDERLINE, text)

    @classmethod
    def failed(cls, text: str) -> str:
        return cls.wrap(cls.FAIL, text)

    @classmethod
    def wrap(cls, start: str, text: str) -> str:
        return f"{start}{text}{cls.ENDC}"


def run(backend: BackendClient, args: argparse.Namespace) -> Tuple[int, str]:
    if not backend.supports_bulk_validate():
        return 1, "bulk validate is only supported via the api token"

    typed_args = ZipArgs.from_args(args)
    chunks = analysis_chunks(typed_args)
    buffer = io.BytesIO()

    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zip_out:
        for name in chunks[0].files:
            zip_out.write(name)

    buffer.seek(0, 0)
    params = BulkUploadParams(zip_bytes=buffer.read())

    return_code = 0
    return_str = ""
    try:
        result = backend.bulk_validate(params)
        if result.is_valid():
            return return_code, f"{BColors.green('validation success')}"

        return_str += "\n-----\n"

        if result.has_error():
            return_str += f"{BColors.bold('Error')}: {result.error}\n-----\n"

        for issue in result.issues():
            if issue.path and issue.path != "":
                return_str += f"{BColors.bold('Path')}: {issue.path}\n"

            if issue.error_message and issue.error_message != "":
                return_str += f"{BColors.bold('Error')}: {issue.error_message}\n"

            return_str += "-----\n"

        return_code = 1
        return_str = f"{return_str}\n{BColors.failed('validation failed')}"
    except UnsupportedEndpointError as err:
        logging.debug(err)
        return 1, BColors.warning("your panther instance does not support this feature")

    except BaseException as err:  # pylint: disable=broad-except
        logging.error("failed to upload to backend: %s", err)
        return_code = 1

    return return_code, return_str
