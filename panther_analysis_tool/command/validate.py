import io
import logging
import zipfile
from dataclasses import dataclass
from typing import List, Tuple

from panther_analysis_tool import cli_output
from panther_analysis_tool.backend.client import (
    BulkUploadParams,
    BulkUploadValidateStatusResponse,
)
from panther_analysis_tool.backend.client import Client as BackendClient
from panther_analysis_tool.backend.client import (
    UnsupportedEndpointError,
)
from panther_analysis_tool.core.parse import Filter
from panther_analysis_tool.zip_chunker import ZipArgs, analysis_chunks


@dataclass
class ValidateArgs:
    out: str
    path: str
    ignore_files: List[str]
    filters: List[Filter]
    filters_inverted: List[Filter]


def run(backend: BackendClient, args: ValidateArgs) -> Tuple[int, str]:
    if backend is None or not backend.supports_bulk_validate():
        return 1, "Invalid backend. `validate` is only supported via API token"

    zip_args = ZipArgs(
        out=args.out,
        path=args.path,
        ignore_files=args.ignore_files,
        filters=args.filters,
        filters_inverted=args.filters_inverted,
    )
    chunks = analysis_chunks(zip_args)
    buffer = io.BytesIO()

    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zip_out:
        for name in chunks[0].files:
            zip_out.write(name)

    buffer.seek(0, 0)
    params = BulkUploadParams(zip_bytes=buffer.read())

    try:
        result = backend.bulk_validate(params)
        if result.is_valid():
            return 0, f"{cli_output.success('Validation success')}"

        return 1, cli_output.multipart_error_msg(result, "Validation failed")
    except UnsupportedEndpointError as err:
        logging.debug(err)
        return 1, cli_output.warning("Your Panther instance does not support this feature")

    except BaseException as err:  # pylint: disable=broad-except
        return 1, cli_output.multipart_error_msg(
            BulkUploadValidateStatusResponse.from_json({"error": str(err)}), "Validation failed"
        )
