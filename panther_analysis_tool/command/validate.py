import io
import json
import logging
import zipfile
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Tuple

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


def _emit_validate_json(return_code: int, result: Any = None, error: str | None = None) -> None:
    """Emit structured JSON for the validate command."""
    envelope: Dict[str, Any] = {
        "command": "validate",
        "return_code": return_code,
        "status": "success" if return_code == 0 else "error",
    }
    if result is not None and hasattr(result, "is_valid"):
        envelope["data"] = {
            "valid": result.is_valid(),
            "error": result.get_error() if result.has_error() else None,
            "issues": [asdict(i) for i in result.get_issues()] if result.has_issues() else [],
        }
    elif error:
        envelope["errors"] = [{"error": error}]
    print(json.dumps(envelope, default=str))


def run(backend: BackendClient, args: ValidateArgs) -> Tuple[int, str]:
    """Run bulk upload validation against a Panther deployment.

    Args:
        backend: API backend client.
        args: Validated command arguments.

    Returns:
        Tuple of (return_code, message_string).
    """
    from panther_analysis_tool.main import is_json_mode

    if backend is None or not backend.supports_bulk_validate():
        if is_json_mode():
            _emit_validate_json(
                1, error="Invalid backend. `validate` is only supported via API token"
            )
            return 1, ""
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
            if is_json_mode():
                _emit_validate_json(0, result=result)
                return 0, ""
            return 0, f"{cli_output.success('Validation success')}"

        if is_json_mode():
            _emit_validate_json(1, result=result)
            return 1, ""
        return 1, cli_output.multipart_error_msg(result, "Validation failed")
    except UnsupportedEndpointError as err:
        logging.debug(err)
        if is_json_mode():
            _emit_validate_json(1, error="Your Panther instance does not support this feature")
            return 1, ""
        return 1, cli_output.warning("Your Panther instance does not support this feature")

    except BaseException as err:  # pylint: disable=broad-except
        if is_json_mode():
            _emit_validate_json(1, error=str(err))
            return 1, ""
        return 1, cli_output.multipart_error_msg(
            BulkUploadValidateStatusResponse.from_json({"error": str(err)}), "Validation failed"
        )
