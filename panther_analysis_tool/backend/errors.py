from typing import Any, Dict, Optional

UPLOAD_IN_PROGRESS_SUBSTR = "another upload"


def is_retryable_error(err: Optional[Dict[str, Any]]) -> bool:
    if err:
        if is_retryable_error_str(err.get("message", "")) or is_retryable_error_str(
            err.get("body", "")
        ):
            return True
    return False


def is_retryable_error_str(err: str) -> bool:
    if not err:
        return False

    return (
        UPLOAD_IN_PROGRESS_SUBSTR in err
        or err == "upload failed"
        or "unknown error occurred" in err
        or "ddb lock" in err
        or "pload does not exist" in err
    )
