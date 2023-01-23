from typing import Any, Dict, Optional

UPLOAD_IN_PROGRESS_SUBSTR = "another upload"


def is_upload_in_progress_error(err: Optional[Dict[str, Any]]) -> bool:
    if err:
        if UPLOAD_IN_PROGRESS_SUBSTR in err.get(
            "message", ""
        ) or UPLOAD_IN_PROGRESS_SUBSTR in err.get("body", ""):
            return True
    return False
