import json
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class EventSource:
    """Identifies where events were loaded from (for error reporting)."""

    path: str


class EventInputError(ValueError):
    pass


def _ensure_event_dict(obj: Any, source: EventSource) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        raise EventInputError(f"{source.path}: expected JSON object, got {type(obj).__name__}")
    return obj


def load_events_from_text(text: str, source: EventSource) -> List[Dict[str, Any]]:
    """
    Load one-or-more events from JSON text.

    Supported formats:
    - A single JSON object: {"k": "v"}
    - A JSON array of objects: [{"k": "v"}, ...]
    - NDJSON / JSON Lines: one JSON object per line
    """
    stripped = text.strip()
    if not stripped:
        return []

    # First try "normal" JSON: object or array.
    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, list):
            return [_ensure_event_dict(item, source) for item in parsed]
        return [_ensure_event_dict(parsed, source)]
    except json.JSONDecodeError:
        pass

    # Fall back to NDJSON / JSON Lines
    events: List[Dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            parsed_line = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EventInputError(
                f"{source.path}:{line_no}: invalid JSON line ({exc.msg})"
            ) from exc
        events.append(_ensure_event_dict(parsed_line, source))
    return events


def load_events_from_path(path: str, encoding: str = "utf-8") -> List[Dict[str, Any]]:
    """
    Load events from a path, or from stdin when path == "-".
    """
    source = EventSource(path=path)
    if path == "-":
        return load_events_from_text(sys.stdin.read(), source)

    try:
        with open(path, "r", encoding=encoding) as handle:
            return load_events_from_text(handle.read(), source)
    except OSError as exc:
        raise EventInputError(f"{path}: unable to read file ({exc})") from exc


def apply_log_type(
    events: List[Dict[str, Any]],
    log_type: Optional[str],
    overwrite: bool,
) -> List[Dict[str, Any]]:
    if not log_type:
        return events
    for event in events:
        if overwrite or "p_log_type" not in event:
            event["p_log_type"] = log_type
    return events

