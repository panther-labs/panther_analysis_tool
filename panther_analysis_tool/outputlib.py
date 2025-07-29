"""This module handles output formatting for the analysis tool."""

from enum import StrEnum
import json
import logging

class JSONFormatter(logging.Formatter):
    """A formatter for JSON output."""
    def format(self, record):
        return json.dumps({
            "level": record.levelname,
            "message": record.getMessage(),
            "filename": record.filename,
            "lineno": record.lineno,
        })

class OutputFormat(StrEnum):
    """The format of the output."""

    TEXT = "text"
    JSON = "json"

OUTPUT_FMT = OutputFormat.TEXT

def set_output_fmt(fmt: str | OutputFormat):
    """Set the output format."""
    global OUTPUT_FMT
    if isinstance(fmt, str):
        fmt = OutputFormat(fmt)
    OUTPUT_FMT = fmt

    match OUTPUT_FMT:
        case OutputFormat.TEXT:
            # setup logger and print version info as necessary
            logging.getLogger().handlers[0].setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        case OutputFormat.JSON:
            logging.getLogger().handlers[0].setFormatter(JSONFormatter())

def get_output_fmt() -> OutputFormat:
    """Get the output format."""
    return OUTPUT_FMT