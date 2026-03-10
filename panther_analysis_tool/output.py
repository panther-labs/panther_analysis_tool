"""Global output format state shared between main and command modules.

This module exists to break the circular import between ``main`` and
the ``command.*`` modules.  Command modules import ``is_json_mode``
from here instead of from ``main``, and ``main.global_options`` calls
``set_output_format`` to update the shared state.
"""

from panther_analysis_tool.command.standard_args import OutputFormat

_output_format: OutputFormat = OutputFormat.text


def set_output_format(fmt: OutputFormat) -> None:
    """Set the globally configured output format (called by main)."""
    global _output_format  # noqa: PLW0603  # pylint: disable=global-statement
    _output_format = fmt


def get_output_format() -> OutputFormat:
    """Return the globally configured output format."""
    return _output_format


def is_json_mode() -> bool:
    """Return True when the global output format is JSON."""
    return _output_format == OutputFormat.json
