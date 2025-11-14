import io
from pathlib import Path
from typing import Any

from ruamel import yaml


class BlockStyleYAML(yaml.YAML):
    """YAML loader that automatically converts flow-style collections to block-style."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.width = 4096
        self.indent(mapping=2, sequence=4, offset=2)
        self.preserve_quotes = True

    def load(self, stream: Path | Any) -> Any:
        """Load YAML and automatically convert flow-style to block-style."""
        data = super().load(stream)
        if data is not None:
            self._convert_to_block_style(data)
        return data

    def _convert_to_block_style(self, data: Any) -> None:
        """
        Recursively convert flow-style collections to block-style.
        This is used to ensure that the YAML is always converted to block-style, even if the original YAML was in flow-style.
        Doing this helps standardize YAML output when there is JSON-like structures in the YAML.

        For example, the following YAML:
        ```yaml
        name:
          family: Smith
          given: Alice
          json: [{"key": "value"}, {"key2": "value2"}, "str"]
        ```
        Will be converted to the following YAML:
        ```yaml
        name:
          family: Smith
          given: Alice
          json:
            - "key": "value"
            - "key2": "value2"
            - "str"
        ```

        Args:
            data: The data to convert to block-style.
        """
        from ruamel.yaml.comments import CommentedMap, CommentedSeq

        if isinstance(data, CommentedMap):
            data.fa.set_block_style()
            for value in data.values():
                self._convert_to_block_style(value)
        elif isinstance(data, CommentedSeq):
            data.fa.set_block_style()
            for item in data:
                self._convert_to_block_style(item)


def load(stream: Path | Any) -> Any:
    """Convenience function to load YAML from a stream."""
    return BlockStyleYAML().load(stream)


def dump(data: Any) -> str:
    """Convenience function to dump YAML to a string."""
    string_io = io.StringIO()
    BlockStyleYAML().dump(data, stream=string_io)
    return string_io.getvalue()
