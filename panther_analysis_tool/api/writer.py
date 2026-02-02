"""Writer function for analysis items."""

import logging
import pathlib

from panther_analysis_tool.api.items import Rule
from panther_analysis_tool.core import yaml


def write_analysis_items(
    items: list[Rule],
    dry_run: bool = False,
) -> None:
    """
    Write analysis items back to disk.

    Writes only to user files. Does NOT update the analysis cache.

    Args:
        items: List of analysis items to write
        dry_run: If True, don't actually write files (for validation)

    Raises:
        ValueError: If items are invalid or missing required fields
        FileNotFoundError: If original file paths no longer exist
    """
    yaml_loader = yaml.BlockStyleYAML()

    for item in items:
        logging.debug("Writing item %s to %s", item.id, item._item.yaml_file_path)

        analysis_item = item._item  # Access internal AnalysisItem

        if analysis_item.yaml_file_path is None:
            raise ValueError(f"Item {item.id} has no YAML file path")

        yaml_path = pathlib.Path(analysis_item.yaml_file_path)

        if not yaml_path.exists() and not dry_run:
            raise FileNotFoundError(f"YAML file does not exist: {yaml_path}")

        if not dry_run:
            # Write YAML file
            with open(yaml_path, "wb") as yaml_file:
                yaml_loader.dump(analysis_item.yaml_file_contents, yaml_file)

            # Write Python file if it exists
            if analysis_item.python_file_path and analysis_item.python_file_contents:
                py_path = pathlib.Path(analysis_item.python_file_path)
                py_path.parent.mkdir(parents=True, exist_ok=True)
                with open(py_path, "wb") as py_file:
                    py_file.write(analysis_item.python_file_contents)
