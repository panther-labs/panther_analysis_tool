import pathlib
from typing import Optional

import pydantic
from ruamel import yaml

from panther_analysis_tool.constants import CACHE_DIR


class AnalysisVersionHistoryItem(pydantic.BaseModel):
    """
    A model for an analysis version history item. The combined commit hash and file path
    can be used to get the analysis item from the panther-analysis repository.

    Attributes:
        commit_hash: The commit hash that the analysis item can be found in.
        yaml_file_path: The file path of the YAML file, relative to the root of the panther-analysis repository.
        py_file_path: The file path of the Python file, relative to the root of the panther-analysis repository.
    """

    commit_hash: str
    yaml_file_path: str
    py_file_path: Optional[str] = None


class AnalysisVersionItem(pydantic.BaseModel):
    """
    A model for an analysis version item in the versions file from panther-analysis.

    Attributes:
        history: A dictionary of version number to analysis version history item.
        sha256: The SHA256 hash of the analysis item, both YAML and Python files, that can be used to see if a file has changed.
        type: The type of the analysis item (e.g. rule, policy, datamodel, etc.).
        version: The version number of the analysis item.
    """

    history: dict[int, AnalysisVersionHistoryItem]
    sha256: str
    type: str
    version: int


class Versions(pydantic.BaseModel):
    """
    A model for the contents of the .versions.yml file.

    Attributes:
        versions: A dictionary of analysis ID to analysis version item.
    """

    versions: dict[str, AnalysisVersionItem]


_VERSIONS: Optional[Versions] = None


def get_versions() -> Versions:
    global _VERSIONS
    if _VERSIONS is None:
        version_file_path = pathlib.Path(CACHE_DIR) / "panther-analysis" / ".versions.yml"
        if not version_file_path.exists():
            raise FileNotFoundError(f"No versions file at {version_file_path}")

        with open(version_file_path, "rb") as version_file:
            versions = yaml.YAML(typ="safe").load(version_file)
            _VERSIONS = Versions(**versions)

    return _VERSIONS
