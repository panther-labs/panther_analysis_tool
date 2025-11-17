"""
A module for migrating analysis items from v1 of Panther Analysis usage, where a user
forks the Panther Analysis repository, to v2 where a user uses the Panther Analysis tool to
manage their analysis items without a fork.
"""

import pathlib
import tempfile

from panther_analysis_tool.analysis_utils import LoadAnalysisSpecsResult
from panther_analysis_tool.core import analysis_cache, diff, git_helpers, yaml


class MigrationTempDir:
    user_yaml_path: pathlib.Path
    base_yaml_path: pathlib.Path
    latest_yaml_path: pathlib.Path
    user_python_path: pathlib.Path
    base_python_path: pathlib.Path
    latest_python_path: pathlib.Path

    def __init__(self, temp_dir: pathlib.Path):
        self.user_yaml_path = temp_dir / "user.yml"
        self.user_yaml_path.touch()
        self.base_yaml_path = temp_dir / "base.yml"
        self.base_yaml_path.touch()
        self.latest_yaml_path = temp_dir / "latest.yml"
        self.latest_yaml_path.touch()
        self.user_python_path = temp_dir / "user.py"
        self.user_python_path.touch()
        self.base_python_path = temp_dir / "base.py"
        self.base_python_path.touch()
        self.latest_python_path = temp_dir / "latest.py"
        self.latest_python_path.touch()

    def add_merge_files(
        self,
        user_spec: LoadAnalysisSpecsResult,
        latest_spec: analysis_cache.AnalysisSpec,
        latest_spec_python: bytes | None,
    ) -> None:
        # dump the user spec dict instead of the raw yaml so it has base version and it formatted consistently
        user_spec.yaml_ctx.dump(user_spec.analysis_spec, self.user_yaml_path)
        self.latest_yaml_path.write_bytes(latest_spec.spec)
        # write BaseVersion so it is not considered a conflict
        # self.base_yaml_path.write_bytes(f"BaseVersion: {latest_spec.version}\n".encode("utf-8"))

        existing_user_py_path = user_spec.python_file_path()
        if existing_user_py_path is not None:
            self.user_python_path.write_bytes(existing_user_py_path.read_bytes())

            # this should never be none when the user spec has python but checking for safety
            if latest_spec_python is not None:
                self.latest_python_path.write_bytes(latest_spec_python)


def migrate_analysis_item(
    user_spec: LoadAnalysisSpecsResult, cache: analysis_cache.AnalysisCache
) -> bool:
    """
    Migrates an analysis item without a BaseVersion to one with a BaseVersion by merging
    the latest version of the analysis item from Panther Analysis into the user's analysis item.
    Performs a 3-way merge with an empty base, which is effectively a 2-way merge with the latest version.

    Args:
        user_spec: The user's analysis item.
        cache: The analysis cache.

    Returns:
        True if there were conflicts, False otherwise.
    """
    spec_id = user_spec.analysis_id()
    latest_spec = cache.get_latest_spec(spec_id)
    if latest_spec is None:
        # there should always be a latest spec for a given analysis ID if this function
        # is being called
        raise ValueError(f"Latest spec not found in cache for analysis ID {spec_id}")

    latest_spec_python = cache.get_file_for_spec(latest_spec.id or -1, latest_spec.version)
    user_spec.analysis_spec["BaseVersion"] = latest_spec.version
    yaml_loader = yaml.BlockStyleYAML()

    with tempfile.TemporaryDirectory(prefix="pat_migration_") as temp_dir_str:
        temp_dir = MigrationTempDir(pathlib.Path(temp_dir_str))
        temp_dir.add_merge_files(user_spec, latest_spec, latest_spec_python)

        # try to merge yaml files
        diff_dict = diff.Dict(yaml_loader.load(temp_dir.user_yaml_path))
        conflicts = diff_dict.merge_dict({}, yaml_loader.load(temp_dir.latest_yaml_path))
        if len(conflicts) == 0:
            yaml_loader.dump(diff_dict.customer_dict, pathlib.Path(user_spec.spec_filename))

        # try to merge python files
        python_has_conflict, python_merged_contents = git_helpers.merge_file(
            temp_dir.user_python_path, temp_dir.base_python_path, temp_dir.latest_python_path
        )
        existing_user_py_path = user_spec.python_file_path()
        if not python_has_conflict and existing_user_py_path is not None:
            pathlib.Path(existing_user_py_path).write_bytes(python_merged_contents)

        return len(conflicts) > 0 or python_has_conflict
