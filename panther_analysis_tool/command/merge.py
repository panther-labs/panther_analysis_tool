import ast
import io
import logging
import os
import pathlib
import re
import sqlite3
import subprocess
import tempfile
from typing import Any, Dict, Optional, Tuple

import ruamel

from panther_analysis_tool import util
from panther_analysis_tool.analysis_utils import (
    LoadAnalysisSpecsResult,
    get_yaml_loader,
    load_analysis_specs_ex,
    lookup_analysis_id,
)
from panther_analysis_tool.constants import AnalysisTypes
from panther_analysis_tool.core import analysis_cache, editor, git
from panther_analysis_tool.core.format import analysis_spec_dump


def run(analysis_id: Optional[str] = None, migrate: bool = False) -> Tuple[int, str]:
    return merge_analysis(analysis_id, migrate)


def merge_analysis(analysis_id: Optional[str] = None, migrate: bool = False) -> Tuple[int, str]:
    yaml = get_yaml_loader(True)

    # load all analysis specs
    all_specs = list(load_analysis_specs_ex(["."], [], True))
    if not all_specs:
        print("Nothing to merge")
        return 0, ""

    update_count = 0
    merge_conflicts = []
    cache = analysis_cache.AnalysisCache()
    cursor = cache.cursor
    git_manager = git.GitManager()

    loader = Loader(cursor, cache, git_manager, yaml)

    # merge managed specs with user specs
    for user_spec in all_specs:
        get_path_from_spec(user_spec)
        base_analysis_id = lookup_analysis_id(user_spec.analysis_spec)
        if analysis_id is not None and analysis_id != base_analysis_id:
            # user specified an analysis id, only merge that one
            continue

        base_spec_bytes, base_file_content = loader.load_base_spec(user_spec, migrate)
        if base_spec_bytes is None:
            logging.warning("Base version not found for %s, skipping", user_spec.spec_filename)
            continue

        # find latest version of the base spec
        latest_base_spec_bytes, latest_file_content, latest_version = loader.load_latest_spec(
            user_spec
        )
        if latest_base_spec_bytes is None:
            if migrate:
                spec_path = pathlib.Path(user_spec.spec_filename)
                if user_spec.analysis_spec.get("AnalysisType") == "pack":
                    # just delete packs
                    os.remove(user_spec.spec_filename)
                    continue
                if loader.was_deleted_by_panther(spec_path):
                    # the spec was deleted by panther
                    os.remove(user_spec.spec_filename)
                    filename = user_spec.analysis_spec.get("Filename")
                    if filename is not None:
                        filename = pathlib.Path(user_spec.spec_filename).parent / filename
                        if loader.was_deleted_by_panther(filename):
                            os.remove(filename)
                    logging.info(
                        "Deleted %s because it was deleted by panther", user_spec.spec_filename
                    )
                    continue
                if loader.still_exists_in_panther(spec_path):
                    # the spec still exists in panther. It is likely the ID changed,
                    # do the diff on it with the current content
                    # TODO: handle this
                    logging.info("Spec changed IDs :%s", user_spec.spec_filename)
                    continue
            logging.warning("Latest version of %s not found, skipping", base_analysis_id)
            continue

        user_spec_str, base_version = strip_base_version(yaml, user_spec.analysis_spec.copy())

        if base_version == latest_version:
            # already up to date
            continue

        spec_conflict, spec_output = merge_yaml(
            base_spec_bytes.decode(), latest_base_spec_bytes.decode(), user_spec_str
        )
        file_conflict, file_output = False, bytes()

        # next check for conflicts in the file
        file_content = load_file_of_spec(user_spec)
        if file_content is not None:
            if base_file_content is None:
                print(f"Base file for {base_analysis_id}@{base_version} not found, skipping")
                continue
            if latest_file_content is None:
                print(f"Latest file for {base_analysis_id}@{base_version} not found, skipping")
                continue

            file_conflict, file_output = merge_strings(
                base_file_content.decode(), latest_file_content.decode(), file_content.decode()
            )

        if spec_conflict or file_conflict:
            if analysis_id is not None:
                # user specified an analysis id, go into merge conflict resolution mode
                if spec_conflict:
                    output = resolve_yaml_conflict(spec_output)
                    if output is None:
                        continue
                    spec_output = output
                if file_conflict:
                    output = resolve_python_conflict(file_output)
                    if output is None:
                        continue
                    file_output = output
            else:
                merge_conflicts.append(util.get_spec_id(user_spec.analysis_spec))
                continue

        # update the base spec
        merged_spec = yaml.load(spec_output.decode())
        merged_spec["BaseVersion"] = latest_version
        string_io = io.StringIO()
        yaml.dump(merged_spec, string_io)
        merged_spec_str = string_io.getvalue()

        # update the base spec
        with open(user_spec.spec_filename, "w", encoding="utf-8") as spec_file:
            spec_file.write(analysis_spec_dump(merged_spec, True))

        # update the file
        if file_output != bytes():
            update_file_of_spec(user_spec, file_output)

        update_count += 1

    if update_count != 0:
        print(f"{update_count} spec(s) updated with latest panther version")
        print("run `git diff` to see the changes")

    if len(merge_conflicts) != 0:
        print(f"{len(merge_conflicts)} merge conflict(s) found")
        print("run `pat merge <id>` to resolve each conflict")
        for conflict in merge_conflicts:
            print(f"  {conflict}")
        return 0, ""
    else:
        # FIXME
        return 0, ""


class Loader:
    def __init__(
        self,
        cursor: sqlite3.Cursor,
        cache: analysis_cache.AnalysisCache,
        git_manager: git.GitManager,
        yaml: ruamel.yaml.YAML,
    ):
        self.cursor = cursor
        self.cache = cache
        self.git_manager = git_manager
        self.yaml = yaml

    def load_base_spec(
        self, spec: LoadAnalysisSpecsResult, use_git: bool
    ) -> Tuple[Optional[bytes], Optional[bytes]]:
        base_version = spec.analysis_spec.get("BaseVersion")
        base_spec_bytes: Optional[bytes] = None
        base_file_content: Optional[bytes] = None
        if base_version is None:
            if not use_git:
                return None, None

            base_spec_bytes = get_base_file_from_git(
                self.git_manager, pathlib.Path(spec.spec_filename)
            )
            if base_spec_bytes is None:
                return None, None

            base_spec = self.yaml.load(base_spec_bytes)
            filename = base_spec.get("Filename")
            if filename is None:
                return base_spec_bytes, None

            # now fetch that file from git
            filename = pathlib.Path(spec.spec_filename).parent / filename
            base_file_content = get_base_file_from_git(self.git_manager, filename)
            return base_spec_bytes, base_file_content

        # otherwise load the base spec from the database
        analysis_id = lookup_analysis_id(spec.analysis_spec)
        base_analysis_id, base_spec_bytes = self.cache.get_spec_for_version(
            analysis_id, base_version
        )
        if base_analysis_id is None or base_spec_bytes is None:
            return None, None
        base_file_content = self.cache.get_file_for_spec(base_analysis_id)

        return base_spec_bytes, base_file_content

    def load_latest_spec(
        self, spec: LoadAnalysisSpecsResult
    ) -> Tuple[Optional[bytes], Optional[bytes], Optional[int]]:
        analysis_id = lookup_analysis_id(spec.analysis_spec)
        spec_id, spec_bytes, spec_version = self.cache.get_latest_spec(analysis_id)
        if spec_id is None:
            return None, None, None

        latest_file_content = self.cache.get_file_for_spec(spec_id)

        return spec_bytes, latest_file_content, spec_version

    def was_deleted_by_panther(self, filename: pathlib.Path) -> bool:
        # see if the spec was deleted by panther
        merge_base = self.git_manager.merge_base("HEAD")

        # normalize the filename for the git repo
        if filename.is_absolute():
            filename = filename.relative_to(self.git_manager.git_root())

        # get the panther commit
        panther_commit = self.git_manager.panther_latest_release_commit()

        proc = subprocess.run(
            [
                "git",
                "log",
                "--diff-filter=D",
                "--oneline",
                "-1",
                f"{merge_base}..{panther_commit}",
                "--",
                filename,
            ],
            check=False,
            capture_output=True,
        )
        return proc.stdout.decode().strip() != ""

    def still_exists_in_panther(self, filename: pathlib.Path) -> Optional[bytes]:
        # see if the spec still exists in panther
        # normalize the filename for the git repo
        if filename.is_absolute():
            filename = filename.relative_to(self.git_manager.git_root())

        # get the panther commit
        panther_commit = self.git_manager.panther_latest_release_commit()

        proc = subprocess.run(
            ["git", "show", f"{panther_commit}:{filename}"], check=False, capture_output=True
        )
        if proc.returncode != 0:
            return None
        return proc.stdout.strip()


def load_file_of_spec(spec: LoadAnalysisSpecsResult) -> Optional[bytes]:
    file_name = spec.analysis_spec.get("Filename")
    if file_name is not None:
        path = pathlib.Path(spec.spec_filename).parent / file_name
        with open(path, "rb") as spec_file:
            return spec_file.read()
    return None


def update_file_of_spec(spec: LoadAnalysisSpecsResult, file_content: bytes) -> None:
    file_name = spec.analysis_spec.get("Filename")
    if file_name is None:
        raise ValueError(f"No file name found for spec {lookup_analysis_id(spec.analysis_spec)}")
    path = pathlib.Path(spec.spec_filename).parent / file_name
    with open(path, "wb") as spec_file:
        spec_file.write(file_content)


def strip_base_version(yaml: ruamel.yaml.YAML, spec: Dict[str, Any]) -> Tuple[str, Optional[int]]:
    version = spec.pop("BaseVersion", None)
    string_io = io.StringIO()
    yaml.dump(spec, string_io)
    return string_io.getvalue(), version


def merge_yaml(base: str, latest: str, user: str) -> Tuple[bool, bytes]:
    base = analysis_spec_dump(base)
    latest = analysis_spec_dump(latest)
    user = analysis_spec_dump(user)
    return merge_strings(base, latest, user)


def merge_strings(base: str, latest: str, user: str) -> Tuple[bool, bytes]:
    # create a temp file for each
    with (
        tempfile.NamedTemporaryFile(delete=False) as temp_file_base,
        tempfile.NamedTemporaryFile(delete=False) as temp_file_latest,
        tempfile.NamedTemporaryFile(delete=False) as temp_file_user,
    ):
        temp_file_base.write(base.encode())
        temp_file_base.flush()

        temp_file_latest.write(latest.encode())
        temp_file_latest.flush()

        temp_file_user.write(user.encode())
        temp_file_user.flush()

        proc = subprocess.run(
            [
                "git",
                "merge-file",
                "-p",
                "-L",
                "ours",
                "-L",
                "base",
                "-L",
                "panther",
                temp_file_user.name,
                temp_file_base.name,
                temp_file_latest.name,
            ],
            check=False,
            capture_output=True,
        )

    return proc.returncode != 0, proc.stdout


def resolve_yaml_conflict(merge_result: bytes) -> Optional[bytes]:
    temp_spec = editor.edit_file(merge_result)

    if temp_spec == merge_result:
        print("No changes made")
        return None

    # todo validate the spec
    yaml = get_yaml_loader(True)
    _ = yaml.load(temp_spec.decode())

    return temp_spec


def resolve_python_conflict(merge_result: bytes) -> Optional[bytes]:
    output = editor.edit_file(merge_result)

    if output == merge_result:
        print("No changes made")
        return None

    # todo validate the file
    try:
        ast.parse(output.decode())
    except SyntaxError as error:
        print("Invalid python file")
        print(f'  File "{error.filename}", line {error.lineno}')
        print(f"    {error.text.strip()}" if error.text else "")
        print(f'    {" " * (error.offset - 1)}^' if error.offset else "")
        print(f"SyntaxError: {error.msg}")
        return None

    return output


def get_base_file_from_git(git_manager: git.GitManager, filename: pathlib.Path) -> bytes:
    # get the base version from the git history
    merge_base = git_manager.merge_base("HEAD")

    # normalize the filename for the git repo
    if filename.is_absolute():
        filename = filename.relative_to(git_manager.git_root())

    # now fetch that file from git
    proc = subprocess.run(["git", "show", f"{merge_base}:{filename}"], capture_output=True)
    if proc.returncode != 0:
        raise Exception(f"Failed to get base file from git: {proc.stderr.decode().strip()}")
    return proc.stdout


def snake_case(name: str) -> str:
    name = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    # replace camelcase with underscores
    # (but don't add _ at the start and don't add _ between acronyms)
    name = re.sub(r"(?<=[^A-Z])([A-Z][0-9A-Z]*)", r"_\1", name)
    # substitute any consecutive underscores with a single underscore
    name = re.sub(r"_+", "_", name)
    return name.lower()


def get_path_from_spec(spec: LoadAnalysisSpecsResult) -> str:
    folder = ""
    analysis_id = lookup_analysis_id(spec.analysis_spec)
    name = snake_case(analysis_id)

    if spec.analysis_spec.get("AnalysisType") == AnalysisTypes.DATA_MODEL:
        folder = "data_models"
        name = name if not name.startswith("standard_") else name[len("standard_") :]
        if not name.endswith("_data_model"):
            name += "_data_model"
    if spec.analysis_spec.get("AnalysisType") == AnalysisTypes.GLOBAL:
        folder = "global_helpers"
    if spec.analysis_spec.get("AnalysisType") == AnalysisTypes.LOOKUP_TABLE:
        folder = "lookup_tables"
    if spec.analysis_spec.get("AnalysisType") == AnalysisTypes.PACK:
        folder = "packs"
    if spec.analysis_spec.get("AnalysisType") == AnalysisTypes.POLICY:
        folder = "policies"
    if spec.analysis_spec.get("AnalysisType") in [
        AnalysisTypes.SAVED_QUERY,
        AnalysisTypes.SCHEDULED_QUERY,
    ]:
        folder = "queries"
        if name.startswith("query_"):
            name = name[len("query_") :]
        if not name.endswith("_query"):
            name += "_query"
    if spec.analysis_spec.get("AnalysisType") == AnalysisTypes.RULE:
        folder = "rules"
    if spec.analysis_spec.get("AnalysisType") == AnalysisTypes.DERIVED:
        raise ValueError(f"Derived rules are not supported")
    if spec.analysis_spec.get("AnalysisType") == AnalysisTypes.SCHEDULED_RULE:
        folder = "rules"
    if spec.analysis_spec.get("AnalysisType") == AnalysisTypes.SIMPLE_DETECTION:
        folder = "simple_rules"
    if spec.analysis_spec.get("AnalysisType") == AnalysisTypes.CORRELATION_RULE:
        folder = "correlation_rules"

    if folder == "" or name == "":
        raise ValueError(f"No folder or name found for spec {spec.spec_filename}")
    name += ".yml"

    if name != pathlib.Path(spec.spec_filename).name:
        # logging.debug(f"Expected name {name} for spec {spec.spec_filename}")
        pass

    return f"{folder}/{name}"
