import ast
import io
import logging
import os
import pathlib
import sqlite3
import subprocess  # nosec:B404
import tempfile
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import ruamel

from panther_analysis_tool.analysis_utils import (
    LoadAnalysisSpecsResult,
    get_yaml_loader,
    load_analysis_specs_ex,
    lookup_analysis_id,
)
from panther_analysis_tool.core import analysis_cache, editor, git
from panther_analysis_tool.core.formatter import analysis_spec_dump


class MergeError(Exception):
    pass


def run(analysis_id: Optional[str], migrate: bool) -> Tuple[int, str]:
    return merge_analysis(analysis_id, migrate)


def merge_analysis(analysis_id: Optional[str], migrate: bool) -> Tuple[int, str]:
    yaml = get_yaml_loader(True)

    # load all analysis specs
    existing_specs = list(load_analysis_specs_ex(["."], [], False))
    if not existing_specs:
        print("Nothing to merge")
        return 0, ""

    do_interactive_merge = analysis_id is None
    update_count = 0
    merge_conflicts = []
    cache = analysis_cache.AnalysisCache()
    cursor = cache.cursor
    git_manager = git.GitManager()

    loader = SpecLoader(cursor, cache, git_manager, yaml)

    for user_spec in existing_specs:
        base_analysis_id = lookup_analysis_id(user_spec.analysis_spec)
        if analysis_id is not None and analysis_id != base_analysis_id:
            # user specified an analysis id, only merge that one
            continue

        load_specs = _load_specs(loader, user_spec, migrate)
        if load_specs is None:
            continue

        user_spec_bytes, base_version = strip_base_version(yaml, user_spec.analysis_spec.copy())

        if base_version == load_specs.latest_version:
            # already up to date
            continue

        spec_conflict, spec_output = merge_yaml(
            load_specs.base_spec_bytes, load_specs.latest_spec_bytes, user_spec_bytes
        )
        file_conflict, file_output = False, bytes()

        # next check for conflicts in the file
        file_content = load_file_of_spec(user_spec)
        if file_content is not None:
            if load_specs.base_file_content is None:
                print(f"Base file for {base_analysis_id}@{base_version} not found, skipping")
                continue
            if load_specs.latest_file_content is None:
                print(f"Latest file for {base_analysis_id}@{base_version} not found, skipping")
                continue

            file_conflict, file_output = merge_bytes(
                load_specs.base_file_content, load_specs.latest_file_content, file_content
            )

        if spec_conflict or file_conflict:
            if not do_interactive_merge:
                merge_conflicts.append(lookup_analysis_id(user_spec.analysis_spec))
                continue

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

        # update the base spec
        merged_spec = yaml.load(spec_output.decode())
        merged_spec["BaseVersion"] = load_specs.latest_version
        with open(user_spec.spec_filename, "wb") as spec_file:
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


@dataclass
class LoadSpecsResult:
    base_spec_bytes: bytes
    base_file_content: Optional[bytes]
    latest_spec_bytes: bytes
    latest_file_content: Optional[bytes]
    latest_version: int


def _load_specs(
    loader: "SpecLoader", user_spec: LoadAnalysisSpecsResult, migrate: bool
) -> Optional[LoadSpecsResult]:
    base_spec_bytes, base_file_content = loader.load_base_spec(user_spec, migrate)
    if base_spec_bytes is None:
        logging.warning("Base version not found for %s, skipping", user_spec.spec_filename)
        return None

    # find latest version of the spec
    latest_base_spec_bytes, latest_file_content, latest_version = loader.load_latest_spec(user_spec)
    if latest_base_spec_bytes is None:
        if migrate:
            _migrate_file(user_spec, loader.git_manager)
            return None
        base_analysis_id = lookup_analysis_id(user_spec.analysis_spec)
        logging.warning("Latest version of %s not found, skipping", base_analysis_id)
        return None
    if latest_version is None:
        logging.warning("Latest version of %s not found, skipping", base_analysis_id)
        return None
    return LoadSpecsResult(
        base_spec_bytes,
        base_file_content,
        latest_base_spec_bytes,
        latest_file_content,
        latest_version,
    )


class SpecLoader:
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
        base_analysis_spec = self.cache.get_spec_for_version(analysis_id, base_version)
        if base_analysis_spec is None:
            return None, None
        base_file_content = self.cache.get_file_for_spec(base_analysis_spec.id)

        return base_analysis_spec.spec, base_file_content

    def load_latest_spec(
        self, spec: LoadAnalysisSpecsResult
    ) -> Tuple[Optional[bytes], Optional[bytes], Optional[int]]:
        analysis_id = lookup_analysis_id(spec.analysis_spec)
        analysis_spec = self.cache.get_latest_spec(analysis_id)
        if analysis_spec is None:
            return None, None, None

        latest_file_content = self.cache.get_file_for_spec(analysis_spec.id)

        return analysis_spec.spec, latest_file_content, analysis_spec.version


def was_deleted_by_panther(git_manager: git.GitManager, filename: pathlib.Path) -> bool:
    # see if the spec was deleted by panther
    merge_base = git_manager.merge_base("HEAD")

    # normalize the filename for the git repo
    if filename.is_absolute():
        filename = filename.relative_to(git_manager.git_root())

    # get the panther commit
    panther_commit = git_manager.panther_latest_release_commit()

    proc = subprocess.run(  # nosec:B607 B603
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


def still_exists_in_panther(git_manager: git.GitManager, filename: pathlib.Path) -> Optional[bytes]:
    # see if the spec still exists in panther
    # normalize the filename for the git repo
    if filename.is_absolute():
        filename = filename.relative_to(git_manager.git_root())

    # get the panther commit
    panther_commit = git_manager.panther_latest_release_commit()

    proc = subprocess.run(  # nosec:B607 B603
        ["git", "show", f"{panther_commit}:{filename}"], check=False, capture_output=True
    )
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def _migrate_file(user_spec: LoadAnalysisSpecsResult, git_manager: git.GitManager) -> None:
    spec_path = pathlib.Path(user_spec.spec_filename)
    if user_spec.analysis_spec.get("AnalysisType") == "pack":
        # just delete packs
        os.remove(user_spec.spec_filename)
        return
    if was_deleted_by_panther(git_manager, spec_path):
        # the spec was deleted by panther
        os.remove(user_spec.spec_filename)
        filename = user_spec.analysis_spec.get("Filename")
        if filename is not None:
            filename = pathlib.Path(user_spec.spec_filename).parent / filename
            if was_deleted_by_panther(git_manager, filename):
                os.remove(filename)
        logging.info("Deleted %s because it was deleted by panther", user_spec.spec_filename)
        return
    if still_exists_in_panther(git_manager, spec_path):
        # the spec still exists in panther. It is likely the ID changed,
        # do the diff on it with the current content
        # TODO: handle this
        logging.info("Spec changed IDs :%s", user_spec.spec_filename)


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


def strip_base_version(yaml: ruamel.yaml.YAML, spec: Dict[str, Any]) -> Tuple[bytes, Optional[int]]:
    version = spec.pop("BaseVersion", None)
    bytes_io = io.BytesIO()
    yaml.dump(spec, bytes_io)
    return bytes_io.getvalue(), version


def merge_yaml(base: bytes, latest: bytes, user: bytes) -> Tuple[bool, bytes]:
    base = analysis_spec_dump(base)
    latest = analysis_spec_dump(latest)
    user = analysis_spec_dump(user)
    return merge_bytes(base, latest, user)


def merge_bytes(base: bytes, latest: bytes, user: bytes) -> Tuple[bool, bytes]:
    # create a temp file for each
    with (
        tempfile.NamedTemporaryFile(delete=False) as temp_file_base,
        tempfile.NamedTemporaryFile(delete=False) as temp_file_latest,
        tempfile.NamedTemporaryFile(delete=False) as temp_file_user,
    ):
        temp_file_base.write(base)
        temp_file_base.flush()

        temp_file_latest.write(latest)
        temp_file_latest.flush()

        temp_file_user.write(user)
        temp_file_user.flush()

        proc = subprocess.run(  # nosec:B607 B603
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
        print(f'    {" " * (error.offset - 1)}^' if error.offset is not None else "")
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
    proc = subprocess.run(
        ["git", "show", f"{merge_base}:{filename}"],
        capture_output=True,
        check=False,
    )  # nosec:B607 B603
    if proc.returncode != 0:
        raise MergeError(f"Failed to get base file from git: {proc.stderr.decode().strip()}")
    return proc.stdout
