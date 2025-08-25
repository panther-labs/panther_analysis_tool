import ast
import io
import logging
import pathlib
import subprocess
import tempfile
from typing import Optional, Tuple

import ruamel

from panther_analysis_tool import util
from panther_analysis_tool.analysis_utils import LoadAnalysisSpecsResult, get_yaml_loader, load_analysis_specs_ex, lookup_analysis_id
from panther_analysis_tool.constants import CACHE_DIR
from panther_analysis_tool.core import analysis_cache
from panther_analysis_tool.core import editor



def run(analysis_id: Optional[str] = None) -> Tuple[int, str]:
    return merge_analysis(analysis_id)


def merge_analysis(analysis_id: Optional[str] = None) -> Tuple[int, str]:
    yaml = get_yaml_loader(True)

    # load all analysis specs
    all_specs = list(load_analysis_specs_ex(["."], [], True))
    if not all_specs:
        print("Nothing to merge")
        return 0

    update_count = 0
    merge_conflicts = []
    cache = analysis_cache.AnalysisCache()
    cursor = cache.cursor
    # merge managed specs with user specs
    for user_spec in all_specs:
        base_version = user_spec.analysis_spec.get("BaseVersion")
        if base_version is None:
            continue

        if analysis_id is not None and analysis_id != lookup_analysis_id(user_spec.analysis_spec):
            continue

        # find the base spec
        analysis_id = lookup_analysis_id(user_spec.analysis_spec)
        cursor.execute("SELECT id, spec FROM analysis_specs WHERE id_value = ? AND version = ?", (analysis_id, base_version))
        row = cursor.fetchone()
        if row is None:
            logging.warning("Base spec %s@%s not found, skipping", analysis_id, base_version)
            continue
        base_spec_id, base_spec = row

        # find latest version of the base spec
        cursor.execute("SELECT id, spec FROM analysis_specs WHERE id_value = ? ORDER BY version DESC LIMIT 1",
                        (analysis_id,))
        row = cursor.fetchone()
        if row is None:
            logging.warning("Latest version of base spec %s not found, skipping", analysis_id)
            continue
        latest_base_spec_id, latest_base_spec = row

        base_spec_str, _ = strip_version(yaml, base_spec)
        latest_base_spec_str, latest_version = strip_version(yaml, latest_base_spec)
        user_spec_str, base_version = strip_base_version(yaml, user_spec.analysis_spec.copy())

        if base_version == latest_version:
            # already up to date
            continue

        spec_conflict, spec_output = merge_strings(base_spec_str, latest_base_spec_str, user_spec_str)
        file_conflict, file_output = False, None

        # next check for conflicts in the file
        file_content = load_file_of_spec(user_spec)
        if file_content is not None:
            base_file_content = cache.get_file_for_spec(base_spec_id)
            latest_file_content = cache.get_file_for_spec(latest_base_spec_id)

            if base_file_content is None:
                print(f"Base file for {analysis_id}@{base_version} not found, skipping")
                continue
            if latest_file_content is None:
                print(f"Latest file for {analysis_id}@{base_version} not found, skipping")
                continue

            file_conflict, file_output = merge_strings(base_file_content.decode(), latest_file_content.decode(), file_content.decode())

        if spec_conflict or file_conflict:
            if analysis_id is not None:
                if spec_conflict:
                    spec_output = resolve_yaml_conflict(spec_output)
                if file_conflict:
                    file_output = resolve_python_conflict(file_output)
                    if file_output is None:
                        continue
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
            spec_file.write(merged_spec_str)

        # update the file
        if file_output is not None:
            update_file_of_spec(user_spec, file_output)

        update_count += 1

    if update_count != 0:
        print(f"{update_count} spec(s) updated with latest panther version")
        print("run `git diff` to see the changes")

    if len(merge_conflicts) != 0:
        print(f"{len(merge_conflicts)} merge conflict(s) found")
        print("run `pat merge <id>` to resolve each conflict")
        for spec_conflict in merge_conflicts:
            print(f"  {spec_conflict}")
        return 0, ""
    else:
        # FIXME
        return 0, ""


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
        raise ValueError(f"No file name found for spec {spec.analysis_spec['BaseID']}")
    path = pathlib.Path(spec.spec_filename).parent / file_name
    with open(path, "wb") as spec_file:
        spec_file.write(file_content)


def strip_base_version(yaml: ruamel.yaml.YAML, spec: str) -> Tuple[str, Optional[str]]:
    version = spec.pop("BaseVersion", None)
    string_io = io.StringIO()
    yaml.dump(spec, string_io)
    return string_io.getvalue(), version


def strip_version(yaml: ruamel.yaml.YAML, spec: str) -> Tuple[str, Optional[str]]:
    spec_stripped = yaml.load(spec)
    version = spec_stripped.pop("Version", None)
    string_io = io.StringIO()
    yaml.dump(spec_stripped, string_io)
    return string_io.getvalue(), version


def merge_strings(base: str, latest: str, user: str) -> Tuple[bool, bytes]:
    # create a temp file for each
    with tempfile.NamedTemporaryFile(delete=False) as temp_file_base, \
        tempfile.NamedTemporaryFile(delete=False) as temp_file_latest, \
        tempfile.NamedTemporaryFile(delete=False) as temp_file_user:
        temp_file_base.write(base.encode())
        temp_file_base.flush()

        temp_file_latest.write(latest.encode())
        temp_file_latest.flush()

        temp_file_user.write(user.encode())
        temp_file_user.flush()

        proc = subprocess.run(["git", "merge-file", "-p", "-L", "ours", "-L", "base", "-L", "panther",
                    temp_file_user.name, temp_file_base.name, temp_file_latest.name],
                    check=False, capture_output=True)

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
        print(f'    {error.text.strip()}' if error.text else '')
        print(f'    {" " * (error.offset - 1)}^' if error.offset else '')
        print(f'SyntaxError: {error.msg}')
        return None

    return output
