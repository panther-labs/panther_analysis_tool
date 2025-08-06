import io
import logging
import os
import pathlib
import sqlite3
import subprocess
import tempfile
from typing import Optional, Tuple

from panther_analysis_tool.analysis_utils import LoadAnalysisSpecsResult, get_yaml_loader, load_analysis_specs_ex
from panther_analysis_tool.constants import CACHE_DIR, DEFAULT_EDITOR

def run(id: Optional[str] = None) -> Tuple[int, str]:
    return merge_analysis(id)


def merge_analysis(id: Optional[str] = None) -> Tuple[int, str]:
    yaml = get_yaml_loader(True)

    # load all analysis specs
    all_specs = list(load_analysis_specs_ex(["."], [], True))
    if not all_specs:
        print("Nothing to merge")
        return 0
    
    user_specs = [x for x in all_specs if CACHE_DIR not in x.spec_filename]
    user_specs = [x for x in all_specs if x.analysis_spec.get("BaseID") is not None and x.analysis_spec.get("BaseVersion") is not None]

    update_count = 0
    merge_conflicts = []
    sqlite_file = pathlib.Path(CACHE_DIR) / "panther-analysis.sqlite"
    conn = sqlite3.connect(sqlite_file)
    cursor = conn.cursor()
    # merge managed specs with user specs
    for user_spec in user_specs:
        if 'BaseID' in user_spec.analysis_spec and 'BaseVersion' in user_spec.analysis_spec:
            if id is not None and id != user_spec.analysis_spec["BaseID"]:
                continue
            
            # find the base spec
            cursor.execute("SELECT spec FROM analysis_specs WHERE id_value = ? AND version = ?", (user_spec.analysis_spec["BaseID"], user_spec.analysis_spec["BaseVersion"]))
            item = cursor.fetchone()
            if item is None:
                logging.warning(f"Base spec {user_spec.analysis_spec['BaseID']} {user_spec.analysis_spec['BaseVersion']} not found, skipping")
                continue
            base_spec = item[0]

            # find latest version of the base spec
            cursor.execute("SELECT spec FROM analysis_specs WHERE id_value = ? ORDER BY version DESC LIMIT 1", (user_spec.analysis_spec["BaseID"],))
            item = cursor.fetchone()
            if item is None:
                logging.warning(f"Latest version of base spec {user_spec.analysis_spec['BaseID']} not found, skipping")
                continue
            latest_base_spec = item[0]
            # strip Version from base spec
            base_spec_stripped = yaml.load(base_spec)
            base_spec_stripped.pop("Version", None)
            string_io = io.StringIO()
            yaml.dump(base_spec_stripped, string_io)
            base_spec_str = string_io.getvalue()

            # strip Version from latest_base_spec
            latest_base_spec_stripped = yaml.load(latest_base_spec)
            latest_version = latest_base_spec_stripped.pop("Version", None)
            string_io = io.StringIO()
            yaml.dump(latest_base_spec_stripped, string_io)
            latest_base_spec_str = string_io.getvalue()

            # convert user_spec to string
            user_spec_stripped = user_spec.analysis_spec.copy()
            user_spec_stripped.pop("BaseID", None)
            base_version = user_spec_stripped.pop("BaseVersion", None)
            string_io = io.StringIO()
            yaml.dump(user_spec_stripped, string_io)
            user_spec_str = string_io.getvalue()
            
            if base_version == latest_version:
                # already up to date
                continue

            no_conflict, output = merge_analysis_spec(base_spec_str, latest_base_spec_str, user_spec_str)
            if not no_conflict:
                if id is not None:
                    output = resolve_conflict(user_spec, output)
                else:
                    merge_conflicts.append(user_spec.spec_filename)
                    continue
            
            # update the base spec
            merged_spec = yaml.load(output.decode())
            merged_spec["BaseID"] = user_spec.analysis_spec["BaseID"]
            merged_spec["BaseVersion"] = latest_version 
            string_io = io.StringIO()
            yaml.dump(merged_spec, string_io)
            merged_spec_str = string_io.getvalue()

            # update the base spec
            with open(user_spec.spec_filename, "w") as f:
                f.write(merged_spec_str)
            update_count += 1
    
    if update_count != 0:
        print(f"{update_count} spec(s) updated with latest panther version")
        print(f"run `git diff` to see the changes")

    if len(merge_conflicts) != 0:
        print(f"{len(merge_conflicts)} merge conflict(s) found")
        print("run `pat merge <id>` to resolve each conflict")
        for conflict in merge_conflicts:
            print(f"  {conflict}")
        return 0, ""
    else:
        return 0, ""
        

def merge_analysis_spec(base_spec: str, latest_base_spec: str, user_spec: str) -> Tuple[bool, bytes]:
    # create a temp file for each of 
    temp_file_base = tempfile.NamedTemporaryFile(delete=False)
    temp_file_base.write(base_spec.encode())
    temp_file_base.flush()

    temp_file_latest = tempfile.NamedTemporaryFile(delete=False)
    temp_file_latest.write(latest_base_spec.encode())
    temp_file_latest.flush()

    temp_file_user = tempfile.NamedTemporaryFile(delete=False)
    temp_file_user.write(user_spec.encode())
    temp_file_user.flush()

    proc = subprocess.run(["git", "merge-file", "-p", "-L", "ours", "-L", "base", "-L", "panther", temp_file_user.name, temp_file_base.name, temp_file_latest.name],
                   capture_output=True)
    
    temp_file_base.close()
    temp_file_latest.close()
    temp_file_user.close()

    return proc.returncode == 0, proc.stdout


def resolve_conflict(spec: LoadAnalysisSpecsResult, merge_result: bytes) -> bytes:
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_file.write(merge_result)
    temp_file.flush()

    editor = os.getenv("EDITOR", DEFAULT_EDITOR)
    rev_command = [editor, temp_file.name]
    subprocess.run(rev_command, check=True)

    # read the temp file and compare it to the original spec
    with open(temp_file.name, "rb") as f:
        temp_spec = f.read()
    temp_file.close()
    
    if temp_spec == spec:
        print("No changes made")
        return

    # todo validate the spec
    yaml = get_yaml_loader(True)
    _ = yaml.load(temp_spec.decode())

    return temp_spec
