import argparse
import io
import pathlib
import sqlite3
import subprocess
import tempfile
from typing import Tuple

import yaml

from panther_analysis_tool.analysis_utils import load_analysis
from panther_analysis_tool.constants import CACHE_DIR

def run(args: argparse.Namespace) -> Tuple[int, str]:
    return merge_analysis(args)

def merge_analysis(args: argparse.Namespace) -> Tuple[int, str]:
    # load all analysis specs
    all_specs, _ = load_analysis(
        ".", True, [], []
    )
    if all_specs.empty():
        return 0, [f"Nothing to merge"]
    
    user_specs = all_specs.apply(lambda l: [x for x in l if CACHE_DIR not in x.file_name])
    user_specs = user_specs.apply(lambda l: [x for x in l if x.analysis_spec["BaseID"] is not None and x.analysis_spec["BaseVersion"] is not None])

    update_count = 0
    merge_conflicts = []
    # merge managed specs with user specs
    for user_spec in user_specs.items():
        if 'BaseID' in user_spec.analysis_spec and 'BaseVersion' in user_spec.analysis_spec:
            # find the base spec
            sqlite_file = pathlib.Path(CACHE_DIR) / "panther-analysis.sqlite"
            conn = sqlite3.connect(sqlite_file)
            cursor = conn.cursor()
            cursor.execute("SELECT spec FROM analysis_specs WHERE id_value = ? AND version = ?", (user_spec.analysis_spec["BaseID"], user_spec.analysis_spec["BaseVersion"]))
            base_spec = cursor.fetchone()[0]
            if base_spec is None:
                return 1, f"Base spec {user_spec.analysis_spec['BaseID']} {user_spec.analysis_spec['BaseVersion']} not found"
            
            # find latest version of the base spec
            cursor.execute("SELECT spec FROM analysis_specs WHERE id_value = ? ORDER BY version DESC LIMIT 1", (user_spec.analysis_spec["BaseID"],))
            latest_base_spec = cursor.fetchone()[0]
            if latest_base_spec is None:
                return 1, f"Latest version of base spec {user_spec.analysis_spec['BaseID']} not found"
            
            # strip Version from base spec
            base_spec_stripped = yaml.safe_load(base_spec)
            base_spec_stripped.pop("Version", None)
            string_io = io.StringIO()
            yaml.dump(base_spec_stripped, string_io)
            base_spec_str = string_io.getvalue()

            # strip Version from latest_base_spec
            latest_base_spec_stripped = yaml.safe_load(latest_base_spec)
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
                print(output)
                return 1, "Merge conflict"
            
            # update the base spec
            merged_spec = yaml.safe_load(output)
            merged_spec["BaseVersion"] = latest_version 
            merged_spec["BaseID"] = user_spec.analysis_spec["BaseID"]
            string_io = io.StringIO()
            yaml.dump(merged_spec, string_io)
            merged_spec_str = string_io.getvalue()

            # update the base spec
            with open(user_spec.file_name, "w") as f:
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
        

def merge_analysis_spec(base_spec: str, latest_base_spec: str, user_spec: str) -> Tuple[bool, str]:
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

    return proc.returncode == 0, proc.stdout.decode()
