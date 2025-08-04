import argparse
import os
import pathlib
import sqlite3
import subprocess
import tempfile
from typing import Tuple

import yaml

from panther_analysis_tool.constants import CACHE_DIR, DEFAULT_EDITOR

def run(args: argparse.Namespace) -> Tuple[int, str]:
    rev_analysis(args)
    return 0, ""

def rev_analysis(args: argparse.Namespace) -> None:
    sqlite_file = pathlib.Path(CACHE_DIR) / "panther-analysis.sqlite"
    conn = sqlite3.connect(sqlite_file)
    cursor = conn.cursor()
    cursor.execute("SELECT id_field, id_value, spec, file_path, version FROM analysis_specs WHERE UPPER(id_value) = ? ORDER BY version DESC LIMIT 1", (args.id.upper(),))
    id_field, id_value, spec, file_path, version = cursor.fetchone()
    if id_field:
        print(f"Reving {id_field} = {id_value} version {version}")
    else:
        print(f"No spec found for {args.id_field} = {args.id_value} and version {args.version}")

    # create a temp file and 

    # create a temp file and write the spec to it
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_file.write(spec.encode())

    # launch the editor with the temp file and wait for it to finish
    editor = os.getenv("EDITOR", DEFAULT_EDITOR)
    rev_command = [editor, temp_file.name]
    subprocess.run(rev_command, check=True)

    # read the temp file and compare it to the original spec
    with open(temp_file.name, "r") as f:
        temp_spec = f.read()
    temp_file.close()
    
    if temp_spec == spec:
        print("No changes made")
        return 0, "No changes made"

    # bump the yaml version and write it back to the db
    spec_yaml = yaml.safe_load(spec)
    spec_version = spec_yaml.get("Version", 1) + 1

    new_spec_yaml = yaml.safe_load(temp_spec)
    new_spec_yaml["Version"] = spec_version
    new_spec = yaml.dump(new_spec_yaml)
    cursor.execute("INSERT INTO analysis_specs (id_field, id_value, spec, file_path, version) VALUES (?, ?, ?, ?, ?)", (id_field, id_value, new_spec, file_path, spec_version))
    conn.commit()
    conn.close()
    print(f"Reved {id_field} = {id_value} version {spec_version}")
    return 0, "Reved"