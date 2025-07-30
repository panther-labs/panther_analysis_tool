import io
import pathlib
import sqlite3
from typing import Tuple

from panther_analysis_tool.constants import CACHE_DIR, DEFAULT_EDITOR
from panther_analysis_tool.analysis_utils import get_yaml_loader
from panther_analysis_tool.libs import editor

def run(analysis_id: str) -> Tuple[int, str]:
    rev_analysis(analysis_id)
    return 0, ""

def rev_analysis(analysis_id: str) -> None:
    sqlite_file = pathlib.Path(CACHE_DIR) / "panther-analysis.sqlite"
    conn = sqlite3.connect(sqlite_file)
    cursor = conn.cursor()
    cursor.execute("SELECT id, id_field, id_value, spec, file_path FROM analysis_specs WHERE UPPER(id_value) = ? ORDER BY version DESC LIMIT 1", (analysis_id.upper(),))
    spec_id, id_field, id_value, spec, file_path = cursor.fetchone()
    if not id_field:
        return 1, f"No spec found for {analysis_id}"
    
    # read the temp file and compare it to the original spec
    temp_spec = editor.edit_file(spec.encode())
    
    if temp_spec == spec:
        print("No changes made")
        # return 0, "No changes made"

    # now check for a file attachement
    file_content = None
    temp_file_content = None
    cursor.execute("SELECT file_id FROM file_mappings WHERE spec_id = ? LIMIT 1", (spec_id,))
    row = cursor.fetchone()
    if row is not None:
        file_id = row[0]
        cursor.execute("SELECT content FROM files WHERE id = ?", (file_id,))
        row = cursor.fetchone()
        if row is not None:
            file_content = row[0]
            temp_file_content = editor.edit_file(file_content)

    if temp_spec == spec and (file_id is None or file_content == temp_file_content):
        print("No changes made")
        return 0, "No changes made"

    # bump the yaml version and write it back to the db
    yaml = get_yaml_loader(roundtrip=True)
    spec_yaml = yaml.load(spec)
    spec_version = spec_yaml.get("Version", 1) + 1

    new_spec_yaml = yaml.load(temp_spec)
    new_spec_yaml["Version"] = spec_version
    stream = io.StringIO()
    yaml.dump(new_spec_yaml, stream)
    new_spec = stream.getvalue()
    new_spec_id = cursor.execute("INSERT INTO analysis_specs (id_field, id_value, spec, file_path, version) VALUES (?, ?, ?, ?, ?)", (id_field, id_value, new_spec, file_path, spec_version)).lastrowid
    
    if file_id is not None:
        if temp_file_content != file_content:
            file_id = cursor.execute("INSERT INTO files (content) VALUES (?)", (temp_file_content,)).lastrowid
        cursor.execute("INSERT INTO file_mappings (spec_id, file_id) VALUES (?, ?)", (new_spec_id, file_id))

    conn.commit()
    conn.close()
    print(f"Reved {id_field} = {id_value} version {spec_version}")
    return 0, "Reved"