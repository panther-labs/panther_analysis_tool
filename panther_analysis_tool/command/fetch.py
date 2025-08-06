import argparse
import pathlib
import sqlite3
from typing import Tuple
import requests
import os
import zipfile  
import io
from panther_analysis_tool.constants import CACHE_DIR, AnalysisTypes, PANTHER_ANALYSIS_URL, PANTHER_ANALYSIS_SQLITE_FILE

def run(**kwargs) -> Tuple[int, str]:
    # git clone latest panther-analysis
    download_panther_analysis_asset()
    return 0, "Fetched"


def download_panther_analysis_asset() -> None:
    response = requests.get(PANTHER_ANALYSIS_URL)
    pa_zip_asset = None
    for asset in response.json()["assets"]:
        if asset["name"] == "panther-analysis-all.zip":
            pa_zip_asset = asset
            break
    if pa_zip_asset is None:
        raise Exception("No panther-analysis-all.zip asset found")
    
    response = requests.get(pa_zip_asset["browser_download_url"])

    # unzip to CACHE_DIR
    os.makedirs(CACHE_DIR, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(response.content), "r") as zip_ref:
        zip_ref.extractall(os.path.join(CACHE_DIR, "panther-analysis"))

    import_sqlite()


def import_sqlite() -> None:
    # defer importing to improve startup time
    from panther_analysis_tool.analysis_utils import load_analysis_specs_ex

    SQLITE_FILE = pathlib.Path(CACHE_DIR) / PANTHER_ANALYSIS_SQLITE_FILE

    conn = sqlite3.connect(SQLITE_FILE)
    cursor = conn.cursor()

    # get all tables
    cursor.execute("CREATE TABLE IF NOT EXISTS analysis_specs (id INTEGER PRIMARY KEY AUTOINCREMENT, id_field TEXT, id_value TEXT, spec TEXT, file_path TEXT, version INTEGER);")
    # unique constrain on id_field, id_value and version
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_analysis_specs_unique ON analysis_specs (id_field, id_value, version);")

    # load all analysis specs
    all_specs = load_analysis_specs_ex(
        [CACHE_DIR], [], True
    )
    
    for spec in all_specs:
        match spec.analysis_type():
            case AnalysisTypes.RULE | AnalysisTypes.SCHEDULED_RULE | AnalysisTypes.CORRELATION_RULE:
                id_field = "RuleID"
            case AnalysisTypes.DATA_MODEL:   
                id_field = "DataModelID"
            case AnalysisTypes.POLICY:
                id_field = "PolicyID"
            case AnalysisTypes.GLOBAL:
                id_field = "GlobalID"
            case AnalysisTypes.SCHEDULED_QUERY | AnalysisTypes.SAVED_QUERY:
                id_field = "QueryName"
            case AnalysisTypes.PACK:
                continue
            case AnalysisTypes.LOOKUP_TABLE:
                id_field = "LookupName"
            case _:
                raise ValueError(f"Unsupported analysis type: {spec.analysis_type()}")
        id_value = spec.analysis_spec.get(id_field)
        yaml_contents = io.StringIO()
        spec.yaml_ctx.dump(spec.analysis_spec, yaml_contents)
        relpath = pathlib.Path(spec.spec_filename).relative_to(pathlib.Path(CACHE_DIR).absolute() / "panther-analysis")
        cursor.execute("INSERT INTO analysis_specs (id_field, id_value, spec, file_path, version) VALUES (?, ?, ?, ?, ?);", 
                    (id_field, id_value, yaml_contents.getvalue(), str(relpath), spec.analysis_spec.get("Version", 1)))
    
    conn.commit()
    conn.close()
