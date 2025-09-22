import io
import json
import os
import pathlib
import shutil
import sqlite3
import subprocess  # nosec:B404
import zipfile
from typing import Tuple

import requests

from panther_analysis_tool.analysis_utils import load_analysis_specs_ex
from panther_analysis_tool.constants import (
    CACHE_DIR,
    PANTHER_ANALYSIS_URL,
    AnalysisTypes,
)
from panther_analysis_tool.core import analysis_cache

PANTHER_ANALYSIS_GITHUB_BRANCH = "dmiller-next"


def run() -> Tuple[int, str]:
    # git clone latest panther-analysis
    import_from_github_branch()
    # import_from_github_release()
    return 0, "Fetched"


def import_from_github_branch() -> None:
    shutil.rmtree(os.path.join(CACHE_DIR), ignore_errors=True)
    os.makedirs(CACHE_DIR, exist_ok=True)

    subprocess.run(  # nosec:B607 B603
        [
            "git",
            "clone",
            "-b",
            PANTHER_ANALYSIS_GITHUB_BRANCH,
            "https://github.com/panther-labs/panther-analysis.git",
            os.path.join(CACHE_DIR, "panther-analysis"),
        ],
        check=True,
    )

    shutil.rmtree(os.path.join(CACHE_DIR, "panther-analysis", "templates"))
    shutil.rmtree(os.path.join(CACHE_DIR, "panther-analysis", "test_scenarios"))
    import_sqlite()


def import_from_github_release() -> None:
    response = requests.get(PANTHER_ANALYSIS_URL, timeout=10)
    pa_zip_asset = None
    for asset in response.json()["assets"]:
        if asset["name"] == "panther-analysis-all.zip":
            pa_zip_asset = asset
            break
    if pa_zip_asset is None:
        raise ValueError("No panther-analysis-all.zip asset found")

    response = requests.get(pa_zip_asset["browser_download_url"], timeout=10)

    # unzip to CACHE_DIR
    os.makedirs(CACHE_DIR, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(response.content), "r") as zip_ref:
        zip_ref.extractall(os.path.join(CACHE_DIR, "panther-analysis"))

    import_sqlite()


def create_tables(cursor: sqlite3.Cursor) -> None:
    # get all tables
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS analysis_specs (id INTEGER PRIMARY KEY AUTOINCREMENT, id_field TEXT,"
        " id_value TEXT, spec BLOB, file_path TEXT, version INTEGER);"
    )
    # unique constrain on id_field, id_value and version
    cursor.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_analysis_specs_unique ON analysis_specs (id_field, id_value, version);"
    )

    cursor.execute(
        "CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY AUTOINCREMENT, content BLOB UNIQUE);"
    )

    cursor.execute(
        "CREATE TABLE IF NOT EXISTS file_mappings (id INTEGER PRIMARY KEY AUTOINCREMENT, spec_id INTEGER,"
        " file_id INTEGER, FOREIGN KEY (spec_id) REFERENCES analysis_specs(id), FOREIGN KEY (file_id) REFERENCES files(id));"
    )
    cursor.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_file_mappings_unique ON file_mappings (spec_id, file_id);"
    )


def import_sqlite() -> None:
    conn = analysis_cache.connect_to_cache()
    cursor = conn.cursor()

    create_tables(cursor)

    versions = {}
    with open(os.path.join(CACHE_DIR, "panther-analysis", "version.json"), "rb") as version_file:
        versions = json.load(version_file)["versions"]

    # load all analysis specs
    for spec in load_analysis_specs_ex([CACHE_DIR], [], False):
        if spec.error is not None:
            continue

        if "AnalysisType" not in spec.analysis_spec:
            raise ValueError(f"Analysis type not found in spec: {spec.analysis_spec}")

        content = None
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

        filename = spec.analysis_spec.get("Filename")
        if filename is not None:
            file_path = pathlib.Path(spec.spec_filename).parent / filename
            with open(file_path, "rb") as spec_file:
                content = spec_file.read()

        file_id = None
        if content is not None:
            try:
                file_id = cursor.execute(
                    "INSERT INTO files (content) VALUES (?);", (content,)
                ).lastrowid
            except sqlite3.IntegrityError:
                file_id = cursor.execute(
                    "SELECT id FROM files WHERE content = ?;", (content,)
                ).fetchone()[0]

        id_value = spec.analysis_spec.get(id_field)
        relpath = pathlib.Path(spec.spec_filename).relative_to(
            pathlib.Path(CACHE_DIR).absolute() / "panther-analysis"
        )
        spec_version = versions[id_value]["version"]
        spec_id = cursor.execute(
            "INSERT INTO analysis_specs (id_field, id_value, spec, file_path, version) VALUES (?, ?, ?, ?, ?);",
            (id_field, id_value, spec.raw_file_content, str(relpath), spec_version),
        ).lastrowid

        if file_id is not None:
            cursor.execute(
                "INSERT INTO file_mappings (spec_id, file_id) VALUES (?, ?);", (spec_id, file_id)
            )
    conn.commit()
    conn.close()
