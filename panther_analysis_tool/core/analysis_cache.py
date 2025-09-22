import pathlib
import sqlite3
from typing import Optional, Tuple

from panther_analysis_tool.constants import CACHE_DIR, PANTHER_ANALYSIS_SQLITE_FILE


def connect_to_cache() -> sqlite3.Connection:
    """
    Connect to the analysis cache database.
    """
    SQLITE_FILE = pathlib.Path(CACHE_DIR) / PANTHER_ANALYSIS_SQLITE_FILE
    return sqlite3.connect(SQLITE_FILE)


class AnalysisCache:
    def __init__(self) -> None:
        self.conn = connect_to_cache()
        self.cursor = self.conn.cursor()

    def list_spec_ids(self) -> list[str]:
        """
        List all analysis specs in the cache directory.
        """
        self.cursor.execute("SELECT DISTINCT id_value FROM analysis_specs")
        return [row[0] for row in self.cursor.fetchall()]

    def get_file_for_spec(self, spec_id: int) -> Optional[bytes]:
        """
        Get the file for a spec.
        """
        row = self.cursor.execute(
            "SELECT file_id FROM file_mappings WHERE spec_id = ?", (spec_id,)
        ).fetchone()
        if row is None:
            return None
        return self.get_file_by_id(row[0])

    def get_file_by_id(self, file_id: int) -> Optional[bytes]:
        """
        Get the file by id.
        """
        row = self.cursor.execute("SELECT content FROM files WHERE id = ?", (file_id,)).fetchone()
        if row is None:
            return None
        return row[0]

    def get_spec_for_version(
        self, analysis_id: str, base_version: int
    ) -> Tuple[Optional[int], Optional[bytes]]:
        self.cursor.execute(
            "SELECT id, spec FROM analysis_specs WHERE id_value = ? AND version = ?",
            (analysis_id, base_version),
        )
        row = self.cursor.fetchone()
        if row is None:
            return None, None
        return row[0], row[1]

    def get_latest_spec(
        self, analysis_id: str
    ) -> Tuple[Optional[int], Optional[bytes], Optional[int]]:
        self.cursor.execute(
            "SELECT id, spec, version FROM analysis_specs WHERE id_value = ? ORDER BY version DESC LIMIT 1",
            (analysis_id,),
        )
        row = self.cursor.fetchone()
        if row is None:
            return None, None, None
        return row[0], row[1], row[2]
