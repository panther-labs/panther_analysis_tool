import pathlib
import sqlite3
from typing import Optional

from panther_analysis_tool.constants import CACHE_DIR, PANTHER_ANALYSIS_SQLITE_FILE


def connect_to_cache() -> sqlite3.Connection:
    """
    Connect to the analysis cache database.
    """
    SQLITE_FILE = pathlib.Path(CACHE_DIR) / PANTHER_ANALYSIS_SQLITE_FILE
    return sqlite3.connect(SQLITE_FILE)


class AnalysisCache:
    def __init__(self):
        self.conn = connect_to_cache()
        self.cursor = self.conn.cursor()

    def list_spec_ids(self) -> list[str]:
        """
        List all analysis specs in the cache directory.
        """
        self.cursor.execute("SELECT id_value FROM analysis_specs")
        return [row[0] for row in self.cursor.fetchall()]

    def get_file_for_spec(self, spec_id: int) -> Optional[bytes]:
        """
        Get the file for a spec.
        """
        row = self.cursor.execute("SELECT file_id FROM file_mappings WHERE spec_id = ?", (spec_id,)).fetchone()
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
