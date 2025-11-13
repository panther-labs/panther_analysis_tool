import dataclasses
import sqlite3
from typing import Optional

from panther_analysis_tool.constants import PANTHER_ANALYSIS_SQLITE_FILE_PATH


class NoCacheException(Exception):
    """
    Exception raised when no cache is found.
    """

    pass


@dataclasses.dataclass
class AnalysisSpec:
    """
    A dataclass representing an analysis item from Panther Analysis.

    Attributes:
        id (int): The unique identifier for the analysis spec.
        spec (bytes): The YAML configuration of the analysis spec.
        version (int): The version number of the analysis spec.
        id_field (str): The field used as the identifier for the analysis spec (e.g. RuleID, PolicyID, etc.).
        id_value (str): The ID of the analysis item.
    """

    id: Optional[int]
    spec: bytes
    version: int
    id_field: str
    id_value: str


class AnalysisCache:
    """
    A class for managing the analysis cache database.
    """

    def __init__(self) -> None:
        """
        Initialize the AnalysisCache by connecting to the cache database and creating a cursor.
        """
        if not PANTHER_ANALYSIS_SQLITE_FILE_PATH.exists():
            raise NoCacheException(
                "No cache found. Please run `pat pull` to pull the latest Panther Analysis content."
            )

        self.conn = sqlite3.connect(PANTHER_ANALYSIS_SQLITE_FILE_PATH)
        self.cursor = self.conn.cursor()

    def create_tables(self) -> None:
        """
        Create the necessary tables and indexes in the cache database if they don't exist.

        Creates 3 tables:
            - analysis_specs: Stores the YAML configuration of the analysis spec.
            - files: Stores the associated Python file for the analysis spec.
            - file_mappings: Stores the mapping between a spec and a file.

        Creates 2 indexes:
            - idx_analysis_specs_unique: Unique index on id_field, id_value and version.
            - idx_file_mappings_unique: Unique index on spec_id and file_id.
        """
        # get all tables
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS analysis_specs (id INTEGER PRIMARY KEY AUTOINCREMENT, id_field TEXT, id_value TEXT, spec BLOB, version INTEGER);"
        )
        # unique constrain on id_field, id_value and version
        self.cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_analysis_specs_unique ON analysis_specs (id_field, id_value, version);"
        )

        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY AUTOINCREMENT, content BLOB UNIQUE);"
        )

        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS file_mappings (id INTEGER PRIMARY KEY AUTOINCREMENT, spec_id INTEGER, version INTEGER, file_id INTEGER, FOREIGN KEY (spec_id) REFERENCES analysis_specs(id), FOREIGN KEY (file_id) REFERENCES files(id));"
        )
        self.cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_file_mappings_unique ON file_mappings (spec_id, version, file_id);"
        )

    def list_spec_ids(self) -> list[str]:
        """
        List all unique analysis spec IDs in the cache.

        Returns:
            list[str]: A list of unique ID values for all analysis specs in the cache.
        """
        self.cursor.execute("SELECT DISTINCT id_value FROM analysis_specs")
        return [row[0] for row in self.cursor.fetchall()]

    def get_file_for_spec(self, analysis_spec_id: int, version: int) -> Optional[bytes]:
        """
        Get the file content associated with a specific analysis spec.

        Args:
            analysis_spec_id (int): The ID of the analysis spec.
            version (int): The version of the analysis spec.

        Returns:
            Optional[bytes]: The file content as bytes if found, None otherwise.
        """
        row = self.cursor.execute(
            "SELECT file_id FROM file_mappings WHERE spec_id = ? AND version = ?",
            (analysis_spec_id, version),
        ).fetchone()
        if row is None:
            return None
        return self.get_file_by_id(row[0])

    def get_file_by_id(self, file_id: int) -> Optional[bytes]:
        """
        Get the file content by its ID in the cache.

        Args:
            file_id (int): The ID of the file in the cache.

        Returns:
            Optional[bytes]: The file content as bytes if found, None otherwise.
        """
        row = self.cursor.execute("SELECT content FROM files WHERE id = ?", (file_id,)).fetchone()
        if row is None:
            return None
        return row[0]

    def get_spec_for_version(self, analysis_id: str, base_version: int) -> Optional[AnalysisSpec]:
        """
        Get the analysis spec for a specific version.

        Args:
            analysis_id (str): The ID of the analysis spec.
            base_version (int): The version number to retrieve.

        Returns:
            Optional[AnalysisSpec]: The AnalysisSpec if found, None otherwise.
        """
        self.cursor.execute(
            "SELECT id, spec, version, id_field, id_value FROM analysis_specs WHERE id_value = ? AND version = ?",
            (analysis_id, base_version),
        )
        row = self.cursor.fetchone()
        if row is None:
            return None
        return AnalysisSpec(
            id=row[0],
            spec=row[1],
            version=row[2],
            id_field=row[3],
            id_value=row[4],
        )

    def get_latest_spec(self, analysis_id: str) -> Optional[AnalysisSpec]:
        """
        Get the latest version of an analysis spec.

        Args:
            analysis_id (str): The ID of the analysis spec.

        Returns:
            Optional[AnalysisSpec]: The latest AnalysisSpec if found, None otherwise.
        """
        self.cursor.execute(
            "SELECT id, spec, version, id_field, id_value FROM analysis_specs WHERE id_value = ? ORDER BY version DESC LIMIT 1",
            (analysis_id,),
        )
        row = self.cursor.fetchone()
        if row is None:
            return None
        return AnalysisSpec(
            id=row[0],
            spec=row[1],
            version=row[2],
            id_field=row[3],
            id_value=row[4],
        )

    def _insert_file(self, content: bytes) -> int:
        """
        Insert a file into the cache or retrieve its ID if it already exists.

        Args:
            content (bytes): The content of the file to insert.

        Returns:
            int: The ID of the inserted or existing file.
        """
        try:
            file_id = self.cursor.execute(
                "INSERT INTO files (content) VALUES (?);", (content,)
            ).lastrowid
        except sqlite3.IntegrityError:
            file_id = self.cursor.execute(
                "SELECT id FROM files WHERE content = ?;", (content,)
            ).fetchone()[0]
        if file_id is None:
            raise ValueError("Failed to insert file, file_id is None")
        return file_id

    def _insert_spec(
        self,
        id_field: str,
        id_value: str,
        spec_content: Optional[bytes],
        spec_version: int,
    ) -> int:
        """
        Insert a new analysis spec into the cache.

        Args:
            id_field (str): The field used as the identifier for the spec.
            id_value (str): The value of the identifier field.
            spec_content (Optional[bytes]): The binary content of the spec.
            spec_version (int): The version number of the spec.

        Returns:
            int: The ID of the newly inserted spec.
        """
        spec_id = self.cursor.execute(
            "INSERT INTO analysis_specs (id_field, id_value, spec, version) VALUES (?, ?, ?, ?);",
            (id_field, id_value, spec_content, spec_version),
        ).lastrowid
        # make typechecker happy
        assert spec_id is not None  # nosec: B101
        return spec_id

    def _insert_file_mapping(self, spec_id: int, version: int, file_id: int) -> None:
        """
        Insert a mapping between a spec and a file in the cache.

        Args:
            spec_id (int): The ID of the analysis spec.
            file_id (int): The ID of the associated file.
        """
        self.cursor.execute(
            "INSERT INTO file_mappings (spec_id, version, file_id) VALUES (?, ?, ?);",
            (spec_id, version, file_id),
        )

    def insert_analysis_spec(
        self, analysis_spec: AnalysisSpec, pyFileContents: Optional[bytes]
    ) -> None:
        """
        Insert an analysis spec into the cache.

        Args:
            analysis_spec (AnalysisSpec): The analysis spec to insert.
            pyFileContents (bytes): The contents of the Python file associated with the analysis spec.

        Returns:
            None
        """

        try:
            spec_id = self._insert_spec(
                analysis_spec.id_field,
                analysis_spec.id_value,
                analysis_spec.spec,
                analysis_spec.version,
            )
            if pyFileContents is not None:
                file_id = self._insert_file(pyFileContents)
                self._insert_file_mapping(spec_id, analysis_spec.version, file_id)

            self.conn.commit()
        except sqlite3.IntegrityError as e:
            if "UNIQUE constraint failed" not in str(e):
                raise e  # simply skip duplicates
        except Exception as e:
            self.conn.rollback()
            raise e

    def delete_analysis_spec(self, analysis_id: str, version: int) -> None:
        """
        Delete an analysis spec from the cache by its ID and version.

        Args:
            analysis_id (str): The ID of the analysis spec to delete.
            version (int): The version of the analysis spec to delete.
        """
        spec = self.get_spec_for_version(analysis_id, version)
        if spec is None:
            raise ValueError(f"Analysis spec {analysis_id} at version {version} not found in cache")

        self.cursor.execute(
            "DELETE FROM analysis_specs WHERE id_value = ? AND version = ?", (analysis_id, version)
        )

        row = self.cursor.execute(
            "SELECT file_id FROM file_mappings WHERE spec_id = ? AND version = ?",
            (analysis_id, version),
        ).fetchone()
        if row is None:
            return None

        file_id = row[0]
        self.cursor.execute(
            "DELETE FROM file_mappings WHERE spec_id = ? AND version = ?", (spec.id or -1, version)
        )
        self.cursor.execute("DELETE FROM files WHERE id = ?", (file_id,))

        self.conn.commit()
