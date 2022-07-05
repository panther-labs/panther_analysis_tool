import base64

from typing import List
from dataclasses import dataclass


@dataclass(frozen=True)
class BulkUploadParams:
    zip_bytes: bytes

    def encoded_bytes(self) -> str:
        return base64.b64encode(self.zip_bytes).decode("utf-8")


@dataclass(frozen=True)
class ListDetectionsParams:
    ids: List[str]
    scheduled_queries: List[str]


@dataclass(frozen=True)
class ListSavedQueriesParams:
    name: str


@dataclass(frozen=True)
class DeleteSavedQueriesParams:
    ids: List[str]


@dataclass(frozen=True)
class DeleteDetectionsParams:
    ids: List[str]


@dataclass(frozen=True)
class UpdateManagedSchemasParams:
    release: str
    manifest_url: str

