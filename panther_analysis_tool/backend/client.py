"""
Panther Analysis Tool is a command line interface for writing,
testing, and packaging policies/rules.
Copyright (C) 2020 Panther Labs Inc

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import base64
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, List, TypeVar, Generic, Optional

ResponseData = TypeVar('ResponseData')


class BackendError(Exception):
    pass


@dataclass(frozen=True)
class BulkUploadPayload:
    data:    bytes
    user_id: str


@dataclass(frozen=True)
class BackendResponse(Generic[ResponseData]):
    data:        ResponseData
    status_code: int


@dataclass(frozen=True)
class BackendCheckResponse:
    success: bool
    message: str


@dataclass(frozen=True)
class BulkUploadParams:
    zip_bytes: bytes

    def encoded_bytes(self) -> str:
        return base64.b64encode(self.zip_bytes).decode("utf-8")


@dataclass(frozen=True)
class DeleteSavedQueriesParams:
    names: List[str]
    dry_run: bool
    include_detections: bool


@dataclass(frozen=True)
class DeleteDetectionsParams:
    ids: List[str]
    dry_run: bool
    include_saved_queries: bool


@dataclass(frozen=True)
class UpdateManagedSchemasParams:
    release: str
    manifest_url: str


@dataclass(frozen=True)
class BulkUploadStatistics:
    new: int
    total: int
    modified: int


@dataclass(frozen=True)
class BulkUploadResponse:
    rules: BulkUploadStatistics
    policies: BulkUploadStatistics
    data_models: BulkUploadStatistics
    lookup_tables: BulkUploadStatistics
    global_helpers: BulkUploadStatistics
    new_detections: Optional[List[Any]]
    updated_detections: Optional[List[Any]]


@dataclass(frozen=True)
class DeleteSavedQueriesResponse:
    names: List[str]
    detection_ids: List[str]


@dataclass(frozen=True)
class DeleteDetectionsResponse:
    ids: List[str]
    saved_query_names: List[str]


class Client(ABC):

    @abstractmethod
    def check(self) -> BackendCheckResponse:
        pass

    @abstractmethod
    def bulk_upload(self, params: BulkUploadParams) -> BackendResponse[BulkUploadResponse]:
        pass

    @abstractmethod
    def delete_saved_queries(self, params: DeleteSavedQueriesParams) -> BackendResponse[DeleteSavedQueriesResponse]:
        pass

    @abstractmethod
    def delete_detections(self, params: DeleteDetectionsParams) -> BackendResponse[DeleteDetectionsResponse]:
        pass

    @abstractmethod
    def list_managed_schema_updates(self) -> BackendResponse[Any]:
        pass

    @abstractmethod
    def update_managed_schemas(self, params: UpdateManagedSchemasParams) -> BackendResponse[Any]:
        pass
