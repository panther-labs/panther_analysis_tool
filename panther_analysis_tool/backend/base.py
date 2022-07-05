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
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from .params import (
    BulkUploadParams,
    ListDetectionsParams,
    DeleteDetectionsParams,
    ListSavedQueriesParams,
    DeleteSavedQueriesParams,
    UpdateManagedSchemasParams
)


@dataclass(frozen=True)
class BulkUploadPayload:
    data: bytes
    user_id: str


@dataclass(frozen=True)
class BackendResponse:
    data: Any


class BackendClient(ABC):

    @abstractmethod
    def bulk_upload(self, params: BulkUploadParams) -> BackendResponse:
        pass

    @abstractmethod
    def list_detections(self, params: ListDetectionsParams) -> BackendResponse:
        pass

    @abstractmethod
    def list_saved_queries(self, params: ListSavedQueriesParams) -> BackendResponse:
        pass

    @abstractmethod
    def delete_saved_queries(self, params: DeleteSavedQueriesParams) -> BackendResponse:
        pass

    @abstractmethod
    def delete_detections(self, params: DeleteDetectionsParams) -> BackendResponse:
        pass

    @abstractmethod
    def list_managed_schema_updates(self) -> BackendResponse:
        pass

    @abstractmethod
    def update_managed_schemas(self, params: UpdateManagedSchemasParams) -> BackendResponse:
        pass

