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
from typing import Any, List, Optional


@dataclass(frozen=True)
class BulkUploadPayload:
    data:    bytes
    user_id: str


@dataclass(frozen=True)
class BackendResponse:
    data:        Any
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
class BulkDeleteParams:
    dry_run:         bool
    user_id:         str
    detection_ids:   Optional[List[str]]
    saved_query_ids: Optional[List[str]]


class Client(ABC):

    @abstractmethod
    def check(self) -> BackendCheckResponse:
        pass

    @abstractmethod
    def bulk_upload(self, params: BulkUploadParams) -> BackendResponse:
        pass

    @abstractmethod
    def bulk_delete(self, params: BulkDeleteParams) -> BackendResponse:
        pass

