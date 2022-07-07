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

from dataclasses import dataclass
from gql import gql, Client

from .client import (
    Client,
    BackendResponse,
    BulkUploadParams,
    ListDetectionsParams,
    DeleteDetectionsParams,
    ListSavedQueriesParams,
    DeleteSavedQueriesParams
)


@dataclass(frozen=True)
class PublicAPIClientOptions:
    token:   str
    user_id: str


class PublicAPIClient(Client):
    _opts: PublicAPIClientOptions

    def __init__(self, opts: PublicAPIClientOptions):
        self._opts = opts

    def bulk_upload(self, params: BulkUploadParams) -> BackendResponse:
        pass

    def list_detections(self, params: ListDetectionsParams) -> BackendResponse:
        pass

    def list_saved_queries(self, params: ListSavedQueriesParams) -> BackendResponse:
        pass

    def delete_saved_queries(self, params: DeleteSavedQueriesParams) -> BackendResponse:
        pass

    def delete_detections(self, params: DeleteDetectionsParams) -> BackendResponse:
        pass
