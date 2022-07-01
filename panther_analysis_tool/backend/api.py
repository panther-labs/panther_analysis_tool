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

from dataclasses import dataclass

from .base import BackendClient
from ..config.base import PATConfig


@dataclass(frozen=True)
class APIClientOptions:
    token:  str
    config: PATConfig


class APIClient(BackendClient):
    _opts: APIClientOptions

    def __init__(self, opts: APIClientOptions):
        self._opts = opts

    def bulk_upload(self):
        pass

    def list_detections(self):
        pass

    def list_saved_queries(self):
        pass

    def delete_saved_queries(self):
        pass

    def delete_detections(self):
        pass

    def list_managed_schema_updates(self):
        pass

    def update_managed_schemas(self):
        pass
