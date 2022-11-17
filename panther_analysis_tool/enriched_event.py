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

from collections.abc import Mapping
from typing import Any, Optional

from panther_core.data_model import E_NO_DATA_MODEL_FOUND, DataModel
from panther_core.exceptions import PantherError

from .immutable import ImmutableCaseInsensitiveDict, json_encoder


class PantherEvent(ImmutableCaseInsensitiveDict):  # pylint: disable=R0901
    """Panther enriched event with unified data model (udm) access."""

    def __init__(self, event: Mapping, data_model: Optional[DataModel]):
        """Create data model lookups

        Args:
            event: Dictionary representing the event.
            data_model: the data model used for the LogType associated with this event
        """
        super().__init__(event)
        self.data_model = data_model

    def udm(self, key: str) -> Any:
        """Converts standard data model field to logtype field"""
        self._validate()
        # access values via standardized fields
        match = self._get_json_path(key)
        if match:
            return self._ensure_immutable(match.value)
        method = self._get_method(key)
        if method:
            return self._ensure_immutable(method(self._ensure_immutable(self._container)))
        # no matches, return None by default
        return None

    def udm_path(self, key: str) -> Optional[str]:
        """Returns the JSON path or method name for the mapped field"""
        self._validate()
        # access values via standardized fields
        match = self._get_json_path(key)
        if match:
            return str(match.full_path)
        method = self._get_method(key)
        if method:
            return getattr(method, "__name__", repr(method))
        # no matches, return None by default
        return None

    def _validate(self) -> None:
        if not self.data_model:
            raise PantherError(E_NO_DATA_MODEL_FOUND, self._container.get("p_log_type"))

    def _get_json_path(self, key: str) -> Any:
        if not self.data_model:  # makes linter happy, we never call this if not set
            return None
        if key not in self.data_model.paths:
            return None
        json_path = self.data_model.paths.get(key)
        if not json_path:
            return None
        matches = json_path.find(self._container)
        if len(matches) == 0:
            return None
        if len(matches) == 1:
            return matches[0]
        raise Exception(
            "JSONPath [{}] in DataModel [{}], matched multiple fields.".format(
                json_path, self.data_model.data_model_id
            )
        )

    def _get_method(self, key: str) -> Any:
        if not self.data_model:  # makes linter happy, we never call this if not set
            return None
        if key not in self.data_model.methods:
            return None
        method = self.data_model.methods.get(key)
        if callable(method):
            return method
        # no matches, return None by default
        return None

    json_encoder = json_encoder
