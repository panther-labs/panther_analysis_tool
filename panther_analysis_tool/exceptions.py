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

from typing import Any, TypeVar

AnyExceptionType = TypeVar("AnyExceptionType", bound="Exception")


class PantherError(Exception):
    """Custom error class that allows equality comparison"""

    def equals(self, other: AnyExceptionType) -> bool:
        """Compare two exception instances,
        not taking the traceback into account"""
        return type(self) is type(other) and self.args == other.args

    def has_message_prefix(self, string: str) -> bool:
        """Check if error belongs in an error category"""
        return self.args[0] == string

    def __str__(self) -> str:
        if len(self.args) > 1:
            return f'{self.args[0]}: {", ".join(map(str, self.args[1:]))}'
        return self.args[0]


class FunctionReturnTypeError(PantherError):
    pass


class UnknownDestinationError(PantherError):
    def result(self) -> Any:
        return self.args[1]
