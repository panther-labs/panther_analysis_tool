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
from collections.abc import Mapping, Sequence
from copy import deepcopy
from typing import Any, Collection, Dict, Iterator, Type, Union, no_type_check


class ImmutableContainerMixin(ABC):
    """Base class for immutable collections"""

    _CONVERSIONS: Dict[Any, Any] = {}

    @classmethod
    @abstractmethod
    def mutable_type(cls) -> Any:
        """Specify the mutable type that corresponds to this immutable container class"""

    @classmethod
    @no_type_check
    def register(cls) -> None:
        """Register the corresponding mutable type for this class"""
        cls._CONVERSIONS[cls.mutable_type()] = cls

    def __init__(self, container: Any):
        self._container = self._shallow_copy(container)

    @abstractmethod
    def _shallow_copy(self, obj: Any) -> Any:
        """Creates a shallow copy of the given object"""

    def copy(self) -> Any:
        """
        Returns a deep copy of the wrapped container object, which is mutable.
        Useful for interoperability with dependencies that perform their own type-checking,
        or when mutation is necessary.
        NOTE: Deep-copying has a performance overhead, so use only when necessary.
        """
        return self.mutable_type()(deepcopy(self._container))

    @no_type_check
    def __getitem__(self, item):
        return self._ensure_immutable(self._container[item])

    def _ensure_immutable(self, value: Any) -> Any:
        immutable_type = self.__class__._CONVERSIONS.get(type(value))  # pylint: disable=W0212
        if immutable_type is not None:
            return immutable_type(value)
        return value

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self._container})"

    def __len__(self) -> int:
        return self._container.__len__()

    def __iter__(self) -> Iterator:
        return iter(self._ensure_immutable(element) for element in self._container)


class ImmutableCaseInsensitiveDict(ImmutableContainerMixin, Mapping):  # pylint: disable=R0901
    """
    Read-only dictionary data type with case-insensitive lookup.
    Assumes keys are strings and can be converted to all-lowercase with .lower().
    """

    def __init__(self, container: Union[Mapping, Collection[str]]):
        super().__init__(container)
        self._case_insensitive_keymap: Dict[str, str] = {}
        self._keymap_key_iterator: Union[None, Iterator[str]] = None
        self._keymap_fully_built = False

    @classmethod
    def mutable_type(cls) -> Type[dict]:
        return dict

    def _shallow_copy(self, obj: dict) -> dict:
        return obj.copy()

    def to_dict(self) -> dict:
        """
        Create a deep copy as a mutable dictionary.
        """
        return self.copy()

    def __getitem__(self, item: str) -> Any:
        # Try with the given key first (speeds up case-sensitive matches)
        # If the wrapped container is empty, which is possible for schemaless fields,
        # reraise early.
        if item in self._container or not self._container:
            return super().__getitem__(item)

        original_key = self._case_insensitive_lookup(item)

        # If no entry exists, raise a KeyError containing the given name
        # in order to retain compatibility with `__contains__` and `get` methods
        if original_key is None:
            raise KeyError(item)

        # The key exists in the container, so call the parent method
        # with the original key, in order to ensure the
        # inherited immutability as well
        return super().__getitem__(original_key)

    def _case_insensitive_lookup(self, key: str) -> Union[None, str]:
        # Convert to lowercase and check if a case-insensitive entry exists in the current map.
        # Note that for relatively small keys (up to 15-20 characters),
        # there is no point in caching the lowercase conversion, as the time to fetch
        # from a dictionary is nearly the same.
        lowercase_key = key.lower()
        original_key = self._case_insensitive_keymap.get(lowercase_key)
        if original_key is not None:
            return original_key

        # If the key was not found we need to continue building the key map,
        # unless the build has been already completed
        if original_key is None and self._keymap_fully_built:
            return None

        return self._build_case_insensitive_keymap(lowercase_key)

    def _build_case_insensitive_keymap(self, lowercase_key: str) -> Union[None, str]:
        # Attribute access in a loop has some cost, which can be reduced
        # by assigning to a local variable
        keymap = self._case_insensitive_keymap
        if self._keymap_key_iterator is None:
            self._keymap_key_iterator = iter(self._container)

        matched_key = None
        for original_key in self._keymap_key_iterator:
            case_insensitive_key = original_key.lower()
            # In case of collisions retain only the first key mapping
            mapped_key = keymap.setdefault(case_insensitive_key, original_key)
            # Build the key map incrementally - speeds up lookups when
            # the first keys in order are used.
            if case_insensitive_key == lowercase_key and mapped_key == original_key:
                matched_key = original_key
                break

        if len(self._case_insensitive_keymap) == len(self._container):
            self._keymap_fully_built = True

        return matched_key


class ImmutableList(ImmutableContainerMixin, Sequence):  # pylint: disable=R0901
    """Read-only sequence data type"""

    @classmethod
    def mutable_type(cls) -> Type[list]:
        return list

    def _shallow_copy(self, obj: list) -> tuple:
        return tuple(obj)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, self.__class__):
            return self._container == other._container

        if isinstance(other, (tuple, list)):
            # Allow comparison with lists and tuples
            return len(self._container) == len(other) and self._container == tuple(other)

        return False

    def as_list(self) -> list:
        """
        Create a deep copy as a mutable list.
        """
        return self.copy()


ImmutableList.register()
ImmutableCaseInsensitiveDict.register()


def json_encoder(obj: Any) -> Any:
    """
    Custom encoder for immutable objects

    :param obj: the object for JSON serialization
    :return: a JSON-serializable object
    """
    if isinstance(obj, ImmutableContainerMixin):
        return obj._container  # pylint: disable=W0212
    raise TypeError(f"object of type {type(obj)} is not JSON serializable")
