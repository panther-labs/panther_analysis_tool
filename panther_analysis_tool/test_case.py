from collections.abc import Mapping
import logging
from typing import Any, Callable, Dict, Iterator, List, Optional
from jsonpath_ng import Fields
from jsonpath_ng.ext import parse


# pylint: disable=too-few-public-methods
class DataModel:

    def __init__(self, data_model_id: str,
                 source_mappings: List[Dict[str, str]], mapping_module: Any):
        self.data_model_id: str = data_model_id
        self.paths: Dict[str, Fields] = dict()
        self.methods: Dict[str, Callable] = dict()
        self.module = mapping_module
        self.extract_mappings(source_mappings)

    def extract_mappings(self, source_mappings: List[Dict[str, str]]) -> None:
        for mapping in source_mappings:
            # every mapping should have a name and either a method or path
            if 'Method' in mapping:
                self.methods[mapping['Name']] = getattr(self.module,
                                                        mapping['Method'])
            else:
                self.paths[mapping['Name']] = parse(mapping['Path'])


class TestCase(Mapping):

    def __init__(self, data: Dict[str, Any],
                 data_model: Optional[DataModel]) -> None:
        """
        Args:
            data (Dict[str, Any]): An AWS Resource representation or Log event to test the policy
            or rule against respectively.
        """
        self._data = data
        self.data_model = data_model

    def __getitem__(self, arg: str) -> Any:
        return self._data.get(arg, None)

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def __iter__(self) -> Iterator:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def get(self, arg: str, default: Any = None) -> Any:
        return self._data.get(arg, default)

    def udm(self, key: str) -> Any:
        """Converts standard data model field to logtype field"""
        # ensure that rules using `udm` have included p_log_type in their test
        try:
            self._data['p_log_type']
        except KeyError as err:
            logging.warning(
                'Rules that use `udm` are required to define [p_log_type] in test cases'
            )
            raise err
        if self.data_model:
            # access values via standardized fields
            if key in self.data_model.paths:
                # we are dealing with a jsonpath
                json_path = self.data_model.paths.get(key)
                if json_path:
                    matches = json_path.find(self._data)
                    if len(matches) == 1:
                        return matches[0].value
                    if len(matches) > 1:
                        raise Exception(
                            'JSONPath [{}] in DataModel [{}], matched multiple fields.'
                            .format(json_path, self.data_model.data_model_id))
            if key in self.data_model.methods:
                # we are dealing with method
                method = self.data_model.methods.get(key)
                if callable(method):
                    result = method(self._data)
                    return result
        # no matches, return None by default
        return None
