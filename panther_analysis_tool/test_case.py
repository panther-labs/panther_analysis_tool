from typing import Any, Callable, Dict, Iterator, List
from jsonpath_ng import Fields, parse


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


class TestCase():

    def __init__(self, data: Dict[str, Any],
                 data_models: List[DataModel]) -> None:
        """
        Args:
            data (Dict[str, Any]): An AWS Resource representation or Log event to test the policy
            or rule against respectively.
        """
        self._data = data
        self.data_models = data_models

    def __getitem__(self, arg: str) -> Any:
        return self._data.get(arg, None)

    def __iter__(self) -> Iterator:
        return iter(self._data)

    def get(self, arg: str, default: Any = None) -> Any:
        return self._data.get(arg, default)

    def udm(self, key: str) -> Any:
        """Converts standard data model field to logtype field"""
        # access values via normal logType fields
        if key in self._data.keys():
            return self.get(key)
        if self.data_models:
            # access values via standardized fields
            # check each data model that could apply
            for data_model in self.data_models:
                if key in data_model.paths.keys():
                    # we are dealing with a jsonpath
                    json_path = data_model.paths.get(key)
                    if json_path:
                        matches = json_path.find(self._data)
                        if len(matches) == 1:
                            return matches[0].value
                        if len(matches) > 1:
                            raise Exception(
                                'JSONPath [{}] in DataModel [{}], matched multiple fields.'
                                .format(json_path, data_model.data_model_id))
                if key in data_model.methods.keys():
                    # we are dealing with method
                    method = data_model.methods.get(key)
                    if callable(method):
                        result = method(self._data)
                        if result:
                            return result
        # no matches, return None by default
        return None
