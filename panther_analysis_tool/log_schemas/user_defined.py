from dataclasses import dataclass
import fnmatch
import json
import logging
import os
from typing import List, Dict, Tuple, Optional, Any, cast

import boto3
from botocore import client
from ruamel.yaml import YAML
from ruamel.yaml.scanner import ScannerError
from ruamel.yaml.parser import ParserError


logger = logging.getLogger(__file__)


class Client:
    _LAMBDA_NAME = 'panther-logtypes-api'
    _LIST_SCHEMAS_ENDPOINT = 'ListSchemas'
    _PUT_SCHEMA_ENDPOINT = 'PutUserSchema'

    def __init__(self) -> None:
        self._lambda_client = None

    @property
    def lambda_client(self) -> client.BaseClient:
        if self._lambda_client is None:
            self._lambda_client = boto3.client("lambda")
        return self._lambda_client

    def list_schemas(self) -> Tuple[bool, dict]:
        return self._invoke(
            self._create_lambda_request(
                endpoint=self._LIST_SCHEMAS_ENDPOINT,
                payload={
                    'isManaged': False
                }
            )
        )

    def put_schema(self, name: str, definition: str, revision: int,  # pylint: disable=too-many-arguments
                   description: str, reference_url: str) -> Tuple[bool, dict]:
        """
        Update a custom schema
        """
        return self._invoke(
            self._create_lambda_request(
                endpoint=self._PUT_SCHEMA_ENDPOINT,
                payload=dict(
                    name=name,
                    referenceURL=reference_url,
                    description=description,
                    spec=definition,
                    revision=revision,
                )
            )
        )

    def _invoke(self, request: dict) -> Tuple[bool, dict]:
        response = self.lambda_client.invoke(**request)
        response = json.loads(response["Payload"].read().decode("utf-8"))
        api_error = response.get("error")
        if api_error is not None:
            return False, response
        return True, response

    def _create_lambda_request(self, endpoint: str, payload: dict) -> dict:
        return dict(
            FunctionName=self._LAMBDA_NAME,
            InvocationType="RequestResponse",
            Payload=json.dumps({endpoint: payload})
        )


@dataclass
class UploaderResult:
    filename: str
    name: Optional[str]
    api_response: Optional[Dict[str, Any]] = None
    definition: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    existed: Optional[bool] = None


@dataclass
class ProcessedFile:
    error: Optional[str] = None
    raw: str = ''
    yaml: Optional[Dict[str, Any]] = None


class Uploader:
    _SCHEMA_NAME_PREFIX = 'Custom.'

    def __init__(self, path: str):
        self._path = path
        self._files: Optional[List[str]] = None
        self._api_client: Optional[Client] = None
        self._existing_schemas: Optional[List[Dict[str, Any]]] = None

    @property
    def api_client(self) -> Client:
        if self._api_client is None:
            self._api_client = Client()
        return self._api_client

    @property
    def files(self) -> List[str]:
        if self._files is None:
            self._files = discover_files(self._path)
        return self._files

    @property
    def existing_schemas(self) -> List[Dict[str, Any]]:
        if self._existing_schemas is None:
            success, response = self.api_client.list_schemas()
            if not success:
                raise RuntimeError('unable to retrieve custom schemas')
            self._existing_schemas = response['results']
        return self._existing_schemas

    def find_schema(self, name: str) -> Optional[Dict[str, Any]]:
        for schema in self.existing_schemas:
            if schema['name'] == name:
                return schema
        return None

    def process(self) -> List[UploaderResult]:
        if not self.files:
            return []

        processed_files = self._load_from_yaml(self.files)
        results = []
        for filename, processed_file in processed_files.items():
            if processed_file.error is not None:
                results.append(
                    UploaderResult(
                        name=None,
                        filename=filename,
                        error=processed_file.error,
                    )
                )

        for filename, processed_file in processed_files.items():
            if processed_file.error is not None:
                continue

            name, error = self._extract_schema_name(processed_file.yaml)
            result = UploaderResult(filename=filename, name=name)

            result.name = name
            result.error = error
            if not result.error:
                existed, success, response = self._update_or_create_schema(name, processed_file)
                result.existed = existed
                if not success:
                    api_error = response.get('error')
                    if api_error is not None:
                        result.error = f'failure to update schema {name}: ' \
                                       f'code={api_error["code"]}, message={api_error["message"]}'
                result.api_response = response
            results.append(result)
        return results

    @staticmethod
    def _load_from_yaml(files: List[str]) -> Dict[str, ProcessedFile]:
        yaml_parser = YAML(typ="safe")

        processed_files = {}
        for filename in files:
            logger.info('Processing schema in file %s', filename)
            processed_file = ProcessedFile()
            processed_files[filename] = processed_file
            try:
                with open(filename, "r") as schema_file:
                    processed_file.raw = schema_file.read()
                processed_file.yaml = yaml_parser.load(processed_file.raw)
            except (ParserError, ScannerError) as exc:
                processed_file.error = f"invalid YAML: {exc}"
        return processed_files

    def _extract_schema_name(
            self,
            definition: Optional[Dict[str, Any]]
    ) -> Tuple[str, Optional[str]]:
        if definition is None:
            raise ValueError('definition cannot be None')

        name = definition.get('schema')

        if name is None:
            return "", "key 'schema' not found"

        if not name.startswith(self._SCHEMA_NAME_PREFIX):
            return "", f"'schema' field: value must start" \
                       f" with the prefix '{self._SCHEMA_NAME_PREFIX}'"

        return name, None

    def _update_or_create_schema(
            self,
            name: str,
            processed_file: ProcessedFile
    ) -> Tuple[bool, bool, Dict[str, Any]]:
        existing_schema = self.find_schema(name)
        current_reference_url = ''
        current_description = ''
        current_revision = 0
        definition = cast(Dict[str, Any], processed_file.yaml)
        existed = False
        if existing_schema is not None:
            existing_schema = cast(Dict[str, Any], existing_schema)
            existed = True
            current_reference_url = existing_schema.get('referenceURL', '')
            current_description = existing_schema.get('description', '')
            current_revision = existing_schema['revision']
        reference_url = definition.get('referenceURL', current_reference_url)
        description = definition.get('description', current_description)
        logger.debug('updating schema %s at revision %d, using '
                     'referenceURL=%s, '
                     'description=%s',
                     name,
                     current_revision,
                     reference_url,
                     description)
        success, response = self.api_client.put_schema(
            name=name,
            definition=processed_file.raw,
            revision=current_revision,
            reference_url=reference_url,
            description=description,
        )
        return existed, success, response


def discover_files(base_path: str, pattern: str = '*.yml') -> List[str]:
    files = []
    for directory, _, filenames in os.walk(base_path):
        for filename in filenames:
            if fnmatch.fnmatch(filename, pattern):
                files.append(os.path.join(directory, filename))
    return sorted(files)


def normalize_path(path: str) -> Optional[str]:
    """Resolve the given path to its absolute form, taking into
    account user home prefix notation.
    Returns:
        The absolute path or None if the path does not exist.
    """
    absolute_path = os.path.abspath(os.path.expanduser(path))
    if not os.path.exists(absolute_path):
        return None
    return absolute_path


def report_summary(base_path: str, results: List[UploaderResult]) -> List[Tuple[bool, str]]:
    """
    Translate uploader results to descriptive status messages.

    Returns:
         A list of status messages along with the corresponding status flag for each message.
         Failure messages are flagged with True.
    """
    summary = []
    for result in sorted(results, key=lambda r: r.filename):
        filename = result.filename.split(base_path)[-1].strip(os.path.sep)
        if result.error:
            summary.append((True, f"Failed to update schema from definition"
                                  f" in file '{filename}': {result.error}"))
        else:
            if result.existed:
                operation = 'updated'
            else:
                operation = 'created'
            summary.append((False, f"Successfully {operation} schema '{result.name}' "
                                   f"from definition in file '{filename}'"))
    return summary
