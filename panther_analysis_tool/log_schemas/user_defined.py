import fnmatch
import json
import logging
import os

import boto3
from ruamel.yaml import YAML
from ruamel.yaml.scanner import ScannerError
from ruamel.yaml.parser import ParserError


logger = logging.getLogger(__file__)


class Uploader:
    _SCHEMA_NAME_PREFIX = 'Custom.'

    def __init__(self, path: str):
        self._path = path
        self._files = None
        self._api_client = None
        self._existing_schemas = None

    @property
    def api_client(self):
        if self._api_client is None:
            self._api_client = Client()
        return self._api_client

    @property
    def files(self):
        if self._files is None:
            self._files = discover_files(self._path)
        return self._files

    @property
    def existing_schemas(self):
        if self._existing_schemas is None:
            success, response = self.api_client.list_schemas()
            if not success:
                raise RuntimeError('unable to retrieve custom schemas')
            self._existing_schemas = response['results']
        return self._existing_schemas

    def find_schema(self, name: str):
        for schema in self.existing_schemas:
            if schema['name'] == name:
                return schema

    def process(self):
        if not self.files:
            return

        processed_files = self._load_from_yaml(self.files)
        results = []
        for filename, processed_file in processed_files.items():
            if processed_file['error'] is not None:
                results.append({'filename': filename,
                                'error': processed_file['error'],
                                'api_response': None,
                                'name': None,
                                'definition': None})

        for filename, processed_file in processed_files.items():
            if processed_file['error'] is not None:
                continue

            definition = processed_file['yaml']
            name, error = self._extract_schema_name(definition)

            if error is not None:
                processed_file['error'] = error

            response = None
            if not processed_file['error']:
                existing_schema = self.find_schema(name)
                current_reference_url = ''
                current_description = ''
                current_revision = 0
                if existing_schema is not None:
                    current_reference_url = existing_schema.get('referenceURL')
                    current_description = existing_schema.get('description')
                    current_revision = existing_schema['revision']
                reference_url = definition.get('referenceURL', current_reference_url)
                description = definition.get('description', current_description)
                logger.debug(f'updating schema {name} at revision {current_revision}, using '
                             f'referenceURL={reference_url}, '
                             f'description={description}')
                success, response = self.api_client.put_schema(
                    name=name,
                    definition=processed_file['raw'],
                    revision=current_revision,
                    reference_url=reference_url,
                    description=description,
                )
                if not success:
                    api_error = response.get('error')
                    if api_error is not None:
                        processed_file['error'] = f'failure to update schema {name}: ' \
                                                  f'code={api_error["code"]}, message={api_error["message"]}'
            results.append({'filename': filename,
                            'error': processed_file['error'],
                            'api_response': response,
                            'name': name,
                            'definition': definition})
        return results

    def _extract_schema_name(self, definition):
        name = definition.get('schema')

        if name is None:
            return None, "key 'schema' not found"

        if not name.startswith(self._SCHEMA_NAME_PREFIX):
            return None, f"'schema' field: value must start with the prefix '{self._SCHEMA_NAME_PREFIX}'"

        return name, None

    @staticmethod
    def _load_from_yaml(files):
        yaml_parser = YAML(typ="safe")

        processed_files = {}
        for filename in files:
            logger.info(f'processing schema in file {filename}')
            processed_file = {'raw': None, 'yaml': None, 'error': None}
            processed_files[filename] = processed_file
            try:
                with open(filename, "r") as f:
                    processed_file['raw'] = f.read()
                processed_file['yaml'] = yaml_parser.load(processed_file['raw'])
            except (ParserError, ScannerError) as exc:
                processed_file['error'] = f"invalid YAML: {exc}"
        return processed_files


class Client:
    _LAMBDA_NAME = 'panther-logtypes-api'
    _LIST_SCHEMAS_ENDPOINT = 'ListSchemas'
    _PUT_SCHEMA_ENDPOINT = 'PutUserSchema'

    def __init__(self):
        self._lambda_client = None

    @property
    def lambda_client(self):
        if self._lambda_client is None:
            self._lambda_client = boto3.client("lambda")
        return self._lambda_client

    def list_schemas(self):
        return self._invoke(
            self._create_lambda_request(
                endpoint=self._LIST_SCHEMAS_ENDPOINT,
                payload={
                    'isManaged': False
                }
            )
        )

    def put_schema(self, name, definition, revision, description, reference_url):
        """
        Update a custom schema

        :param definition:
        :param revision:
        :return:
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

    def _invoke(self, request: dict) -> (bool, dict):
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


def discover_files(base_path: str, pattern: str = '*.yml'):
    files = []
    for directory, _, filenames in os.walk(base_path):
        for filename in filenames:
            if fnmatch.fnmatch(filename, pattern):
                files.append(os.path.join(directory, filename))
    return sorted(files)


def normalize_path(path):
    absolute_path = os.path.abspath(os.path.expanduser(path))
    if not os.path.exists(absolute_path):
        return
    return absolute_path


def report_summary(base_path, results):
    summary = []
    for result in sorted(results, key=lambda f: f['filename']):
        filename = result['filename'].split(base_path)[-1].strip(os.path.sep)
        if result['error']:
            summary.append((True, f"Failed to update schema from definition"
                                  f" in file '{filename}': {result['error']}"))
        else:
            summary.append((False, f"Successfully updated schema '{result['name']}' "
                                   f"from definition in file '{filename}'"))
    return summary
