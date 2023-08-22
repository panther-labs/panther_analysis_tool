import os
import unittest
from unittest import mock
from unittest.mock import MagicMock, create_autospec

from panther_analysis_tool.backend.client import (
    BackendResponse,
    Client,
    ListSchemasResponse,
    Schema,
    UpdateSchemaParams,
    UpdateSchemaResponse,
)
from panther_analysis_tool.backend.mocks import MockBackend
from panther_analysis_tool.log_schemas import user_defined

FIXTURES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../", "fixtures"))


class TestUtilities(unittest.TestCase):
    def test_report_summary(self):
        summary = user_defined.report_summary(
            "/a/b/schemas",
            [
                user_defined.UploaderResult(
                    error="yaml.scanner.ScannerError: mapping values are not allowed here",
                    filename="/a/b/schemas/s1.yml",
                    name=None,
                )
            ],
        )
        self.assertListEqual(
            summary,
            [
                (
                    True,
                    "Failed to update schema from definition in file 's1.yml': "
                    "yaml.scanner.ScannerError: mapping values are not allowed here",
                )
            ],
        )

    def test_discover_files(self):
        path = os.path.join(FIXTURES_PATH, "custom-schemas", "valid")
        files = user_defined.discover_files(path, user_defined.Uploader._SCHEMA_FILE_GLOB_PATTERNS)
        self.assertListEqual(
            files,
            [
                os.path.join(path, "lookup-table-schema-1.yml"),
                os.path.join(path, "schema-1.yml"),
                os.path.join(path, "schema-2.yaml"),
                os.path.join(path, "schema-3.yml"),
                os.path.join(path, "schema_1_tests.yml"),
            ],
        )

    def test_ignore_schema_test_files(self):
        base_path = os.path.join(FIXTURES_PATH, "custom-schemas", "valid")
        schema_files = ["lookup-table-schema-1.yml", "schema-1.yml", "schema-2.yml", "schema-3.yml"]
        schema_test_files = ["schema_1_tests.yml"]

        all_files = [
            os.path.join(base_path, filename) for filename in schema_files + schema_test_files
        ]
        self.assertListEqual(
            user_defined.ignore_schema_test_files(all_files), all_files[: len(schema_files)]
        )

    def test_normalize_path(self):
        # If path does not exist
        self.assertIsNone(user_defined.normalize_path("some-random-path"))
        self.assertTrue(user_defined.normalize_path(".").endswith(os.path.abspath(".")))


class TestUploader(unittest.TestCase):
    def setUp(self) -> None:
        self.valid_schema_path = os.path.join(FIXTURES_PATH, "custom-schemas/valid")
        self.invalid_schema_path = os.path.join(FIXTURES_PATH, "custom-schemas/invalid")

        with open(os.path.join(self.valid_schema_path, "lookup-table-schema-1.yml")) as f:
            self.valid_schema0 = f.read()

        with open(os.path.join(self.valid_schema_path, "schema-1.yml")) as f:
            self.valid_schema1 = f.read()

        with open(os.path.join(self.valid_schema_path, "schema-2.yaml")) as f:
            self.valid_schema2 = f.read()

        with open(os.path.join(self.valid_schema_path, "schema-3.yml")) as f:
            self.valid_schema3 = f.read()

        self.list_schemas_response = BackendResponse(
            status_code=200,
            data=ListSchemasResponse(
                schemas=[
                    Schema(
                        created_at="2021-05-11T14:08:08.42627193Z",
                        description="A verbose description",
                        is_managed=False,
                        name="Custom.AWSAccountIDs",
                        reference_url="https://example.com",
                        revision=17,
                        spec=self.valid_schema0,
                        updated_at="2021-05-14T12:05:13.928862479Z",
                        field_discovery_enabled=False,
                    ),
                    Schema(
                        created_at="2021-05-11T14:08:08.42627193Z",
                        description="A verbose description",
                        is_managed=False,
                        name="Custom.SampleSchema1",
                        reference_url="https://example.com",
                        revision=17,
                        spec=self.valid_schema1,
                        updated_at="2021-05-14T12:05:13.928862479Z",
                        field_discovery_enabled=False,
                    ),
                    Schema(
                        created_at="2021-05-11T14:08:08.42627193Z",
                        description="A verbose description",
                        is_managed=False,
                        name="Custom.SampleSchema2",
                        reference_url="https://example.com",
                        revision=17,
                        spec=self.valid_schema2,
                        updated_at="2021-05-14T12:05:13.928862479Z",
                        field_discovery_enabled=False,
                    ),
                    Schema(
                        created_at="2021-05-11T14:08:08.42627193Z",
                        description="A verbose description",
                        is_managed=False,
                        name="Custom.Sample.Schema3",
                        reference_url="https://example.com",
                        revision=17,
                        spec=self.valid_schema3,
                        updated_at="2021-05-14T12:05:13.928862479Z",
                        field_discovery_enabled=True,
                    ),
                ]
            ),
        )
        self.put_schema_response = lambda: Schema(
            name="Custom.SampleSchema1",
            revision=0,
            updated_at="2021-05-17T10:34:18.192993496Z",
            created_at="2021-05-17T10:15:38.18907328Z",
            is_managed=False,
            reference_url="https://github.com/random",
            spec="",
            field_discovery_enabled=False,
        )
        self.put_schema_response2 = lambda: {
            "record": {
                "name": "Custom.SampleSchema1",
                "revision": 0,
                "updatedAt": "2021-05-17T10:34:18.192993496Z",
                "createdAt": "2021-05-17T10:15:38.18907328Z",
                "managed": False,
                "disabled": False,
                "referenceURL": "https://github.com/random",
                "spec": "",
                "active": False,
                "native": False,
                "fieldDiscoveryEnabled": False,
            }
        }

    def test_existing_schemas(self):
        backend = MockBackend()
        backend.list_schemas = mock.MagicMock(return_value=self.list_schemas_response)
        uploader = user_defined.Uploader(self.valid_schema_path, backend)
        self.assertListEqual(uploader.existing_schemas, self.list_schemas_response.data.schemas)
        backend.list_schemas.assert_called_once()

    def test_existing_schemas_empty_results_from_backend(self):
        backend = MockBackend()
        backend.list_schemas = mock.MagicMock(
            return_value=BackendResponse(status_code=200, data=ListSchemasResponse(schemas=[]))
        )

        uploader = user_defined.Uploader(self.valid_schema_path, backend)
        self.assertListEqual(uploader.existing_schemas, [])
        backend.list_schemas.assert_called_once()

    def test_find_schema(self):
        backend = MockBackend()
        backend.list_schemas = mock.MagicMock(return_value=self.list_schemas_response)
        uploader = user_defined.Uploader(self.valid_schema_path, backend)
        self.assertEqual(
            uploader.find_schema("Custom.SampleSchema2"), self.list_schemas_response.data.schemas[2]
        )
        self.assertIsNone(uploader.find_schema("unknown-schema"))
        backend.list_schemas.assert_called_once()

    def test_files(self):
        uploader = user_defined.Uploader(self.valid_schema_path, None)
        self.assertListEqual(
            uploader.files,
            [
                os.path.join(self.valid_schema_path, "lookup-table-schema-1.yml"),
                os.path.join(self.valid_schema_path, "schema-1.yml"),
                os.path.join(self.valid_schema_path, "schema-2.yaml"),
                os.path.join(self.valid_schema_path, "schema-3.yml"),
            ],
        )

    def test_process(self):
        backend = MockBackend()
        backend.list_schemas = mock.MagicMock(return_value=self.list_schemas_response)

        put_schema_responses = []
        for response in self.list_schemas_response.data.schemas:
            put_schema_responses.append(
                UpdateSchemaResponse(
                    schema=Schema(
                        name=response.name,
                        revision=response.revision + 1,
                        updated_at="2021-05-17T10:34:18.192993496Z",
                        created_at="2021-05-17T10:15:38.18907328Z",
                        is_managed=False,
                        reference_url="https://github.com/random",
                        spec="",
                        description="",
                        field_discovery_enabled=response.field_discovery_enabled,
                    )
                )
            )

        backend.update_schema = mock.MagicMock(side_effect=put_schema_responses)
        uploader = user_defined.Uploader(self.valid_schema_path, backend)
        results = uploader.process()
        self.assertEqual(len(results), 4)
        self.assertListEqual(
            [r.name for r in results],
            [
                "Custom.AWSAccountIDs",
                "Custom.SampleSchema1",
                "Custom.SampleSchema2",
                "Custom.Sample.Schema3",
            ],
        )

        my_mock_call = backend.update_schema.call_count
        self.assertEqual(my_mock_call, 4)

        self.assertListEqual([r.existed for r in results], [True, True, True, True])
        self.assertEqual(backend.update_schema.call_count, 4)
        backend.update_schema.assert_has_calls(
            [
                mock.call(
                    params=UpdateSchemaParams(
                        name="Custom.AWSAccountIDs",
                        spec=self.valid_schema0,
                        description="Sample Lookup Table Schema 1",
                        reference_url="https://runpanther.io",
                        revision=17,
                        field_discovery_enabled=False,
                    )
                )
            ]
        )

        backend.update_schema.assert_has_calls(
            [
                mock.call(
                    params=UpdateSchemaParams(
                        name="Custom.Sample.Schema3",
                        spec=self.valid_schema3,
                        description="Sample Schema 3",
                        reference_url="https://runpanther.io",
                        revision=17,
                        field_discovery_enabled=True,
                    )
                )
            ]
        )
