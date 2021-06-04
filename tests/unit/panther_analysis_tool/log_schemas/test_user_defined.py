import os
import unittest
from unittest import mock

from panther_analysis_tool.log_schemas import user_defined


FIXTURES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../', 'fixtures'))


class TestUtilities(unittest.TestCase):
    def test_report_summary(self):
        summary = user_defined.report_summary(
            '/a/b/schemas',
            [user_defined.UploaderResult(
                error='yaml.scanner.ScannerError: mapping values are not allowed here',
                filename='/a/b/schemas/s1.yml',
                name=None,
            )]
        )
        self.assertListEqual(summary, [(
            True,
            "Failed to update schema from definition in file 's1.yml': "
            "yaml.scanner.ScannerError: mapping values are not allowed here")])

    def test_discover_files(self):
        path = os.path.join(FIXTURES_PATH, 'custom-schemas', 'valid')
        files = user_defined.discover_files(path, user_defined.Uploader._SCHEMA_FILE_GLOB_PATTERNS)
        self.assertListEqual(files, [os.path.join(path, 'schema-1.yml'),
                                     os.path.join(path, 'schema-2.yaml')])

    def test_normalize_path(self):
        # If path does not exist
        self.assertIsNone(user_defined.normalize_path('some-random-path'))
        self.assertTrue(
            user_defined.normalize_path('.').endswith(os.path.abspath('.'))
        )


class TestUploader(unittest.TestCase):
    def setUp(self) -> None:
        self.valid_schema_path = os.path.join(FIXTURES_PATH, 'custom-schemas/valid')
        self.invalid_schema_path = os.path.join(FIXTURES_PATH, 'custom-schemas/invalid')
        with open(os.path.join(self.valid_schema_path, 'schema-1.yml')) as f:
            self.valid_schema1 = f.read()

        with open(os.path.join(self.valid_schema_path, 'schema-2.yaml')) as f:
            self.valid_schema2 = f.read()

        self.list_schemas_response = {
            'results': [
                {
                    'name': 'Custom.SampleSchema1',
                    'revision': 17,
                    'updatedAt': '2021-05-14T12:05:13.928862479Z',
                    'createdAt': '2021-05-11T14:08:08.42627193Z',
                    'managed': False,
                    'disabled': True,
                    'description': 'A verbose description',
                    'referenceURL': 'https://example.com',
                    'spec': self.valid_schema1,
                    'active': False,
                    'native': False
                },
                {
                    'name': 'Custom.SampleSchema2',
                    'revision': 17,
                    'updatedAt': '2021-05-14T12:05:13.928862479Z',
                    'createdAt': '2021-05-11T14:08:08.42627193Z',
                    'managed': False,
                    'disabled': False,
                    'description': 'A verbose description',
                    'referenceURL': 'https://example.com',
                    'spec': self.valid_schema2,
                    'active': False,
                    'native': False
                }
            ]
        }
        self.put_schema_response = lambda: {
            'record': {
                'name': 'Custom.SampleSchema1',
                'revision': 0,
                'updatedAt': '2021-05-17T10:34:18.192993496Z',
                'createdAt': '2021-05-17T10:15:38.18907328Z',
                'managed': False,
                'disabled': False,
                'referenceURL': 'https://github.com/random',
                'spec': '',
                'active': False,
                'native': False
            }
        }

    def test_existing_schemas(self):
        with mock.patch('panther_analysis_tool.log_schemas.user_defined.Uploader.api_client',
                        autospec=user_defined.Client) as mock_uploader_client:
            mock_uploader_client.list_schemas = mock.MagicMock(
                return_value=(True, self.list_schemas_response)
            )
            uploader = user_defined.Uploader(self.valid_schema_path)
            self.assertListEqual(uploader.existing_schemas, self.list_schemas_response['results'])
            mock_uploader_client.list_schemas.assert_called_once()

    def test_find_schema(self):
        with mock.patch('panther_analysis_tool.log_schemas.user_defined.Uploader.existing_schemas',
                        self.list_schemas_response['results']):
            uploader = user_defined.Uploader(self.valid_schema_path)
            self.assertDictEqual(uploader.find_schema('Custom.SampleSchema2'),
                                 self.list_schemas_response['results'][1])
            self.assertIsNone(uploader.find_schema('unknown-schema'))

    def test_files(self):
        uploader = user_defined.Uploader(self.valid_schema_path)
        self.assertListEqual(
            uploader.files,
            [os.path.join(self.valid_schema_path, 'schema-1.yml'),
             os.path.join(self.valid_schema_path, 'schema-2.yaml')]
        )

    def test_process(self):
        with mock.patch('panther_analysis_tool.log_schemas.user_defined.Uploader.api_client',
                        autospec=user_defined.Client) as mock_uploader_client:
            mock_uploader_client.list_schemas = mock.MagicMock(
                return_value=(True, self.list_schemas_response)
            )
            put_schema_responses = []
            for response in self.list_schemas_response['results']:
                put_schema_response = self.put_schema_response()
                put_schema_response['record']['revision'] = response['revision'] + 1
                put_schema_response['record']['name'] = response['name']
                put_schema_responses.append((True, put_schema_response))

            # Empty spec field to verify uploaded data
            for response in self.list_schemas_response['results']:
                response['spec'] = ''

            mock_uploader_client.put_schema = mock.MagicMock(
                side_effect=put_schema_responses
            )
            uploader = user_defined.Uploader(self.valid_schema_path)
            results = uploader.process()
            self.assertEqual(len(results), 2)
            self.assertListEqual([r.name for r in results],
                                 ['Custom.SampleSchema1', 'Custom.SampleSchema2'])
            self.assertListEqual([r.existed for r in results], [True, True])
            self.assertEqual(mock_uploader_client.put_schema.call_count, 2)
            mock_uploader_client.put_schema.assert_has_calls(
              [
                  mock.call(
                      name="Custom.SampleSchema1",
                      definition=self.valid_schema1,
                      description='Sample Schema 1',
                      reference_url='https://runpanther.io',
                      revision=17
                  ),
                  mock.call(
                      name="Custom.SampleSchema2",
                      definition=self.valid_schema2,
                      description='Sample Schema 2',
                      reference_url='https://runpanther.io',
                      revision=17
                  ),
              ]
            )
