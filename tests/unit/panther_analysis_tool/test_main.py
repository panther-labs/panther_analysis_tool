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

from datetime import datetime
import os
import shutil

from pyfakefs.fake_filesystem_unittest import TestCase, Pause

from schema import SchemaWrongKeyError
from nose.tools import assert_equal, assert_is_instance, assert_true, assert_false

from panther_analysis_tool import main as pat
from panther_analysis_tool.data_model import _DATAMODEL_FOLDER
from panther_analysis_tool.main import validate_outputs

FIXTURES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../', 'fixtures'))
DETECTIONS_FIXTURES_PATH = os.path.join(FIXTURES_PATH, 'detections')

print('Using fixtures path:', FIXTURES_PATH)


class TestPantherAnalysisTool(TestCase):
    def setUp(self):
        # Data Models write the source code to a file and import it as module.
        # This will not work if we are simply writing on the in-memory, fake filesystem.
        # We thus copy to a temporary space the Data Model Python modules.
        self.data_model_modules = [os.path.join(DETECTIONS_FIXTURES_PATH,
                                                'valid_analysis/data_models/GSuite.Events.DataModel.py')]
        for data_model_module in self.data_model_modules:
            shutil.copy(data_model_module, _DATAMODEL_FOLDER)

        self.setUpPyfakefs()
        self.fs.add_real_directory(FIXTURES_PATH)

    def tearDown(self) -> None:
        with Pause(self.fs):
            for data_model_module in self.data_model_modules:
                os.remove(os.path.join(_DATAMODEL_FOLDER, os.path.split(data_model_module)[-1]))

    def test_valid_json_policy_spec(self):
        for spec_filename, _, loaded_spec, _ in pat.load_analysis_specs([DETECTIONS_FIXTURES_PATH]):
            if spec_filename.endswith('example_policy.json'):
                assert_is_instance(loaded_spec, dict)
                assert_true(loaded_spec != {})

    def test_valid_yaml_policy_spec(self):
        for spec_filename, _, loaded_spec, _ in pat.load_analysis_specs([DETECTIONS_FIXTURES_PATH]):
            if spec_filename.endswith('example_policy.yml'):
                assert_is_instance(loaded_spec, dict)
                assert_true(loaded_spec != {})

    def test_valid_pack_spec(self):
        pack_loaded = False
        for spec_filename, _, loaded_spec, _ in pat.load_analysis_specs([DETECTIONS_FIXTURES_PATH]):
            if spec_filename.endswith('sample-pack.yml'):
                assert_is_instance(loaded_spec, dict)
                assert_true(loaded_spec != {})
                pack_loaded = True
        assert_true(pack_loaded)

    def test_datetime_converted(self):
        test_date = datetime.now()
        test_date_string = pat.datetime_converted(test_date)
        assert_is_instance(test_date_string, str)

    def test_handle_wrong_key_error(self):
        sample_keys = ['DisplayName', 'Enabled', 'Filename']
        expected_output = '{} not in list of valid keys: {}'
        # test successful regex match and correct error returned
        test_str = "Wrong key 'DisplaName' in {'DisplaName':'one','Enabled':true, 'Filename':'sample'}"
        exc = SchemaWrongKeyError(test_str)
        err = pat.handle_wrong_key_error(exc, sample_keys)
        assert_equal(str(err), expected_output.format("'DisplaName'", sample_keys))
        # test failing regex match
        test_str = "Will not match"
        exc = SchemaWrongKeyError(test_str)
        err = pat.handle_wrong_key_error(exc, sample_keys)
        assert_equal(str(err),  expected_output.format("UNKNOWN_KEY", sample_keys))

    def test_load_policy_specs_from_folder(self):
        args = pat.setup_parser().parse_args(f'test --path {DETECTIONS_FIXTURES_PATH}'.split())
        args.filter_inverted = {}
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)
        assert_equal(invalid_specs[0][0],
                     f'{DETECTIONS_FIXTURES_PATH}/example_malformed_policy.yml')
        assert_equal(len(invalid_specs), 10)

    def test_policies_from_folder(self):
        args = pat.setup_parser().parse_args(f'test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis/policies'.split())
        args.filter_inverted = {}
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_rules_from_folder(self):
        args = pat.setup_parser().parse_args(f'test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis/rules'.split())
        args.filter_inverted = {}
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_queries_from_folder(self):
        args = pat.setup_parser().parse_args(f'test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis/queries'.split())
        args.filter_inverted = {}
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_scheduled_rules_from_folder(self):
        args = pat.setup_parser().parse_args(f'test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis/scheduled_rules'.split())
        args.filter_inverted = {}
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_rules_from_current_dir(self):
        # This is a work around to test running tool against current directory
        return_code = -1
        invalid_specs = None
        valid_rule_path = os.path.join(DETECTIONS_FIXTURES_PATH, 'valid_analysis/policies')
        # test default path, '.'
        with Pause(self.fs):
            original_path = os.getcwd()
            try:
                os.chdir(valid_rule_path)
                args = pat.setup_parser().parse_args('test'.split())
                args.filter_inverted = {}
                return_code, invalid_specs = pat.test_analysis(args)
            finally:
                os.chdir(original_path)
        # asserts are outside of the pause to ensure the fakefs gets resumed
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)
        return_code = -1
        invalid_specs = None
        # test explicitly setting current dir
        with Pause(self.fs):
            original_path = os.getcwd()
            os.chdir(valid_rule_path)
            args = pat.setup_parser().parse_args('test --path ./'.split())
            args.filter_inverted = {}
            return_code, invalid_specs = pat.test_analysis(args)
            os.chdir(original_path)
        # asserts are outside of the pause to ensure the fakefs gets resumed
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_parse_filters(self):
        args = pat.setup_parser().parse_args(f'test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --filter AnalysisType=policy,global Severity=Critical'.split())
        args.filter, args.filter_inverted = pat.parse_filter(args.filter)
        assert_true('AnalysisType' in args.filter.keys())
        assert_true('policy' in args.filter['AnalysisType'])
        assert_true('global' in args.filter['AnalysisType'])
        assert_true('Severity' in args.filter.keys())
        assert_true('Critical' in args.filter['Severity'])

    def test_with_filters(self):
        args = pat.setup_parser().parse_args(
            f'test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --filter AnalysisType=policy,global'.split())
        args.filter, args.filter_inverted = pat.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_aws_profiles(self):
        aws_profile = 'AWS_PROFILE'
        args = pat.setup_parser().parse_args(
            f'upload --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --aws-profile myprofile'.split())
        pat.set_env(aws_profile, args.aws_profile)
        assert_equal('myprofile', args.aws_profile)
        assert_equal(args.aws_profile, os.environ.get(aws_profile))

    def test_invalid_rule_definition(self):
        args = pat.setup_parser().parse_args(
            f'test --path {DETECTIONS_FIXTURES_PATH} --filter RuleID=AWS.CloudTrail.MFAEnabled'.split())
        args.filter, args.filter_inverted = pat.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)
        assert_equal(len(invalid_specs), 7)

    def test_invalid_rule_test(self):
        args = pat.setup_parser().parse_args(
            f'test --path {DETECTIONS_FIXTURES_PATH} --filter RuleID=Example.Rule.Invalid.Test'.split())
        args.filter, args.filter_inverted = pat.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)
        assert_equal(len(invalid_specs), 7)

    def test_invalid_characters(self):
        args = pat.setup_parser().parse_args(
            f'test --path {DETECTIONS_FIXTURES_PATH} --filter Severity=High ResourceTypes=AWS.IAM.User'.split())
        args.filter, args.filter_inverted = pat.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)
        assert_equal(len(invalid_specs), 8)

    def test_unknown_exception(self):
        args = pat.setup_parser().parse_args(
            f'test --path {DETECTIONS_FIXTURES_PATH} --filter RuleID=Example.Rule.Unknown.Exception'.split())
        args.filter, args.filter_inverted = pat.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)
        assert_equal(len(invalid_specs), 7)

    def test_with_invalid_mocks(self):
        args = pat.setup_parser().parse_args(
            f'test --path {DETECTIONS_FIXTURES_PATH} --filter Severity=Critical RuleID=Example.Rule.Invalid.Mock'.split())
        args.filter, args.filter_inverted = pat.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)
        assert_equal(len(invalid_specs), 7)

    def test_validate_outputs(self):
        example_valid_outputs = [
            ("dedup", "example title"),
            ("title", "example title"),
            ("description", "example description"),
            ("reference", "example reference"),
            ("severity", "CRITICAL"),
            ("runbook", "example runbook"),
            ("destinations", ["example destination"]),
            ("destinations", []),
        ]
        example_invalid_outputs = [
            ("dedup", None),
            ("title", None),
            ("description", None),
            ("reference", None),
            ("severity", "CRITICAL-ISH"),
            ("severity", None),
            ("runbook", None),
            ("destinations", ""),
            ("destinations", ["", None]),
        ]
        invalid = False
        for valid_invalid_outputs in [example_valid_outputs, example_invalid_outputs]:
            for each_example in valid_invalid_outputs:
                result = validate_outputs(each_example[0], each_example[1])
                if invalid:
                    assert_false(result[0])
                    assert_false(result[1] == each_example[1])
                else:
                    assert_true(result[0])
                    assert_equal(result[1], each_example[1])
            invalid = True

    def test_with_tag_filters(self):
        args = pat.setup_parser().parse_args(
            f'test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --filter Tags=AWS,CIS'.split())
        args.filter, args.filter_inverted = pat.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_with_tag_filters_inverted(self):
        # Note: a comparison of the tests passed is required to make this test robust
        # (8 passing vs 1 passing)
        args = pat.setup_parser().parse_args(
            f'test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --filter Tags=AWS,CIS Tags!=SOC2'.split())
        args.filter, args.filter_inverted = pat.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_with_minimum_tests(self):
        args = pat.setup_parser().parse_args(
            f'test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --minimum-tests 1'.split())
        args.filter_inverted = {}
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_with_minimum_tests_failing(self):
        args = pat.setup_parser().parse_args(
            f'test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --minimum-tests 2'.split())
        args.filter_inverted = {}
        return_code, invalid_specs = pat.test_analysis(args)
        # Failing, because some of the fixtures only have one test case
        assert_equal(return_code, 1)
        assert_equal(len(invalid_specs), 0)

    def test_with_minimum_tests_no_passing(self):
        args = pat.setup_parser().parse_args(
            f'test --path {DETECTIONS_FIXTURES_PATH} --filter PolicyID=IAM.MFAEnabled.Required.Tests --minimum-tests 2'.split())
        args.filter, args.filter_inverted = pat.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        # Failing, because while there are two unit tests they both have expected result False
        assert_equal(return_code, 1)
        assert_equal(len(invalid_specs), 7)

    def test_invalid_resource_type(self):
        args = pat.setup_parser().parse_args(
            f'test --path {DETECTIONS_FIXTURES_PATH} --filter PolicyID=Example.Bad.Resource.Type'.split())
        args.filter, args.filter_inverted = pat.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)
        assert_equal(len(invalid_specs), 7)

    def test_invalid_log_type(self):
        args = pat.setup_parser().parse_args(
            f'test --path {DETECTIONS_FIXTURES_PATH} --filter RuleID=Example.Bad.Log.Type'.split())
        args.filter, args.filter_inverted = pat.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)
        self.equal = assert_equal(len(invalid_specs), 7)

    def test_zip_analysis(self):
        # Note: This is a workaround for CI
        try:
            self.fs.create_dir('tmp/')
        except OSError:
            pass

        args = pat.setup_parser().parse_args(
            f'zip --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --out tmp/'.split())
        return_code, out_filename = pat.zip_analysis(args)
        assert_true(out_filename.startswith("tmp/"))
        statinfo = os.stat(out_filename)
        assert_true(statinfo.st_size > 0)
        assert_equal(return_code, 0)
        assert_true(out_filename.endswith('.zip'))

    def test_generate_release_assets(self):
        # Note: This is a workaround for CI
        try:
            self.fs.create_dir('tmp/release/')
        except OSError:
            pass

        args = pat.setup_parser().parse_args(
            f'release --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --out tmp/release/'.split())
        return_code, _ = pat.generate_release_assets(args)
        analysis_file = 'tmp/release/panther-analysis-all.zip'
        statinfo = os.stat(analysis_file)
        assert_true(statinfo.st_size > 0)
        assert_equal(return_code, 0)

    def test_update_custom_schemas(self):
        from panther_analysis_tool.log_schemas.user_defined import Client
        from unittest import mock
        import logging

        # If path does not exist, exits with failure code
        args = pat.setup_parser().parse_args(
            f'update-custom-schemas --path _unknown_path_/'.split()
        )
        return_code, _ = pat.update_custom_schemas(args)
        self.assertEqual(return_code, 1)

        # If path exists and contains valid YAML files
        schema_path = os.path.join(FIXTURES_PATH, 'custom-schemas/valid')
        args = pat.setup_parser().parse_args(
            f'update-custom-schemas --path {schema_path}'.split()
        )

        with mock.patch('panther_analysis_tool.log_schemas.user_defined.Uploader') as mock_uploader:
            _, _ = pat.update_custom_schemas(args)
            mock_uploader.assert_called_once_with(f'{FIXTURES_PATH}/custom-schemas/valid')

        with open(os.path.join(schema_path, 'schema-1.yml')) as f:
            schema1 = f.read()

        with open(os.path.join(schema_path, 'schema-2.yaml')) as f:
            schema2 = f.read()

        with mock.patch.multiple(logging, error=mock.DEFAULT, info=mock.DEFAULT) as mocks:
            with mock.patch('panther_analysis_tool.log_schemas.user_defined.Uploader.api_client', autospec=Client) \
                    as mock_uploader_client:
                mock_uploader_client.list_schemas = mock.MagicMock(
                    return_value=(
                        True,
                        {
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
                                    'spec': schema1,
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
                                    'spec': schema2,
                                    'active': False,
                                    'native': False
                                }
                            ]
                        }
                    )
                )
                mock_uploader_client.put_schema = mock.MagicMock(return_value=(True, {'results': []}))
                return_code, _ = pat.update_custom_schemas(args)
                self.assertEqual(return_code, 0)
                mocks['error'].assert_not_called()
                self.assertEqual(mocks['info'].call_count, 2)

        with mock.patch.multiple(logging, error=mock.DEFAULT, info=mock.DEFAULT) as mocks:
            with mock.patch('panther_analysis_tool.log_schemas.user_defined.Uploader.api_client', autospec=Client) \
                    as mock_uploader_client:
                mock_uploader_client.list_schemas = mock.MagicMock(
                    return_value=(True, {'results': []})
                )
                mock_uploader_client.put_schema = mock.MagicMock(
                    return_value=(True, {'results': []})
                )
                # If path exists and does not contain valid YAML files
                schema_path = os.path.join(FIXTURES_PATH, 'custom-schemas/invalid')
                args = pat.setup_parser().parse_args(
                    f'update-custom-schemas --path {schema_path}'.split()
                )
                return_code, _ = pat.update_custom_schemas(args)
                self.assertEqual(return_code, 1)
                self.assertEqual(mocks['info'].call_count, 1)
                self.assertEqual(mocks['error'].call_count, 1)

