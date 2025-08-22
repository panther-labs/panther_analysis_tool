import io
import json
import os
import shutil
from datetime import datetime
from unittest import mock

import jsonschema
from colorama import Fore, Style
from panther_core.data_model import _DATAMODEL_FOLDER
from pyfakefs.fake_filesystem_unittest import Pause, TestCase
from schema import SchemaWrongKeyError

from panther_analysis_tool import main as pat
from panther_analysis_tool import util
from panther_analysis_tool.backend.client import (
    BackendError,
    BackendResponse,
    BulkUploadResponse,
    BulkUploadStatistics,
    BulkUploadValidateResult,
    BulkUploadValidateStatusResponse,
    GetRuleBodyParams,
    GetRuleBodyResponse,
    TestCorrelationRuleResponse,
    TranspileFiltersResponse,
    TranspileToPythonResponse,
    UnsupportedEndpointError,
)
from panther_analysis_tool.backend.mocks import MockBackend
from panther_analysis_tool.command import validate
from panther_analysis_tool.core import parse

FIXTURES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../", "fixtures"))
DETECTIONS_FIXTURES_PATH = os.path.join(FIXTURES_PATH, "detections")

print("Using fixtures path:", FIXTURES_PATH)


def _mock_invoke(**_kwargs):  # pylint: disable=C0103
    return {
        "Payload": io.BytesIO(
            json.dumps(
                {
                    "statusCode": 400,
                    "body": "another upload is in process",
                }
            ).encode("utf-8")
        ),
        "StatusCode": 400,
    }


class TestPantherAnalysisTool(TestCase):
    def setUp(self):
        # Data Models and Globals write the source code to a file and import it as module.
        # This will not work if we are simply writing on the in-memory, fake filesystem.
        # We thus copy to a temporary space the Data Model Python modules.

        # Ensure _DATAMODEL_FOLDER is a directory, not a file
        if os.path.exists(_DATAMODEL_FOLDER) and not os.path.isdir(_DATAMODEL_FOLDER):
            os.remove(_DATAMODEL_FOLDER)
        os.makedirs(_DATAMODEL_FOLDER, exist_ok=True)

        self.data_model_modules = [
            os.path.join(
                DETECTIONS_FIXTURES_PATH, "valid_analysis/data_models/GSuite.Events.DataModel.py"
            )
        ]
        for data_model_module in self.data_model_modules:
            shutil.copy(data_model_module, _DATAMODEL_FOLDER)
        os.makedirs(pat.TMP_HELPER_MODULE_LOCATION, exist_ok=True)
        self.global_modules = {
            "panther": os.path.join(
                DETECTIONS_FIXTURES_PATH, "valid_analysis/global_helpers/helpers.py"
            ),
            "a_helper": os.path.join(
                DETECTIONS_FIXTURES_PATH, "valid_analysis/global_helpers/a_helper.py"
            ),
            "b_helper": os.path.join(
                DETECTIONS_FIXTURES_PATH, "valid_analysis/global_helpers/b_helper.py"
            ),
        }
        for module_name, filename in self.global_modules.items():
            shutil.copy(filename, os.path.join(pat.TMP_HELPER_MODULE_LOCATION, f"{module_name}.py"))
        self.setUpPyfakefs()
        self.fs.add_real_directory(FIXTURES_PATH)
        self.fs.add_real_directory(pat.TMP_HELPER_MODULE_LOCATION, read_only=False)
        # jsonschema needs to be able to access '.../site-packages/jsonschema/schemas/vocabularies' to work
        self.fs.add_real_directory(jsonschema.__path__[0])

    def tearDown(self) -> None:
        with Pause(self.fs):
            for data_model_module in self.data_model_modules:
                file_path = os.path.join(_DATAMODEL_FOLDER, os.path.split(data_model_module)[-1])
                if os.path.exists(file_path):
                    os.remove(file_path)

    def test_valid_json_policy_spec(self):
        for spec_filename, _, loaded_spec, _ in pat.load_analysis_specs(
            [DETECTIONS_FIXTURES_PATH], ignore_files=[]
        ):
            if spec_filename.endswith("example_policy.json"):
                self.assertIsInstance(loaded_spec, dict)
                self.assertTrue(loaded_spec != {})

    def test_ignored_files_are_not_loaded(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/example_malformed_yaml --ignore-files {DETECTIONS_FIXTURES_PATH}/example_malformed_yaml.yml".split()
        )
        args.filter_inverted = {}
        return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 1)  # no specs throws error
        self.assertIn("Nothing to test in", invalid_specs[0])

    def test_valid_yaml_policy_spec(self):
        for spec_filename, _, loaded_spec, _ in pat.load_analysis_specs(
            [DETECTIONS_FIXTURES_PATH], ignore_files=[]
        ):
            if spec_filename.endswith("example_policy.yml"):
                self.assertIsInstance(loaded_spec, dict)
                self.assertTrue(loaded_spec != {})

    def test_valid_pack_spec(self):
        pack_loaded = False
        for spec_filename, _, loaded_spec, _ in pat.load_analysis_specs(
            [DETECTIONS_FIXTURES_PATH], ignore_files=[]
        ):
            if spec_filename.endswith("sample-pack.yml"):
                self.assertIsInstance(loaded_spec, dict)
                self.assertTrue(loaded_spec != {})
                pack_loaded = True
        self.assertTrue(pack_loaded)

    def test_datetime_converted(self):
        test_date = datetime.now()
        test_date_string = pat.datetime_converted(test_date)
        self.assertIsInstance(test_date_string, str)

    def test_handle_wrong_key_error(self):
        sample_keys = ["DisplayName", "Enabled", "Filename"]
        expected_output = "{} not in list of valid keys: {}"
        # test successful regex match and correct error returned
        test_str = (
            "Wrong key 'DisplaName' in {'DisplaName':'one','Enabled':true, 'Filename':'sample'}"
        )
        exc = SchemaWrongKeyError(test_str)
        err = pat.handle_wrong_key_error(exc, sample_keys)
        self.assertEqual(str(err), expected_output.format("'DisplaName'", sample_keys))
        # test failing regex match
        test_str = "Will not match"
        exc = SchemaWrongKeyError(test_str)
        err = pat.handle_wrong_key_error(exc, sample_keys)
        self.assertEqual(str(err), expected_output.format("UNKNOWN_KEY", sample_keys))

    def test_load_policy_specs_from_folder(self):
        args = pat.setup_parser().parse_args(f"test --path {DETECTIONS_FIXTURES_PATH}".split())
        args.filter_inverted = {}
        return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 1)
        self.assertEqual(
            invalid_specs[0][0], f"{DETECTIONS_FIXTURES_PATH}/example_malformed_policy.yml"
        )
        self.assertEqual(len(invalid_specs), 13)

    def test_policies_from_folder(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis/policies".split()
        )
        args.filter_inverted = {}
        return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_rules_from_folder(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis/rules".split()
        )
        args.filter_inverted = {}
        return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_queries_from_folder(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis/queries".split()
        )
        args.filter_inverted = {}
        return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_scheduled_rules_from_folder(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis/scheduled_rules".split()
        )
        args.filter_inverted = {}
        return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_rules_from_current_dir(self):
        # This is a work around to test running tool against current directory
        return_code = -1
        invalid_specs = None
        valid_rule_path = os.path.join(DETECTIONS_FIXTURES_PATH, "valid_analysis/policies")
        # test default path, '.'
        with Pause(self.fs):
            original_path = os.getcwd()
            try:
                os.chdir(valid_rule_path)
                args = pat.setup_parser().parse_args("test".split())
                args.filter_inverted = {}
                return_code, invalid_specs = pat.test_analysis(args)
            finally:
                os.chdir(original_path)
        # asserts are outside of the pause to ensure the fakefs gets resumed
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)
        return_code = -1
        invalid_specs = None
        # test explicitly setting current dir
        with Pause(self.fs):
            original_path = os.getcwd()
            os.chdir(valid_rule_path)
            args = pat.setup_parser().parse_args("test --path ./".split())
            args.filter_inverted = {}
            return_code, invalid_specs = pat.test_analysis(args)
            os.chdir(original_path)
        # asserts are outside of the pause to ensure the fakefs gets resumed
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_with_filters(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --filter AnalysisType=policy,global".split()
        )
        args.filter, args.filter_inverted = parse.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_enabled_filter(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/disabled_rule --filter Enabled=true".split()
        )
        args.filter, args.filter_inverted = parse.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_enabled_filter_inverted(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/disabled_rule --filter Enabled!=false".split()
        )
        args.filter, args.filter_inverted = parse.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_aws_profiles(self):
        aws_profile = "AWS_PROFILE"
        args = pat.setup_parser().parse_args(
            f"upload --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --aws-profile myprofile".split()
        )
        util.set_env(aws_profile, args.aws_profile)
        self.assertEqual("myprofile", args.aws_profile)
        self.assertEqual(args.aws_profile, os.environ.get(aws_profile))

    def test_invalid_rule_definition(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter RuleID=AWS.CloudTrail.MFAEnabled".split()
        )
        args.filter, args.filter_inverted = parse.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 9)

    def test_invalid_rule_test(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter RuleID=Example.Rule.Invalid.Test".split()
        )
        args.filter, args.filter_inverted = parse.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 9)

    def test_invalid_characters(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter Severity=High ResourceTypes=AWS.IAM.User".split()
        )
        args.filter, args.filter_inverted = parse.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 10)

    def test_unknown_exception(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter RuleID=Example.Rule.Unknown.Exception".split()
        )
        args.filter, args.filter_inverted = parse.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 9)

    def test_with_invalid_mocks(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter Severity=Critical RuleID=Example.Rule.Invalid.Mock".split()
        )
        args.filter, args.filter_inverted = parse.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 9)

    def test_with_tag_filters(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --filter Tags=AWS,CIS".split()
        )
        args.filter, args.filter_inverted = parse.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_with_tag_filters_inverted(self):
        # Note: a comparison of the tests passed is required to make this test robust
        # (8 passing vs 1 passing)
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --filter Tags=AWS,CIS Tags!=SOC2".split()
        )
        args.filter, args.filter_inverted = parse.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_with_test_names_filter(self):
        # Test that we can filter tests by name using --test-names
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --test-names 'True Event'".split()
        )
        args.filter_inverted = {}
        return_code, invalid_specs = pat.test_analysis(args)
        # Should pass because the specified test exists in the fixtures
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_with_test_names_filter_and_rule_filter(self):
        # Test combining rule filter with test name filter
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --filter RuleID=Example.Rule --test-names 'True Event'".split()
        )
        args.filter, args.filter_inverted = parse.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        # Should pass because we're filtering to a specific rule and test
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_with_test_names_filter_nonexistent_test(self):
        # Test with a test name that doesn't exist
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --test-names 'Nonexistent Test'".split()
        )
        args.filter_inverted = {}
        return_code, invalid_specs = pat.test_analysis(args)
        # Should still return 0 because no tests failing, just no tests matching the filter
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_with_minimum_tests(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --minimum-tests 1".split()
        )
        args.filter_inverted = {}
        return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_with_minimum_tests_failing(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --minimum-tests 2".split()
        )
        args.filter_inverted = {}
        return_code, invalid_specs = pat.test_analysis(args)
        # Failing, because some of the fixtures only have one test case
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 0)

    def test_with_minimum_tests_no_passing(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter PolicyID=IAM.MFAEnabled.Required.Tests --minimum-tests 2".split()
        )
        args.filter, args.filter_inverted = parse.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        # Failing, because while there are two unit tests they both have expected result False
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 9)

    def test_invalid_resource_type(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter PolicyID=Example.Bad.Resource.Type".split()
        )
        args.filter, args.filter_inverted = parse.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 9)

    def test_invalid_log_type(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter RuleID=Example.Bad.Log.Type".split()
        )
        args.filter, args.filter_inverted = parse.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 1)
        self.equal = self.assertEqual(len(invalid_specs), 9)

    def test_zip_analysis(self):
        # Note: This is a workaround for CI
        try:
            self.fs.create_dir("tmp/")
        except OSError:
            pass
        args = pat.setup_parser().parse_args(
            f"zip --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --out tmp/".split()
        )

        return_code, out_filename = pat.zip_analysis(args)
        self.assertEqual(return_code, 0)
        self.assertTrue(out_filename.startswith("tmp/"))
        statinfo = os.stat(out_filename)
        self.assertTrue(statinfo.st_size > 0)
        self.assertTrue(out_filename.endswith(".zip"))

    def test_zip_analysis_chunks(self):
        # Note: This is a workaround for CI
        try:
            self.fs.create_dir("tmp/")
        except OSError:
            pass
        args = pat.setup_parser().parse_args(
            f"upload --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --out tmp/ --batch".split()
        )

        results = pat.zip_analysis_chunks(args)
        for out_filename in results:
            self.assertTrue(out_filename.startswith("tmp/"))
            statinfo = os.stat(out_filename)
            self.assertTrue(statinfo.st_size > 0)
            self.assertTrue(out_filename.endswith(".zip"))

        self.assertEqual(7, len(results))

    def test_generate_release_assets(self):
        # Note: This is a workaround for CI
        try:
            self.fs.create_dir("tmp/release/")
        except OSError:
            pass

        args = pat.setup_parser().parse_args(
            f"release --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --out tmp/release/".split()
        )
        return_code, _ = pat.generate_release_assets(args)
        analysis_file = "tmp/release/panther-analysis-all.zip"
        statinfo = os.stat(analysis_file)
        self.assertTrue(statinfo.st_size > 0)
        self.assertEqual(return_code, 0)

    def test_feature_flags_dont_err_the_upload(self):
        backend = MockBackend()
        backend.feature_flags = mock.MagicMock(
            side_effect=BaseException("something about the lambda doesnt support your request")
        )
        stats = BulkUploadStatistics(
            new=2,
            total=3,
            modified=4,
        )
        backend.bulk_upload = mock.MagicMock(
            return_value=BackendResponse(
                data=BulkUploadResponse(
                    rules=stats,
                    queries=stats,
                    policies=stats,
                    data_models=stats,
                    lookup_tables=stats,
                    global_helpers=stats,
                    correlation_rules=stats,
                ),
                status_code=200,
            )
        )

        args = pat.setup_parser().parse_args(
            f"--debug upload --path {DETECTIONS_FIXTURES_PATH}/valid_analysis".split()
        )
        return_code, _ = pat.upload_analysis(backend, args)
        self.assertEqual(return_code, 0)

    def test_retry_uploads(self):
        import logging

        backend = MockBackend()
        backend.bulk_upload = mock.MagicMock(
            side_effect=BackendError("another upload is in process")
        )

        args = pat.setup_parser().parse_args(
            f"--debug upload --path {DETECTIONS_FIXTURES_PATH}/valid_analysis".split()
        )

        # fails max of 10 times on default
        with mock.patch("time.sleep", return_value=None) as time_mock:
            with mock.patch.multiple(
                logging, debug=mock.DEFAULT, warning=mock.DEFAULT, info=mock.DEFAULT
            ) as logging_mocks:
                return_code, _ = pat.upload_analysis(backend, args)
                self.assertEqual(return_code, 1)
                self.assertEqual(logging_mocks["debug"].call_count, 20)
                self.assertEqual(logging_mocks["warning"].call_count, 1)
                # test + zip + upload messages
                self.assertEqual(logging_mocks["info"].call_count, 3)
                self.assertEqual(time_mock.call_count, 10)

        # invalid retry count, default to 0
        args = pat.setup_parser().parse_args(
            f"--debug upload --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --max-retries -1".split()
        )
        with mock.patch("time.sleep", return_value=None) as time_mock:
            with mock.patch.multiple(
                logging, debug=mock.DEFAULT, warning=mock.DEFAULT, info=mock.DEFAULT
            ) as logging_mocks:
                return_code, _ = pat.upload_analysis(backend, args)
                self.assertEqual(return_code, 1)
                self.assertEqual(logging_mocks["debug"].call_count, 0)
                self.assertEqual(logging_mocks["warning"].call_count, 2)
                self.assertEqual(logging_mocks["info"].call_count, 3)
                self.assertEqual(time_mock.call_count, 0)

        # invalid retry count, default to 10
        args = pat.setup_parser().parse_args(
            f"--debug upload --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --max-retries 100".split()
        )
        with mock.patch("time.sleep", return_value=None) as time_mock:
            with mock.patch.multiple(
                logging, debug=mock.DEFAULT, warning=mock.DEFAULT, info=mock.DEFAULT
            ) as logging_mocks:
                return_code, _ = pat.upload_analysis(backend, args)
                self.assertEqual(return_code, 1)
                self.assertEqual(logging_mocks["debug"].call_count, 20)
                # warning about max and final error
                self.assertEqual(logging_mocks["warning"].call_count, 2)
                self.assertEqual(logging_mocks["info"].call_count, 3)
                self.assertEqual(time_mock.call_count, 10)

    def test_available_destination_names_invalid_name_returned(self):
        """When an available destination is given but does not match the returned names"""
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis "
            "--available-destination Pagerduty".split()
        )
        return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 1)

    def test_available_destination_names_valid_name_returned(self):
        """When an available destination is given but matches the returned name"""
        args = pat.setup_parser().parse_args(
            f"test "
            f"--path "
            f" {DETECTIONS_FIXTURES_PATH}/destinations "
            "--available-destination Pagerduty".split()
        )
        return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 0)

    def test_invalid_query(self):
        # sqlfluff doesn't load correctly with the fake file system
        with Pause(self.fs):
            args = pat.setup_parser().parse_args(
                f"test --path {FIXTURES_PATH}/queries/invalid".split()
            )
            args.filter_inverted = {}
            return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 4)

    def test_invalid_query_passes_when_unchecked(self):
        # sqlfluff doesn't load correctly with the fake file system
        with Pause(self.fs):
            args = pat.setup_parser().parse_args(
                f"test --path {FIXTURES_PATH}/queries/invalid --ignore-table-names".split()
            )
            args.filter_inverted = {}
            return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_invalid_query_passes_when_table_name_provided(self):
        # sqlfluff doesn't load correctly with the fake file system
        with Pause(self.fs):
            args = pat.setup_parser().parse_args(
                f"test --path {FIXTURES_PATH}/queries/invalid --valid-table-names datalake.public* *login_history".split()
            )
            args.filter_inverted = {}
            return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_invalid_query_fails_when_partial_table_name_provided(self):
        # sqlfluff doesn't load correctly with the fake file system
        with Pause(self.fs):
            args = pat.setup_parser().parse_args(
                f"test --path {FIXTURES_PATH}/queries/invalid --valid-table-names datalake.public* *.*.login_history".split()
            )
            args.filter_inverted = {}
            return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 1)

    def test_valid_simple_detections(self):
        with Pause(self.fs):
            args = pat.setup_parser().parse_args(
                f"test " f"--path " f" {FIXTURES_PATH}/simple-detections/valid ".split()
            )
            # Force the PAT schema explicitly to ignore extra keys.
            pat.RULE_SCHEMA._ignore_extra_keys = True  # pylint: disable=protected-access
            return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_invalid_simple_detections(self):
        with Pause(self.fs):
            args = pat.setup_parser().parse_args(
                f"test " f"--path " f" {FIXTURES_PATH}/simple-detections/invalid ".split()
            )
            return_code, invalid_specs = pat.test_analysis(args)
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 3)

    # This function was generated in whole or in part by GitHub Copilot.
    def test_simple_detection_with_transpile(self):
        with Pause(self.fs):
            file_path = f"{FIXTURES_PATH}/simple-detections/valid"
            number_of_test_files = len(
                [
                    name
                    for name in os.listdir(file_path)
                    if os.path.isfile(os.path.join(file_path, name))
                ]
            )
            backend = MockBackend()
            backend.transpile_simple_detection_to_python = mock.MagicMock(
                return_value=BackendResponse(
                    data=TranspileToPythonResponse(
                        transpiled_python=[
                            "def rule(event): return True" for _ in range(number_of_test_files)
                        ],
                    ),
                    status_code=200,
                )
            )
            args = pat.setup_parser().parse_args(f"test " f"--path " f" {file_path}".split())
            # Force the PAT schema explicitly to ignore extra keys.
            pat.RULE_SCHEMA._ignore_extra_keys = True  # pylint: disable=protected-access
            return_code, invalid_specs = pat.test_analysis(args, backend=backend)
        # our mock transpiled code always returns true, so we should have some failing tests
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 0)

    def test_run_tests_with_filters(self):
        with Pause(self.fs):
            file_path = f"{FIXTURES_PATH}/inline-filters"
            number_of_test_files = len(
                [
                    name
                    for name in os.listdir(file_path)
                    if os.path.isfile(os.path.join(file_path, name))
                ]
            )
            backend = MockBackend()
            backend.transpile_simple_detection_to_python = mock.MagicMock(
                return_value=BackendResponse(
                    data=TranspileToPythonResponse(
                        transpiled_python=[
                            "def rule(event): return event.get('userAgent') == 'Max'"
                            for _ in range(number_of_test_files)
                        ],
                    ),
                    status_code=200,
                )
            )
            backend.transpile_filters = mock.MagicMock(
                return_value=BackendResponse(
                    data=TranspileFiltersResponse(
                        transpiled_filters=[
                            json.dumps(
                                {
                                    "statement": {
                                        "and": [
                                            {
                                                "target": "actionName",
                                                "value": "Beans",
                                                "operator": "==",
                                            }
                                        ]
                                    },
                                }
                            )
                            for _ in range(number_of_test_files)
                        ],
                    ),
                    status_code=200,
                )
            )
            args = pat.setup_parser().parse_args(f"test " f"--path " f" {file_path}".split())
            return_code, invalid_specs = pat.test_analysis(args, backend=backend)
        # our mock transpiled code always returns true, so we should have some failing tests
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_correlation_rules_skipped_if_feature_not_enabled(self):
        import logging

        with Pause(self.fs):
            file_path = f"{FIXTURES_PATH}/correlation-unit-tests/passes"
            backend = MockBackend()
            backend.test_correlation_rule = mock.MagicMock(
                side_effect=BackendError("correlation rule testing not enabled for you")
            )
            with mock.patch.multiple(
                logging, debug=mock.DEFAULT, warning=mock.DEFAULT, info=mock.DEFAULT
            ) as logging_mocks:
                logging.warn("to instantiate the warning call args")
                args = pat.setup_parser().parse_args(f"test " f"--path " f" {file_path}".split())
                return_code, _ = pat.test_analysis(args, backend=backend)
                warning_logs = logging_mocks["warning"].call_args.args
                warning_logged = False
                for warning_log in warning_logs:
                    if isinstance(warning_log, str):
                        if "Error running tests remotely for correlation rule" in warning_log:
                            warning_logged = True
                self.assertTrue(warning_logged)
        self.assertEqual(return_code, 0)

    def test_correlation_rules_can_report_pass(self):
        import sys
        from io import StringIO

        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        with Pause(self.fs):
            file_path = f"{FIXTURES_PATH}/correlation-unit-tests/passes"
            backend = MockBackend()
            backend.test_correlation_rule = mock.MagicMock(
                return_value=BackendResponse(
                    data=TestCorrelationRuleResponse(
                        results=[{"name": "t1", "error": None, "passed": True}]
                    ),
                    status_code=200,
                )
            )
            args = pat.setup_parser().parse_args(f"test " f"--path " f" {file_path}".split())
            return_code, invalid_specs = pat.test_analysis(args, backend=backend)
        sys.stdout = old_stdout
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)
        stdout_str = mystdout.getvalue()
        self.assertEqual(stdout_str.count(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] t1"), 1)

    def test_correlation_rules_can_report_failure(self):
        import sys
        from io import StringIO

        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        with Pause(self.fs):
            file_path = f"{FIXTURES_PATH}/correlation-unit-tests/fails"
            backend = MockBackend()
            backend.test_correlation_rule = mock.MagicMock(
                return_value=BackendResponse(
                    data=TestCorrelationRuleResponse(
                        results=[{"name": "t1", "error": None, "passed": False}]
                    ),
                    status_code=200,
                )
            )
            args = pat.setup_parser().parse_args(f"test " f"--path " f" {file_path}".split())
            return_code, invalid_specs = pat.test_analysis(args, backend=backend)
        sys.stdout = old_stdout
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 0)
        stdout_str = mystdout.getvalue()
        self.assertEqual(stdout_str.count(f"[{Fore.RED}FAIL{Style.RESET_ALL}] t1"), 1)
        self.assertEqual(stdout_str.count("Failed: 1"), 1)

    def test_correlation_rules_skipped_without_backend(self):
        """Confirms that correlation rules are skipped if no backend is provided."""
        import sys
        from io import StringIO

        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        with Pause(self.fs):
            file_path = f"{FIXTURES_PATH}/correlation-unit-tests"
            args = pat.setup_parser().parse_args(f"test " f"--path " f" {file_path}".split())
            return_code, invalid_specs = pat.test_analysis(args, backend=None)
        sys.stdout = old_stdout
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)
        stdout_str = mystdout.getvalue()
        # Ensure skipped tests don't count towards "Passed" total
        self.assertEqual(stdout_str.count("Passed: 0"), 1)
        # Ensure skipped tests are accurately summarized
        self.assertEqual(stdout_str.count("Skipped: 2"), 1)

    def test_can_retrieve_base_detection_for_test(self):
        import logging

        with Pause(self.fs):
            file_path = f"{FIXTURES_PATH}/derived_without_base"
            backend = MockBackend()
            backend.get_rule_body = mock.MagicMock(
                return_value=BackendResponse(
                    data=GetRuleBodyResponse(body="def rule(_):\n\treturn False", tests=[]),
                    status_code=200,
                )
            )
            with mock.patch.multiple(
                logging, debug=mock.DEFAULT, warning=mock.DEFAULT, info=mock.DEFAULT
            ) as logging_mocks:
                logging.warn("to instantiate the warning call args")
                args = pat.setup_parser().parse_args(f"test " f"--path " f" {file_path}".split())
                return_code, invalid_specs = pat.test_analysis(args, backend=backend)
                warning_logs = logging_mocks["warning"].call_args.args
                # assert that we were able to look up the base of this derived detection
                self.assertTrue(all("Skipping Derived Detection" not in s for s in warning_logs))
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_logs_warning_if_cannot_retrieve_base(self):
        import logging

        with Pause(self.fs):
            file_path = f"{FIXTURES_PATH}/derived_without_base"
            backend = MockBackend()
            # we mock a response for getting an error when retrieving the base
            backend.get_rule_body = mock.MagicMock(
                return_value=BackendResponse(
                    data=GetRuleBodyResponse(
                        body="i am writing a unit test i can write anything i want here", tests=[]
                    ),
                    status_code=403,
                )
            )
            with mock.patch.multiple(
                logging, debug=mock.DEFAULT, warning=mock.DEFAULT, info=mock.DEFAULT
            ) as logging_mocks:
                logging.warn("to instantiate the warning call args")
                args = pat.setup_parser().parse_args(f"test " f"--path " f" {file_path}".split())
                return_code, invalid_specs = pat.test_analysis(args, backend=backend)
                warning_logs = logging_mocks["warning"].call_args.args
                # assert that we skipped because we could not lookup base
                self.assertTrue(any("Skipping Derived Detection" in s for s in warning_logs))
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_can_inherit_tests_from_base(self):
        import sys
        from io import StringIO

        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        with Pause(self.fs):
            file_path = f"{FIXTURES_PATH}/tests_can_be_inherited"
            args = pat.setup_parser().parse_args(f"test " f"--path " f" {file_path}".split())
            return_code, invalid_specs = pat.test_analysis(args)
        sys.stdout = old_stdout
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)
        stdout_str = mystdout.getvalue()
        self.assertEqual(stdout_str.count(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] t1"), 2)
        self.assertEqual(stdout_str.count(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] t2"), 2)

    def test_bulk_validate_happy_path(self):
        backend = MockBackend()
        backend.supports_bulk_validate = mock.MagicMock(return_value=True)
        backend.bulk_validate = mock.MagicMock(
            return_value=BulkUploadValidateStatusResponse(status="COMPLETE", error="")
        )

        args = pat.setup_parser().parse_args(
            f"--debug validate --path {DETECTIONS_FIXTURES_PATH}/valid_analysis".split()
        )

        return_code, return_str = validate.run(backend, args)
        self.assertEqual(return_code, 0)
        self.assertTrue("Validation success" in return_str, f"match not found: {return_str}")
        backend.bulk_validate.assert_called_once()
        params = backend.bulk_validate.call_args[0][0]
        self.assertIsNotNone(params.zip_bytes, "zip data was unexpectedly empty")

    def test_bulk_validate_with_exception(self):
        backend = MockBackend()
        backend.supports_bulk_validate = mock.MagicMock(return_value=True)
        backend.bulk_validate = mock.MagicMock(
            side_effect=BackendError("ruh oh something went wrong")
        )

        args = pat.setup_parser().parse_args(
            f"--debug validate --path {DETECTIONS_FIXTURES_PATH}/valid_analysis".split()
        )

        return_code, _ = validate.run(backend, args)
        self.assertEqual(return_code, 1)

    def test_bulk_validate_without_support(self):
        backend = MockBackend()
        backend.bulk_validate = mock.MagicMock(
            side_effect=BackendError("ruh oh something went wrong")
        )

        args = pat.setup_parser().parse_args(
            f"--debug validate --path {DETECTIONS_FIXTURES_PATH}/valid_analysis".split()
        )

        return_code, return_str = validate.run(backend, args)
        self.assertEqual(return_code, 1)
        self.assertTrue(
            "Invalid backend. `validate` is only supported via API token" in return_str,
            f"match not found in {return_str}",
        )

    def test_bulk_validate_unsupported_exception(self):
        backend = MockBackend()
        backend.supports_bulk_validate = mock.MagicMock(return_value=True)
        backend.bulk_validate = mock.MagicMock(
            side_effect=UnsupportedEndpointError("ruh oh something went wrong")
        )

        args = pat.setup_parser().parse_args(
            f"--debug validate --path {DETECTIONS_FIXTURES_PATH}/valid_analysis".split()
        )

        return_code, return_str = validate.run(backend, args)
        self.assertEqual(return_code, 1)
        self.assertTrue(
            "Your Panther instance does not support this feature" in return_str,
            f"match not found in {return_str}",
        )

    def test_bulk_validate_with_expected_failures(self):
        backend = MockBackend()
        backend.supports_bulk_validate = mock.MagicMock(return_value=True)
        fake_response = BulkUploadValidateStatusResponse(
            error="oh snap",
            status="FAILED",
            result=BulkUploadValidateResult.from_json(
                {
                    "issues": [
                        {"path": "ok.some.path.text", "errorMessage": "ruh oh"},
                        {"path": "simple.yml", "errorMessage": "oh noz"},
                    ]
                }
            ),
        )
        backend.bulk_validate = mock.MagicMock(return_value=fake_response)

        args = pat.setup_parser().parse_args(
            f"--debug validate --path {DETECTIONS_FIXTURES_PATH}/valid_analysis".split()
        )

        return_code, return_str = validate.run(backend, args)
        self.assertEqual(return_code, 1)
        expected_strs = [fake_response.error]
        for issue in fake_response.get_issues():
            expected_strs.append(issue.path)
            expected_strs.append(issue.error_message)

        for expected in expected_strs:
            self.assertTrue(
                expected in return_str,
                f"expected to find {expected} in {return_str} but no matches found",
            )

    def test_classify_analysis_valid_specs(self):
        """Test classify_analysis with valid analysis specs"""
        # Valid rule spec
        valid_rule_spec = {
            "AnalysisType": "rule",
            "RuleID": "Test.Rule.ID",
            "DisplayName": "Test Rule",
            "Enabled": True,
            "Filename": "test_rule.py",
            "LogTypes": ["AWS.CloudTrail"],
            "Severity": "High",
        }

        # Valid policy spec
        valid_policy_spec = {
            "AnalysisType": "policy",
            "PolicyID": "Test.Policy.ID",
            "DisplayName": "Test Policy",
            "Enabled": True,
            "Filename": "test_policy.py",
            "ResourceTypes": ["AWS.S3.Bucket"],
            "Severity": "High",
        }

        # Valid global spec
        valid_global_spec = {
            "AnalysisType": "global",
            "GlobalID": "Test.Global.ID",
            "Filename": "test_global.py",
        }

        specs = [
            ("test_rule.yml", "/test", valid_rule_spec, None),
            ("test_policy.yml", "/test", valid_policy_spec, None),
            ("test_global.yml", "/test", valid_global_spec, None),
        ]

        all_specs, invalid_specs = pat.classify_analysis(
            specs, ignore_table_names=True, valid_table_names=[]
        )

        # Should have no invalid specs
        self.assertEqual(len(invalid_specs), 0)

        # Should classify correctly
        self.assertEqual(len(all_specs.detections), 2)  # rule and policy
        self.assertEqual(len(all_specs.globals), 1)
        self.assertEqual(len(all_specs.data_models), 0)
        self.assertEqual(len(all_specs.queries), 0)
        self.assertEqual(len(all_specs.lookup_tables), 0)
        self.assertEqual(len(all_specs.packs), 0)

    def test_classify_analysis_invalid_specs(self):
        """Test classify_analysis with invalid analysis specs"""
        # Invalid spec - missing required fields
        invalid_spec = {
            "AnalysisType": "rule",
            # Missing RuleID, DisplayName, etc.
        }

        specs = [
            ("invalid_rule.yml", "/test", invalid_spec, None),
        ]

        all_specs, invalid_specs = pat.classify_analysis(
            specs, ignore_table_names=True, valid_table_names=[]
        )

        # Should have one invalid spec
        self.assertEqual(len(invalid_specs), 1)
        self.assertEqual(invalid_specs[0][0], "invalid_rule.yml")

        # Should have no valid specs
        self.assertTrue(all_specs.empty())

    def test_classify_analysis_duplicate_ids(self):
        """Test classify_analysis with duplicate analysis IDs"""
        duplicate_rule_spec1 = {
            "AnalysisType": "rule",
            "RuleID": "Duplicate.Rule.ID",
            "DisplayName": "Test Rule 1",
            "Enabled": True,
            "Filename": "test_rule1.py",
            "LogTypes": ["AWS.CloudTrail"],
            "Severity": "High",
        }

        duplicate_rule_spec2 = {
            "AnalysisType": "rule",
            "RuleID": "Duplicate.Rule.ID",  # Same ID as above
            "DisplayName": "Test Rule 2",
            "Enabled": True,
            "Filename": "test_rule2.py",
            "LogTypes": ["AWS.CloudTrail"],
            "Severity": "High",
        }

        specs = [
            ("test_rule1.yml", "/test", duplicate_rule_spec1, None),
            ("test_rule2.yml", "/test", duplicate_rule_spec2, None),
        ]

        all_specs, invalid_specs = pat.classify_analysis(
            specs, ignore_table_names=True, valid_table_names=[]
        )

        # Should have one valid spec and one invalid (duplicate)
        self.assertEqual(len(invalid_specs), 1)
        self.assertEqual(len(all_specs.detections), 1)

        # Check the invalid spec is the duplicate one
        self.assertEqual(invalid_specs[0][0], "test_rule2.yml")
        self.assertIsInstance(invalid_specs[0][1], pat.AnalysisIDConflictException)

    def test_classify_analysis_with_parsing_errors(self):
        """Test classify_analysis with parsing errors passed in"""
        valid_spec = {
            "AnalysisType": "rule",
            "RuleID": "Test.Rule.ID",
            "DisplayName": "Test Rule",
            "Enabled": True,
            "Filename": "test_rule.py",
            "LogTypes": ["AWS.CloudTrail"],
            "Severity": "High",
        }

        # Simulate a parsing error
        parsing_error = ValueError("Invalid YAML syntax")

        specs = [
            ("valid_rule.yml", "/test", valid_spec, None),
            ("invalid_yaml.yml", "/test", {}, parsing_error),  # Error passed in
        ]

        all_specs, invalid_specs = pat.classify_analysis(
            specs, ignore_table_names=True, valid_table_names=[]
        )

        # Should have one valid spec and one invalid
        self.assertEqual(len(invalid_specs), 1)
        self.assertEqual(len(all_specs.detections), 1)

        # Check the invalid spec has the parsing error
        self.assertEqual(invalid_specs[0][0], "invalid_yaml.yml")
        self.assertIsInstance(invalid_specs[0][1], ValueError)

    def test_classify_analysis_scheduled_query_table_names(self):
        """Test classify_analysis with scheduled query table name validation"""
        from panther_analysis_tool.main import (
            AnalysisContainsInvalidTableNamesException,
        )

        # Valid scheduled query spec with invalid table name
        scheduled_query_spec = {
            "AnalysisType": "scheduled_query",
            "QueryName": "Test.Query",
            "Enabled": True,
            "Query": "SELECT * FROM invalid_table_name",
            "Schedule": {"RateMinutes": 60, "TimeoutMinutes": 5},
        }

        specs = [
            ("test_query.yml", "/test", scheduled_query_spec, None),
        ]

        # Test with table name validation enabled (ignore_table_names=False)
        all_specs, invalid_specs = pat.classify_analysis(
            specs, ignore_table_names=False, valid_table_names=[]
        )

        # Should have one invalid spec due to invalid table names
        self.assertEqual(len(invalid_specs), 1)
        self.assertEqual(invalid_specs[0][0], "test_query.yml")
        self.assertIsInstance(invalid_specs[0][1], AnalysisContainsInvalidTableNamesException)

        # Test with table name validation disabled (ignore_table_names=True)
        all_specs, invalid_specs = pat.classify_analysis(
            specs, ignore_table_names=True, valid_table_names=[]
        )

        # Should have no invalid specs when ignoring table names
        self.assertEqual(len(invalid_specs), 0)
        self.assertEqual(len(all_specs.queries), 1)

    def test_classify_analysis_dedup_warnings(self):
        """Test classify_analysis with DedupPeriodMinutes warnings"""
        import logging

        # Rule spec with DedupPeriodMinutes = 0
        rule_spec_zero_dedup = {
            "AnalysisType": "rule",
            "RuleID": "Test.Rule.Zero.Dedup",
            "DisplayName": "Test Rule Zero Dedup",
            "Enabled": True,
            "Filename": "test_rule.py",
            "LogTypes": ["AWS.CloudTrail"],
            "Severity": "High",
            "DedupPeriodMinutes": 0,
        }

        # Rule spec with DedupPeriodMinutes < 5
        rule_spec_low_dedup = {
            "AnalysisType": "rule",
            "RuleID": "Test.Rule.Low.Dedup",
            "DisplayName": "Test Rule Low Dedup",
            "Enabled": True,
            "Filename": "test_rule.py",
            "LogTypes": ["AWS.CloudTrail"],
            "Severity": "High",
            "DedupPeriodMinutes": 3,
        }

        specs = [
            ("test_rule_zero.yml", "/test", rule_spec_zero_dedup, None),
            ("test_rule_low.yml", "/test", rule_spec_low_dedup, None),
        ]

        with mock.patch.object(logging, "warning") as mock_warning:
            all_specs, invalid_specs = pat.classify_analysis(
                specs, ignore_table_names=True, valid_table_names=[]
            )

            # Should have no invalid specs (warnings don't make specs invalid)
            self.assertEqual(len(invalid_specs), 0)
            self.assertEqual(len(all_specs.detections), 2)

            # Should have logged warnings
            self.assertEqual(mock_warning.call_count, 2)
            warning_messages = [call.args[0] for call in mock_warning.call_args_list]
            self.assertTrue(
                any("DedupPeriodMinutes is set to 0" in msg for msg in warning_messages)
            )
            self.assertTrue(
                any(
                    "DedupPeriodMinutes for Test.Rule.Low.Dedup is less than 5" in msg
                    for msg in warning_messages
                )
            )

    def test_classify_analysis_derived_detection(self):
        """Test classify_analysis with derived detection"""
        # Derived detection spec
        derived_spec = {
            "AnalysisType": "rule",
            "RuleID": "Derived.Rule.ID",
            "DisplayName": "Derived Rule",
            "Enabled": True,
            "BaseDetection": "Base.Rule.ID",  # This makes it a derived detection
            "Severity": "High",
        }

        specs = [
            ("derived_rule.yml", "/test", derived_spec, None),
        ]

        all_specs, invalid_specs = pat.classify_analysis(
            specs, ignore_table_names=True, valid_table_names=[]
        )

        # Should classify as a valid detection
        self.assertEqual(len(invalid_specs), 0)
        self.assertEqual(len(all_specs.detections), 1)

        # Check that it was classified correctly
        derived_analysis = all_specs.detections[0]
        self.assertEqual(derived_analysis.analysis_spec["RuleID"], "Derived.Rule.ID")
        self.assertEqual(derived_analysis.analysis_spec["BaseDetection"], "Base.Rule.ID")
