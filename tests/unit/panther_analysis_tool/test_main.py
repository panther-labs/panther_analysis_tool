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
import io
import json
import os
import shutil
from datetime import datetime
from unittest import mock

import jsonschema
from nose.tools import assert_equal, assert_is_instance, assert_true
from panther_core.data_model import _DATAMODEL_FOLDER
from pyfakefs.fake_filesystem_unittest import Pause, TestCase
from schema import SchemaWrongKeyError

from panther_analysis_tool import main as pat
from panther_analysis_tool import util
from panther_analysis_tool.analysis_utils import add_analysis_filters_to_args
from panther_analysis_tool.backend.client import (
    BackendError,
    BackendResponse,
    BulkUploadValidateResult,
    BulkUploadValidateStatusResponse,
    GetRuleBodyResponse,
    TranspileFiltersResponse,
    TranspileToPythonResponse,
    UnsupportedEndpointError,
)
from panther_analysis_tool.backend.mocks import MockBackend
from panther_analysis_tool.command import validate

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
                os.remove(os.path.join(_DATAMODEL_FOLDER, os.path.split(data_model_module)[-1]))

    def test_valid_json_policy_spec(self):
        for spec_filename, _, loaded_spec, _ in pat.load_analysis_specs(
            [DETECTIONS_FIXTURES_PATH], ignore_files=[]
        ):
            if spec_filename.endswith("example_policy.json"):
                assert_is_instance(loaded_spec, dict)
                assert_true(loaded_spec != {})

    def test_ignored_files_are_not_loaded(self):
        for spec_filename, _, loaded_spec, _ in pat.load_analysis_specs(
            [DETECTIONS_FIXTURES_PATH], ignore_files=["./example_ignored.yml"]
        ):
            assert_true(loaded_spec != "example_ignored.yml")

    def test_multiple_ignored_files_are_not_loaded(self):
        for spec_filename, _, loaded_spec, _ in pat.load_analysis_specs(
            [DETECTIONS_FIXTURES_PATH],
            ignore_files=["./example_ignored.yml", "./example_ignored_multi.yml"],
        ):
            assert_true(
                loaded_spec != "example_ignored.yml" and loaded_spec != "example_ignored_multi.yml"
            )

    def test_valid_yaml_policy_spec(self):
        for spec_filename, _, loaded_spec, _ in pat.load_analysis_specs(
            [DETECTIONS_FIXTURES_PATH], ignore_files=[]
        ):
            if spec_filename.endswith("example_policy.yml"):
                assert_is_instance(loaded_spec, dict)
                assert_true(loaded_spec != {})

    def test_valid_pack_spec(self):
        pack_loaded = False
        for spec_filename, _, loaded_spec, _ in pat.load_analysis_specs(
            [DETECTIONS_FIXTURES_PATH], ignore_files=[]
        ):
            if spec_filename.endswith("sample-pack.yml"):
                assert_is_instance(loaded_spec, dict)
                assert_true(loaded_spec != {})
                pack_loaded = True
        assert_true(pack_loaded)

    def test_datetime_converted(self):
        test_date = datetime.now()
        test_date_string = pat.datetime_converted(test_date)
        assert_is_instance(test_date_string, str)

    def test_handle_wrong_key_error(self):
        sample_keys = ["DisplayName", "Enabled", "Filename"]
        expected_output = "{} not in list of valid keys: {}"
        # test successful regex match and correct error returned
        test_str = (
            "Wrong key 'DisplaName' in {'DisplaName':'one','Enabled':true, 'Filename':'sample'}"
        )
        exc = SchemaWrongKeyError(test_str)
        err = pat.handle_wrong_key_error(exc, sample_keys)
        assert_equal(str(err), expected_output.format("'DisplaName'", sample_keys))
        # test failing regex match
        test_str = "Will not match"
        exc = SchemaWrongKeyError(test_str)
        err = pat.handle_wrong_key_error(exc, sample_keys)
        assert_equal(str(err), expected_output.format("UNKNOWN_KEY", sample_keys))

    def test_load_policy_specs_from_folder(self):
        args = pat.setup_parser().parse_args(f"test --path {DETECTIONS_FIXTURES_PATH}".split())
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)
        assert_equal(
            invalid_specs[0][0], f"{DETECTIONS_FIXTURES_PATH}/example_malformed_policy.yml"
        )
        assert_equal(len(invalid_specs), 13)

    def test_policies_from_folder(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis/policies".split()
        )
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_rules_from_folder(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis/rules".split()
        )
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_queries_from_folder(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis/queries".split()
        )
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_scheduled_rules_from_folder(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis/scheduled_rules".split()
        )
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_signals_from_folder(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis/signals".split()
        )
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

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
                add_analysis_filters_to_args(args)
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
            args = pat.setup_parser().parse_args("test --path ./".split())
            add_analysis_filters_to_args(args)
            return_code, invalid_specs = pat.test_analysis(args)
            os.chdir(original_path)
        # asserts are outside of the pause to ensure the fakefs gets resumed
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_parse_filters(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --filter AnalysisType=policy,global Severity=Critical Enabled=true".split()
        )
        add_analysis_filters_to_args(args)
        filters = args.analysis_filters.filters
        assert_true("AnalysisType" in filters.keys())
        assert_true("policy" in filters["AnalysisType"])
        assert_true("global" in filters["AnalysisType"])
        assert_true("Severity" in filters.keys())
        assert_true("Critical" in filters["Severity"])
        assert_true("Enabled" in filters.keys())
        assert_true(True in filters["Enabled"])

    def test_with_filters(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --filter AnalysisType=policy,global".split()
        )
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_enabled_filter(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/disabled_rule --filter Enabled=true".split()
        )
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_enabled_filter_inverted(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/disabled_rule --filter Enabled!=false".split()
        )
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_aws_profiles(self):
        aws_profile = "AWS_PROFILE"
        args = pat.setup_parser().parse_args(
            f"upload --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --aws-profile myprofile".split()
        )
        util.set_env(aws_profile, args.aws_profile)
        assert_equal("myprofile", args.aws_profile)
        assert_equal(args.aws_profile, os.environ.get(aws_profile))

    def test_invalid_rule_definition(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter RuleID=AWS.CloudTrail.MFAEnabled".split()
        )
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)
        assert_equal(len(invalid_specs), 9)

    def test_invalid_rule_test(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter RuleID=Example.Rule.Invalid.Test".split()
        )
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)
        assert_equal(len(invalid_specs), 9)

    def test_invalid_characters(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter Severity=High ResourceTypes=AWS.IAM.User".split()
        )
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)
        assert_equal(len(invalid_specs), 10)

    def test_unknown_exception(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter RuleID=Example.Rule.Unknown.Exception".split()
        )
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)
        assert_equal(len(invalid_specs), 9)

    def test_with_invalid_mocks(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter Severity=Critical RuleID=Example.Rule.Invalid.Mock".split()
        )
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)
        assert_equal(len(invalid_specs), 9)

    def test_with_tag_filters(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --filter Tags=AWS,CIS".split()
        )
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_with_tag_filters_inverted(self):
        # Note: a comparison of the tests passed is required to make this test robust
        # (8 passing vs 1 passing)
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --filter Tags=AWS,CIS Tags!=SOC2".split()
        )
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_with_minimum_tests(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --minimum-tests 1".split()
        )
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_with_minimum_tests_failing(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --minimum-tests 2".split()
        )
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        # Failing, because some of the fixtures only have one test case
        assert_equal(return_code, 1)
        assert_equal(len(invalid_specs), 0)

    def test_with_minimum_tests_no_passing(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter PolicyID=IAM.MFAEnabled.Required.Tests --minimum-tests 2".split()
        )
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        # Failing, because while there are two unit tests they both have expected result False
        assert_equal(return_code, 1)
        assert_equal(len(invalid_specs), 9)

    def test_invalid_resource_type(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter PolicyID=Example.Bad.Resource.Type".split()
        )
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)
        assert_equal(len(invalid_specs), 9)

    def test_invalid_log_type(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter RuleID=Example.Bad.Log.Type".split()
        )
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)
        self.equal = assert_equal(len(invalid_specs), 9)

    def test_signal_filter(self):
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis/signals --filter SignalID=list.detections".split()
        )
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_zip_analysis(self):
        # Note: This is a workaround for CI
        try:
            self.fs.create_dir("tmp/")
        except OSError:
            pass
        args = pat.setup_parser().parse_args(
            f"zip --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --out tmp/".split()
        )
        add_analysis_filters_to_args(args)

        return_code, out_filename = pat.zip_analysis(args)
        assert_true(out_filename.startswith("tmp/"))
        statinfo = os.stat(out_filename)
        assert_true(statinfo.st_size > 0)
        assert_equal(return_code, 0)
        assert_true(out_filename.endswith(".zip"))

    def test_zip_analysis_chunks(self):
        # Note: This is a workaround for CI
        try:
            self.fs.create_dir("tmp/")
        except OSError:
            pass
        args = pat.setup_parser().parse_args(
            f"upload --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --out tmp/ --batch".split()
        )
        add_analysis_filters_to_args(args)

        results = pat.zip_analysis_chunks(args)
        for out_filename in results:
            assert_true(out_filename.startswith("tmp/"))
            statinfo = os.stat(out_filename)
            assert_true(statinfo.st_size > 0)
            assert_true(out_filename.endswith(".zip"))

        assert_equal(8, len(results))

    def test_generate_release_assets(self):
        # Note: This is a workaround for CI
        try:
            self.fs.create_dir("tmp/release/")
        except OSError:
            pass

        args = pat.setup_parser().parse_args(
            f"release --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --out tmp/release/".split()
        )
        add_analysis_filters_to_args(args)
        return_code, _ = pat.generate_release_assets(args)
        analysis_file = "tmp/release/panther-analysis-all.zip"
        statinfo = os.stat(analysis_file)
        assert_true(statinfo.st_size > 0)
        assert_equal(return_code, 0)

    def test_retry_uploads(self):
        import logging

        backend = MockBackend()
        backend.bulk_upload = mock.MagicMock(
            side_effect=BackendError("another upload is in process")
        )

        args = pat.setup_parser().parse_args(
            f"--debug upload --path {DETECTIONS_FIXTURES_PATH}/valid_analysis".split()
        )
        add_analysis_filters_to_args(args)

        # fails max of 10 times on default
        with mock.patch("time.sleep", return_value=None) as time_mock:
            with mock.patch.multiple(
                logging, debug=mock.DEFAULT, warning=mock.DEFAULT, info=mock.DEFAULT
            ) as logging_mocks:
                return_code, _ = pat.upload_analysis(backend, args)
                assert_equal(return_code, 1)
                assert_equal(logging_mocks["debug"].call_count, 20)
                assert_equal(logging_mocks["warning"].call_count, 3)
                # test + zip + upload messages, + 3 messages about sqlfluff loading improperly,
                # which can be removed by pausing the fake file system
                assert_equal(logging_mocks["info"].call_count, 5)
                assert_equal(time_mock.call_count, 10)

        # invalid retry count, default to 0
        args = pat.setup_parser().parse_args(
            f"--debug upload --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --max-retries -1".split()
        )
        add_analysis_filters_to_args(args)
        with mock.patch("time.sleep", return_value=None) as time_mock:
            with mock.patch.multiple(
                logging, debug=mock.DEFAULT, warning=mock.DEFAULT, info=mock.DEFAULT
            ) as logging_mocks:
                return_code, _ = pat.upload_analysis(backend, args)
                assert_equal(return_code, 1)
                assert_equal(logging_mocks["debug"].call_count, 0)
                assert_equal(logging_mocks["warning"].call_count, 4)
                assert_equal(logging_mocks["info"].call_count, 5)
                assert_equal(time_mock.call_count, 0)

        # invalid retry count, default to 10
        args = pat.setup_parser().parse_args(
            f"--debug upload --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --max-retries 100".split()
        )
        add_analysis_filters_to_args(args)
        with mock.patch("time.sleep", return_value=None) as time_mock:
            with mock.patch.multiple(
                logging, debug=mock.DEFAULT, warning=mock.DEFAULT, info=mock.DEFAULT
            ) as logging_mocks:
                return_code, _ = pat.upload_analysis(backend, args)
                assert_equal(return_code, 1)
                assert_equal(logging_mocks["debug"].call_count, 20)
                # warning about max and final error
                assert_equal(logging_mocks["warning"].call_count, 4)
                assert_equal(logging_mocks["info"].call_count, 5)
                assert_equal(time_mock.call_count, 10)

    def test_available_destination_names_invalid_name_returned(self):
        """When an available destination is given but does not match the returned names"""
        args = pat.setup_parser().parse_args(
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis "
            "--available-destination Pagerduty".split()
        )
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)

    def test_available_destination_names_valid_name_returned(self):
        """When an available destination is given but matches the returned name"""
        args = pat.setup_parser().parse_args(
            f"test "
            f"--path "
            f" {DETECTIONS_FIXTURES_PATH}/destinations "
            "--available-destination Pagerduty".split()
        )
        add_analysis_filters_to_args(args)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)

    def test_invalid_query(self):
        # sqlfluff doesn't load correctly with the fake file system
        with Pause(self.fs):
            args = pat.setup_parser().parse_args(
                f"test --path {FIXTURES_PATH}/queries/invalid".split()
            )
            add_analysis_filters_to_args(args)
            return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)
        assert_equal(len(invalid_specs), 4)

    def test_invalid_query_passes_when_unchecked(self):
        # sqlfluff doesn't load correctly with the fake file system
        with Pause(self.fs):
            args = pat.setup_parser().parse_args(
                f"test --path {FIXTURES_PATH}/queries/invalid --ignore-table-names".split()
            )
            add_analysis_filters_to_args(args)
            return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_invalid_query_passes_when_table_name_provided(self):
        # sqlfluff doesn't load correctly with the fake file system
        with Pause(self.fs):
            args = pat.setup_parser().parse_args(
                f"test --path {FIXTURES_PATH}/queries/invalid --valid-table-names datalake.public* *login_history".split()
            )
            add_analysis_filters_to_args(args)
            return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_invalid_query_fails_when_partial_table_name_provided(self):
        # sqlfluff doesn't load correctly with the fake file system
        with Pause(self.fs):
            args = pat.setup_parser().parse_args(
                f"test --path {FIXTURES_PATH}/queries/invalid --valid-table-names datalake.public* *.*.login_history".split()
            )
            add_analysis_filters_to_args(args)
            return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)
        assert_equal(len(invalid_specs), 1)

    def test_valid_simple_detections(self):
        with Pause(self.fs):
            args = pat.setup_parser().parse_args(
                f"test " f"--path " f" {FIXTURES_PATH}/simple-detections/valid ".split()
            )
            add_analysis_filters_to_args(args)
            # Force the PAT schema explicitly to ignore extra keys.
            pat.RULE_SCHEMA._ignore_extra_keys = True  # pylint: disable=protected-access
            return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_invalid_simple_detections(self):
        with Pause(self.fs):
            args = pat.setup_parser().parse_args(
                f"test " f"--path " f" {FIXTURES_PATH}/simple-detections/invalid ".split()
            )
            add_analysis_filters_to_args(args)
            return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)
        assert_equal(len(invalid_specs), 3)

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
            add_analysis_filters_to_args(args)
            # Force the PAT schema explicitly to ignore extra keys.
            pat.RULE_SCHEMA._ignore_extra_keys = True  # pylint: disable=protected-access
            return_code, invalid_specs = pat.test_analysis(args, backend=backend)
        # our mock transpiled code always returns true, so we should have some failing tests
        assert_equal(return_code, 1)
        assert_equal(len(invalid_specs), 0)

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
            add_analysis_filters_to_args(args)
            return_code, invalid_specs = pat.test_analysis(args, backend=backend)
        # our mock transpiled code always returns true, so we should have some failing tests
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_signals_with_transpile(self):
        with Pause(self.fs):
            file_path = f"{FIXTURES_PATH}/detections/valid_analysis/signals"
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
            add_analysis_filters_to_args(args)
            # Force the PAT schema explicitly to ignore extra keys.
            # pat.RULE_SCHEMA._ignore_extra_keys = True  # pylint: disable=protected-access
            return_code, invalid_specs = pat.test_analysis(args, backend=backend)
        # our mock transpiled code always returns true, so we should have some failing tests
        assert_equal(return_code, 1)
        assert_equal(len(invalid_specs), 0)

    def test_can_retrieve_base_detection_for_test(self):
        import logging

        with Pause(self.fs):
            file_path = f"{FIXTURES_PATH}/derived_without_base"
            backend = MockBackend()
            backend.get_rule_body = mock.MagicMock(
                return_value=BackendResponse(
                    data=GetRuleBodyResponse(body="def rule(_):\n\treturn False"),
                    status_code=200,
                )
            )
            with mock.patch.multiple(
                logging, debug=mock.DEFAULT, warning=mock.DEFAULT, info=mock.DEFAULT
            ) as logging_mocks:
                logging.warn("to instantiate the warning call args")
                args = pat.setup_parser().parse_args(f"test " f"--path " f" {file_path}".split())
                add_analysis_filters_to_args(args)
                return_code, invalid_specs = pat.test_analysis(args, backend=backend)
                warning_logs = logging_mocks["warning"].call_args.args
                # assert that we were able to look up the base of this derived detection
                assert_true(all("Skipping Derived Detection" not in s for s in warning_logs))
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_logs_warning_if_cannot_retrieve_base(self):
        import logging

        with Pause(self.fs):
            file_path = f"{FIXTURES_PATH}/derived_without_base"
            backend = MockBackend()
            # we mock a response for getting an error when retrieving the base
            backend.get_rule_body = mock.MagicMock(
                return_value=BackendResponse(
                    data=GetRuleBodyResponse(
                        body="i am writing a unit test i can write anything i want here"
                    ),
                    status_code=403,
                )
            )
            with mock.patch.multiple(
                logging, debug=mock.DEFAULT, warning=mock.DEFAULT, info=mock.DEFAULT
            ) as logging_mocks:
                logging.warn("to instantiate the warning call args")
                args = pat.setup_parser().parse_args(f"test " f"--path " f" {file_path}".split())
                add_analysis_filters_to_args(args)
                return_code, invalid_specs = pat.test_analysis(args, backend=backend)
                warning_logs = logging_mocks["warning"].call_args.args
                # assert that we skipped because we could not lookup base
                assert_true(any("Skipping Derived Detection" in s for s in warning_logs))
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_can_inherit_tests_from_base(self):
        import sys
        from io import StringIO

        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        with Pause(self.fs):
            file_path = f"{FIXTURES_PATH}/tests_can_be_inherited"
            args = pat.setup_parser().parse_args(f"test " f"--path " f" {file_path}".split())
            add_analysis_filters_to_args(args)
            return_code, invalid_specs = pat.test_analysis(args)
        sys.stdout = old_stdout
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)
        stdout_str = mystdout.getvalue()
        assert_equal(stdout_str.count("[PASS] t1"), 2)
        assert_equal(stdout_str.count("[PASS] t2"), 2)

    def test_bulk_validate_happy_path(self):
        backend = MockBackend()
        backend.supports_bulk_validate = mock.MagicMock(return_value=True)
        backend.bulk_validate = mock.MagicMock(
            return_value=BulkUploadValidateStatusResponse(status="COMPLETE", error="")
        )

        args = pat.setup_parser().parse_args(
            f"--debug validate --path {DETECTIONS_FIXTURES_PATH}/valid_analysis".split()
        )
        add_analysis_filters_to_args(args)

        return_code, return_str = validate.run(backend, args)
        assert_equal(return_code, 0)
        assert_true("Validation success" in return_str, f"match not found: {return_str}")
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
        add_analysis_filters_to_args(args)

        return_code, _ = validate.run(backend, args)
        assert_equal(return_code, 1)

    def test_bulk_validate_without_support(self):
        backend = MockBackend()
        backend.bulk_validate = mock.MagicMock(
            side_effect=BackendError("ruh oh something went wrong")
        )

        args = pat.setup_parser().parse_args(
            f"--debug validate --path {DETECTIONS_FIXTURES_PATH}/valid_analysis".split()
        )
        add_analysis_filters_to_args(args)

        return_code, return_str = validate.run(backend, args)
        assert_equal(return_code, 1)
        assert_true(
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
        add_analysis_filters_to_args(args)

        return_code, return_str = validate.run(backend, args)
        assert_equal(return_code, 1)
        assert_true(
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
        add_analysis_filters_to_args(args)

        return_code, return_str = validate.run(backend, args)
        assert_equal(return_code, 1)
        expected_strs = [fake_response.error]
        for issue in fake_response.get_issues():
            expected_strs.append(issue.path)
            expected_strs.append(issue.error_message)

        for expected in expected_strs:
            assert_true(
                expected in return_str,
                f"expected to find {expected} in {return_str} but no matches found",
            )
