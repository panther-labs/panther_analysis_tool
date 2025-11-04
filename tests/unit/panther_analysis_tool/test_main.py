import json
import os
import shutil
import zipfile
from datetime import datetime
from unittest import mock
from unittest.mock import patch

import jsonschema
from colorama import Fore, Style
from panther_core.data_model import _DATAMODEL_FOLDER
from pyfakefs.fake_filesystem_unittest import Pause, TestCase
from typer.testing import CliRunner, Result

from panther_analysis_tool import analysis_utils
from panther_analysis_tool import main
from panther_analysis_tool import main as pat
from panther_analysis_tool.backend.client import (
    BackendError,
    BackendResponse,
    BulkUploadResponse,
    BulkUploadStatistics,
    BulkUploadValidateResult,
    BulkUploadValidateStatusResponse,
    GetRuleBodyResponse,
    TestCorrelationRuleResponse,
    TranspileFiltersResponse,
    TranspileToPythonResponse,
    UnsupportedEndpointError,
)
from panther_analysis_tool.backend.mocks import MockBackend
from panther_analysis_tool.main import app, upload_analysis

FIXTURES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../", "fixtures"))
DETECTIONS_FIXTURES_PATH = os.path.join(FIXTURES_PATH, "detections")

print("Using fixtures path:", FIXTURES_PATH)

runner = CliRunner()


def mock_test_analysis(tc: TestCase, args: list[str]) -> tuple[int, list[str]]:
    return mock_test_analysis_results(tc, args)[:2]


def mock_test_analysis_results(tc: TestCase, args: list[str]) -> tuple[int, list[str], Result]:
    from panther_analysis_tool.main import test_analysis

    return_code = -1
    invalid_specs = None

    def check_result(*args, **kwargs) -> tuple[int, list[str]]:
        nonlocal return_code, invalid_specs
        return_code, invalid_specs = test_analysis(*args, **kwargs)
        return return_code, invalid_specs

    with patch(
        "panther_analysis_tool.main.test_analysis", side_effect=check_result
    ) as mock_test_analysis:
        result = runner.invoke(app, args)
        if result.exception:
            if not isinstance(result.exception, SystemExit):
                # re-raise the exception
                raise result.exception
        tc.assertEqual(mock_test_analysis.call_count, 1)

    return return_code, invalid_specs, result


def mock_upload_analysis(tc: TestCase, args: list[str]) -> tuple[int, list[str]]:
    return_code = -1
    invalid_specs = None

    def check_result(*args, **kwargs) -> tuple[int, list[str]]:
        nonlocal return_code, invalid_specs
        return_code, invalid_specs = upload_analysis(*args, **kwargs)
        return return_code, invalid_specs

    with patch(
        "panther_analysis_tool.main.upload_analysis", side_effect=check_result
    ) as mock_upload_analysis:
        result = runner.invoke(app, args)
        if result.exception:
            if not isinstance(result.exception, SystemExit):
                # re-raise the exception
                raise result.exception
        tc.assertEqual(mock_upload_analysis.call_count, 1)

    return return_code, invalid_specs


def mock_validate(tc: TestCase, args: list[str]) -> tuple[int, list[str]]:
    from panther_analysis_tool.command.validate import run as validate_run

    return_code = -1
    invalid_specs = None

    def check_result(*args, **kwargs) -> tuple[int, str]:
        nonlocal return_code, invalid_specs
        return_code, invalid_specs = validate_run(*args, **kwargs)
        return return_code, invalid_specs

    with patch(
        "panther_analysis_tool.main.validate.run", side_effect=check_result
    ) as mock_upload_analysis:
        result = runner.invoke(app, args)
        if result.exception:
            if not isinstance(result.exception, SystemExit):
                # re-raise the exception
                raise result.exception
        tc.assertEqual(mock_upload_analysis.call_count, 1)

    return return_code, invalid_specs


class TestPantherAnalysisTool(TestCase):
    def setUp(self) -> None:
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
        os.makedirs(analysis_utils.get_tmp_helper_module_location(), exist_ok=True)
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
            shutil.copy(
                filename,
                os.path.join(analysis_utils.get_tmp_helper_module_location(), f"{module_name}.py"),
            )
        self.setUpPyfakefs()
        self.fs.add_real_directory(FIXTURES_PATH)
        self.fs.add_real_directory(analysis_utils.get_tmp_helper_module_location(), read_only=False)
        # jsonschema needs to be able to access '.../site-packages/jsonschema/schemas/vocabularies' to work
        self.fs.add_real_directory(jsonschema.__path__[0])
        # sqlfluff needs to be able to access its package metadata to work
        self.fs.add_package_metadata("sqlfluff")

        main._DISABLE_PANTHER_EXCEPTION_HANDLER = True
        # skip the http check
        main._SKIP_HTTP_VERSION_CHECK = True

    def tearDown(self) -> None:
        main._DISABLE_PANTHER_EXCEPTION_HANDLER = False
        with Pause(self.fs):
            for data_model_module in self.data_model_modules:
                file_path = os.path.join(_DATAMODEL_FOLDER, os.path.split(data_model_module)[-1])
                if os.path.exists(file_path):
                    os.remove(file_path)

    def test_valid_json_policy_spec(self) -> None:
        for spec_filename, _, loaded_spec, _ in analysis_utils.load_analysis_specs(
            [DETECTIONS_FIXTURES_PATH], ignore_files=[]
        ):
            if spec_filename.endswith("example_policy.json"):
                self.assertIsInstance(loaded_spec, dict)
                self.assertTrue(loaded_spec != {})

    def test_ignored_files_are_not_loaded(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self,
            f"test --path {DETECTIONS_FIXTURES_PATH}/example_malformed_yaml --ignore-files {DETECTIONS_FIXTURES_PATH}/example_malformed_yaml.yml".split(),
        )
        self.assertEqual(return_code, 1)  # no specs throws error
        self.assertIn("Nothing to test in", invalid_specs[0])

    def test_valid_yaml_policy_spec(self) -> None:
        for spec_filename, _, loaded_spec, _ in analysis_utils.load_analysis_specs(
            [DETECTIONS_FIXTURES_PATH], ignore_files=[]
        ):
            if spec_filename.endswith("example_policy.yml"):
                self.assertIsInstance(loaded_spec, dict)
                self.assertTrue(loaded_spec != {})

    def test_valid_pack_spec(self) -> None:
        pack_loaded = False
        for spec_filename, _, loaded_spec, _ in analysis_utils.load_analysis_specs(
            [DETECTIONS_FIXTURES_PATH], ignore_files=[]
        ):
            if spec_filename.endswith("sample-pack.yml"):
                self.assertIsInstance(loaded_spec, dict)
                self.assertTrue(loaded_spec != {})
                pack_loaded = True
        self.assertTrue(pack_loaded)

    def test_datetime_converted(self) -> None:
        test_date = datetime.now()
        test_date_string = pat.datetime_converted(test_date)
        self.assertIsInstance(test_date_string, str)

    def test_load_policy_specs_from_folder(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self, ["test", "--path", DETECTIONS_FIXTURES_PATH]
        )
        self.assertEqual(return_code, 1)
        self.assertEqual(
            invalid_specs[0][0], f"{DETECTIONS_FIXTURES_PATH}/example_malformed_policy.yml"
        )
        self.assertEqual(len(invalid_specs), 13)

    def test_policies_from_folder(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self, f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis/policies".split()
        )
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_rules_from_folder(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self, f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis/rules".split()
        )
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_queries_from_folder(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self, f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis/queries".split()
        )
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_scheduled_rules_from_folder(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self, f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis/scheduled_rules".split()
        )
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_rules_from_current_dir(self) -> None:
        # This is a work around to test running tool against current directory
        return_code = -1
        invalid_specs = None
        valid_rule_path = os.path.join(DETECTIONS_FIXTURES_PATH, "valid_analysis/policies")
        # test default path, '.'
        with Pause(self.fs):
            original_path = os.getcwd()
            try:
                os.chdir(valid_rule_path)
                return_code, invalid_specs = mock_test_analysis(self, ["test"])
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

            return_code, invalid_specs = mock_test_analysis(self, ["test", "--path", "./"])
            os.chdir(original_path)
        # asserts are outside of the pause to ensure the fakefs gets resumed
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_with_filters(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self,
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --filter AnalysisType=policy,global".split(),
        )
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_status_deprecated_filtered_out(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self,
            f"test --path {DETECTIONS_FIXTURES_PATH}/status_deprecated".split(),
        )
        # by default deprecated status should have been filtered out
        # so this should error since there was nothing to test
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 1)
        self.assertIn("No", invalid_specs[0])
        self.assertIn("matched filters", invalid_specs[0])

    def test_status_experimental_filtered_out(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self,
            f"test --path {DETECTIONS_FIXTURES_PATH}/status_experimental".split(),
        )
        # by default experimental status should have been filtered out
        # so this should error since there was nothing to test
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 1)
        self.assertIn("No", invalid_specs[0])
        self.assertIn("matched filters", invalid_specs[0])

    def test_status_stable_not_filtered_out(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self,
            f"test --path {DETECTIONS_FIXTURES_PATH}/status_stable".split(),
        )
        # stable detections are not filtered out by default
        # this should run and return a success
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_enabled_filter(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self,
            f"test --path {DETECTIONS_FIXTURES_PATH}/disabled_rule --filter Enabled=true".split(),
        )
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_enabled_filter_inverted(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self,
            f"test --path {DETECTIONS_FIXTURES_PATH}/disabled_rule --filter Enabled!=false".split(),
        )
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_aws_profiles(self) -> None:
        backend = MockBackend()
        with (
            patch(
                "panther_analysis_tool.main.pat_utils.get_backend", return_value=backend
            ) as mock_get_backend,
            patch("panther_analysis_tool.main.upload_zip") as mock_upload_zip,
        ):
            mock_upload_zip.return_value = (0, "")
            result = runner.invoke(
                app,
                f"upload --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --aws-profile myprofile".split(),
            )

        if result.exception:
            raise result.exception

        self.assertEqual(result.exit_code, 0)
        self.assertEqual("myprofile", mock_get_backend.call_args[0][2])

    def test_invalid_rule_definition(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self,
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter RuleID=AWS.CloudTrail.MFAEnabled".split(),
        )
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 9)

    def test_invalid_rule_test(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self,
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter RuleID=Example.Rule.Invalid.Test".split(),
        )
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 9)

    def test_invalid_characters(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self,
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter Severity=High --filter ResourceTypes=AWS.IAM.User".split(),
        )
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 10)

    def test_unknown_exception(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self,
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter RuleID=Example.Rule.Unknown.Exception".split(),
        )
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 9)

    def test_with_invalid_mocks(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self,
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter Severity=Critical --filter RuleID=Example.Rule.Invalid.Mock".split(),
        )
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 9)

    def test_with_tag_filters(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self,
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --filter Tags=AWS,CIS".split(),
        )
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_with_tag_filters_inverted(self) -> None:
        # Note: a comparison of the tests passed is required to make this test robust
        # (8 passing vs 1 passing)
        return_code, invalid_specs = mock_test_analysis(
            self,
            f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --filter Tags=AWS,CIS --filter Tags!=SOC2".split(),
        )
        self.assertEqual(invalid_specs, [])
        self.assertEqual(return_code, 0)

    def test_with_test_names_filter(self) -> None:
        # Test that we can filter tests by name using --test-names
        return_code, invalid_specs = mock_test_analysis(
            self,
            [
                "test",
                "--path",
                f"{DETECTIONS_FIXTURES_PATH}/valid_analysis",
                "--test-names",
                "True Event",
            ],
        )
        # Should pass because the specified test exists in the fixtures
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_with_test_names_filter_and_rule_filter(self) -> None:
        # Test combining rule filter with test name filter
        return_code, invalid_specs = mock_test_analysis(
            self,
            [
                "test",
                "--path",
                f"{DETECTIONS_FIXTURES_PATH}/valid_analysis",
                "--filter",
                "RuleID=Example.Rule",
                "--test-names",
                "True Event",
            ],
        )
        # Should pass because we're filtering to a specific rule and test
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_with_test_names_filter_nonexistent_test(self):
        # Test with a test name that doesn't exist
        return_code, invalid_specs = mock_test_analysis(
            self,
            [
                "test",
                "--path",
                f"{DETECTIONS_FIXTURES_PATH}/valid_analysis",
                "--test-names",
                "Nonexistent Test",
            ],
        )
        # Should still return 0 because no tests failing, just no tests matching the filter
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_with_minimum_tests(self):
        return_code, invalid_specs = mock_test_analysis(
            self, f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --minimum-tests 1".split()
        )
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_with_minimum_tests_failing(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self, f"test --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --minimum-tests 2".split()
        )
        # Failing, because some of the fixtures only have one test case
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 0)

    def test_with_minimum_tests_no_passing(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self,
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter PolicyID=IAM.MFAEnabled.Required.Tests --minimum-tests 2".split(),
        )
        # Failing, because while there are two unit tests they both have expected result False
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 9)

    def test_invalid_resource_type(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self,
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter PolicyID=Example.Bad.Resource.Type".split(),
        )
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 9)

    def test_invalid_log_type(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self,
            f"test --path {DETECTIONS_FIXTURES_PATH} --filter RuleID=Example.Bad.Log.Type".split(),
        )
        self.assertEqual(return_code, 1)
        self.equal = self.assertEqual(len(invalid_specs), 9)

    def test_zip_analysis(self) -> None:
        # Note: This is a workaround for CI
        try:
            self.fs.create_dir("tmp/")
        except OSError:
            pass

        from panther_analysis_tool.main import zip_analysis

        def check_result(*args, **kwargs):
            results = zip_analysis(*args, **kwargs)
            for out_filename in results:
                self.assertTrue(out_filename.startswith("tmp/"))
                statinfo = os.stat(out_filename)
                self.assertTrue(statinfo.st_size > 0)
                self.assertTrue(out_filename.endswith(".zip"))

        with patch(
            "panther_analysis_tool.main.zip_analysis", side_effect=check_result
        ) as mock_zip_analysis_chunks:
            runner.invoke(
                app, f"zip --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --out tmp/".split()
            )
            self.assertEqual(mock_zip_analysis_chunks.call_count, 1)

    def test_zip_excludes_deprecated_experimental(self) -> None:
        # Note: This is a workaround for CI
        try:
            self.fs.create_dir("tmp/")
            self.fs.create_dir("tmp/zipped")
        except OSError:
            pass

        from panther_analysis_tool.main import zip_analysis

        def check_result(*args, **kwargs):
            results = zip_analysis(*args, **kwargs)
            for out_filename in results:
                self.assertTrue(out_filename.startswith("tmp/"))
                statinfo = os.stat(out_filename)
                self.assertTrue(statinfo.st_size > 0)
                self.assertTrue(out_filename.endswith(".zip"))

        with patch(
            "panther_analysis_tool.main.zip_analysis", side_effect=check_result
        ) as mock_zip_analysis_chunks:
            runner.invoke(
                app, f"zip --path {DETECTIONS_FIXTURES_PATH}/all_statuses --out tmp/zipped".split()
            )
            self.assertEqual(mock_zip_analysis_chunks.call_count, 1)
            zipped_items = os.listdir("/tmp/zipped")
            self.assertEqual(1, len(zipped_items))
            zip_name = zipped_items[0]
            zip_file_path = os.path.join("tmp/zipped", zip_name)
            with zipfile.ZipFile(zip_file_path, "r") as zip_file:
                file_list = zip_file.namelist()
                # there should only be 4 files in the list: one python and one yml
                # file for stable. and likewise for the no_status detection.
                # the experimental and deprecated detections should be
                # filtered out by default
                self.assertEqual(4, len(file_list))
                self.assertIn("no_status.yml", file_list[0])
                self.assertIn("no_status.py", file_list[1])
                self.assertIn("status_stable.yml", file_list[2])
                self.assertIn("status_stable.py", file_list[3])

    def test_zip_can_include_deprecated_experimental(self) -> None:
        """
        like the above 'test_zip_excludes_deprecated_experimental' test but
        we test that users can choose to include experimental/deprecated by explicitly
        adding a filter on the Status field
        """
        # Note: This is a workaround for CI
        try:
            self.fs.create_dir("tmp/")
            self.fs.create_dir("tmp/zipped2")
        except OSError:
            pass

        from panther_analysis_tool.main import zip_analysis

        def check_result(*args, **kwargs):
            results = zip_analysis(*args, **kwargs)
            for out_filename in results:
                self.assertTrue(out_filename.startswith("tmp/"))
                statinfo = os.stat(out_filename)
                self.assertTrue(statinfo.st_size > 0)
                self.assertTrue(out_filename.endswith(".zip"))

        with patch(
            "panther_analysis_tool.main.zip_analysis", side_effect=check_result
        ) as mock_zip_analysis_chunks:
            runner.invoke(
                app,
                f"zip --path {DETECTIONS_FIXTURES_PATH}/all_statuses --filter Status!=blah --out tmp/zipped2".split(),
            )
            self.assertEqual(mock_zip_analysis_chunks.call_count, 1)
            zipped_items = os.listdir("/tmp/zipped2")
            self.assertEqual(1, len(zipped_items))
            zip_name = zipped_items[0]
            zip_file_path = os.path.join("tmp/zipped2", zip_name)
            with zipfile.ZipFile(zip_file_path, "r") as zip_file:
                file_list = zip_file.namelist()
                # there should be 8 files in the list: there's 4 detections, and each detection has 2 files
                # a python and a yaml file
                self.assertEqual(8, len(file_list))
                self.assertIn("no_status.yml", file_list[0])
                self.assertIn("no_status.py", file_list[1])
                self.assertIn("status_deprecated.yml", file_list[2])
                self.assertIn("status_deprecated.py", file_list[3])
                self.assertIn("status_experimental.yml", file_list[4])
                self.assertIn("status_experimental.py", file_list[5])
                self.assertIn("status_stable.yml", file_list[6])
                self.assertIn("status_stable.py", file_list[7])

    def test_zip_analysis_chunks(self) -> None:
        # Note: This is a workaround for CI
        try:
            self.fs.create_dir("tmp/")
        except OSError:
            pass

        results = pat.zip_analysis_chunks(
            "tmp/", f"{DETECTIONS_FIXTURES_PATH}/valid_analysis", {}, {}, {}
        )
        for out_filename in results:
            self.assertTrue(out_filename.startswith("tmp/"))
            statinfo = os.stat(out_filename)
            self.assertTrue(statinfo.st_size > 0)
            self.assertTrue(out_filename.endswith(".zip"))

        self.assertEqual(7, len(results))

    def test_generate_release_assets(self) -> None:
        # Note: This is a workaround for CI
        try:
            self.fs.create_dir("tmp/release/")
        except OSError:
            pass

        results = runner.invoke(
            app,
            f"release --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --out tmp/release/".split(),
        )
        if results.exception:
            raise results.exception

        return_code = results.exit_code
        analysis_file = "tmp/release/panther-analysis-all.zip"
        statinfo = os.stat(analysis_file)
        self.assertTrue(statinfo.st_size > 0)
        self.assertEqual(return_code, 0)

    def test_release_includes_all_by_default(self) -> None:
        # Note: This is a workaround for CI
        try:
            self.fs.create_dir("tmp/release2")
        except OSError:
            pass

        results = runner.invoke(
            app,
            f"release --path {DETECTIONS_FIXTURES_PATH}/all_statuses --out tmp/release2/".split(),
        )
        if results.exception:
            raise results.exception

        return_code = results.exit_code
        self.assertEqual(return_code, 0)
        analysis_file = "tmp/release2/panther-analysis-all.zip"
        with zipfile.ZipFile(analysis_file, "r") as zip_file:
            file_list = zip_file.namelist()
            # there should be 8 files in the release: there's 4 detections, and each detection has 2 files
            # a python and a yaml file
            self.assertEqual(8, len(file_list))
            self.assertIn("no_status.yml", file_list[0])
            self.assertIn("no_status.py", file_list[1])
            self.assertIn("status_deprecated.yml", file_list[2])
            self.assertIn("status_deprecated.py", file_list[3])
            self.assertIn("status_experimental.yml", file_list[4])
            self.assertIn("status_experimental.py", file_list[5])
            self.assertIn("status_stable.yml", file_list[6])
            self.assertIn("status_stable.py", file_list[7])

    def test_feature_flags_dont_err_the_upload(self) -> None:
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

        with patch("panther_analysis_tool.main.pat_utils.get_backend", return_value=backend):
            return_code, _ = mock_upload_analysis(
                self, f"--debug upload --path {DETECTIONS_FIXTURES_PATH}/valid_analysis".split()
            )
            self.assertEqual(return_code, 0)

    def test_retry_uploads(self) -> None:
        import logging

        backend = MockBackend()
        backend.bulk_upload = mock.MagicMock(
            side_effect=BackendError("another upload is in process")
        )

        # fails max of 10 times on default
        with (
            mock.patch("time.sleep", return_value=None) as time_mock,
            mock.patch.multiple(
                logging, debug=mock.DEFAULT, warning=mock.DEFAULT, info=mock.DEFAULT
            ) as logging_mocks,
            patch("panther_analysis_tool.main.pat_utils.get_backend", return_value=backend),
        ):
            return_code, _ = mock_upload_analysis(
                self, f"upload --path {DETECTIONS_FIXTURES_PATH}/valid_analysis".split()
            )
            self.assertEqual(return_code, 1)
            self.assertEqual(time_mock.call_count, 10)

        # invalid retry count, default to 0
        with (
            mock.patch("time.sleep", return_value=None) as time_mock,
            mock.patch.multiple(
                logging, debug=mock.DEFAULT, warning=mock.DEFAULT, info=mock.DEFAULT
            ) as logging_mocks,
            patch("panther_analysis_tool.main.pat_utils.get_backend", return_value=backend),
        ):
            return_code, _ = mock_upload_analysis(
                self,
                f"upload --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --max-retries -1".split(),
            )
            self.assertEqual(return_code, 1)
            self.assertEqual(time_mock.call_count, 0)

        # invalid retry count, default to 10
        with (
            mock.patch("time.sleep", return_value=None) as time_mock,
            mock.patch.multiple(
                logging, debug=mock.DEFAULT, warning=mock.DEFAULT, info=mock.DEFAULT
            ) as logging_mocks,
            patch("panther_analysis_tool.main.pat_utils.get_backend", return_value=backend),
        ):
            return_code, _ = mock_upload_analysis(
                self,
                f"upload --path {DETECTIONS_FIXTURES_PATH}/valid_analysis --max-retries 100".split(),
            )
            self.assertEqual(return_code, 1)
            self.assertEqual(time_mock.call_count, 10)

    def test_available_destination_names_invalid_name_returned(self) -> None:
        """When an available destination is given but does not match the returned names"""
        return_code, invalid_specs = mock_test_analysis(
            self,
            [
                "test",
                "--path",
                f"{DETECTIONS_FIXTURES_PATH}/valid_analysis",
                "--available-destination",
                "Pagerduty",
            ],
        )
        self.assertEqual(return_code, 1)

    def test_available_destination_names_valid_name_returned(self) -> None:
        """When an available destination is given but matches the returned name"""
        return_code, invalid_specs = mock_test_analysis(
            self,
            [
                "test",
                "--path",
                f"{DETECTIONS_FIXTURES_PATH}/destinations",
                "--available-destination",
                "Pagerduty",
            ],
        )
        self.assertEqual(return_code, 0)

    def test_invalid_query(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self, f"test --path {FIXTURES_PATH}/queries/invalid".split()
        )
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 4)

    def test_invalid_query_passes_when_unchecked(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self, f"test --path {FIXTURES_PATH}/queries/invalid --ignore-table-names".split()
        )
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_invalid_query_passes_when_table_name_provided(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self,
            f"test --path {FIXTURES_PATH}/queries/invalid --valid-table-names datalake.public* --valid-table-names *login_history".split(),
        )
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_invalid_query_fails_when_partial_table_name_provided(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self,
            f"test --path {FIXTURES_PATH}/queries/invalid --valid-table-names datalake.public* --valid-table-names *.*.login_history".split(),
        )
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 1)

    def test_valid_simple_detections(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self,
            ["test", "--path", f"{FIXTURES_PATH}/simple-detections/valid", "--ignore-extra-keys"],
        )
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_invalid_simple_detections(self) -> None:
        return_code, invalid_specs = mock_test_analysis(
            self, f"test --path {FIXTURES_PATH}/simple-detections/invalid".split()
        )
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 3)

    # This function was generated in whole or in part by GitHub Copilot.
    def test_simple_detection_with_transpile(self) -> None:
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
            with patch(
                "panther_analysis_tool.main.pat_utils.get_optional_backend", return_value=backend
            ):
                return_code, invalid_specs = mock_test_analysis(
                    self, ["test", "--path", file_path, "--ignore-extra-keys"]
                )

        # our mock transpiled code always returns true, so we should have some failing tests
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 0)

    def test_run_tests_with_filters(self) -> None:
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
            with patch(
                "panther_analysis_tool.main.pat_utils.get_optional_backend", return_value=backend
            ):
                return_code, invalid_specs = mock_test_analysis(self, ["test", "--path", file_path])

        # our mock transpiled code always returns true, so we should have some failing tests
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_correlation_rules_skipped_if_feature_not_enabled(self) -> None:
        import logging

        file_path = f"{FIXTURES_PATH}/correlation-unit-tests/passes"
        backend = MockBackend()
        backend.test_correlation_rule = mock.MagicMock(
            side_effect=BackendError("correlation rule testing not enabled for you")
        )
        with (
            mock.patch.multiple(
                logging, debug=mock.DEFAULT, warning=mock.DEFAULT, info=mock.DEFAULT
            ) as logging_mocks,
            patch(
                "panther_analysis_tool.main.pat_utils.get_optional_backend", return_value=backend
            ),
        ):
            logging.warning("to instantiate the warning call args")
            return_code, _ = mock_test_analysis(self, ["test", "--path", file_path])
            warning_logs = logging_mocks["warning"].call_args.args
            warning_logged = False
            for warning_log in warning_logs:
                if isinstance(warning_log, str):
                    if "Error running tests remotely for correlation rule" in warning_log:
                        warning_logged = True
            self.assertTrue(warning_logged)
        self.assertEqual(return_code, 0)

    def test_correlation_rules_can_report_pass(self) -> None:
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
        with patch(
            "panther_analysis_tool.main.pat_utils.get_optional_backend", return_value=backend
        ):
            return_code, invalid_specs, result = mock_test_analysis_results(
                self, ["test", "--path", file_path]
            )

        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)
        stdout_str = result.stdout
        self.assertEqual(stdout_str.count(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] t1"), 1)

    def test_correlation_rules_can_report_failure(self) -> None:
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
        with patch(
            "panther_analysis_tool.main.pat_utils.get_optional_backend", return_value=backend
        ):
            return_code, invalid_specs, result = mock_test_analysis_results(
                self, ["test", "--path", file_path]
            )
        self.assertEqual(return_code, 1)
        self.assertEqual(len(invalid_specs), 0)
        stdout_str = result.stdout
        self.assertEqual(stdout_str.count(f"[{Fore.RED}FAIL{Style.RESET_ALL}] t1"), 1)
        self.assertEqual(stdout_str.count("Failed: 1"), 1)

    def test_correlation_rules_skipped_without_backend(self) -> None:
        """Confirms that correlation rules are skipped if no backend is provided."""
        file_path = f"{FIXTURES_PATH}/correlation-unit-tests"
        with patch("panther_analysis_tool.main.pat_utils.get_optional_backend", return_value=None):
            return_code, invalid_specs, result = mock_test_analysis_results(
                self, ["test", "--path", file_path]
            )
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)
        stdout_str = result.stdout
        # Ensure skipped tests don't count towards "Passed" total
        self.assertEqual(stdout_str.count("Passed: 0"), 1)
        # Ensure skipped tests are accurately summarized
        self.assertEqual(stdout_str.count("Skipped: 2"), 1)

    def test_can_retrieve_base_detection_for_test(self) -> None:
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
                logging.warning("to instantiate the warning call args")
                with patch(
                    "panther_analysis_tool.main.pat_utils.get_optional_backend",
                    return_value=backend,
                ):
                    return_code, invalid_specs = mock_test_analysis(
                        self, ["test", "--path", file_path]
                    )
                warning_logs = logging_mocks["warning"].call_args.args
                # assert that we were able to look up the base of this derived detection
                self.assertTrue(all("Skipping Derived Detection" not in s for s in warning_logs))
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_logs_warning_if_cannot_retrieve_base(self) -> None:
        import logging

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
            logging.warning("to instantiate the warning call args")
            with patch(
                "panther_analysis_tool.main.pat_utils.get_optional_backend", return_value=backend
            ):
                return_code, invalid_specs = mock_test_analysis(self, ["test", "--path", file_path])
            warning_logs = logging_mocks["warning"].call_args.args
            # assert that we skipped because we could not lookup base
            self.assertTrue(any("Skipping Derived Detection" in s for s in warning_logs))
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)

    def test_can_inherit_tests_from_base(self) -> None:
        file_path = f"{FIXTURES_PATH}/tests_can_be_inherited"
        return_code, invalid_specs, result = mock_test_analysis_results(
            self, ["test", "--path", file_path]
        )
        self.assertEqual(return_code, 0)
        self.assertEqual(len(invalid_specs), 0)
        stdout_str = result.stdout
        self.assertEqual(stdout_str.count(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] t1"), 2)
        self.assertEqual(stdout_str.count(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] t2"), 2)

    def test_bulk_validate_happy_path(self) -> None:
        backend = MockBackend()
        backend.supports_bulk_validate = mock.MagicMock(return_value=True)
        backend.bulk_validate = mock.MagicMock(
            return_value=BulkUploadValidateStatusResponse(status="COMPLETE", error="")
        )

        with patch("panther_analysis_tool.main.pat_utils.get_api_backend", return_value=backend):
            return_code, return_str = mock_validate(
                self, f"--debug validate --path {DETECTIONS_FIXTURES_PATH}/valid_analysis".split()
            )
        self.assertEqual(return_code, 0)
        self.assertTrue("Validation success" in return_str, f"match not found: {return_str}")
        backend.bulk_validate.assert_called_once()
        params = backend.bulk_validate.call_args[0][0]
        self.assertIsNotNone(params.zip_bytes, "zip data was unexpectedly empty")

    def test_bulk_validate_with_exception(self) -> None:
        backend = MockBackend()
        backend.supports_bulk_validate = mock.MagicMock(return_value=True)
        backend.bulk_validate = mock.MagicMock(
            side_effect=BackendError("ruh oh something went wrong")
        )

        with patch("panther_analysis_tool.main.pat_utils.get_api_backend", return_value=backend):
            result = runner.invoke(
                app, f"--debug validate --path {DETECTIONS_FIXTURES_PATH}/valid_analysis".split()
            )

        self.assertEqual(result.exit_code, 1)

    def test_bulk_validate_without_support(self) -> None:
        backend = MockBackend()
        backend.bulk_validate = mock.MagicMock(
            side_effect=BackendError("ruh oh something went wrong")
        )

        with patch("panther_analysis_tool.main.pat_utils.get_api_backend", return_value=backend):
            return_code, return_str = mock_validate(
                self,
                f"--debug validate --path {DETECTIONS_FIXTURES_PATH}/valid_analysis".split(),
            )
        self.assertEqual(return_code, 1)
        self.assertTrue(
            "Invalid backend. `validate` is only supported via API token" in return_str,
            f"match not found in {return_str}",
        )

    def test_bulk_validate_unsupported_exception(self) -> None:
        backend = MockBackend()
        backend.supports_bulk_validate = mock.MagicMock(return_value=True)
        backend.bulk_validate = mock.MagicMock(
            side_effect=UnsupportedEndpointError("ruh oh something went wrong")
        )

        with patch("panther_analysis_tool.main.pat_utils.get_api_backend", return_value=backend):
            return_code, return_str = mock_validate(
                self, f"--debug validate --path {DETECTIONS_FIXTURES_PATH}/valid_analysis".split()
            )
        self.assertEqual(return_code, 1)
        self.assertTrue(
            "Your Panther instance does not support this feature" in return_str,
            f"match not found in {return_str}",
        )

    def test_bulk_validate_with_expected_failures(self) -> None:
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

        with patch("panther_analysis_tool.main.pat_utils.get_api_backend", return_value=backend):
            return_code, return_str = mock_validate(
                self, f"--debug validate --path {DETECTIONS_FIXTURES_PATH}/valid_analysis".split()
            )
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

    def test_classify_analysis_valid_specs(self) -> None:
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
            specs,
            ignore_table_names=True,
            valid_table_names=[],
            ignore_extra_keys=False,
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

    def test_classify_analysis_invalid_specs(self) -> None:
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
            specs,
            ignore_table_names=True,
            valid_table_names=[],
            ignore_extra_keys=False,
        )

        # Should have one invalid spec
        self.assertEqual(len(invalid_specs), 1)
        self.assertEqual(invalid_specs[0][0], "invalid_rule.yml")

        # Should have no valid specs
        self.assertTrue(all_specs.empty())

    def test_classify_analysis_duplicate_ids(self) -> None:
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
            specs,
            ignore_table_names=True,
            valid_table_names=[],
            ignore_extra_keys=False,
        )

        # Should have one valid spec and one invalid (duplicate)
        self.assertEqual(len(invalid_specs), 1)
        self.assertEqual(len(all_specs.detections), 1)

        # Check the invalid spec is the duplicate one
        self.assertEqual(invalid_specs[0][0], "test_rule2.yml")
        self.assertIsInstance(invalid_specs[0][1], analysis_utils.AnalysisIDConflictException)

    def test_classify_analysis_with_parsing_errors(self) -> None:
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
            specs,
            ignore_table_names=True,
            valid_table_names=[],
            ignore_extra_keys=False,
        )

        # Should have one valid spec and one invalid
        self.assertEqual(len(invalid_specs), 1)
        self.assertEqual(len(all_specs.detections), 1)

        # Check the invalid spec has the parsing error
        self.assertEqual(invalid_specs[0][0], "invalid_yaml.yml")
        self.assertIsInstance(invalid_specs[0][1], ValueError)

    def test_classify_analysis_scheduled_query_table_names(self) -> None:
        """Test classify_analysis with scheduled query table name validation"""
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
            specs,
            ignore_table_names=False,
            valid_table_names=[],
            ignore_extra_keys=False,
        )

        # Should have one invalid spec due to invalid table names
        self.assertEqual(len(invalid_specs), 1)
        self.assertEqual(invalid_specs[0][0], "test_query.yml")
        self.assertIsInstance(
            invalid_specs[0][1], analysis_utils.AnalysisContainsInvalidTableNamesException
        )

        # Test with table name validation disabled (ignore_table_names=True)
        all_specs, invalid_specs = pat.classify_analysis(
            specs,
            ignore_table_names=True,
            valid_table_names=[],
            ignore_extra_keys=False,
        )

        # Should have no invalid specs when ignoring table names
        self.assertEqual(len(invalid_specs), 0)
        self.assertEqual(len(all_specs.queries), 1)

    def test_classify_analysis_dedup_warnings(self) -> None:
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
                specs,
                ignore_table_names=True,
                valid_table_names=[],
                ignore_extra_keys=False,
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

    def test_classify_analysis_derived_detection(self) -> None:
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
            specs,
            ignore_table_names=True,
            valid_table_names=[],
            ignore_extra_keys=False,
        )

        # Should classify as a valid detection
        self.assertEqual(len(invalid_specs), 0)
        self.assertEqual(len(all_specs.detections), 1)

        # Check that it was classified correctly
        derived_analysis = all_specs.detections[0]
        self.assertEqual(derived_analysis.analysis_spec["RuleID"], "Derived.Rule.ID")
        self.assertEqual(derived_analysis.analysis_spec["BaseDetection"], "Base.Rule.ID")
