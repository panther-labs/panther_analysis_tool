from datetime import datetime
import os

from pyfakefs.fake_filesystem_unittest import TestCase
from nose.tools import (assert_equal, assert_false, assert_is_instance,
                        assert_is_none, assert_true, raises, nottest,
                        with_setup)

from panther_analysis_tool import main as pat


class TestPantherAnalysisTool(TestCase):
    fixture_path = 'tests/fixtures/'

    def setUp(self):
        self.setUpPyfakefs()
        self.fs.add_real_directory(self.fixture_path)

    def test_valid_json_policy_spec(self):
        for spec_filename, _, loaded_spec in pat.load_analysis_specs('tests/fixtures'):
            if spec_filename == 'example_policy.json':
                assert_is_instance(loaded_spec, dict)
                assert_true(loaded_spec != {})

    def test_valid_yaml_policy_spec(self):
        for spec_filename, _, loaded_spec in pat.load_analysis_specs('tests/fixtures'):
            if spec_filename == 'example_policy.yml':
                assert_is_instance(loaded_spec, dict)
                assert_true(loaded_spec != {})

    def test_datetime_converted(self):
        test_date = datetime.now()
        test_date_string = pat.datetime_converted(test_date)
        assert_is_instance(test_date_string, str)

    def test_load_policy_specs_from_folder(self):
        args = pat.setup_parser().parse_args('test --analysis tests/fixtures'.split())
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)
        assert_equal(invalid_specs[0][0],
                     'tests/fixtures/example_malformed_policy.yml')

    def test_zip_analysis(self):
        # Note: This is a workaround for CI
        try:
            self.fs.create_dir('tmp/')
        except OSError:
            pass

        args = pat.setup_parser().parse_args(
            'zip --analysis tests/fixtures/valid_policies --output-path tmp/'.split())
        return_code, out_filename = pat.zip_analysis(args)
        statinfo = os.stat(out_filename)
        assert_true(statinfo.st_size > 0)
        assert_equal(return_code, 0)
        assert_true(out_filename.endswith('.zip'))
