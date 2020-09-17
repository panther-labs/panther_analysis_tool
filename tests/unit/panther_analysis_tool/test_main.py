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
        args = pat.setup_parser().parse_args('test --path tests/fixtures'.split())
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)
        assert_equal(invalid_specs[0][0],
                     'tests/fixtures/example_malformed_policy.yml')

    def test_rules_from_folder(self):
        args = pat.setup_parser().parse_args('test --path tests/fixtures/valid_analysis/rules'.split())
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_parse_filters(self):
        args = pat.setup_parser().parse_args('test --path tests/fixtures/valid_analysis --filter AnalysisType=policy,global Severity=Critical'.split())
        args.filter = pat.parse_filter(args.filter)
        assert_true('AnalysisType' in args.filter.keys())
        assert_true('policy' in args.filter['AnalysisType'])
        assert_true('global' in args.filter['AnalysisType'])
        assert_true('Severity' in args.filter.keys())
        assert_true('Critical' in args.filter['Severity'])

    def test_with_filters(self):
        args = pat.setup_parser().parse_args('test --path tests/fixtures/valid_analysis --filter AnalysisType=policy,global'.split())
        args.filter = pat.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_invalid_rule_definition(self):
        args = pat.setup_parser().parse_args('test --path tests/fixtures --filter Severity=Critical RuleID=AWS.CloudTrail.MFAEnabled'.split())
        args.filter = pat.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)
        assert_equal(len(invalid_specs), 2)

    def test_invalid_characters(self):
        args = pat.setup_parser().parse_args('test --path tests/fixtures --filter Severity=High PolicyID=AWS.IAM.MFAEnabled&'.split())
        args.filter = pat.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 1)
        assert_equal(len(invalid_specs), 2)

    def test_with_tag_filters(self):
        args = pat.setup_parser().parse_args('test --path tests/fixtures/valid_analysis --filter Tags=AWS,CIS'.split())
        args.filter = pat.parse_filter(args.filter)
        return_code, invalid_specs = pat.test_analysis(args)
        assert_equal(return_code, 0)
        assert_equal(len(invalid_specs), 0)

    def test_zip_analysis(self):
        # Note: This is a workaround for CI
        try:
            self.fs.create_dir('tmp/')
        except OSError:
            pass

        args = pat.setup_parser().parse_args(
            'zip --path tests/fixtures/valid_analysis --out tmp/'.split())
        return_code, out_filename = pat.zip_analysis(args)
        statinfo = os.stat(out_filename)
        assert_true(statinfo.st_size > 0)
        assert_equal(return_code, 0)
        assert_true(out_filename.endswith('.zip'))
