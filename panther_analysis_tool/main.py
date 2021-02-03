'''
Copyright 2020 Panther Labs Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

from collections import defaultdict
from datetime import datetime
from fnmatch import fnmatch
from importlib.abc import Loader
from typing import Any, DefaultDict, Dict, Iterator, List, Set, Tuple
import argparse
import base64
import importlib.util
import json
import logging
import os
import re
import sys
import zipfile

from ruamel.yaml import YAML, parser as YAMLParser, scanner as YAMLScanner
from schema import (Optional, SchemaError, SchemaWrongKeyError,
                    SchemaMissingKeyError, SchemaForbiddenKeyError,
                    SchemaUnexpectedTypeError)
import boto3

from panther_analysis_tool.schemas import (TYPE_SCHEMA, DATA_MODEL_SCHEMA,
                                           GLOBAL_SCHEMA, POLICY_SCHEMA,
                                           RULE_SCHEMA)
from panther_analysis_tool.test_case import DataModel, TestCase

DATA_MODEL_LOCATION = './data_models'
HELPERS_LOCATION = './global_helpers'

DATA_MODEL_PATH_PATTERN = '*data_models*'
HELPERS_PATH_PATTERN = '*/global_helpers'
RULES_PATH_PATTERN = '*rules*'
POLICIES_PATH_PATTERN = '*policies*'

DATAMODEL = 'datamodel'
GLOBAL = 'global'
RULE = 'rule'
POLICY = 'policy'


# exception for conflicting ids
class AnalysisIDConflictException(Exception):

    def __init__(self, analysis_id: str):
        self.message = 'Conflicting AnalysisID: [{}]'.format(analysis_id)
        super().__init__(self.message)


def load_module(filename: str) -> Tuple[Any, Any]:
    """Loads the analysis function module from a file.

    Args:
        filename: The relative path to the file.

    Returns:
        A loaded Python module.
    """
    module_name = filename.split('.')[0]
    spec = importlib.util.spec_from_file_location(module_name, filename)
    module = importlib.util.module_from_spec(spec)
    try:
        assert isinstance(spec.loader, Loader)  #nosec
        spec.loader.exec_module(module)
    except FileNotFoundError as err:
        print('\t[ERROR] File not found: ' + filename + ', skipping\n')
        return None, err
    except Exception as err:  # pylint: disable=broad-except
        # Catch arbitrary exceptions thrown by user code
        print('\t[ERROR] Error loading module, skipping\n')
        return None, err
    return module, None


def load_analysis_specs(
        directories: List[str]) -> Iterator[Tuple[str, str, Any, Any]]:
    """Loads the analysis specifications from a file.

    Args:
        directory: The relative path to Panther policies or rules.

    Yields:
        A tuple of the relative filepath, directory name, and loaded analysis specification dict.
    """
    # setup a list of paths to ensure we do not import the same files
    # multiple times, which can happen when testing from root directory without filters
    loaded_specs = []
    for directory in directories:
        for relative_path, _, file_list in os.walk(directory):
            # setup yaml object
            yaml = YAML(typ='safe')
            # If the user runs with no path args, filter to make sure
            # we only run folders with valid analysis files. Ensure we test
            # files in the current directory by not skipping this iteration
            # when relative_path is the current dir
            if directory in ['.', './'] and relative_path not in ['.', './']:
                if not any([
                        fnmatch(relative_path, path_pattern)
                        for path_pattern in (
                            DATA_MODEL_PATH_PATTERN, HELPERS_PATH_PATTERN,
                            RULES_PATH_PATTERN, POLICIES_PATH_PATTERN)
                ]):
                    logging.debug('Skipping path %s', relative_path)
                    continue
            for filename in sorted(file_list):
                spec_filename = os.path.join(relative_path, filename)
                # skip loading files that have already been imported
                if spec_filename in loaded_specs:
                    continue
                loaded_specs.append(spec_filename)
                if fnmatch(filename, '*.y*ml'):
                    with open(spec_filename, 'r') as spec_file_obj:
                        try:
                            yield spec_filename, relative_path, yaml.load(
                                spec_file_obj), None
                        except (YAMLParser.ParserError,
                                YAMLScanner.ScannerError) as err:
                            # recreate the yaml object and yeild the error
                            yaml = YAML(typ='safe')
                            yield spec_filename, relative_path, None, err
                if fnmatch(filename, '*.json'):
                    with open(spec_filename, 'r') as spec_file_obj:
                        try:
                            yield spec_filename, relative_path, json.load(
                                spec_file_obj), None
                        except ValueError as err:
                            yield spec_filename, relative_path, None, err


def datetime_converted(obj: Any) -> Any:
    """A helper function for dumping spec files to JSON.

    Args:
        obj: Any object to convert.

    Returns:
        A string representation of the datetime.
    """
    if isinstance(obj, datetime):
        return obj.__str__()
    return obj


def zip_analysis(args: argparse.Namespace) -> Tuple[int, str]:
    """Tests, validates, and then archives all policies and rules into a local zip file.

    Returns 1 if the analysis tests or validation fails.

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A tuple of return code and the archive filename.
    """
    if not args.skip_tests:
        return_code, _ = test_analysis(args)
        if return_code == 1:
            return return_code, ''

    logging.info('Zipping analysis packs in %s to %s', args.path, args.out)
    # example: 2019-08-05T18-23-25
    # The colon character is not valid in filenames.
    current_time = datetime.now().isoformat(timespec='seconds').replace(
        ':', '-')
    filename = 'panther-analysis-{}.zip'.format(current_time)
    with zipfile.ZipFile(filename, 'w', zipfile.ZIP_DEFLATED) as zip_out:
        # Always zip the helpers and data models
        analysis = []
        files: Set[str] = set()
        for (file_name, f_path, spec, _) in list(
                load_analysis_specs(
                    [args.path, HELPERS_LOCATION, DATA_MODEL_LOCATION])):
            if file_name not in files:
                analysis.append((file_name, f_path, spec))
                files.add(file_name)
                files.add('./' + file_name)
        analysis = filter_analysis(analysis, args.filter)
        for analysis_spec_filename, dir_name, analysis_spec in analysis:
            zip_out.write(analysis_spec_filename)
            # datamodels may not have python body
            if 'Filename' in analysis_spec:
                zip_out.write(os.path.join(dir_name, analysis_spec['Filename']))

    return 0, filename


def upload_analysis(args: argparse.Namespace) -> Tuple[int, str]:
    """Tests, validates, packages, and uploads all policies and rules into a Panther deployment.

    Returns 1 if the analysis tests, validation, or packaging fails.

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A tuple of return code and the archive filename.
    """
    return_code, archive = zip_analysis(args)
    if return_code == 1:
        return return_code, ''

    # optionally set env variable for profile passed as argument
    # this must be called prior to setting up the client
    if args.aws_profile is not None:
        logging.info('Using AWS profile: %s', args.aws_profile)
        set_env("AWS_PROFILE", args.aws_profile)

    client = boto3.client('lambda')

    with open(archive, 'rb') as analysis_zip:
        zip_bytes = analysis_zip.read()
        payload = {
            'bulkUpload': {
                'data': base64.b64encode(zip_bytes).decode('utf-8'),
                # The UserID is required by Panther for this API call, but we have no way of
                # acquiring it and it isn't used for anything. This is a valid UUID used by the
                # Panther deployment tool to indicate this action was performed automatically.
                'userId': '00000000-0000-4000-8000-000000000000',
            },
        }

        logging.info('Uploading pack to Panther')
        response = client.invoke(FunctionName='panther-analysis-api',
                                 InvocationType='RequestResponse',
                                 LogType='None',
                                 Payload=json.dumps(payload))

        response_str = response['Payload'].read().decode('utf-8')
        response_payload = json.loads(response_str)

        if response_payload.get('statusCode') != 200:
            logging.warning(
                'Failed to upload to Panther\n\tstatus code: %s\n\terror message: %s',
                response_payload.get('statusCode', 0),
                response_payload.get('errorMessage',
                                     response_payload.get('body')))
            return 1, ''

        body = json.loads(response_payload['body'])
        logging.info('Upload success.')
        logging.info('API Response:\n%s',
                     json.dumps(body, indent=2, sort_keys=True))

    return 0, ''


def test_analysis(args: argparse.Namespace) -> Tuple[int, list]:
    """Imports each policy or rule and runs their tests.

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A tuple of the return code, and a list of tuples containing invalid specs and their error.
    """
    failed_tests: DefaultDict[str, list] = defaultdict(list)
    logging.info('Testing analysis packs in %s\n', args.path)

    # First classify each file, always include globals and data models location
    data_models, global_analysis, analysis, invalid_specs = classify_analysis(
        list(
            load_analysis_specs(
                [args.path, HELPERS_LOCATION, DATA_MODEL_LOCATION])))

    if all(len(x) == 0 for x in [data_models, global_analysis, analysis]):
        if len(invalid_specs) > 0:
            return 1, invalid_specs
        return 1, ["Nothing to test in {}".format(args.path)]

    # Apply the filters as needed
    data_models = filter_analysis(data_models, args.filter)
    global_analysis = filter_analysis(global_analysis, args.filter)
    analysis = filter_analysis(analysis, args.filter)

    if all(len(x) == 0 for x in [data_models, global_analysis, analysis]):
        return 1, [
            "No analyses in {} matched filters {}".format(
                args.path, args.filter)
        ]

    # import each data model, global, policy, or rule and run its tests
    # first import the globals
    #   add them sys.modules to be used by rule and/or policies tests
    invalid_globals = setup_global_helpers(global_analysis)
    invalid_specs.extend(invalid_globals)

    # then, setup data model dictionary to be used in rule/policy tests
    log_type_to_data_model, invalid_data_models = setup_data_models(data_models)
    invalid_specs.extend(invalid_data_models)

    # then, import rules and policies; run tests
    failed_tests, invalid_detection = setup_run_tests(log_type_to_data_model,
                                                      analysis,
                                                      args.minimum_tests)
    invalid_specs.extend(invalid_detection)

    print_summary(args.path, len(analysis), failed_tests, invalid_specs)
    return int(bool(failed_tests or invalid_specs)), invalid_specs


def setup_global_helpers(global_analysis: List[Any]) -> List[Any]:
    invalid_specs = []
    for analysis_spec_filename, dir_name, analysis_spec in global_analysis:
        analysis_id = analysis_spec['GlobalID']
        module, load_err = load_module(
            os.path.join(dir_name, analysis_spec['Filename']))
        # If the module could not be loaded, continue to the next
        if load_err:
            invalid_specs.append((analysis_spec_filename, load_err))
            continue
        sys.modules[analysis_id] = module
    return invalid_specs


def setup_data_models(
        data_models: List[Any]) -> Tuple[Dict[str, DataModel], List[Any]]:
    invalid_specs = []
    # log_type_to_data_model is a dict used to map LogType to a unique
    # data model, ensuring there is at most one DataModel per LogType
    log_type_to_data_model: Dict[str, DataModel] = dict()
    for analysis_spec_filename, dir_name, analysis_spec in data_models:
        analysis_id = analysis_spec['DataModelID']
        if analysis_spec['Enabled']:
            # load optional python modules
            module = None
            if 'Filename' in analysis_spec:
                module, load_err = load_module(
                    os.path.join(dir_name, analysis_spec['Filename']))
                # If the module could not be loaded, continue to the next
                if load_err:
                    invalid_specs.append((analysis_spec_filename, load_err))
                    continue
                sys.modules[analysis_id] = module
            # setup the mapping lookups
            data_model = DataModel(analysis_id, analysis_spec['Mappings'],
                                   module)
            # check if the LogType already has an enabled data model
            for log_type in analysis_spec['LogTypes']:
                if log_type in log_type_to_data_model:
                    print('\t[ERROR] Conflicting Enabled LogTypes\n')
                    invalid_specs.append(
                        (analysis_spec_filename,
                         'Conflicting Enabled LogType [{}] in Data Model [{}]'.
                         format(log_type, analysis_id)))
                    continue
                log_type_to_data_model[log_type] = data_model
    return log_type_to_data_model, invalid_specs


def setup_run_tests(
        log_type_to_data_model: Dict[str, DataModel], analysis: List[Any],
        minimum_tests: int) -> Tuple[DefaultDict[str, List[Any]], List[Any]]:
    invalid_specs = []
    failed_tests: DefaultDict[str, list] = defaultdict(list)
    for analysis_spec_filename, dir_name, analysis_spec in analysis:
        analysis_type = analysis_spec['AnalysisType']
        analysis_id = analysis_spec.get('PolicyID') or analysis_spec['RuleID']
        print(analysis_id)

        module, load_err = load_module(
            os.path.join(dir_name, analysis_spec['Filename']))
        # If the module could not be loaded, continue to the next
        if load_err:
            invalid_specs.append((analysis_spec_filename, load_err))
            continue

        analysis_funcs = {}
        if analysis_type == POLICY:
            analysis_funcs['run'] = module.policy
        elif analysis_type == RULE:
            analysis_funcs['run'] = module.rule
            if 'dedup' in dir(module):
                analysis_funcs['dedup'] = module.dedup
            if 'title' in dir(module):
                analysis_funcs['title'] = module.title

        failed_tests = run_tests(analysis_spec, analysis_funcs,
                                 log_type_to_data_model, failed_tests,
                                 minimum_tests)
        print('')
    return failed_tests, invalid_specs


def print_summary(test_path: str, num_tests: int, failed_tests: Dict[str, list],
                  invalid_specs: List[Any]) -> None:
    '''Print a summary of passed, failed, and invalid specs'''
    print('--------------------------')
    print('Panther CLI Test Summary')
    print('\tPath: {}'.format(test_path))
    print("\tPassed: {}".format(num_tests -
                                (len(failed_tests) + len(invalid_specs))))
    print("\tFailed: {}".format(len(failed_tests)))
    print("\tInvalid: {}\n".format(len(invalid_specs)))

    err_message = "\t{}\n\t\t{}\n"

    if failed_tests:
        print('--------------------------')
        print('Failed Tests Summary')
        for analysis_id in failed_tests:
            print(err_message.format(analysis_id, failed_tests[analysis_id]))

    if invalid_specs:
        print('--------------------------')
        print('Invalid Tests Summary')
        for spec_filename, spec_error in invalid_specs:
            print(err_message.format(spec_filename, spec_error))


def filter_analysis(analysis: List[Any], filters: Dict[str, List]) -> List[Any]:
    if filters is None:
        return analysis

    filtered_analysis = []
    for file_name, dir_name, analysis_spec in analysis:
        if fnmatch(dir_name, HELPERS_PATH_PATTERN):
            logging.debug('auto-adding helpers file %s',
                          os.path.join(file_name))
            filtered_analysis.append((file_name, dir_name, analysis_spec))
            continue
        if fnmatch(dir_name, DATA_MODEL_LOCATION):
            logging.debug('auto-adding data model file %s',
                          os.path.join(file_name))
            filtered_analysis.append((file_name, dir_name, analysis_spec))
            continue
        match = True
        for key, values in filters.items():
            spec_value = analysis_spec.get(key, "")
            spec_value = spec_value if isinstance(spec_value,
                                                  list) else [spec_value]
            if not set(spec_value).intersection(values):
                match = False
                break

        if match:
            filtered_analysis.append((file_name, dir_name, analysis_spec))

    return filtered_analysis


def classify_analysis(
    specs: List[Tuple[str, str, Any, Any]]
) -> Tuple[List[Any], List[Any], List[Any], List[Any]]:

    # First determine the type of each file
    data_models = []
    global_analysis = []
    analysis = []
    invalid_specs = []
    # each analysis type must have a unique id, track used ids and
    # add any duplicates to the invalid_specs
    analysis_ids = []

    for analysis_spec_filename, dir_name, analysis_spec, error in specs:
        keys = list()
        try:
            # check for parsing errors from json.loads (ValueError) / yaml.safe_load (YAMLError)
            if error:
                raise error
            # validate the schema
            TYPE_SCHEMA.validate(analysis_spec)
            if analysis_spec['AnalysisType'] == 'datamodel':
                keys = list(DATA_MODEL_SCHEMA.schema.keys())
                DATA_MODEL_SCHEMA.validate(analysis_spec)
                if analysis_spec['DataModelID'] in analysis_ids:
                    raise AnalysisIDConflictException(
                        analysis_spec['DataModelID'])
                analysis_ids.append(analysis_spec['DataModelID'])
                data_models.append(
                    (analysis_spec_filename, dir_name, analysis_spec))
            if analysis_spec['AnalysisType'] == 'global':
                keys = list(GLOBAL_SCHEMA.schema.keys())
                GLOBAL_SCHEMA.validate(analysis_spec)
                if analysis_spec['GlobalID'] in analysis_ids:
                    raise AnalysisIDConflictException(analysis_spec['GlobalID'])
                analysis_ids.append(analysis_spec['GlobalID'])
                global_analysis.append(
                    (analysis_spec_filename, dir_name, analysis_spec))
            if analysis_spec['AnalysisType'] == 'policy':
                keys = list(POLICY_SCHEMA.schema.keys())
                POLICY_SCHEMA.validate(analysis_spec)
                if analysis_spec['PolicyID'] in analysis_ids:
                    raise AnalysisIDConflictException(analysis_spec['PolicyID'])
                analysis_ids.append(analysis_spec['PolicyID'])
                analysis.append(
                    (analysis_spec_filename, dir_name, analysis_spec))
            if analysis_spec['AnalysisType'] == 'rule':
                keys = list(RULE_SCHEMA.schema.keys())
                RULE_SCHEMA.validate(analysis_spec)
                if analysis_spec['RuleID'] in analysis_ids:
                    raise AnalysisIDConflictException(analysis_spec['RuleID'])
                analysis_ids.append(analysis_spec['RuleID'])
                analysis.append(
                    (analysis_spec_filename, dir_name, analysis_spec))
        except SchemaWrongKeyError as err:
            invalid_specs.append(
                (analysis_spec_filename, handle_wrong_key_error(err, keys)))
        except (SchemaError, SchemaMissingKeyError, SchemaForbiddenKeyError,
                SchemaUnexpectedTypeError) as err:
            invalid_specs.append((analysis_spec_filename, err))
            continue
        except Exception as err:  # pylint: disable=broad-except
            # Catch arbitrary exceptions thrown by bad specification files
            invalid_specs.append((analysis_spec_filename, err))
            continue

    return (data_models, global_analysis, analysis, invalid_specs)


def handle_wrong_key_error(err: SchemaWrongKeyError, keys: list) -> Exception:
    regex = r"Wrong key(?:s)? (.+?) in (.*)$"
    matches = re.match(regex, str(err))
    msg = '{} not in list of valid keys: {}'
    try:
        if matches:
            raise SchemaWrongKeyError(msg.format(matches.group(1),
                                                 keys)) from err
        raise SchemaWrongKeyError(msg.format('UNKNOWN_KEY', keys)) from err
    except SchemaWrongKeyError as exc:
        return exc


def run_tests(analysis: Dict[str, Any], analysis_funcs: Dict[str, Any],
              analysis_data_models: Dict[str, DataModel],
              failed_tests: DefaultDict[str, list],
              minimum_tests: int) -> DefaultDict[str, list]:

    if len(analysis.get('Tests', [])) < minimum_tests:
        failed_tests[analysis.get('PolicyID') or analysis['RuleID']].append(
            'Insufficient test coverage: {} tests required but only {} found'.
            format(minimum_tests, len(analysis.get('Tests', []))))

    # First check if any tests exist, so we can print a helpful message if not
    if 'Tests' not in analysis:
        analysis_id = analysis.get('PolicyID') or analysis['RuleID']
        print('\tNo tests configured for {}'.format(analysis_id))
        return failed_tests

    for unit_test in analysis['Tests']:
        try:
            entry = unit_test.get('Resource') or unit_test['Log']
            log_type = entry.get('p_log_type', '')
            # set up each test case, including any relevant data models
            test_case = TestCase(entry, analysis_data_models.get(log_type))
            result = analysis_funcs['run'](test_case)
        except KeyError as err:
            logging.warning('KeyError: {%s}', err)
            failed_tests[analysis.get('PolicyID') or
                         analysis['RuleID']].append(unit_test['Name'])
            continue
        except Exception as err:  # pylint: disable=broad-except
            # Catch arbitrary exceptions raised by user code
            logging.warning('Unexpected exception: {%s}', err)
            failed_tests[analysis.get('PolicyID') or
                         analysis['RuleID']].append(unit_test['Name'])
            continue

        # using a dictionary to map between the tests and their outcomes
        # assume the test passes (default "PASS")
        # until failure condition is found (set to "FAIL")
        test_result = defaultdict(lambda: 'PASS')
        # check expected result
        if result != unit_test['ExpectedResult']:
            test_result['outcome'] = 'FAIL'

        # check dedup and title function return non-None
        # Only applies to rules which match an incoming event
        if unit_test['ExpectedResult']:
            for func in ['dedup', 'title']:
                if analysis_funcs.get(func):
                    if not analysis_funcs[func](test_case):
                        test_result[func] = 'FAIL'
                        test_result['outcome'] = 'FAIL'

        if test_result['outcome'] == 'FAIL':
            failed_tests[analysis.get('PolicyID') or
                         analysis['RuleID']].append(unit_test['Name'])

        # print results
        print('\t[{}] {}'.format(test_result['outcome'], unit_test['Name']))
        for func in ['dedup', 'title']:
            if analysis_funcs.get(func) and unit_test['ExpectedResult']:
                print('\t\t[{}] [{}] {}'.format(
                    test_result[func], func, analysis_funcs[func](test_case)))

    if minimum_tests > 1 and not (
        [x for x in analysis['Tests'] if x['ExpectedResult']] and
        [x for x in analysis['Tests'] if not x['ExpectedResult']]):
        failed_tests[analysis.get('PolicyID') or analysis['RuleID']].append(
            'Insufficient test coverage: expected at least one positive and one negative test'
        )

    return failed_tests


def setup_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=
        'Panther Analysis Tool: A command line tool for managing Panther policies and rules.',
        prog='panther_analysis_tool')
    parser.add_argument('--version',
                        action='version',
                        version='panther_analysis_tool 0.4.5')
    subparsers = parser.add_subparsers()

    test_parser = subparsers.add_parser(
        'test',
        help='Validate analysis specifications and run policy and rule tests.')
    test_parser.add_argument(
        '--path',
        default='.',
        type=str,
        help='The relative path to Panther policies and rules.',
        required=False)
    test_parser.add_argument('--filter',
                             required=False,
                             metavar="KEY=VALUE",
                             nargs='+')
    test_parser.add_argument(
        '--minimum-tests',
        default='0',
        type=int,
        help=
        'The minimum number of tests in order for a detection to be considered passing. If a number'
        +
        'greater than 1 is specified, at least one True and one False test is required.',
        required=False)
    test_parser.add_argument('--debug', action='store_true', dest='debug')
    test_parser.set_defaults(func=test_analysis)

    zip_parser = subparsers.add_parser(
        'zip',
        help=
        'Create an archive of local policies and rules for uploading to Panther.'
    )
    zip_parser.add_argument(
        '--path',
        default='.',
        type=str,
        help='The relative path to Panther policies and rules.',
        required=False)
    zip_parser.add_argument(
        '--out',
        default='.',
        type=str,
        help='The path to write zipped policies and rules to.',
        required=False)
    zip_parser.add_argument('--filter',
                            required=False,
                            metavar="KEY=VALUE",
                            nargs='+')
    zip_parser.add_argument(
        '--minimum-tests',
        default='0',
        type=int,
        help=
        'The minimum number of tests in order for a detection to be considered passing. If a number'
        +
        'greater than 1 is specified, at least one True and one False test is required.',
        required=False)
    zip_parser.add_argument('--debug', action='store_true', dest='debug')
    zip_parser.add_argument('--skip-tests',
                            action='store_true',
                            dest='skip_tests')
    zip_parser.set_defaults(func=zip_analysis)

    upload_parser = subparsers.add_parser(
        'upload',
        help='Upload specified policies and rules to a Panther deployment.')
    upload_parser.add_argument(
        '--aws-profile',
        type=str,
        help=
        'The AWS profile to use when uploading to an AWS Panther deployment.',
        required=False)
    upload_parser.add_argument(
        '--path',
        default='.',
        type=str,
        help='The relative path to Panther policies and rules.',
        required=False)
    upload_parser.add_argument(
        '--out',
        default='.',
        type=str,
        help=
        'The location to store a local copy of the packaged policies and rules.',
        required=False)
    upload_parser.add_argument(
        '--minimum-tests',
        default='0',
        type=int,
        help=
        'The minimum number of tests in order for a detection to be considered passing. If a number'
        +
        'greater than 1 is specified, at least one True and one False test is required.',
        required=False)
    upload_parser.add_argument('--filter',
                               required=False,
                               metavar="KEY=VALUE",
                               nargs='+')
    upload_parser.add_argument('--debug', action='store_true', dest='debug')
    upload_parser.add_argument('--skip-tests',
                               action='store_true',
                               dest='skip_tests')
    upload_parser.set_defaults(func=upload_analysis)

    return parser


# Parses the filters, expects a list of strings
def parse_filter(filters: List[str]) -> Dict[str, Any]:
    parsed_filters = {}
    for filt in filters:
        split = filt.split('=')
        if len(split) != 2 or split[0] == '' or split[1] == '':
            logging.warning('Filter %s is not in format KEY=VALUE, skipping',
                            filt)
            continue
        key = split[0]
        if not any([
                key in (list(GLOBAL_SCHEMA.schema.keys()) +
                        list(POLICY_SCHEMA.schema.keys()) +
                        list(RULE_SCHEMA.schema.keys()))
                for key in (key, Optional(key))
        ]):
            logging.warning(
                'Filter key %s is not a valid filter field, skipping', key)
            continue
        parsed_filters[key] = split[1].split(',')
    return parsed_filters


def set_env(key: str, value: str) -> None:
    os.environ[key] = value


def run() -> None:
    parser = setup_parser()
    # if no args are passed, print the help output
    args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])

    logging.basicConfig(format='[%(levelname)s]: %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    try:
        if args.filter is not None:
            args.filter = parse_filter(args.filter)
        return_code, out = args.func(args)
    except Exception as err:  # pylint: disable=broad-except
        # Catch arbitrary exceptions without printing help message
        logging.warning('Unhandled exception: "%s"', err)
        sys.exit(1)

    if return_code == 1:
        if out:
            logging.error(out)
    elif return_code == 0:
        if out:
            logging.info(out)

    sys.exit(return_code)


if __name__ == '__main__':
    run()
