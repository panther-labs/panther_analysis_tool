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
from typing import Any, DefaultDict, Dict, Iterator, List, Tuple
import argparse
import base64
import importlib.util
import json
import logging
import os
import sys
import zipfile

from schema import (Optional, SchemaError, SchemaMissingKeyError,
                    SchemaForbiddenKeyError, SchemaUnexpectedTypeError)
import boto3
import yaml

from panther_analysis_tool.schemas import TYPE_SCHEMA, GLOBAL_SCHEMA, POLICY_SCHEMA, RULE_SCHEMA

HELPERS_LOCATION = './global_helpers'

HELPERS_PATH_PATTERN = '*/global_helpers'
RULES_PATH_PATTERN = '*rules*'
POLICIES_PATH_PATTERN = '*policies*'


class TestCase():

    def __init__(self, data: Dict[str, Any], schema: str) -> None:
        self._data = data
        self.schema = schema

    def __getitem__(self, arg: str) -> Any:
        return self._data.get(arg, None)

    def __iter__(self) -> Iterator:
        return iter(self._data)

    def get(self, arg: str, default: Any = None) -> Any:
        return self._data.get(arg, default)


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
        print('\t[ERROR] File not found, skipping\n')
        return None, err
    except Exception as err:  # pylint: disable=broad-except
        # Catch arbitrary exceptions thrown by user code
        print('\t[ERROR] Error loading module, skipping\n')
        return None, err
    return module, None


def load_analysis_specs(directory: str) -> Iterator[Tuple[str, str, Any]]:
    """Loads the analysis specifications from a file.

    Args:
        directory: The relative path to Panther policies or rules.

    Yields:
        A tuple of the relative filepath, directory name, and loaded analysis specification dict.
    """
    for relative_path, _, file_list in os.walk(directory):
        # If the user runs with no path/out args, filter to make sure
        # we only run folders with valid analysis files.
        if directory == '.':
            if not any([
                    fnmatch(relative_path, path_pattern)
                    for path_pattern in (HELPERS_PATH_PATTERN,
                                         RULES_PATH_PATTERN,
                                         POLICIES_PATH_PATTERN)
            ]):
                logging.debug('Skipping path %s', relative_path)
                continue
        for filename in sorted(file_list):
            spec_filename = os.path.join(relative_path, filename)
            if fnmatch(filename, '*.y*ml'):
                with open(spec_filename, 'r') as spec_file_obj:
                    yield spec_filename, relative_path, yaml.safe_load(
                        spec_file_obj)
            if fnmatch(filename, '*.json'):
                with open(spec_filename, 'r') as spec_file_obj:
                    yield spec_filename, relative_path, json.load(spec_file_obj)


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
        # Always zip the helpers
        analysis = []
        files: Dict[str, Any] = {}
        for (file_name, f_path, spec) in list(load_analysis_specs(
                args.path)) + list(load_analysis_specs(HELPERS_LOCATION)):
            if file_name not in files:
                analysis.append((file_name, f_path, spec))
                files[file_name] = None
        analysis = filter_analysis(analysis, args.filter)
        for analysis_spec_filename, dir_name, analysis_spec in analysis:
            zip_out.write(analysis_spec_filename)
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

    client = boto3.client('lambda')

    with open(archive, 'rb') as analysis_zip:
        zip_bytes = analysis_zip.read()
        payload = {
            'resource':
                '/upload',
            'HTTPMethod':
                'POST',
            'Body':
                json.dumps({
                    'Data': base64.b64encode(zip_bytes).decode('utf-8'),
                    # The UserID is required by Panther for this API call, but we have no way of
                    # acquiring it and it isn't used for anything. This is a valid UUID used by the
                    # Panther deployment tool to indicate this action was performed automatically.
                    'UserID': '00000000-0000-4000-8000-000000000000',
                }),
        }

        logging.info('Uploading pack to Panther')
        response = client.invoke(FunctionName='panther-analysis-api',
                                 InvocationType='RequestResponse',
                                 LogType='None',
                                 Payload=json.dumps(payload))

        response_str = response['Payload'].read().decode('utf-8')
        response_payload = json.loads(response_str)

        if response_payload['statusCode'] != 200:
            logging.warning(
                'Failed to upload to Panther\n\tstatus code: %s\n\terror message: %s',
                response_payload['statusCode'], response_payload['body'])
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
    tests: List[str] = []
    logging.info('Testing analysis packs in %s\n', args.path)

    # First classify each file
    global_analysis, analysis, invalid_specs = classify_analysis(
        list(load_analysis_specs(args.path)) +
        list(load_analysis_specs(HELPERS_LOCATION)))

    if len(analysis) == 0:
        return 1, ["Nothing to test in {}".format(args.path)]

    # Apply the filters as needed
    global_analysis = filter_analysis(global_analysis, args.filter)
    analysis = filter_analysis(analysis, args.filter)

    if len(analysis) == 0:
        return 1, [
            "No analyses in {} matched filters {}".format(
                args.path, args.filter)
        ]

    # First import the globals
    for analysis_spec_filename, dir_name, analysis_spec in global_analysis:
        module, load_err = load_module(
            os.path.join(dir_name, analysis_spec['Filename']))
        # If the module could not be loaded, continue to the next
        if load_err:
            invalid_specs.append((analysis_spec_filename, load_err))
            break
        sys.modules[analysis_spec['GlobalID']] = module

    # Next import each policy or rule and run its tests
    for analysis_spec_filename, dir_name, analysis_spec in analysis:
        analysis_id = analysis_spec.get('PolicyID') or analysis_spec['RuleID']
        print(analysis_id)

        # Check if the AnalysisID has already been loaded
        if analysis_id in tests:
            print('\t[ERROR] Conflicting AnalysisID\n')
            invalid_specs.append(
                (analysis_spec_filename,
                 'Conflicting AnalysisID: {}'.format(analysis_id)))
            continue

        module, load_err = load_module(
            os.path.join(dir_name, analysis_spec['Filename']))
        # If the module could not be loaded, continue to the next
        if load_err:
            invalid_specs.append((analysis_spec_filename, load_err))
            continue

        tests.append(analysis_id)
        analysis_funcs = {}
        if analysis_spec['AnalysisType'] == 'policy':
            analysis_funcs['run'] = module.policy
        elif analysis_spec['AnalysisType'] == 'rule':
            analysis_funcs['run'] = module.rule
            if 'dedup' in dir(module):
                analysis_funcs['dedup'] = module.dedup
            if 'title' in dir(module):
                analysis_funcs['title'] = module.title

        failed_tests = run_tests(analysis_spec, analysis_funcs, failed_tests)
        print('')

    print_summary(args.path, len(analysis), failed_tests, invalid_specs)
    return int(bool(failed_tests or invalid_specs)), invalid_specs


def print_summary(test_path: str, num_tests: int, failed_tests: List[Any],
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
    specs: List[Tuple[str, str, Any]]
) -> Tuple[List[Any], List[Any], List[Any]]:
    # First determine the type of each file
    global_analysis = []
    analysis = []
    invalid_specs = []

    for analysis_spec_filename, dir_name, analysis_spec in specs:
        try:
            TYPE_SCHEMA.validate(analysis_spec)
            if analysis_spec['AnalysisType'] == 'policy':
                POLICY_SCHEMA.validate(analysis_spec)
                analysis.append(
                    (analysis_spec_filename, dir_name, analysis_spec))
            if analysis_spec['AnalysisType'] == 'rule':
                RULE_SCHEMA.validate(analysis_spec)
                analysis.append(
                    (analysis_spec_filename, dir_name, analysis_spec))
            if analysis_spec['AnalysisType'] == 'global':
                GLOBAL_SCHEMA.validate(analysis_spec)
                global_analysis.append(
                    (analysis_spec_filename, dir_name, analysis_spec))
        except (SchemaError, SchemaMissingKeyError, SchemaForbiddenKeyError,
                SchemaUnexpectedTypeError) as err:
            invalid_specs.append((analysis_spec_filename, err))
            continue
        except Exception as err:  # pylint: disable=broad-except
            # Catch arbitrary exceptions thrown by bad specification files
            invalid_specs.append((analysis_spec_filename, err))
            continue

    return (global_analysis, analysis, invalid_specs)


def run_tests(analysis: Dict[str, Any], analysis_funcs: Dict[str, Any],
              failed_tests: DefaultDict[str, list]) -> DefaultDict[str, list]:

    # First check if any tests exist, so we can print a helpful message if not
    if 'Tests' not in analysis:
        analysis_id = analysis.get('PolicyID') or analysis['RuleID']
        print('\tNo tests configured for {}'.format(analysis_id))
        return failed_tests

    for unit_test in analysis['Tests']:
        try:
            test_case = TestCase(
                unit_test.get('Resource') or unit_test['Log'],
                unit_test.get('ResourceType') or unit_test['LogType'])
            result = analysis_funcs['run'](test_case)
        except KeyError as err:
            logging.warning('KeyError: {%s}', err)
            continue
        except Exception as err:  # pylint: disable=broad-except
            # Catch arbitrary exceptions raised by user code
            logging.warning('Unexpected exception: {%s}', err)
            continue
        test_result = 'PASS'
        if result != unit_test['ExpectedResult']:
            test_result = 'FAIL'
            failed_tests[analysis.get('PolicyID') or
                         analysis['RuleID']].append(unit_test['Name'])
        print('\t[{}] {}'.format(test_result, unit_test['Name']))
        if analysis_funcs.get('title') and unit_test['ExpectedResult']:
            print('\t\t[Title] {}'.format(analysis_funcs['title'](test_case)))
        if analysis_funcs.get('dedup') and unit_test['ExpectedResult']:
            print('\t\t[Dedup] {}'.format(analysis_funcs['dedup'](test_case)))

    return failed_tests


def setup_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=
        'Panther Analysis Tool: A command line tool for managing Panther policies and rules.',
        prog='panther_analysis_tool')
    parser.add_argument('--version',
                        action='version',
                        version='panther_analysis_tool 0.3.2')
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
    zip_parser.add_argument('--debug', action='store_true', dest='debug')
    zip_parser.set_defaults(func=zip_analysis)

    upload_parser = subparsers.add_parser(
        'upload',
        help='Upload specified policies and rules to a Panther deployment.')
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
    upload_parser.add_argument('--filter',
                               required=False,
                               metavar="KEY=VALUE",
                               nargs='+')
    upload_parser.add_argument('--debug', action='store_true', dest='debug')
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


def run() -> None:
    parser = setup_parser()
    args = parser.parse_args()

    logging.basicConfig(format='[%(levelname)s]: %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    try:
        if args.filter is not None:
            args.filter = parse_filter(args.filter)
        return_code, out = args.func(args)
    except AttributeError:
        parser.print_help()
        sys.exit(1)
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
