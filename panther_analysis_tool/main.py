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

import argparse
import base64
from datetime import datetime
import importlib.util
from importlib.abc import Loader
from collections import defaultdict
import json
import logging
import os
import sys
from typing import Any, Callable, DefaultDict, Dict, Iterator, List, Tuple
import zipfile
from schema import (Optional, Or, Schema, SchemaError, SchemaMissingKeyError,
                    SchemaForbiddenKeyError, SchemaUnexpectedTypeError)
import yaml

import boto3


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


TYPE_SCHEMA = Schema({
    'AnalysisType': Or("policy", "rule", "global"),
},
                     ignore_extra_keys=True)

GLOBAL_SCHEMA = Schema(
    {
        'AnalysisType': Or("global"),
        'Filename': str,
        Optional('Description'): str,
        Optional('Tags'): [str],
    },
    ignore_extra_keys=False)

POLICY_SCHEMA = Schema(
    {
        'AnalysisType':
            Or("policy"),
        'Enabled':
            bool,
        'Filename':
            str,
        'PolicyID':
            str,
        'ResourceTypes': [str],
        'Severity':
            Or("Info", "Low", "Medium", "High", "Critical"),
        Optional('ActionDelaySeconds'):
            int,
        Optional('AutoRemediationID'):
            str,
        Optional('AutoRemediationParameters'):
            object,
        Optional('Description'):
            str,
        Optional('DisplayName'):
            str,
        Optional('Reference'):
            str,
        Optional('Runbook'):
            str,
        Optional('Suppressions'): [str],
        Optional('Tags'): [str],
        Optional('Reports'): {
            str: object
        },
        Optional('Tests'): [{
            'Name': str,
            'ResourceType': str,
            'ExpectedResult': bool,
            'Resource': object,
        }],
    },
    ignore_extra_keys=False)

RULE_SCHEMA = Schema(
    {
        'AnalysisType':
            Or("rule"),
        'Enabled':
            bool,
        'Filename':
            str,
        'RuleID':
            str,
        'LogTypes': [str],
        'Severity':
            Or("Info", "Low", "Medium", "High", "Critical"),
        Optional('Description'):
            str,
        Optional('DedupPeriodMinutes'):
            int,
        Optional('DisplayName'):
            str,
        Optional('Reference'):
            str,
        Optional('Runbook'):
            str,
        Optional('Suppressions'): [str],
        Optional('Tags'): [str],
        Optional('Reports'): {
            str: object
        },
        Optional('Tests'): [{
            'Name': str,
            'LogType': str,
            'ExpectedResult': bool,
            'Log': object,
        }],
    },
    ignore_extra_keys=False)


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
    for dir_name, _, file_list in os.walk(directory):
        for filename in sorted(file_list):
            spec_filename = os.path.join(dir_name, filename)
            if filename.endswith('.yaml') or filename.endswith('.yml'):
                with open(spec_filename, 'r') as spec_file_obj:
                    yield spec_filename, dir_name, yaml.safe_load(spec_file_obj)
            if filename.endswith('.json'):
                with open(spec_filename, 'r') as spec_file_obj:
                    yield spec_filename, dir_name, json.load(spec_file_obj)


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
        analysis = filter_analysis(list(load_analysis_specs(args.path)),
                                   args.filter)
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
    specs = list(load_analysis_specs(args.path))
    global_analysis, analysis, invalid_specs = classify_analysis(specs)

    # Apply the filters as needed
    global_analysis = filter_analysis(global_analysis, args.filter)
    analysis = filter_analysis(analysis, args.filter)

    # First import the globals
    for analysis_spec_filename, dir_name, analysis_spec in global_analysis:
        module, load_err = load_module(
            os.path.join(dir_name, analysis_spec['Filename']))
        # If the module could not be loaded, continue to the next
        if load_err:
            invalid_specs.append((analysis_spec_filename, load_err))
            break
        sys.modules['panther'] = module

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
        if analysis_spec['AnalysisType'] == 'policy':
            failed_tests = run_tests(analysis_spec, module.policy, failed_tests)
        elif analysis_spec['AnalysisType'] == 'rule':
            failed_tests = run_tests(analysis_spec, module.rule, failed_tests)
        print('')

    for analysis_id in failed_tests:
        print("Failed: {}\n\t{}\n".format(analysis_id,
                                          failed_tests[analysis_id]))

    for spec_filename, spec_error in invalid_specs:
        print("Invalid: {}\n\t{}\n".format(spec_filename, spec_error))

    return int(bool(failed_tests or invalid_specs)), invalid_specs


def filter_analysis(analysis: List[Any], filters: Dict[str, List]) -> List[Any]:
    if filters is None:
        return analysis

    filtered_analysis = []
    for file_name, dir_name, analysis_spec in analysis:
        if all(
                analysis_spec.get(key, "") in values
                for key, values in filters.items()):
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

    return (global_analysis, analysis, invalid_specs)


def run_tests(analysis: Dict[str, Any], run_func: Callable[[TestCase], bool],
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
            result = run_func(test_case)
        except KeyError as err:
            print("KeyError: {0}".format(err))
            continue
        test_result = 'PASS'
        if result != unit_test['ExpectedResult']:
            test_result = 'FAIL'
            failed_tests[analysis.get('PolicyID') or
                         analysis['RuleID']].append(unit_test['Name'])
        print('\t[{}] {}'.format(test_result, unit_test['Name']))

    return failed_tests


def setup_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=
        'Panther Analysis Tool: A command line tool for managing Panther policies and rules.',
        prog='panther_analysis_tool')
    parser.add_argument('--version',
                        action='version',
                        version='panther_analysis_tool 0.2.2')
    subparsers = parser.add_subparsers()

    test_parser = subparsers.add_parser(
        'test',
        help='Validate analysis specifications and run policy and rule tests.')
    test_parser.add_argument(
        '--path',
        type=str,
        help='The relative path to Panther policies and rules.',
        required=True)
    test_parser.add_argument('--filter',
                             required=False,
                             metavar="KEY=VALUE",
                             nargs='+')
    test_parser.set_defaults(func=test_analysis)

    zip_parser = subparsers.add_parser(
        'zip',
        help=
        'Create an archive of local policies and rules for uploading to Panther.'
    )
    zip_parser.add_argument(
        '--path',
        type=str,
        help='The relative path to Panther policies and rules.',
        required=True)
    zip_parser.add_argument(
        '--out',
        type=str,
        help='The path to write zipped policies and rules to.',
        required=True)
    zip_parser.add_argument('--filter',
                            required=False,
                            metavar="KEY=VALUE",
                            nargs='+')
    zip_parser.set_defaults(func=zip_analysis)

    upload_parser = subparsers.add_parser(
        'upload',
        help='Upload specified policies and rules to a Panther deployment.')
    upload_parser.add_argument(
        '--path',
        type=str,
        help='The relative path to Panther policies and rules.',
        required=True)
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
        if key not in list(GLOBAL_SCHEMA.schema.keys()) + list(
                POLICY_SCHEMA.schema.keys()) + list(RULE_SCHEMA.schema.keys()):
            logging.warning(
                'Filter key %s is not a valid filter field, skipping', key)
            continue
        parsed_filters[key] = split[1].split(',')
    return parsed_filters


def run() -> None:
    logging.basicConfig(format='[%(levelname)s]: %(message)s',
                        level=logging.INFO)

    parser = setup_parser()
    args = parser.parse_args()
    try:
        if args.filter is not None:
            args.filter = parse_filter(args.filter)
        return_code, out = args.func(args)
    except AttributeError:
        parser.print_help()
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
