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

from schema import Optional, Or, Schema

TYPE_SCHEMA = Schema({
    'AnalysisType': Or("policy", "rule", "global"),
},
                     ignore_extra_keys=True)

GLOBAL_SCHEMA = Schema(
    {
        'AnalysisType': Or("global"),
        'Filename': str,
        'GlobalID': str,
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
        Optional('OutputIds'): [str],
        Optional('Reference'):
            str,
        Optional('Runbook'):
            str,
        Optional('Suppressions'): [str],
        Optional('Tags'): [str],
        Optional('Reports'): {
            str: list
        },
        Optional('Tests'): [{
            'Name': str,
            Optional('ResourceType'):
                str,  # Not needed anymore, optional for backwards compatibility
            'ExpectedResult': bool,
            'Resource': object,
        }],
    },
    ignore_extra_keys=False)  # Prevent user typos on optional fields

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
        Optional('OutputIds'): [str],
        Optional('Reference'):
            str,
        Optional('Runbook'):
            str,
        Optional('Threshold'):
            str,
        Optional('Suppressions'): [str],
        Optional('Tags'): [str],
        Optional('Reports'): {
            str: list
        },
        Optional('Tests'): [{
            'Name': str,
            Optional('LogType'):
                str,  # Not needed anymore, optional for backwards compatibility
            'ExpectedResult': bool,
            'Log': object,
        }],
    },
    ignore_extra_keys=False)  # Prevent user typos on optional fields
