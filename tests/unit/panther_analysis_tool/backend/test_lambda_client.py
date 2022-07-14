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

import json
from typing import Any, Dict
from unittest import TestCase, mock

from panther_analysis_tool.backend.client import BulkUploadParams
from panther_analysis_tool.backend.lambda_client import LambdaClient, LambdaClientOpts


class MockBoto:
    invoke: mock.MagicMock

    def __init__(self, invoke_returns: Any) -> None:
        self.invoke = mock.MagicMock(return_value=invoke_returns)


def _make_mock_response(http_status: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "Payload": json.dumps(payload).encode('utf-8'),
        "ResponseMetadata": {"HTTPStatusCode": http_status},
    }


class TestLambdaClient(TestCase):

    def test_init(self) -> None:
        with mock.patch('boto3.client', return_value=MockBoto(invoke_returns=None)):
            lc = LambdaClient(LambdaClientOpts(datalake_lambda="x", user_id="user", aws_profile=None))
            self.assertEqual(lc._user_id, "user")

    def test_bulk_upload(self) -> None:
        mock_lambda_res = _make_mock_response(http_status=200, payload={"totalPolicies": 2})

        with mock.patch('boto3.client', return_value=MockBoto(invoke_returns=mock_lambda_res)):
            lc = LambdaClient(LambdaClientOpts(datalake_lambda="x", user_id="user", aws_profile=None))
            result = lc.bulk_upload(BulkUploadParams(zip_bytes=b""))
            self.assertEqual(result.data["totalPolicies"], 2)
