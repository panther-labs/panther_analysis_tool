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
from typing import Any, Dict
from unittest import TestCase, mock

from panther_analysis_tool.backend.client import (
    BulkUploadParams,
    DeleteDetectionsParams,
    TranspileFiltersParams,
    TranspileToPythonParams,
)
from panther_analysis_tool.backend.lambda_client import LambdaClient, LambdaClientOpts


class MockBoto:
    invoke: mock.MagicMock

    def __init__(self, invoke_returns: Any) -> None:
        self.invoke = mock.MagicMock(return_value=invoke_returns)


# use this for standard lambda responses
def _make_mock_response(http_status: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "Payload": io.BytesIO(json.dumps(payload).encode("utf-8")),
        "ResponseMetadata": {"HTTPStatusCode": http_status},
    }


# use this for wrapped "gateway" responses
def _make_mock_response_with_string_body(
    http_status: int, payload: Dict[str, Any]
) -> Dict[str, Any]:
    return _make_mock_response(
        http_status=http_status,
        payload={
            "body": json.dumps(payload),
            "headers": {},
            "statusCode": http_status,
            "multiValueHeaders": {},
        },
    )


class TestLambdaClient(TestCase):
    def test_init(self) -> None:
        with mock.patch("boto3.client", return_value=MockBoto(invoke_returns=None)):
            lc = LambdaClient(
                LambdaClientOpts(datalake_lambda="x", user_id="user", aws_profile=None)
            )
            self.assertEqual(lc._user_id, "user")

    def test_bulk_upload(self) -> None:
        mock_lambda_res = _make_mock_response_with_string_body(
            http_status=200, payload={"policies": {"total": 2, "new": 0, "modified": 0}}
        )

        with mock.patch("boto3.client", return_value=MockBoto(invoke_returns=mock_lambda_res)):
            lc = LambdaClient(
                LambdaClientOpts(datalake_lambda="x", user_id="user", aws_profile=None)
            )
            result = lc.bulk_upload(BulkUploadParams(zip_bytes=b""))

            self.assertEqual(result.data.policies.total, 2)
            self.assertEqual(result.data.rules.total, 0)

    def test_bulk_validate(self) -> None:
        with self.assertRaises(BaseException):
            lc = LambdaClient(
                LambdaClientOpts(datalake_lambda="x", user_id="user", aws_profile=None)
            )
            lc.bulk_validate(BulkUploadParams(zip_bytes=b"yo"))

    def test_delete_detections(self) -> None:
        mock_lambda_res = _make_mock_response_with_string_body(
            http_status=200, payload={"ids": ["1", "2"], "savedQueryNames": None}
        )

        with mock.patch("boto3.client", return_value=MockBoto(invoke_returns=mock_lambda_res)):
            lc = LambdaClient(
                LambdaClientOpts(datalake_lambda="x", user_id="user", aws_profile=None)
            )
            result = lc.delete_detections(
                DeleteDetectionsParams(
                    dry_run=True, ids=["1", "2", "3"], include_saved_queries=False
                )
            )

            self.assertEqual(["1", "2"], result.data.ids)
            self.assertEqual([], result.data.saved_query_names)

    def test_transpile_to_python(self) -> None:
        with self.assertRaises(BaseException):
            lc = LambdaClient(
                LambdaClientOpts(datalake_lambda="x", user_id="user", aws_profile=None)
            )
            lc.transpile_simple_detection_to_python(TranspileToPythonParams(data=[""]))

    def test_transpile_filters(self) -> None:
        with self.assertRaises(BaseException):
            lc = LambdaClient(
                LambdaClientOpts(datalake_lambda="x", user_id="user", aws_profile=None)
            )
            lc.transpile_filters(TranspileFiltersParams(data=[""]))
