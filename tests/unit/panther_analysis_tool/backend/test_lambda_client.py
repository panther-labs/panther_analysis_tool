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
            http_status=200,
            payload={
                "rules": {"total": 0, "new": 0, "modified": 0, "deleted": 0},
                "queries": {"total": 0, "new": 0, "modified": 0, "deleted": 0},
                "policies": {"total": 2, "new": 0, "modified": 0, "deleted": 0},
                "data_models": {"total": 0, "new": 0, "modified": 0, "deleted": 0},
                "lookup_tables": {"total": 0, "new": 0, "modified": 0, "deleted": 0},
                "global_helpers": {"total": 0, "new": 0, "modified": 0, "deleted": 0},
                "correlation_rules": {"total": 0, "new": 0, "modified": 0, "deleted": 0},
            },
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
