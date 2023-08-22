import unittest
from unittest import mock

from panther_analysis_tool.backend.client import (
    BackendResponse,
    DeleteDetectionsResponse,
    DeleteSavedQueriesResponse,
)
from panther_analysis_tool.backend.mocks import MockBackend
from panther_analysis_tool.command.bulk_delete import (
    _delete_detections_dry_run,
    _delete_queries_dry_run,
)


class TestBulkDelete(unittest.TestCase):
    def test_delete_detections_dry_run(self) -> None:
        mock_ids = ["1", "2", "3"]
        backend = MockBackend()
        backend.delete_detections = mock.MagicMock(
            return_value=BackendResponse(
                data=DeleteDetectionsResponse(ids=mock_ids, saved_query_names=["a"]),
                status_code=200,
            )
        )

        code, msg = _delete_detections_dry_run(backend, mock_ids)
        self.assertEqual(code, 0)
        self.assertEqual(msg, "")

    def test_delete_queries_dry_run(self) -> None:
        mock_names = ["a", "b", "c"]
        backend = MockBackend()
        backend.delete_saved_queries = mock.MagicMock(
            return_value=BackendResponse(
                data=DeleteSavedQueriesResponse(names=mock_names, detection_ids=["1"]),
                status_code=200,
            )
        )

        code, msg = _delete_queries_dry_run(backend, mock_names)
        self.assertEqual(code, 0)
        self.assertEqual(msg, "")
