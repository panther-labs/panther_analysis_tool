from unittest import mock

from panther_analysis_tool.backend.client import (
    Client as BackendClient,
    BackendResponse,
    BulkUploadParams,
    ListDetectionsParams,
    DeleteDetectionsParams,
    ListSavedQueriesParams,
    DeleteSavedQueriesParams,
)

class MockBackend(BackendClient):
    bulk_upload_returns: BackendResponse
    list_detections_returns: BackendResponse
    delete_detections_returns: BackendResponse
    list_saved_queries_returns: BackendResponse
    delete_saved_queries_returns: BackendResponse

    def bulk_upload(self, params: BulkUploadParams) -> BackendResponse:
        return self.bulk_upload_returns

    def list_detections(self, params: ListDetectionsParams) -> BackendResponse:
        return self.list_detections_returns

    def list_saved_queries(self, params: ListSavedQueriesParams) -> BackendResponse:
        return self.list_saved_queries_returns

    def delete_saved_queries(self, params: DeleteSavedQueriesParams) -> BackendResponse:
        return self.delete_saved_queries_returns

    def delete_detections(self, params: DeleteDetectionsParams) -> BackendResponse:
        return self.delete_detections_returns


