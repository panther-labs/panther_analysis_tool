from typing import Any, Optional

from panther_analysis_tool.backend.client import (
    Client as BackendClient,
    BackendResponse,
    BulkUploadParams,
    BulkUploadResponse,
    BackendCheckResponse,
    DeleteDetectionsParams,
    DeleteDetectionsResponse,
    DeleteSavedQueriesParams,
    UpdateManagedSchemasParams,
    DeleteSavedQueriesResponse, ListSchemasParams,
)


class MockBackend(BackendClient):
    check_returns: BackendCheckResponse
    bulk_upload_returns: BackendResponse[BulkUploadResponse]
    delete_detections_returns: BackendResponse[DeleteDetectionsResponse]
    delete_saved_queries_returns: BackendResponse[DeleteSavedQueriesResponse]
    update_managed_schemas_returns: BackendResponse[Any]
    list_managed_schemas_returns: BackendResponse[Any]

    bulk_upload_error: Optional[Exception]

    def bulk_upload(self, params: BulkUploadParams) -> BackendResponse[BulkUploadResponse]:
        if self.bulk_upload_error:
            raise self.bulk_upload_error

        return self.bulk_upload_returns

    def check(self) -> BackendCheckResponse:
        return self.check_returns

    def list_managed_schemas(self, params: ListSchemasParams) -> BackendResponse[Any]:
        return self.list_managed_schemas_returns

    def update_managed_schemas(self, params: UpdateManagedSchemasParams) -> BackendResponse[Any]:
        return self.update_managed_schemas_returns

    def delete_saved_queries(self, params: DeleteSavedQueriesParams) -> BackendResponse[Any]:
        return self.delete_saved_queries_returns

    def delete_detections(self, params: DeleteDetectionsParams) -> BackendResponse[Any]:
        return self.delete_detections_returns
