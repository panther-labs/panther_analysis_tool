from typing import Any

from panther_analysis_tool.backend.client import (
    Client as BackendClient,
    BackendResponse,
    BulkUploadParams,
    BackendCheckResponse,
    DeleteDetectionsParams,
    DeleteSavedQueriesParams,
    UpdateManagedSchemasParams,
)


class MockBackend(BackendClient):
    check_returns: BackendCheckResponse
    bulk_upload_returns: BackendResponse
    delete_detections_returns: BackendResponse
    delete_saved_queries_returns: BackendResponse
    update_managed_schemas_returns: BackendResponse[Any]
    list_managed_schema_updates_returns: BackendResponse[Any]

    def bulk_upload(self, params: BulkUploadParams) -> BackendResponse[Any]:
        return self.bulk_upload_returns

    def check(self) -> BackendCheckResponse:
        return self.check_returns

    def list_managed_schema_updates(self) -> BackendResponse[Any]:
        return self.list_managed_schema_updates_returns

    def update_managed_schemas(self, params: UpdateManagedSchemasParams) -> BackendResponse[Any]:
        return self.update_managed_schemas_returns

    def delete_saved_queries(self, params: DeleteSavedQueriesParams) -> BackendResponse[Any]:
        return self.delete_saved_queries_returns

    def delete_detections(self, params: DeleteDetectionsParams) -> BackendResponse[Any]:
        return self.delete_detections_returns
