from typing import Any

from panther_analysis_tool.backend.client import (
    BackendCheckResponse,
    BackendResponse,
    BulkUploadParams,
    BulkUploadResponse,
)
from panther_analysis_tool.backend.client import Client as BackendClient
from panther_analysis_tool.backend.client import (
    DeleteDetectionsParams,
    DeleteSavedQueriesParams,
    ListSchemasParams,
    PantherSDKBulkUploadParams,
    UpdateManagedSchemaParams,
)


class MockBackend(BackendClient):
    def bulk_upload(self, params: BulkUploadParams) -> BackendResponse[BulkUploadResponse]:
        pass

    def check(self) -> BackendCheckResponse:
        pass

    def list_managed_schemas(self, params: ListSchemasParams) -> BackendResponse[Any]:
        pass

    def update_managed_schema(self, params: UpdateManagedSchemaParams) -> BackendResponse[Any]:
        pass

    def delete_saved_queries(self, params: DeleteSavedQueriesParams) -> BackendResponse[Any]:
        pass

    def delete_detections(self, params: DeleteDetectionsParams) -> BackendResponse[Any]:
        pass

    def panthersdk_bulk_upload(self, params: PantherSDKBulkUploadParams) -> BackendResponse[Any]:
        pass
