from typing import Any

from panther_analysis_tool.backend.client import (
    BackendCheckResponse,
    BackendResponse,
    BulkUploadParams,
    BulkUploadResponse,
    BulkUploadValidateStatusResponse,
)
from panther_analysis_tool.backend.client import Client as BackendClient
from panther_analysis_tool.backend.client import (
    DeleteDetectionsParams,
    DeleteSavedQueriesParams,
    ListSchemasParams,
    PantherSDKBulkUploadParams,
    TranspileFiltersParams,
    TranspileFiltersResponse,
    TranspileToPythonParams,
    UpdateSchemaParams,
)


class MockBackend(BackendClient):
    def async_bulk_upload(self, params: BulkUploadParams) -> BackendResponse[BulkUploadResponse]:
        pass

    def bulk_upload(self, params: BulkUploadParams) -> BackendResponse[BulkUploadResponse]:
        pass

    def check(self) -> BackendCheckResponse:
        pass

    def list_schemas(self, params: ListSchemasParams) -> BackendResponse[Any]:
        pass

    def update_schema(self, params: UpdateSchemaParams) -> BackendResponse[Any]:
        pass

    def delete_saved_queries(self, params: DeleteSavedQueriesParams) -> BackendResponse[Any]:
        pass

    def delete_detections(self, params: DeleteDetectionsParams) -> BackendResponse[Any]:
        pass

    def panthersdk_bulk_upload(self, params: PantherSDKBulkUploadParams) -> BackendResponse[Any]:
        pass

    def supports_async_uploads(self) -> bool:
        pass

    def transpile_simple_detection_to_python(
        self, params: TranspileToPythonParams
    ) -> BackendResponse[Any]:
        pass

    def transpile_filters(
        self, params: TranspileFiltersParams
    ) -> BackendResponse[TranspileFiltersResponse]:
        pass

    def supports_bulk_validate(self) -> bool:
        pass

    def bulk_validate(self, params: BulkUploadParams) -> BulkUploadValidateStatusResponse:
        pass
