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
    GenerateEnrichedEventParams,
    GenerateEnrichedEventResponse,
    ListSchemasParams,
    MetricsParams,
    MetricsResponse,
    PerfTestParams,
    ReplayResponse,
    TranspileFiltersParams,
    TranspileFiltersResponse,
    TranspileToPythonParams,
    UpdateSchemaParams,
)


class MockBackend(BackendClient):
    def async_bulk_upload(self, params: BulkUploadParams) -> BackendResponse[BulkUploadResponse]:  # type: ignore[empty-body]
        pass

    def bulk_upload(self, params: BulkUploadParams) -> BackendResponse[BulkUploadResponse]:  # type: ignore[empty-body]
        pass

    def check(self) -> BackendCheckResponse:  # type: ignore[empty-body]
        pass

    def list_schemas(self, params: ListSchemasParams) -> BackendResponse[Any]:  # type: ignore[empty-body]
        pass

    def update_schema(self, params: UpdateSchemaParams) -> BackendResponse[Any]:  # type: ignore[empty-body]
        pass

    def delete_saved_queries(self, params: DeleteSavedQueriesParams) -> BackendResponse[Any]:  # type: ignore[empty-body]
        pass

    def delete_detections(self, params: DeleteDetectionsParams) -> BackendResponse[Any]:  # type: ignore[empty-body]
        pass

    def supports_async_uploads(self) -> bool:  # type: ignore[empty-body]
        pass

    def transpile_simple_detection_to_python(self, params: TranspileToPythonParams) -> BackendResponse[Any]:  # type: ignore[empty-body]
        pass

    def transpile_filters(self, params: TranspileFiltersParams) -> BackendResponse[TranspileFiltersResponse]:  # type: ignore[empty-body]
        pass

    def supports_bulk_validate(self) -> bool:  # type: ignore[empty-body]
        pass

    def bulk_validate(self, params: BulkUploadParams) -> BulkUploadValidateStatusResponse:  # type: ignore[empty-body]
        pass

    def supports_perf_test(self) -> bool:  # type: ignore[empty-body]
        pass

    def get_metrics(self, params: MetricsParams) -> BackendResponse[MetricsResponse]:  # type: ignore[empty-body]
        pass

    def run_perf_test(self, params: PerfTestParams) -> BackendResponse[ReplayResponse]:  # type: ignore[empty-body]
        pass

    def supports_enrich_test_data(self) -> bool:  # type: ignore[empty-body]
        pass

    def generate_enriched_event_input(
        self, params: GenerateEnrichedEventParams
    ) -> BackendResponse[GenerateEnrichedEventResponse]:  # type: ignore
        pass
