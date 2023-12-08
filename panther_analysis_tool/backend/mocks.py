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
    FeatureFlagsParams,
    FeatureFlagsResponse,
    GenerateEnrichedEventParams,
    GenerateEnrichedEventResponse,
    GetRuleBodyParams,
    GetRuleBodyResponse,
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

    def supports_async_uploads(self) -> bool:
        pass

    def get_rule_body(self, params: GetRuleBodyParams) -> BackendResponse[GetRuleBodyResponse]:
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

    def supports_perf_test(self) -> bool:
        pass

    def get_metrics(self, params: MetricsParams) -> BackendResponse[MetricsResponse]:
        pass

    def run_perf_test(self, params: PerfTestParams) -> BackendResponse[ReplayResponse]:
        pass

    def supports_enrich_test_data(self) -> bool:
        pass

    def generate_enriched_event_input(
        self, params: GenerateEnrichedEventParams
    ) -> BackendResponse[GenerateEnrichedEventResponse]:
        pass

    def feature_flags(self, params: FeatureFlagsParams) -> BackendResponse[FeatureFlagsResponse]:
        pass
