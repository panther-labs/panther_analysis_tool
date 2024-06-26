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
    TestCorrelationRuleParams,
    TestCorrelationRuleResponse,
    TranspileFiltersParams,
    TranspileFiltersResponse,
    TranspileToPythonParams,
    UpdateSchemaParams,
)


class MockBackend(BackendClient):
    def async_bulk_upload(self, params: BulkUploadParams) -> BackendResponse[BulkUploadResponse]:  # type: ignore
        pass

    def bulk_upload(self, params: BulkUploadParams) -> BackendResponse[BulkUploadResponse]:  # type: ignore
        pass

    def check(self) -> BackendCheckResponse:  # type: ignore
        pass

    def list_schemas(self, params: ListSchemasParams) -> BackendResponse[Any]:  # type: ignore
        pass

    def update_schema(self, params: UpdateSchemaParams) -> BackendResponse[Any]:  # type: ignore
        pass

    def delete_saved_queries(self, params: DeleteSavedQueriesParams) -> BackendResponse[Any]:  # type: ignore
        pass

    def delete_detections(self, params: DeleteDetectionsParams) -> BackendResponse[Any]:  # type: ignore
        pass

    def supports_async_uploads(self) -> bool:  # type: ignore
        pass

    def get_rule_body(self, params: GetRuleBodyParams) -> BackendResponse[GetRuleBodyResponse]:  # type: ignore
        pass

    def transpile_simple_detection_to_python(  # type: ignore
        self, params: TranspileToPythonParams
    ) -> BackendResponse[Any]:
        pass

    def test_correlation_rule(  # type: ignore
        self, params: TestCorrelationRuleParams
    ) -> BackendResponse[TestCorrelationRuleResponse]:
        pass

    def transpile_filters(  # type: ignore
        self, params: TranspileFiltersParams
    ) -> BackendResponse[TranspileFiltersResponse]:
        pass

    def supports_bulk_validate(self) -> bool:  # type: ignore
        pass

    def bulk_validate(self, params: BulkUploadParams) -> BulkUploadValidateStatusResponse:  # type: ignore
        pass

    def supports_perf_test(self) -> bool:  # type: ignore
        pass

    def get_metrics(self, params: MetricsParams) -> BackendResponse[MetricsResponse]:  # type: ignore
        pass

    def run_perf_test(self, params: PerfTestParams) -> BackendResponse[ReplayResponse]:  # type: ignore
        pass

    def supports_enrich_test_data(self) -> bool:  # type: ignore
        pass

    def generate_enriched_event_input(  # type: ignore
        self, params: GenerateEnrichedEventParams
    ) -> BackendResponse[GenerateEnrichedEventResponse]:
        pass

    def feature_flags(self, params: FeatureFlagsParams) -> BackendResponse[FeatureFlagsResponse]:  # type: ignore
        pass
