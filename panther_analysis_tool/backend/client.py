"""
Panther Analysis Tool is a command line interface for writing,
testing, and packaging policies/rules.
Copyright (C) 2020 Panther Labs Inc

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
import ast
import base64
import datetime
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Generic, List, Optional, TypeVar

import dateutil.parser

ResponseData = TypeVar("ResponseData")


class BackendError(Exception):
    permanent: bool = False


class PermanentBackendError(BackendError):
    permanent: bool = True


class UnsupportedEndpointError(Exception):
    pass


@dataclass(frozen=True)
class BulkUploadPayload:
    data: bytes
    user_id: str


@dataclass(frozen=True)
class BackendResponse(Generic[ResponseData]):
    data: ResponseData
    status_code: int


@dataclass(frozen=True)
class BackendCheckResponse:
    success: bool
    message: str


@dataclass(frozen=True)
class BulkUploadParams:
    zip_bytes: bytes

    def encoded_bytes(self) -> str:
        return base64.b64encode(self.zip_bytes).decode("utf-8")


@dataclass(frozen=True)
class DeleteSavedQueriesParams:
    names: List[str]
    dry_run: bool
    include_detections: bool


@dataclass(frozen=True)
class DeleteDetectionsParams:
    ids: List[str]
    dry_run: bool
    include_saved_queries: bool


@dataclass(frozen=True)
class ListSchemasParams:
    is_managed: bool


@dataclass(frozen=True)
class UpdateSchemaParams:
    description: str
    name: str
    reference_url: str
    revision: int
    spec: str
    field_discovery_enabled: bool


@dataclass(frozen=True)
class BulkUploadStatistics:
    new: int
    total: int
    modified: int


@dataclass(frozen=True)
class BulkUploadIssue:
    path: str
    error_message: str

    @classmethod
    def from_json(cls, data: Optional[Dict[str, Any]]) -> Optional["BulkUploadIssue"]:
        if not data:
            return None

        return cls(path=data.get("path", ""), error_message=data.get("errorMessage", ""))


class BackendMultipartError(ABC):
    @abstractmethod
    def has_error(self) -> bool:
        pass

    @abstractmethod
    def get_error(self) -> Optional[str]:
        pass

    @abstractmethod
    def has_issues(self) -> bool:
        pass

    @abstractmethod
    def get_issues(self) -> List[BulkUploadIssue]:
        pass


@dataclass
class BulkUploadMultipartError(BackendMultipartError):
    error: str
    issues: List[BulkUploadIssue] = field(default_factory=lambda: [])

    @classmethod
    def from_jsons(cls, data: str) -> "BulkUploadMultipartError":
        try:
            return BulkUploadMultipartError.from_dict(json.loads(data))
        except json.decoder.JSONDecodeError:
            return BulkUploadMultipartError.from_dict({"error": data})

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "BulkUploadMultipartError":
        if not data:
            return cls(error="")

        raw_issues = data.get("issues", []) or []
        issues: List[BulkUploadIssue] = []
        for issue in raw_issues:
            issues.append(BulkUploadIssue.from_json(issue))  # type: ignore

        err = data.get("error") or ""
        err = parse_graphql_error(err)

        return cls(issues=issues, error=err)

    def has_error(self) -> bool:
        return self.error is not None and len(self.error) > 0

    def get_error(self) -> Optional[str]:
        return self.error

    def has_issues(self) -> bool:
        return self.issues is not None and len(self.issues) > 0

    def get_issues(self) -> List[BulkUploadIssue]:
        if not self.has_issues():
            return []

        return self.issues or []


@dataclass(frozen=True)
class BulkUploadValidateResult:
    issues: List[BulkUploadIssue] = field(default_factory=lambda: [])

    @classmethod
    def from_json(cls, data: Optional[Dict[str, Any]]) -> Optional["BulkUploadValidateResult"]:
        if not data:
            return None

        raw_issues = data.get("issues", []) or []
        issues: List[BulkUploadIssue] = []
        for issue in raw_issues:
            issues.append(BulkUploadIssue.from_json(issue))  # type: ignore

        return cls(issues=issues)


@dataclass(frozen=True)
class BulkUploadValidateStatusResponse(BackendMultipartError):
    status: str
    error: str
    result: Optional[BulkUploadValidateResult] = None

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "BulkUploadValidateStatusResponse":
        result = BulkUploadValidateResult.from_json(data.get("result"))
        status = data.get("status") or ""
        err = data.get("error") or ""
        err = parse_graphql_error(err)
        return cls(result=result, status=status, error=err)

    def has_error(self) -> bool:
        return self.error is not None and len(self.error) > 0

    def get_error(self) -> Optional[str]:
        return self.error

    def has_issues(self) -> bool:
        return self.result is not None and len(self.result.issues) > 0

    def get_issues(self) -> List[BulkUploadIssue]:
        if not self.has_issues():
            return []

        return self.result.issues or []  # type: ignore

    def is_valid(self) -> bool:
        if self.has_error():
            return False

        if self.has_issues():
            return False

        return True


@dataclass(frozen=True)
class BulkUploadResponse:
    rules: BulkUploadStatistics
    queries: BulkUploadStatistics
    policies: BulkUploadStatistics
    data_models: BulkUploadStatistics
    lookup_tables: BulkUploadStatistics
    global_helpers: BulkUploadStatistics
    correlation_rules: BulkUploadStatistics


@dataclass(frozen=True)
class DeleteSavedQueriesResponse:
    names: List[str]
    detection_ids: List[str]


@dataclass(frozen=True)
class DeleteDetectionsResponse:
    ids: List[str]
    saved_query_names: List[str]


# pylint: disable=too-many-instance-attributes
@dataclass(frozen=True)
class Schema:
    created_at: str
    description: str
    is_managed: bool
    name: str
    reference_url: str
    revision: int
    spec: str
    updated_at: str
    field_discovery_enabled: bool


@dataclass(frozen=True)
class ListSchemasResponse:
    schemas: List[Schema]


@dataclass(frozen=True)
class UpdateSchemaResponse:
    schema: Schema


@dataclass(frozen=True)
class TranspileToPythonParams:
    data: List[str]


@dataclass(frozen=True)
class TranspileToPythonResponse:
    transpiled_python: List[str]


@dataclass(frozen=True)
class GetRuleBodyParams:
    id: str  # pylint: disable=invalid-name


@dataclass(frozen=True)
class GetRuleBodyResponse:
    body: str
    tests: List[Dict[str, Any]]


@dataclass(frozen=True)
class TranspileFiltersParams:
    data: List[str]
    pat_version: str


@dataclass(frozen=True)
class TranspileFiltersResponse:
    transpiled_filters: List[str]


@dataclass(frozen=True)
class MetricsParams:
    from_date: datetime.datetime
    to_date: datetime.datetime
    interval_in_minutes: int


@dataclass(frozen=True)
class SeriesWithBreakdown:
    breakdown: Dict[str, Any]
    label: str
    value: float


@dataclass(frozen=True)
class MetricsResponse:
    bytes_processed_per_source: List[SeriesWithBreakdown]


@dataclass(frozen=True)
class PerfTestParams(BulkUploadParams):
    hour: datetime.datetime
    log_type: str
    timeout: datetime.datetime


@dataclass(frozen=True)
class TimeWindow:
    starts_at: datetime.datetime
    ends_at: datetime.datetime


@dataclass(frozen=True)
class SizeWindow:
    max_size_in_gb: int


@dataclass(frozen=True)
class DataWindow:
    size_window: Optional[SizeWindow]
    time_window: Optional[TimeWindow]


@dataclass(frozen=True)
class ReplayScope:
    log_types: List[str]
    data_window: DataWindow


@dataclass(frozen=True)
class ReplaySummary:
    total_alerts: int
    completed_at: Optional[datetime.datetime]
    rule_error_count: int
    rule_match_count: int
    evaluation_progress: int
    computation_progress: int
    log_data_size_estimate: int
    matches_processed_count: int
    events_processed_count: int
    events_matched_count: int
    read_time_nanos: int
    processing_time_nanos: int


@dataclass(frozen=True)
class ReplayResponse:
    replay_id: str
    state: str
    created_at: datetime.datetime
    updated_at: datetime.datetime
    completed_at: Optional[datetime.datetime]
    detection_id: str
    replay_type: str
    replay_scope: ReplayScope
    replay_summary: ReplaySummary

    @classmethod
    def from_json(cls, data: Dict[str, Any], replay_id: str, status: str) -> "ReplayResponse":
        scope = data.get("scope", {})
        data_window = scope.get("dataWindow", {})
        retrieved_size_window = data_window.get("size_window")
        size_window = (
            None
            if retrieved_size_window is None
            else SizeWindow(max_size_in_gb=retrieved_size_window.get("maxSizeInGB"))
        )
        retrieved_time_window = data_window.get("time_window")
        time_window = (
            None
            if retrieved_time_window is None
            else TimeWindow(
                starts_at=dateutil.parser.parse(retrieved_time_window.get("startsAt")),
                ends_at=dateutil.parser.parse(retrieved_time_window.get("endsAt")),
            )
        )
        summary = data.get("summary", {})

        return ReplayResponse(
            replay_id=replay_id,
            state=status,
            created_at=dateutil.parser.parse(data.get("createdAt")),  # type: ignore
            updated_at=dateutil.parser.parse(data.get("updatedAt")),  # type: ignore
            completed_at=parse_optional_time(data.get("completedAt")),
            detection_id=data.get("detectionId"),  # type: ignore
            replay_type=data.get("replayType"),  # type: ignore
            replay_scope=ReplayScope(
                log_types=scope.get("logTypes"),
                data_window=DataWindow(size_window=size_window, time_window=time_window),
            ),
            replay_summary=ReplaySummary(
                total_alerts=summary.get("totalAlerts"),
                completed_at=parse_optional_time(summary.get("completedAt")),
                rule_error_count=summary.get("ruleErrorCount"),
                rule_match_count=summary.get("ruleMatchCount"),
                evaluation_progress=summary.get("evaluationProgress"),
                computation_progress=summary.get("computationProgress"),
                log_data_size_estimate=summary.get("logDataSizeEstimate"),
                matches_processed_count=summary.get("matchesProcessedCount"),
                events_processed_count=summary.get("eventsProcessedCount"),
                events_matched_count=summary.get("eventsMatchedCount"),
                read_time_nanos=summary.get("readTimeNanos"),
                processing_time_nanos=summary.get("processingTimeNanos"),
            ),
        )


@dataclass(frozen=True)
class GenerateEnrichedEventParams:
    event: Dict[str, Any]  # json


@dataclass(frozen=True)
class GenerateEnrichedEventResponse:
    enriched_event: Dict[str, Any]  # json


@dataclass(frozen=True)
class FeatureFlagWithDefault:
    flag: str
    default_treatment: Optional[bool] = None


@dataclass(frozen=True)
class FeatureFlagTreatment:
    flag: str
    treatment: bool


@dataclass(frozen=True)
class FeatureFlagsParams:
    flags: List[FeatureFlagWithDefault]


@dataclass(frozen=True)
class FeatureFlagsResponse:
    flags: List[FeatureFlagTreatment]


class Client(ABC):
    @abstractmethod
    def check(self) -> BackendCheckResponse:
        pass

    @abstractmethod
    def async_bulk_upload(self, params: BulkUploadParams) -> BackendResponse[BulkUploadResponse]:
        pass

    @abstractmethod
    def bulk_upload(self, params: BulkUploadParams) -> BackendResponse[BulkUploadResponse]:
        pass

    @abstractmethod
    def bulk_validate(self, params: BulkUploadParams) -> BulkUploadValidateStatusResponse:
        pass

    @abstractmethod
    def get_rule_body(self, params: GetRuleBodyParams) -> BackendResponse[GetRuleBodyResponse]:
        pass

    @abstractmethod
    def transpile_simple_detection_to_python(
        self, params: TranspileToPythonParams
    ) -> BackendResponse[TranspileToPythonResponse]:
        pass

    @abstractmethod
    def transpile_filters(
        self, params: TranspileFiltersParams
    ) -> BackendResponse[TranspileFiltersResponse]:
        pass

    @abstractmethod
    def delete_saved_queries(
        self, params: DeleteSavedQueriesParams
    ) -> BackendResponse[DeleteSavedQueriesResponse]:
        pass

    @abstractmethod
    def delete_detections(
        self, params: DeleteDetectionsParams
    ) -> BackendResponse[DeleteDetectionsResponse]:
        pass

    @abstractmethod
    def list_schemas(self, params: ListSchemasParams) -> BackendResponse[ListSchemasResponse]:
        pass

    @abstractmethod
    def update_schema(self, params: UpdateSchemaParams) -> BackendResponse[Any]:
        pass

    @abstractmethod
    def supports_async_uploads(self) -> bool:
        pass

    @abstractmethod
    def supports_bulk_validate(self) -> bool:
        pass

    @abstractmethod
    def supports_perf_test(self) -> bool:
        pass

    @abstractmethod
    def get_metrics(self, params: MetricsParams) -> BackendResponse[MetricsResponse]:
        pass

    @abstractmethod
    def run_perf_test(self, params: PerfTestParams) -> BackendResponse[ReplayResponse]:
        pass

    @abstractmethod
    def supports_enrich_test_data(self) -> bool:
        pass

    @abstractmethod
    def generate_enriched_event_input(
        self, params: GenerateEnrichedEventParams
    ) -> BackendResponse[GenerateEnrichedEventResponse]:
        pass

    @abstractmethod
    def feature_flags(self, params: FeatureFlagsParams) -> BackendResponse[FeatureFlagsResponse]:
        pass


def backend_response_failed(resp: BackendResponse) -> bool:
    return resp.status_code >= 400 or resp.data.get("statusCode", 0) >= 400


def to_bulk_upload_response(data: Any) -> BackendResponse[BulkUploadResponse]:
    default_stats = dict(total=0, new=0, modified=0)
    return BackendResponse(
        status_code=200,
        data=BulkUploadResponse(
            rules=BulkUploadStatistics(**data.get("rules", default_stats)),
            queries=BulkUploadStatistics(**data.get("queries", default_stats)),
            policies=BulkUploadStatistics(**data.get("policies", default_stats)),
            data_models=BulkUploadStatistics(**data.get("dataModels", default_stats)),
            lookup_tables=BulkUploadStatistics(**data.get("lookupTables", default_stats)),
            global_helpers=BulkUploadStatistics(**data.get("globalHelpers", default_stats)),
            correlation_rules=BulkUploadStatistics(**data.get("correlationRules", default_stats)),
        ),
    )


def parse_optional_time(time: Optional[str]) -> Optional[datetime.datetime]:
    return None if time is None else dateutil.parser.parse(time)


def parse_graphql_error(err: str) -> str:
    """
    Attempt to take what might be a graphql error from the backend and turn it into a dict.
    If it is not a graphql error or could not be turned into a dict, the original error is
    returned.
    """
    try:
        # if the backend returns a graphqlerror, it has single quotes which json can't
        # handle. So we need to use literal eval here and then check if it has the
        # message field which an error would
        return ast.literal_eval(str(err)).get("message") or err
    except BaseException:  # pylint: disable=broad-except
        return err
