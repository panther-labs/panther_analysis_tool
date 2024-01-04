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
import datetime
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from gql import Client as GraphQLClient
from gql import gql
from gql.transport.aiohttp import AIOHTTPTransport
from gql.transport.exceptions import TransportQueryError
from graphql import DocumentNode, ExecutionResult

from ..constants import VERSION_STRING, ReplayStatus
from .client import (
    BackendCheckResponse,
    BackendError,
    BackendResponse,
    BulkUploadParams,
    BulkUploadResponse,
    BulkUploadValidateStatusResponse,
    Client,
    DeleteDetectionsParams,
    DeleteDetectionsResponse,
    DeleteSavedQueriesParams,
    DeleteSavedQueriesResponse,
    FeatureFlagsParams,
    FeatureFlagsResponse,
    FeatureFlagTreatment,
    GenerateEnrichedEventParams,
    GenerateEnrichedEventResponse,
    GetRuleBodyParams,
    GetRuleBodyResponse,
    ListSchemasParams,
    ListSchemasResponse,
    MetricsParams,
    MetricsResponse,
    PerfTestParams,
    PermanentBackendError,
    ReplayResponse,
    Schema,
    SeriesWithBreakdown,
    TranspileFiltersParams,
    TranspileFiltersResponse,
    TranspileToPythonParams,
    TranspileToPythonResponse,
    UnsupportedEndpointError,
    UpdateSchemaParams,
    UpdateSchemaResponse,
    to_bulk_upload_response,
)
from .errors import is_retryable_error, is_retryable_error_str


@dataclass(frozen=True)
class PublicAPIClientOptions:
    host: str
    token: str
    user_id: str


class PublicAPIRequests:
    _cache: Dict[str, str]

    def __init__(self) -> None:
        self._cache = dict()

    def version_query(self) -> DocumentNode:
        return self._load("get_version")

    def delete_detections_query(self) -> DocumentNode:
        return self._load("delete_detections")

    def async_bulk_upload_mutation(self) -> DocumentNode:
        return self._load("async_bulk_upload")

    def async_bulk_upload_status_query(self) -> DocumentNode:
        return self._load("async_bulk_upload_status")

    def bulk_upload_mutation(self) -> DocumentNode:
        return self._load("bulk_upload")

    def validate_bulk_upload_mutation(self) -> DocumentNode:
        return self._load("validate_bulk_upload")

    def validate_bulk_upload_status_query(self) -> DocumentNode:
        return self._load("validate_bulk_upload_status")

    def list_schemas_query(self) -> DocumentNode:
        return self._load("list_schemas")

    def update_schema_mutation(self) -> DocumentNode:
        return self._load("create_or_update_schema")

    def delete_saved_queries(self) -> DocumentNode:
        return self._load("delete_saved_queries")

    def get_rule_body(self) -> DocumentNode:
        return self._load("get_rule_body")

    def transpile_simple_detection_to_python(self) -> DocumentNode:
        return self._load("transpile_sdl")

    def transpile_filters(self) -> DocumentNode:
        return self._load("transpile_filters")

    def introspection_query(self) -> DocumentNode:
        return self._load("introspection_query")

    def metrics_query(self) -> DocumentNode:
        return self._load("metrics")

    def create_perf_test_mutation(self) -> DocumentNode:
        return self._load("create_perf_test")

    def replay_query(self) -> DocumentNode:
        return self._load("replay")

    def stop_replay_mutation(self) -> DocumentNode:
        return self._load("stop_replay")

    def generate_enriched_event_query(self) -> DocumentNode:
        return self._load("generate_enriched_event")

    def feature_flags_query(self) -> DocumentNode:
        return self._load("feature_flags")

    def _load(self, name: str) -> DocumentNode:
        if name not in self._cache:
            self._cache[name] = Path(_get_graphql_content_filepath(name)).read_text()

        return gql(self._cache[name])


class PublicAPIClient(Client):
    _user_id: str
    _requests: PublicAPIRequests
    _gql_client: GraphQLClient

    def __init__(self, opts: PublicAPIClientOptions):
        self._user_id = opts.user_id
        self._requests = PublicAPIRequests()
        self._gql_client = _build_client(opts.host, opts.token)

    def check(self) -> BackendCheckResponse:
        res = self._execute(self._requests.version_query())

        if res.errors:
            for err in res.errors:
                logging.error(err.message)

            return BackendCheckResponse(success=False, message="connection check failed")

        if res.data is None:
            return BackendCheckResponse(success=False, message="backend sent empty response")

        panther_version = res.data.get("generalSettings", {}).get("pantherVersion")
        if panther_version is None:
            return BackendCheckResponse(
                success=False,
                message="did not receive version in response",
            )

        return BackendCheckResponse(
            success=True, message=f"connected to Panther backend on version: {panther_version}"
        )

    def async_bulk_upload(self, params: BulkUploadParams) -> BackendResponse[BulkUploadResponse]:
        query = self._requests.async_bulk_upload_mutation()
        upload_params = {"input": {"data": params.encoded_bytes(), "patVersion": VERSION_STRING}}
        res = self._safe_execute(query, variable_values=upload_params)
        receipt_id = res.data.get("uploadDetectionEntitiesAsync", {}).get("receiptId")  # type: ignore
        if not receipt_id:
            raise BackendError("empty data")

        while True:
            time.sleep(2)
            query = self._requests.async_bulk_upload_status_query()
            params = {"input": receipt_id}  # type: ignore
            res = self._safe_execute(query, variable_values=params)  # type: ignore
            result = res.data.get("detectionEntitiesUploadStatus", {})  # type: ignore
            status = result.get("status", "")
            error = result.get("error")
            data = result.get("result")
            if status == "FAILED":
                if is_retryable_error_str(error):
                    raise BackendError(error)
                raise PermanentBackendError(error)

            if status == "COMPLETED":
                return to_bulk_upload_response(data)

            if status not in ["NOT_PROCESSED"]:
                raise BackendError(f"unexpected status: {status}")

    def bulk_upload(self, params: BulkUploadParams) -> BackendResponse[BulkUploadResponse]:
        query = self._requests.bulk_upload_mutation()
        upload_params = {"input": {"data": params.encoded_bytes()}}
        res = self._safe_execute(query, variable_values=upload_params)
        data = res.data.get("uploadDetectionEntities", {})  # type: ignore

        return to_bulk_upload_response(data)

    def bulk_validate(self, params: BulkUploadParams) -> BulkUploadValidateStatusResponse:
        mutation = self._requests.validate_bulk_upload_mutation()
        upload_params = {"input": {"data": params.encoded_bytes(), "patVersion": VERSION_STRING}}
        res = self._potentially_supported_execute(mutation, variable_values=upload_params)
        receipt_id = res.data.get("validateBulkUpload", {}).get("receiptId")  # type: ignore
        if not receipt_id:
            raise BackendError("empty data")

        while True:
            time.sleep(2)
            query = self._requests.validate_bulk_upload_status_query()
            params = {"input": receipt_id}  # type: ignore
            res = self._potentially_supported_execute(query, variable_values=params)  # type: ignore
            result = res.data.get("validateBulkUploadStatus", {})  # type: ignore
            status = result.get("status")

            if status in ["FAILED", "COMPLETED"]:
                return BulkUploadValidateStatusResponse.from_json(data=result)

            if status not in ["NOT_PROCESSED"]:
                raise BackendError(f"unexpected status: {status}")

    # This function was generated in whole or in part by GitHub Copilot.
    def get_rule_body(self, params: GetRuleBodyParams) -> BackendResponse[GetRuleBodyResponse]:
        query: DocumentNode = self._requests.get_rule_body()
        params = {"input": params.id}  # type: ignore
        res = self._safe_execute(query, variable_values=params)  # type: ignore
        data = res.data.get("rulePythonBody", {})  # type: ignore
        tests = data.get("tests", [])
        out_tests = []
        for test in tests:
            out_mocks = []
            for mock in test.get("mocks") or []:
                out_mock = dict()
                out_mock["ObjectName"] = mock["objectName"]
                out_mock["ReturnValue"] = mock["returnValue"]
                out_mocks.append(out_mock)
            out_test = dict()
            out_test["ExpectedResult"] = test["expectedResult"]
            out_test["Name"] = test["name"]
            out_test["Log"] = json.loads(test["resource"])
            out_tests.append(out_test)

        return BackendResponse(
            status_code=200,
            data=GetRuleBodyResponse(
                body=data.get("pythonBody") or "",
                tests=out_tests,
            ),
        )

    # This function was generated in whole or in part by GitHub Copilot.
    def transpile_simple_detection_to_python(
        self, params: TranspileToPythonParams
    ) -> BackendResponse[TranspileToPythonResponse]:
        query = self._requests.transpile_simple_detection_to_python()
        transpile_input = {"input": {"data": params.data}}
        res = self._safe_execute(query, variable_values=transpile_input)
        data = res.data.get("transpileSimpleDetectionsToPython", {})  # type: ignore

        return BackendResponse(
            status_code=200,
            data=TranspileToPythonResponse(
                transpiled_python=data.get("transpiledPython") or [],
            ),
        )

    def transpile_filters(
        self, params: TranspileFiltersParams
    ) -> BackendResponse[TranspileFiltersResponse]:
        query = self._requests.transpile_filters()
        transpile_input = {"input": {"data": params.data, "patVersion": params.pat_version}}
        res = self._safe_execute(query, variable_values=transpile_input)
        data = res.data.get("transpileFilters", {})  # type: ignore

        return BackendResponse(
            status_code=200,
            data=TranspileFiltersResponse(
                transpiled_filters=data.get("transpiledFilters") or [],
            ),
        )

    def delete_saved_queries(
        self, params: DeleteSavedQueriesParams
    ) -> BackendResponse[DeleteSavedQueriesResponse]:
        query = self._requests.delete_saved_queries()
        delete_params = {
            "input": {
                "dryRun": params.dry_run,
                "includeDetections": params.include_detections,
                "names": params.names,
            }
        }
        res = self._execute(query, variable_values=delete_params)

        if res.errors:
            raise BackendError(res.errors)

        if res.data is None:
            raise BackendError("empty data")

        data = res.data.get("deleteSavedQueriesByName", {})

        return BackendResponse(
            status_code=200,
            data=DeleteSavedQueriesResponse(
                names=data.get("names") or [],
                detection_ids=data.get("detectionIDs") or [],
            ),
        )

    def delete_detections(
        self, params: DeleteDetectionsParams
    ) -> BackendResponse[DeleteDetectionsResponse]:
        gql_params = {
            "input": {
                "dryRun": params.dry_run,
                "includeSavedQueries": params.include_saved_queries,
                "ids": params.ids,
            }
        }
        res = self._execute(self._requests.delete_detections_query(), gql_params)
        if res.errors:
            for err in res.errors:
                logging.error(err.message)

            raise BackendError(res.errors)

        if res.data is None:
            raise BackendError("empty data")

        data = res.data.get("deleteDetections", {})

        return BackendResponse(
            status_code=200,
            data=DeleteDetectionsResponse(
                ids=data.get("ids") or [],
                saved_query_names=data.get("savedQueryNames") or [],
            ),
        )

    def list_schemas(self, params: ListSchemasParams) -> BackendResponse[ListSchemasResponse]:
        gql_params = {
            "input": {
                "isManaged": params.is_managed,
            }
        }
        res = self._execute(self._requests.list_schemas_query(), gql_params)
        if res.errors:
            for err in res.errors:
                logging.error(err.message)
            raise BackendError(res.errors)

        if res.data is None:
            raise BackendError("empty data")

        schemas = []
        for edge in res.data.get("schemas", {}).get("edges", []):
            node = edge.get("node", {})
            schema = Schema(
                created_at=node.get("createdAt", ""),
                description=node.get("description", ""),
                is_managed=node.get("isManaged", False),
                name=node.get("name", ""),
                reference_url=node.get("referenceURL", ""),
                revision=node.get("revision", ""),
                spec=node.get("spec", ""),
                updated_at=node.get("updatedAt", ""),
                field_discovery_enabled=node.get("fieldDiscoveryEnabled", False),
            )
            schemas.append(schema)

        return BackendResponse(status_code=200, data=ListSchemasResponse(schemas=schemas))

    def update_schema(self, params: UpdateSchemaParams) -> BackendResponse:
        gql_params = {
            "input": {
                "description": params.description,
                "name": params.name,
                "referenceURL": params.reference_url,
                "revision": params.revision,
                "spec": params.spec,
                "isFieldDiscoveryEnabled": params.field_discovery_enabled,
            }
        }
        res = self._execute(self._requests.update_schema_mutation(), gql_params)
        if res.errors:
            for err in res.errors:
                logging.error(err.message)
            raise BackendError(res.errors)

        if res.data is None:
            raise BackendError("empty data")

        schema = res.data.get("schema", {})
        return BackendResponse(
            status_code=200,
            data=UpdateSchemaResponse(
                schema=Schema(
                    created_at=schema.get("createdAt", ""),
                    description=schema.get("description", ""),
                    is_managed=schema.get("isManaged", False),
                    name=schema.get("name", ""),
                    reference_url=schema.get("referenceURL", ""),
                    revision=schema.get("revision", ""),
                    spec=schema.get("spec", ""),
                    updated_at=schema.get("updatedAt", ""),
                    field_discovery_enabled=schema.get("fieldDiscoveryEnabled", False),
                )
            ),
        )

    def has_graphql_endpoints(self, endpoints: List[str]) -> bool:
        res = self._execute(self._requests.introspection_query())
        if res.errors:
            return False

        expected = len(endpoints)
        seen = 0
        for graphql_type in res.data.get("__schema", {}).get("types", []):  # type: ignore
            if (graphql_type["name"] in ["Mutation", "Query"]) and graphql_type["kind"] == "OBJECT":
                for endpoint in graphql_type["fields"]:
                    if endpoint["name"] in endpoints:
                        seen += 1
                        if seen == expected:
                            return True

        return False

    def supports_async_uploads(self) -> bool:
        return self.has_graphql_endpoints(
            ["uploadDetectionEntitiesAsync", "detectionEntitiesUploadStatus"]
        )

    def supports_bulk_validate(self) -> bool:
        return True

    def supports_perf_test(self) -> bool:
        return True

    def get_metrics(self, params: MetricsParams) -> BackendResponse[MetricsResponse]:
        gql_params = {
            "input": {
                "fromDate": params.from_date.astimezone().isoformat(),
                "toDate": params.to_date.astimezone().isoformat(),
                "intervalInMinutes": params.interval_in_minutes,
            }
        }
        res = self._execute(self._requests.metrics_query(), gql_params)
        if res.errors:
            for err in res.errors:
                logging.error(err.message)
            raise BackendError(res.errors)

        if res.data is None:
            raise BackendError("empty data")

        all_metrics = res.data.get("metrics", {})
        bytes_processed_per_source_list = all_metrics.get("bytesProcessedPerSource", [])

        return BackendResponse(
            status_code=200,
            data=MetricsResponse(
                bytes_processed_per_source=[
                    SeriesWithBreakdown(
                        breakdown=x["breakdown"],
                        label=x["label"],
                        value=x["value"],
                    )
                    for x in bytes_processed_per_source_list
                ]
            ),
        )

    def run_perf_test(self, params: PerfTestParams) -> BackendResponse[ReplayResponse]:
        query = self._requests.create_perf_test_mutation()
        create_params = {
            "input": {
                "detection": params.encoded_bytes(),
                "hour": params.hour.astimezone().isoformat(),
                "logType": params.log_type,
            }
        }
        res = self._potentially_supported_execute(query, variable_values=create_params)
        replay_id = res.data.get("createPerfTest", {}).get("replay", {}).get("id")  # type: ignore
        if not replay_id:
            raise BackendError("empty data")
        stopped = False
        terminal_statuses = [
            ReplayStatus.DONE,
            ReplayStatus.CANCELED,
            ReplayStatus.ERROR_EVALUATION,
            ReplayStatus.ERROR_COMPUTATION,
        ]

        while True:
            if not stopped and params.timeout < datetime.datetime.now().astimezone():
                stop_params = {"input": {"id": replay_id}}
                query = self._requests.stop_replay_mutation()
                self._potentially_supported_execute(query, variable_values=stop_params)
                stopped = True

            time.sleep(0.25)
            query = self._requests.replay_query()
            get_params = {"input": replay_id}
            res = self._potentially_supported_execute(query, variable_values=get_params)
            result = res.data.get("replay", {})  # type: ignore
            status = result.get("state", "")
            if status in terminal_statuses:
                replay_response = ReplayResponse.from_json(result, replay_id, status)
                return BackendResponse(status_code=200, data=replay_response)

            if status not in terminal_statuses + (
                [ReplayStatus.EVALUATION_IN_PROGRESS, ReplayStatus.COMPUTATION_IN_PROGRESS]
            ):
                raise BackendError(f"unexpected status: {status}")

    def supports_enrich_test_data(self) -> bool:
        return True

    def generate_enriched_event_input(
        self, params: GenerateEnrichedEventParams
    ) -> BackendResponse[GenerateEnrichedEventResponse]:
        query = self._requests.generate_enriched_event_query()
        query_input = {"input": {"event": params.event}}
        res = self._safe_execute(query, variable_values=query_input)
        data = res.data.get("generateEnrichedEvent", {})  # type: ignore
        enriched_event = data.get("enrichedEvent", {})

        return BackendResponse(
            status_code=200,
            data=GenerateEnrichedEventResponse(
                enriched_event=enriched_event,
            ),
        )

    def feature_flags(self, params: FeatureFlagsParams) -> BackendResponse[FeatureFlagsResponse]:
        query = self._requests.feature_flags_query()
        query_input = {
            "input": {
                "flags": [
                    {"flag": flag.flag, "defaultTreatment": flag.default_treatment}
                    for flag in params.flags
                ]
            }
        }
        res = self._safe_execute(query, variable_values=query_input)
        data = res.data.get("featureFlags", {})  # type: ignore

        return BackendResponse(
            status_code=200,
            data=FeatureFlagsResponse(
                flags=[
                    FeatureFlagTreatment(flag=flag.get("flag"), treatment=flag.get("treatment"))
                    for flag in data.get("flags") or []
                ]
            ),
        )

    def _execute(
        self,
        request: DocumentNode,
        variable_values: Optional[Dict[str, Any]] = None,
    ) -> ExecutionResult:
        return self._gql_client.execute(
            request, variable_values=variable_values, get_execution_result=True
        )

    def _safe_execute(
        self,
        request: DocumentNode,
        variable_values: Optional[Dict[str, Any]] = None,
    ) -> ExecutionResult:
        try:
            res = self._execute(request, variable_values=variable_values)
        except TransportQueryError as e:  # pylint: disable=C0103
            err = PermanentBackendError(e)
            if e.errors and len(e.errors) > 0:
                err = BackendError(e.errors[0])  # type: ignore
                err.permanent = not is_retryable_error(e.errors[0])
            raise err from e

        if res.errors:
            raise PermanentBackendError(res.errors)

        if res.data is None:
            raise BackendError("empty data")

        return res

    def _potentially_supported_execute(
        self,
        request: DocumentNode,
        variable_values: Optional[Dict[str, Any]] = None,
    ) -> ExecutionResult:
        """
        Same behavior as _safe_execute but throws an UnSupportedEndpointError
        whenever a graphql validation error is detected
        """
        try:
            return self._safe_execute(request, variable_values)
        except BaseException as err:
            not_supported = False
            try:
                not_supported = (
                    err.args[0]["extensions"]["code"]  # pylint: disable=invalid-sequence-index
                    == "GRAPHQL_VALIDATION_FAILED"
                )
            except BaseException:  # pylint: disable=broad-except
                pass

            if not_supported:
                raise UnsupportedEndpointError(err) from err

            raise err


_API_URL_PATH = "public/graphql"
_API_DOMAIN_PREFIX = "api"
_API_TOKEN_HEADER = "X-API-Key"  # nosec


def _build_client(host: str, token: str) -> GraphQLClient:
    graphql_url = _build_api_url(host)
    logging.info("Panther Public API endpoint: %s", graphql_url)

    transport = AIOHTTPTransport(url=graphql_url, headers={_API_TOKEN_HEADER: token})

    return GraphQLClient(transport=transport, fetch_schema_from_transport=False, execute_timeout=30)


def is_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False


def _build_api_url(host: str) -> str:
    if is_url(host):
        return host

    return f"https://{_API_DOMAIN_PREFIX}.{host}/{_API_URL_PATH}"


def _get_graphql_content_filepath(name: str) -> str:
    work_dir = os.path.dirname(__file__)
    return os.path.join(work_dir, "graphql", f"{name}.graphql")
