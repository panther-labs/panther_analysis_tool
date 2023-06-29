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
import base64
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

from ..constants import VERSION_STRING
from .client import (
    BackendCheckResponse,
    BackendError,
    BackendResponse,
    BulkUploadParams,
    BulkUploadResponse,
    BulkUploadStatistics,
    BulkUploadValidateResult,
    BulkUploadValidateStatusResponse,
    Client,
    DeleteDetectionsParams,
    DeleteDetectionsResponse,
    DeleteSavedQueriesParams,
    DeleteSavedQueriesResponse,
    ListSchemasParams,
    ListSchemasResponse,
    PantherSDKBulkUploadParams,
    PantherSDKBulkUploadResponse,
    PermanentBackendError,
    Schema,
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

    def panthersdk_upload_mutation(self) -> DocumentNode:
        return self._load("sdk_upload")

    def transpile_simple_detection_to_python(self) -> DocumentNode:
        return self._load("transpile_sdl")

    def transpile_filters(self) -> DocumentNode:
        return self._load("transpile_filters")

    def introspection_query(self) -> DocumentNode:
        return self._load("introspection_query")

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
            status = result.get("status", "")
            error = result.get("error", "")

            response = BulkUploadValidateStatusResponse(
                error=error,
                status=status,
                result=BulkUploadValidateResult.from_json(result.get("result")),
            )

            if status in ["FAILED", "COMPLETED"]:
                return response

            if status not in ["NOT_PROCESSED"]:
                raise BackendError(f"unexpected status: {status}")

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
                )
            ),
        )

    def panthersdk_bulk_upload(self, params: PantherSDKBulkUploadParams) -> BackendResponse:
        gql_params = {
            "input": {
                "mode": "CONFIG_SDK",
                "data": base64.b64encode(params.content.encode("utf-8")).decode("utf-8"),
            }
        }
        res = self._execute(self._requests.panthersdk_upload_mutation(), gql_params)

        if res.errors:
            for err in res.errors:
                logging.error(err.message)
            raise BackendError(res.errors)

        if res.data is None:
            raise BackendError("empty data")

        rule_upload_stats = res.data.get("uploadDetectionEntities", {}).get("rules", {})
        policy_upload_stats = res.data.get("uploadDetectionEntities", {}).get("policies", {})
        query_upload_stats = res.data.get("uploadDetectionEntities", {}).get("queries", {})
        data_models_upload_stats = res.data.get("uploadDetectionEntities", {}).get("dataModels", {})
        return BackendResponse(
            status_code=200,
            data=PantherSDKBulkUploadResponse(
                rules=BulkUploadStatistics(
                    modified=rule_upload_stats.get("modified"),
                    new=rule_upload_stats.get("new"),
                    total=rule_upload_stats.get("total"),
                ),
                policies=BulkUploadStatistics(
                    modified=policy_upload_stats.get("modified"),
                    new=policy_upload_stats.get("new"),
                    total=policy_upload_stats.get("total"),
                ),
                queries=BulkUploadStatistics(
                    modified=query_upload_stats.get("modified"),
                    new=query_upload_stats.get("new"),
                    total=query_upload_stats.get("total"),
                ),
                data_models=BulkUploadStatistics(
                    modified=data_models_upload_stats.get("modified"),
                    new=data_models_upload_stats.get("new"),
                    total=data_models_upload_stats.get("total"),
                ),
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
