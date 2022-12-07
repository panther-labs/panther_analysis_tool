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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from gql import Client as GraphQLClient
from gql import gql
from gql.transport.aiohttp import AIOHTTPTransport
from graphql import DocumentNode, ExecutionResult

from .client import (
    BackendCheckResponse,
    BackendError,
    BackendResponse,
    BulkUploadParams,
    BulkUploadResponse,
    BulkUploadStatistics,
    Client,
    DeleteDetectionsParams,
    DeleteDetectionsResponse,
    DeleteSavedQueriesParams,
    DeleteSavedQueriesResponse,
    ListManagedSchemasResponse,
    ListSchemasParams,
    ManagedSchema,
    PantherSDKBulkUploadParams,
    PantherSDKBulkUploadResponse,
    UpdateManagedSchemaParams,
    UpdateManagedSchemaResponse,
)


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

    def bulk_upload_mutation(self) -> DocumentNode:
        return self._load("bulk_upload")

    def list_schemas_query(self) -> DocumentNode:
        return self._load("list_schemas")

    def update_schema_mutation(self) -> DocumentNode:
        return self._load("create_or_update_schema")

    def delete_saved_queries(self) -> DocumentNode:
        return self._load("delete_saved_queries")

    def panthersdk_upload_mutation(self) -> DocumentNode:
        return self._load("sdk_upload")

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

    def bulk_upload(self, params: BulkUploadParams) -> BackendResponse[BulkUploadResponse]:
        query = self._requests.bulk_upload_mutation()
        upload_params = {"input": {"data": params.encoded_bytes()}}
        default_stats = dict(total=0, new=0, modified=0)
        res = self._execute(query, variable_values=upload_params)

        if res.errors:
            raise BackendError(res.errors)

        if res.data is None:
            raise BackendError("empty data")

        data = res.data.get("uploadDetectionEntities", {})

        return BackendResponse(
            status_code=200,
            data=BulkUploadResponse(
                rules=BulkUploadStatistics(**data.get("rules", default_stats)),
                policies=BulkUploadStatistics(**data.get("policies", default_stats)),
                data_models=BulkUploadStatistics(**data.get("dataModels", default_stats)),
                lookup_tables=BulkUploadStatistics(**data.get("lookupTables", default_stats)),
                global_helpers=BulkUploadStatistics(**data.get("globalHelpers", default_stats)),
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

    def list_managed_schemas(
        self, params: ListSchemasParams
    ) -> BackendResponse[ListManagedSchemasResponse]:
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
            schema = ManagedSchema(
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

        return BackendResponse(status_code=200, data=ListManagedSchemasResponse(schemas=schemas))

    def update_managed_schema(self, params: UpdateManagedSchemaParams) -> BackendResponse:
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
            data=UpdateManagedSchemaResponse(
                schema=ManagedSchema(
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


_API_URL_PATH = "public/graphql"
_API_DOMAIN_PREFIX = "api"
_API_TOKEN_HEADER = "X-API-Key"  # nosec


def _build_client(host: str, token: str) -> GraphQLClient:
    graphql_url = _build_api_url(host)
    logging.info("Panther Public API endpoint: %s", graphql_url)

    transport = AIOHTTPTransport(url=graphql_url, headers={_API_TOKEN_HEADER: token})

    return GraphQLClient(transport=transport, fetch_schema_from_transport=True, execute_timeout=30)


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
