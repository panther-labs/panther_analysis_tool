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

import os
import logging

from typing import Dict
from pathlib import Path
from dataclasses import dataclass

from gql import Client as GraphQLClient, gql
from gql.transport.aiohttp import AIOHTTPTransport
from graphql import DocumentNode, ExecutionResult

from .client import (
    Client,
    BackendResponse,
    BulkUploadParams,
    BackendCheckResponse,
    DeleteDetectionsParams,
    DeleteDetectionsResponse,
    DeleteSavedQueriesParams,
    DeleteSavedQueriesResponse,
    UpdateManagedSchemasParams,
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

            return BackendCheckResponse(
                success=False,
                message="connection check failed"
            )

        if res.data is None:
            return BackendCheckResponse(
                success=False,
                message="backend sent empty response"
            )

        panther_version = res.data.get("generalSettings", {}).get("pantherVersion")
        if panther_version is None:
            return BackendCheckResponse(
                success=False,
                message="did not receive version in response",
            )

        return BackendCheckResponse(
            success=True,
            message=f"connected to Panther backend on version: {panther_version}"
        )

    def bulk_upload(self, params: BulkUploadParams) -> BackendResponse:
        pass

    def delete_saved_queries(self, params: DeleteSavedQueriesParams) -> BackendResponse[DeleteSavedQueriesResponse]:
        pass

    def delete_detections(self, params: DeleteDetectionsParams) -> BackendResponse[DeleteDetectionsResponse]:
        pass

    def list_managed_schema_updates(self) -> BackendResponse:
        pass

    def update_managed_schemas(self, params: UpdateManagedSchemasParams) -> BackendResponse:
        pass

    def _execute(self, request: DocumentNode) -> ExecutionResult:
        return self._gql_client.execute(request, get_execution_result=True)


_API_URL_PATH = "public/graphql"
_API_DOMAIN_PREFIX = "api"
_API_TOKEN_HEADER = "X-API-Key"  # nosec


def _build_client(host: str, token: str) -> GraphQLClient:
    graphql_url = _build_api_url(host)
    logging.info("Panther Public API endpoint: %s", graphql_url)

    transport = AIOHTTPTransport(url=graphql_url, headers={_API_TOKEN_HEADER: token})

    return GraphQLClient(transport=transport, fetch_schema_from_transport=True)


def _build_api_url(host: str) -> str:
    return f"https://{_API_DOMAIN_PREFIX}.{host}/{_API_URL_PATH}"


def _get_graphql_content_filepath(name: str) -> str:
    work_dir = os.path.dirname(__file__)
    return os.path.join(work_dir, "graphql", f"{name}.graphql")
