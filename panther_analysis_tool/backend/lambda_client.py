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
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import os
import json
import logging

from typing import Dict, Any, Optional
from dataclasses import dataclass

import boto3

from .client import (
    Client,
    BackendError,
    BackendResponse,
    BulkUploadParams,
    BulkUploadResponse,
    BulkUploadStatistics,
    BackendCheckResponse,
    DeleteDetectionsParams,
    DeleteDetectionsResponse,
    DeleteSavedQueriesParams,
    DeleteSavedQueriesResponse,
    UpdateManagedSchemasParams,
)


LAMBDA_CLIENT_NAME = "lambda"
AWS_PROFILE_ENV_KEY = "AWS_PROFILE"


@dataclass(frozen=True)
class LambdaClientOpts:
    user_id:         str
    aws_profile:     Optional[str]
    datalake_lambda: str


class LambdaClient(Client):
    _user_id:         str
    _lambda_client:   boto3.client
    _datalake_lambda: str

    def __init__(self, opts: LambdaClientOpts):
        self._user_id = opts.user_id
        self._datalake_lambda = opts.datalake_lambda

        if opts.aws_profile is None:
            self._setup_client()
        else:
            self._setup_client_with_profile(opts.aws_profile)

    def _setup_client(self) -> None:
        self._lambda_client = boto3.client(LAMBDA_CLIENT_NAME)

    def _setup_client_with_profile(self, profile: str) -> None:
        logging.info("Using AWS profile: %s", profile)
        os.environ[AWS_PROFILE_ENV_KEY] = profile
        self._lambda_client = boto3.Session(profile_name=profile).client(LAMBDA_CLIENT_NAME)

    def check(self) -> BackendCheckResponse:
        return BackendCheckResponse(success=True, message="not implemented")

    def bulk_upload(self, params: BulkUploadParams) -> BackendResponse[BulkUploadResponse]:
        res = self._parse_response(self._lambda_client.invoke(
            FunctionName="panther-analysis-api",
            InvocationType="RequestResponse",
            LogType="None",
            Payload=self._serialize_request({
                "bulkUpload": {
                    "data": params.encoded_bytes(),
                    "userId": self._user_id,
                },
            }),
        ))

        body = json.loads(res.data['body'])

        default_stats = dict(total=0, new=0, modified=0)

        return BackendResponse(
            status_code=res.status_code,
            data=BulkUploadResponse(
                rules=BulkUploadStatistics(**body.get('rules', default_stats)),
                policies=BulkUploadStatistics(**body.get('policies', default_stats)),
                data_models=BulkUploadStatistics(**body.get('dataModels', default_stats)),
                lookup_tables=BulkUploadStatistics(**body.get('lookupTables', default_stats)),
                global_helpers=BulkUploadStatistics(**body.get('globalHelpers', default_stats)),
                new_detections=body.get('newDetections'),
                updated_detections=body.get('updatedDetections'),
            )
        )

    def delete_detections(self, params: DeleteDetectionsParams) -> BackendResponse[DeleteDetectionsResponse]:
        entries = []
        for id_to_delete in params.ids:
            entries.append({"id": id_to_delete})

        res = self._parse_response(self._lambda_client.invoke(
            FunctionName="panther-analysis-api",
            InvocationType="RequestResponse",
            LogType="None",
            Payload=self._serialize_request({
                "deleteDetections": {
                    "dryRun": params.dry_run,
                    "userId": self._user_id,
                    "entries": entries,
                    "includeSavedQueries": params.include_saved_queries,
                }
            }),
        ))

        body = json.loads(res.data['body'])

        return BackendResponse(
            status_code=res.status_code,
            data=DeleteDetectionsResponse(
                ids=body.get('ids') or [],
                saved_query_names=body.get('savedQueryNames') or [],
            )
        )

    def delete_saved_queries(self, params: DeleteSavedQueriesParams) -> BackendResponse[DeleteSavedQueriesResponse]:
        res = self._parse_response(self._lambda_client.invoke(
            FunctionName="panther-analysis-api",
            InvocationType="RequestResponse",
            LogType="None",
            Payload=self._serialize_request({
                "deleteSavedQueries": {
                    "ids": params.names,
                    "dryRun": params.dry_run,
                    "userId": self._user_id,
                    "includeDetections": params.include_detections,
                }
            }),
        ))

        return BackendResponse(
            status_code=res.status_code,
            data=DeleteSavedQueriesResponse(
                names=res.data.get("names", []),
                detection_ids=res.data.get("detectionIds", []),
            )
        )

    def list_managed_schema_updates(self) -> BackendResponse:
        return self._parse_response(self._lambda_client.invoke(
            FunctionName="panther-logtypes-api",
            InvocationType="RequestResponse",
            Payload=self._serialize_request({
                "ListManagedSchemaUpdates": {},
            }),
        ))

    def update_managed_schemas(self, params: UpdateManagedSchemasParams) -> BackendResponse:
        return self._parse_response(self._lambda_client.invoke(
            FunctionName="panther-logtypes-api",
            InvocationType="RequestResponse",
            Payload=self._serialize_request({
                "UpdateManagedSchemas": {
                    "release": params.release,
                    "manifestURL": params.manifest_url,
                }
            }),
        ))

    @staticmethod
    def _serialize_request(data: Dict[str, Any]) -> str:
        logging.debug(">>> %s", data)
        return json.dumps(data)

    @staticmethod
    def _parse_response(response: Dict[str, Any]) -> BackendResponse[Dict[str, Any]]:
        logging.debug("<<< %s", response)
        payload_str = response["Payload"].read().decode("utf-8")
        logging.debug("<<< %s", payload_str)

        status_code = response["ResponseMetadata"]["HTTPStatusCode"]
        payload = json.loads(payload_str)

        if status_code > 299 or response.get("FunctionError") == "Unhandled":
            logging.warning("backend error received: %s", payload)
            raise BackendError(payload.get('errorMessage', 'unknown error'))

        return BackendResponse(
            data=payload,
            status_code=status_code,
        )
