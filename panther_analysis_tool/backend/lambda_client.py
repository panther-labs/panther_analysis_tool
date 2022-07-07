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
import boto3
import logging

from dataclasses import dataclass

from .client import (
    Client,
    BackendResponse,
    BulkUploadParams,
    ListDetectionsParams,
    DeleteDetectionsParams,
    ListSavedQueriesParams,
    DeleteSavedQueriesParams,
)


LAMBDA_CLIENT_NAME = "lambda"
AWS_PROFILE_ENV_KEY = "AWS_PROFILE"


@dataclass(frozen=True)
class LambdaClientOpts:
    user_id: str
    aws_profile: str
    datalake_lambda: str


class LambdaClient(Client):
    _user_id: str
    _lambda_client: boto3.client
    _datalake_lambda: str

    def __init__(self, opts: LambdaClientOpts):
        self._user_id = opts.user_id
        self._datalake_lambda = opts.datalake_lambda

        if opts.aws_profile is not None:
            logging.info("Using AWS profile: %s", opts.aws_profile)
            os.environ[AWS_PROFILE_ENV_KEY] = opts.aws_profile
            self.setup_client_with_profile(opts.aws_profile)
        else:
            self.setup_client()

    def setup_client(self):
        self._lambda_client = boto3.client(LAMBDA_CLIENT_NAME)

    def setup_client_with_profile(self, profile: str):
        self._lambda_client = boto3.Session(profile_name=profile).client(LAMBDA_CLIENT_NAME)

    def bulk_upload(self, params: BulkUploadParams) -> BackendResponse:
        return self._parse_response(self._lambda_client.invoke(
            FunctionName="panther-analysis-api",
            InvocationType="RequestResponse",
            LogType="None",
            Payload=json.dumps({
                "bulkUpload": {
                    "data": params.encoded_bytes(),
                    # The UserID is required by Panther for this API call, but we have no way of
                    # acquiring it, and it isn't used for anything. This is a valid UUID used by the
                    # Panther deployment tool to indicate this action was performed automatically.
                    "userId": self._user_id,
                },
            }),
        ))

    def list_detections(self, params: ListDetectionsParams) -> BackendResponse:
        list_query = {}

        if params.ids:
            list_query["ids"] = params.ids

        if params.scheduled_queries:
            list_query["scheduledQueries"] = params.scheduled_queries

        return self._parse_response(self._lambda_client.invoke(
            FunctionName="panther-analysis-api",
            InvocationType="RequestResponse",
            LogType="None",
            Payload=json.dumps({
                "listDetections": list_query
            }),
        ))

    def list_saved_queries(self, params: ListSavedQueriesParams) -> BackendResponse:
        return self._parse_response(self._lambda_client.invoke(
            FunctionName=self._datalake_lambda,
            InvocationType="RequestResponse",
            LogType="None",
            Payload=json.dumps({
                "listSavedQueries": {
                    "name": params.name,
                    "pageSize": 1
                }
            }),
        ))

    def delete_saved_queries(self, params: DeleteSavedQueriesParams) -> BackendResponse:
        return self._parse_response(self._lambda_client.invoke(
            FunctionName=self._datalake_lambda,
            InvocationType="RequestResponse",
            LogType="None",
            Payload=json.dumps({
                "deleteSavedQueries": {
                    "ids": params.ids,
                    "userId": self._user_id,
                }
            }),
        ))

    def delete_detections(self, params: DeleteDetectionsParams) -> BackendResponse:
        entries = []
        for id_to_delete in params.ids:
            entries.append({"id": id_to_delete})

        return self._parse_response(self._lambda_client.invoke(
            FunctionName="panther-analysis-api",
            InvocationType="RequestResponse",
            LogType="None",
            Payload=json.dumps({
                "deleteDetections": {
                    "entries": entries,
                }
            }),
        ))

    @staticmethod
    def _parse_response(response) -> BackendResponse:
        return BackendResponse(
            data=json.loads(response["Payload"].read().decode("utf-8")),
            status_code=response["ResponseMetadata"]["HTTPStatusCode"],
        )
