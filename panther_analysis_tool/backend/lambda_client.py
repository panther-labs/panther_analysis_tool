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
from typing import Dict, Any

import boto3
import logging

from dataclasses import dataclass

from .client import (
    Client,
    BackendResponse,
    BulkUploadParams,
    BulkDeleteParams,
    BackendCheckResponse,
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

    def bulk_upload(self, params: BulkUploadParams) -> BackendResponse:
        return self._parse_response(self._lambda_client.invoke(
            FunctionName="panther-analysis-api",
            InvocationType="RequestResponse",
            LogType="None",
            Payload=json.dumps({
                "bulkUpload": {
                    "data": params.encoded_bytes(),
                    "userId": self._user_id,
                },
            }),
        ))

    def bulk_delete(self, params: BulkDeleteParams) -> BackendResponse:
        return self._parse_response(self._lambda_client.invoke(
            FunctionName="panther-analysis-api",
            InvocationType="RequestResponse",
            LogType="None",
            Payload=json.dumps({
                "bulkDelete": {
                    "userId": self._user_id,
                    "detectionIds": params.detection_ids,
                    "savedQueryIds": params.saved_query_ids,
                },
            }),
        ))

    @staticmethod
    def _parse_response(response: Dict[str, Any]) -> BackendResponse:
        return BackendResponse(
            data=json.loads(response["Payload"].read().decode("utf-8")),
            status_code=response["ResponseMetadata"]["HTTPStatusCode"],
        )
