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
import json
import logging
import os
import typing
from dataclasses import dataclass
from typing import Any, Dict, Optional

import boto3

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
    TranspileFiltersParams,
    TranspileFiltersResponse,
    TranspileToPythonParams,
    TranspileToPythonResponse,
    UpdateSchemaParams,
    UpdateSchemaResponse,
    backend_response_failed,
    to_bulk_upload_response,
)
from .errors import is_retryable_error

LAMBDA_CLIENT_NAME = "lambda"
AWS_PROFILE_ENV_KEY = "AWS_PROFILE"


def decode_body(res: BackendResponse) -> typing.Any:
    try:
        return json.loads(res.data["body"])
    except json.decoder.JSONDecodeError as decode_error:
        raise Exception(res.data["body"]) from decode_error


@dataclass(frozen=True)
class LambdaClientOpts:
    user_id: str
    aws_profile: Optional[str]
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

    def async_bulk_upload(self, params: BulkUploadParams) -> BackendResponse[BulkUploadResponse]:
        raise BaseException("async uploads not supported with lambda client")

    def bulk_upload(self, params: BulkUploadParams) -> BackendResponse[BulkUploadResponse]:
        resp = self._parse_response(
            self._lambda_client.invoke(
                FunctionName="panther-analysis-api",
                InvocationType="RequestResponse",
                LogType="None",
                Payload=self._serialize_request(
                    {
                        "bulkUpload": {
                            "data": params.encoded_bytes(),
                            "userId": self._user_id,
                        },
                    }
                ),
            )
        )

        if backend_response_failed(resp):
            err = PermanentBackendError(resp.data)
            err.permanent = not is_retryable_error(resp.data)

            raise err

        body = decode_body(resp)
        return to_bulk_upload_response(body)

    def bulk_validate(self, params: BulkUploadParams) -> BulkUploadValidateStatusResponse:
        raise BaseException("bulk validate is not supported with lambda client")

    def delete_detections(
        self, params: DeleteDetectionsParams
    ) -> BackendResponse[DeleteDetectionsResponse]:
        entries = []
        for id_to_delete in params.ids:
            entries.append({"id": id_to_delete})

        res = self._parse_response(
            self._lambda_client.invoke(
                FunctionName="panther-analysis-api",
                InvocationType="RequestResponse",
                LogType="None",
                Payload=self._serialize_request(
                    {
                        "deleteDetections": {
                            "dryRun": params.dry_run,
                            "userId": self._user_id,
                            "entries": entries,
                            "includeSavedQueries": params.include_saved_queries,
                        }
                    }
                ),
            )
        )

        body = decode_body(res)

        return BackendResponse(
            status_code=res.status_code,
            data=DeleteDetectionsResponse(
                ids=body.get("ids") or [],
                saved_query_names=body.get("savedQueryNames") or [],
            ),
        )

    def delete_saved_queries(
        self, params: DeleteSavedQueriesParams
    ) -> BackendResponse[DeleteSavedQueriesResponse]:
        res = self._parse_response(
            self._lambda_client.invoke(
                FunctionName="panther-analysis-api",
                InvocationType="RequestResponse",
                LogType="None",
                Payload=self._serialize_request(
                    {
                        "deleteSavedQueriesByName": {
                            "names": params.names,
                            "dryRun": params.dry_run,
                            "userId": self._user_id,
                            "includeDetections": params.include_detections,
                        }
                    }
                ),
            )
        )

        body = decode_body(res)

        return BackendResponse(
            status_code=res.status_code,
            data=DeleteSavedQueriesResponse(
                names=body.get("names", []),
                detection_ids=body.get("detectionIds", []),
            ),
        )

    def list_schemas(self, params: ListSchemasParams) -> BackendResponse[ListSchemasResponse]:
        res = self._parse_response(
            self._lambda_client.invoke(
                FunctionName="panther-logtypes-api",
                InvocationType="RequestResponse",
                Payload=self._serialize_request(
                    {
                        "ListSchemas": {"isManaged": params.is_managed},
                    }
                ),
            )
        )
        if res.data.get("error") is not None:
            raise BackendError(res.data.get("error"))

        schemas = []
        for result in res.data["results"]:
            schemas.append(
                Schema(
                    created_at=result.get("createdAt", ""),
                    description=result.get("description", ""),
                    is_managed=result.get("isManaged", False),
                    name=result.get("name", ""),
                    reference_url=result.get("referenceURL", ""),
                    revision=result.get("revision", ""),
                    spec=result.get("spec", ""),
                    updated_at=result.get("updatedAt", ""),
                    field_discovery_enabled=result.get("fieldDiscoveryEnabled", False),
                )
            )

        return BackendResponse(status_code=200, data=ListSchemasResponse(schemas=schemas))

    def update_schema(self, params: UpdateSchemaParams) -> BackendResponse:
        res = self._parse_response(
            self._lambda_client.invoke(
                FunctionName="panther-logtypes-api",
                InvocationType="RequestResponse",
                Payload=self._serialize_request(
                    {
                        "PutUserSchema": {
                            "description": params.description,
                            "name": params.name,
                            "reference_url": params.reference_url,
                            "revision": params.revision,
                            "spec": params.spec,
                            "fieldDiscoveryEnabled": params.field_discovery_enabled,
                        }
                    }
                ),
            )
        )
        if res.data.get("error") is not None:
            raise BackendError(res.data.get("error"))

        schema = res.data.get("result", {})
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

    def transpile_simple_detection_to_python(
        self, params: TranspileToPythonParams
    ) -> BackendResponse[TranspileToPythonResponse]:
        raise BaseException(
            "transpile simple detections to python is not supported with lambda client"
        )

    def transpile_filters(
        self, params: TranspileFiltersParams
    ) -> BackendResponse[TranspileFiltersResponse]:
        raise BaseException("transpile filters is not supported with lambda client")

    def get_rule_body(self, params: GetRuleBodyParams) -> BackendResponse[GetRuleBodyResponse]:
        raise BaseException("get rule body is not supported with lambda client")

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
            raise BackendError(payload.get("errorMessage", "unknown error"))

        return BackendResponse(
            data=payload,
            status_code=status_code,
        )

    def supports_async_uploads(self) -> bool:
        return False

    def supports_bulk_validate(self) -> bool:
        return False

    def supports_perf_test(self) -> bool:
        return False

    def get_metrics(self, params: MetricsParams) -> BackendResponse[MetricsResponse]:
        raise BaseException("get metrics is not supported with lambda client")

    def run_perf_test(self, params: PerfTestParams) -> BackendResponse[ReplayResponse]:
        raise BaseException("run perf test is not supported with lambda client")

    def supports_enrich_test_data(self) -> bool:
        return False

    def generate_enriched_event_input(
        self, params: GenerateEnrichedEventParams
    ) -> BackendResponse[GenerateEnrichedEventResponse]:
        raise BaseException("enrich-test-data is not supported with lambda client")

    def feature_flags(self, params: FeatureFlagsParams) -> BackendResponse[FeatureFlagsResponse]:
        raise BaseException("feature-flags is not supported with lambda client")
