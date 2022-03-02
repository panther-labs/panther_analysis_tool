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

import requests

from panther_analysis_tool.util import get_client

LOOKUP_LAMBDA_NAME = "panther-lookup-tables-api"


class LookupTable:
    """A Panther Lookup Table"""

    def __init__(self, spec: dict, spec_dir: str, aws_profile: str):
        """Instantiate a Lookup Table object

        Args:
            spec: a dict representing the configuration of a Lookup Table
            spec_dir: a string representing the directory containing the spec file
            aws_profile: a string respresenting the AWS profile used to run PAT
        """
        self._spec = spec
        self._spec_dir = spec_dir
        self._aws_profile = aws_profile
        self._client = get_client(self._aws_profile, "lambda")
        self._lookup_id = None
        self._data_file = self._spec.get("dataFile", None)
        self._refresh = self._spec.get("refresh", None)
        logging.info("Creating/updating the lookup table %s", self._spec["name"])

    def update(self) -> int:
        """Create a new Lookup Table or update a pre-existing one in Panther

        Returns 1 if the operation fails

        Args: none

        Returns:
        An integer return code
        """
        logging.info("Creating or updating the %s lookup table", self._spec["name"])

        create_update = {
            "createOrUpdateLookup": {
                "name": self._spec["name"],
                "enabled": self._spec["enabled"],
                "description": self._spec.get("description", ""),
                "reference": self._spec.get("reference", ""),
                "lookupSchema": self._spec["lookupSchema"],
                "logTypeMap": self._spec["logTypeMap"],
            }
        }
        if self._refresh:
            create_update["createOrUpdateLookup"]["refresh"] = self._refresh
        request_payload = json.dumps(create_update)
        logging.debug(request_payload)

        response = self._client.invoke(
            FunctionName=LOOKUP_LAMBDA_NAME,
            InvocationType="RequestResponse",
            Payload=request_payload,
        )
        response_str = response["Payload"].read().decode("utf-8")
        response_payload = json.loads(response_str)
        logging.debug(response_payload)

        error_msg = response_payload.get("errorMessage", None)
        status_code = response["StatusCode"]
        if status_code != 200 or error_msg:
            logging.warning(
                "Failed to create/update the %s Lookup Table\n\tstatus code: %s\n\terror: %s",
                self._spec["name"],
                status_code,
                response_payload.get("errorMessage", response_payload.get("body")),
            )
            return 1

        self._lookup_id = response_payload["id"]
        # If we have an input file, upload it to S3
        if self._data_file:
            upload_url = self.upload_data()
            if not upload_url:
                return 1
            # Now "upload" the file from S3 to create the Lookup Table's index
            return self.upload_from_s3(upload_url)

        return 0  # no local file i.e. refresh config was specified

    # Upload the local data file to S3
    def upload_data(self) -> str:
        upload_url = ""
        try:
            logging.info("Uploading the data file %s to S3", self._data_file)
            file_path = os.path.join(self._spec_dir, self._data_file)

            request_payload = json.dumps({"uploadUrl": {"key": self._data_file}})
            logging.debug(request_payload)

            response = self._client.invoke(
                FunctionName=LOOKUP_LAMBDA_NAME,
                InvocationType="RequestResponse",
                Payload=request_payload,
            )
            logging.debug(response)
            response_str = response["Payload"].read().decode("utf-8")
            api_response = json.loads(response_str)
            upload_url = api_response["url"]

            put_response = requests.put(upload_url, data=open(file_path, "rb"))

            if put_response.status_code != 200:
                logging.warning(
                    "Failed to upload the the data file %s\nhttp response: %s",
                    self._data_file,
                    put_response.text,
                )
        except Exception as err:  # pylint: disable=broad-except
            logging.warning(
                "Failed to upload the the data file %s\nerror message: %s", self._data_file, err
            )
        return upload_url

    # Upload the data from S3 to the Lookup Table API to generate a new Lookup index
    # If the file hasn't changed, no further processing occurs
    def upload_from_s3(self, s3_url: str) -> int:
        request_payload = json.dumps(
            {"upload": {"id": self._lookup_id, "s3Path": s3_url, "isPresigned": True}}
        )
        logging.info("Uploading the S3 input data to the %s Lookup Table", self._spec["name"])
        logging.debug(request_payload)

        response = self._client.invoke(
            FunctionName=LOOKUP_LAMBDA_NAME,
            InvocationType="RequestResponse",
            Payload=request_payload,
        )

        response_str = response["Payload"].read().decode("utf-8")
        response_payload = json.loads(response_str)
        logging.debug(response_payload)
        status_code = response["StatusCode"]
        error_msg = response_payload.get("errorMessage", None)

        if status_code != 200 or error_msg:
            logging.error(
                "Failed to upload the S3 file %s to the %s Lookup Table\n\tstatus code: %s \
                \n\terror message: %s",
                s3_url,
                self._spec["name"],
                status_code,
                response_payload.get("errorMessage", response_payload.get("body")),
            )
            return 1
        return 0
