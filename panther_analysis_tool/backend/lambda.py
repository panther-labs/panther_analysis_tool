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

import boto3
import logging
from .base import BackendClient
from dataclasses import dataclass
from ..config.base import PATConfig

LAMBDA_CLIENT_NAME = "lambda"


@dataclass(frozen=True)
class LambdaClientOpts:
    config:      PATConfig
    aws_profile: str


class LambdaClient(BackendClient):
    _config: PATConfig
    _lambda_client: boto3.client

    def __init__(self, opts: LambdaClientOpts):
        self._config = opts.config

        if opts.aws_profile is not None:
            logging.info("Using AWS profile: %s", opts.aws_profile)
            self._config.set_aws_profile_env(opts.aws_profile)
            self.setup_client_with_profile(opts.aws_profile)
        else:
            self.setup_client()

    def setup_client(self):
        self._lambda_client = boto3.client(LAMBDA_CLIENT_NAME)

    def setup_client_with_profile(self, profile: str):
        self._lambda_client = boto3.Session(profile_name=profile).client(LAMBDA_CLIENT_NAME)

    def bulk_upload(self):
        pass

    def list_detections(self):
        pass

    def list_saved_queries(self):
        pass

    def delete_saved_queries(self):
        pass

    def delete_detections(self):
        pass

    def list_managed_schema_updates(self):
        pass

    def update_managed_schemas(self):
        pass
