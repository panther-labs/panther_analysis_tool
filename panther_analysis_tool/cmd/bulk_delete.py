"""
 Analysis Tool is a command line interface for writing,
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

import argparse
import logging
from typing import Tuple
from panther_analysis_tool.backend.client import Client as BackendClient, BulkDeletePayload


def run(backend: BackendClient, args: argparse.Namespace) -> Tuple[int, str]:
    logging.info("preparing bulk delete...")

    dry_run_res = backend.bulk_delete(BulkDeletePayload(dry_run=True, detection_ids=args.analysis_ids, saved_query_ids=args.query_ids))

    # TODO: introspect on dry run metadata, prompt as necessary...
    # potentially expand the scope of the delete...

    res = backend.bulk_delete(BulkDeletePayload(dry_run=False, detection_ids=args.analysis_ids, saved_query_ids=args.query_ids))

    return 0, ""
