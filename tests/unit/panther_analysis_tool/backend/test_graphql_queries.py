"""Tests asserting that the GraphQL query files request the fields we expect.

A regression where a field is dropped from a `.graphql` file is otherwise silent —
GraphQL responses simply omit unrequested fields, and the response parsers default
the missing values to zero. These tests guard against that class of bug for the
bulk-upload mutation and async-upload status query selection sets.
"""

import unittest

from panther_analysis_tool.backend.public_api_client import (
    _get_graphql_content_filepath,
)

# Every per-entity-type stat field the upload response parsers read. Adding a new
# category to to_bulk_upload_response without selecting it here would silently zero
# its counts in the upload summary.
_KNOWN_CATEGORIES = (
    "dataModels",
    "globalHelpers",
    "lookupTables",
    "policies",
    "rules",
    "queries",
    "correlationRules",
    "skills",
    "scheduledPrompts",
)


def _read_graphql(name: str) -> str:
    with open(_get_graphql_content_filepath(name), encoding="utf-8") as f:
        return f.read()


class TestBulkUploadGraphQLQueries(unittest.TestCase):
    def test_bulk_upload_requests_skills_field(self) -> None:
        contents = _read_graphql("bulk_upload")
        self.assertIn("skills {", contents)

    def test_async_bulk_upload_status_requests_skills_field(self) -> None:
        contents = _read_graphql("async_bulk_upload_status")
        self.assertIn("skills {", contents)

    def test_bulk_upload_requests_scheduled_prompts_field(self) -> None:
        self.assertIn("scheduledPrompts {", _read_graphql("bulk_upload"))

    def test_async_bulk_upload_status_requests_scheduled_prompts_field(self) -> None:
        self.assertIn("scheduledPrompts {", _read_graphql("async_bulk_upload_status"))

    def test_bulk_upload_requests_all_known_categories(self) -> None:
        contents = _read_graphql("bulk_upload")
        for field in _KNOWN_CATEGORIES:
            self.assertIn(f"{field} {{", contents, msg=f"missing {field} selection")

    def test_async_bulk_upload_status_requests_all_known_categories(self) -> None:
        contents = _read_graphql("async_bulk_upload_status")
        for field in _KNOWN_CATEGORIES:
            self.assertIn(f"{field} {{", contents, msg=f"missing {field} selection")
