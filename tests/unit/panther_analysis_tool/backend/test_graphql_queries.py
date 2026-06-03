"""Tests asserting that the GraphQL query files request the fields we expect.

A regression where a field is dropped from a `.graphql` file is otherwise silent —
GraphQL responses simply omit unrequested fields, and the response parsers default
the missing values to zero. These tests guard against that class of bug for the
`skills` field on bulk-upload mutations and async-upload status queries.
"""

import unittest

from panther_analysis_tool.backend.public_api_client import _get_graphql_content_filepath


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

    def test_bulk_upload_requests_all_known_categories(self) -> None:
        # Acts as a checklist — adding a new category to to_bulk_upload_response
        # without selecting it here would silently zero its counts.
        contents = _read_graphql("bulk_upload")
        for field in (
            "dataModels",
            "globalHelpers",
            "lookupTables",
            "policies",
            "rules",
            "queries",
            "correlationRules",
            "skills",
        ):
            self.assertIn(f"{field} {{", contents, msg=f"missing {field} selection")

    def test_async_bulk_upload_status_requests_all_known_categories(self) -> None:
        contents = _read_graphql("async_bulk_upload_status")
        for field in (
            "dataModels",
            "globalHelpers",
            "lookupTables",
            "policies",
            "rules",
            "queries",
            "correlationRules",
            "skills",
        ):
            self.assertIn(f"{field} {{", contents, msg=f"missing {field} selection")
