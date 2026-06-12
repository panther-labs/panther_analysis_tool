import os
import tempfile
import unittest
from unittest import mock

from panther_analysis_tool.backend.client import (
    BackendResponse,
    ExecuteDataLakeQueryResponse,
    GetDataLakeQueryResponse,
)
from panther_analysis_tool.backend.mocks import MockBackend
from panther_analysis_tool.command import validate_sql

SCHEDULED_QUERY_YAML = """
AnalysisType: scheduled_query
QueryName: My Scheduled Query
Enabled: true
Query: |
  SELECT * FROM panther_logs.public.aws_cloudtrail WHERE p_occurs_since('1 day')
Schedule:
  RateMinutes: 60
  TimeoutMinutes: 5
"""

SAVED_QUERY_YAML = """
AnalysisType: saved_query
QueryName: My Saved Query
SnowflakeQuery: SELECT 1;
"""

DISABLED_QUERY_YAML = """
AnalysisType: scheduled_query
QueryName: My Disabled Query
Enabled: false
Query: SELECT * FROM panther_logs.public.some_table
Schedule:
  RateMinutes: 60
  TimeoutMinutes: 5
"""

SQL_LOOKUP_TABLE_YAML = """
AnalysisType: lookup_table
LookupName: My SQL Lookup
Enabled: true
Query: SELECT actor FROM panther_logs.public.aws_cloudtrail
LogTypeMap:
  PrimaryKey: actor
Refresh:
  PeriodMinutes: 60
"""

FILE_LOOKUP_TABLE_YAML = """
AnalysisType: lookup_table
LookupName: My File Lookup
Enabled: true
Filename: lookup.csv
Schema: My.Schema
LogTypeMap:
  PrimaryKey: actor
"""

RULE_YAML = """
AnalysisType: rule
RuleID: My.Rule
Enabled: true
Filename: my_rule.py
LogTypes:
  - AWS.CloudTrail
Severity: Info
"""

MACRO_LIBRARY_YAML = """
AnalysisType: saved_query
QueryName: My Macros
Query: |
  -- pragma: template
  {% macro my_macro(subquery) export %}
  select * from {{ subquery }}
  {% endmacro %}
"""

PLACEHOLDER_TEMPLATE_YAML = """
AnalysisType: saved_query
QueryName: My Investigation Template
Query: |
  SELECT * FROM panther_logs.public.okta_systemlog
  WHERE p_occurs_since('<WINDOW>') AND actor:id = '<ACTOR_ID>'
"""

MISSING_TABLE_ERROR = (
    "SQL compilation error:\n"
    "Object 'PANTHER_LOGS.PUBLIC.SOME_TABLE' does not exist or not authorized."
)


def _make_backend(statuses=None) -> MockBackend:
    backend = MockBackend()
    backend.supports_data_lake_queries = mock.MagicMock(return_value=True)
    backend.execute_data_lake_query = mock.MagicMock(
        return_value=BackendResponse(
            data=ExecuteDataLakeQueryResponse(id="query-id"), status_code=200
        )
    )
    backend.get_data_lake_query = mock.MagicMock(
        side_effect=[
            BackendResponse(
                data=GetDataLakeQueryResponse(status=status, message=message), status_code=200
            )
            for status, message in (statuses or [("succeeded", "done")] * 10)
        ]
    )
    return backend


class TestValidateSql(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp_dir.cleanup)
        for name, content in [
            ("scheduled_query.yml", SCHEDULED_QUERY_YAML),
            ("saved_query.yml", SAVED_QUERY_YAML),
            ("disabled_query.yml", DISABLED_QUERY_YAML),
            ("sql_lookup.yml", SQL_LOOKUP_TABLE_YAML),
            ("file_lookup.yml", FILE_LOOKUP_TABLE_YAML),
            ("rule.yml", RULE_YAML),
            ("macros.yml", MACRO_LIBRARY_YAML),
            ("placeholder_template.yml", PLACEHOLDER_TEMPLATE_YAML),
        ]:
            with open(os.path.join(self.tmp_dir.name, name), "w", encoding="utf-8") as out:
                out.write(content)

        self.args = validate_sql.ValidateSqlArgs(
            path=self.tmp_dir.name, ignore_files=[], filters=[], filters_inverted=[]
        )

    def test_unsupported_backend(self) -> None:
        backend = MockBackend()
        backend.supports_data_lake_queries = mock.MagicMock(return_value=False)

        code, msg = validate_sql.run(backend, self.args)
        self.assertEqual(code, 1)
        self.assertIn("API token", msg)

    def test_collect_targets(self) -> None:
        targets = validate_sql._collect_targets(self.args)

        self.assertEqual(
            {t.analysis_id: t.enabled for t in targets},
            {
                "My Scheduled Query": True,
                "My Saved Query": True,
                "My Disabled Query": False,
                "My SQL Lookup": True,
            },
        )

    def test_all_queries_valid(self) -> None:
        backend = _make_backend()

        code, msg = validate_sql.run(backend, self.args)
        self.assertEqual(code, 0)
        self.assertIn("all 4 queries", msg)
        self.assertEqual(backend.execute_data_lake_query.call_count, 4)

        for call in backend.execute_data_lake_query.call_args_list:
            sql = call.args[0].sql
            self.assertTrue(sql.startswith("EXPLAIN "))
            self.assertFalse(sql.rstrip().endswith(";"))

    def _statuses_for(self, status_by_id):
        """Builds a get_data_lake_query status list matching target collection order."""
        targets = validate_sql._collect_targets(self.args)
        return [status_by_id.get(t.analysis_id, ("succeeded", "done")) for t in targets]

    def test_invalid_query_fails(self) -> None:
        backend = _make_backend(
            statuses=self._statuses_for(
                {"My Saved Query": ("failed", "SQL compilation error:\ninvalid identifier 'FOO'")}
            )
        )

        code, msg = validate_sql.run(backend, self.args)
        self.assertEqual(code, 1)
        self.assertIn("1 of 4", msg)

    def test_disabled_query_with_missing_table_is_skipped_by_default(self) -> None:
        backend = _make_backend(
            statuses=self._statuses_for({"My Disabled Query": ("failed", MISSING_TABLE_ERROR)})
        )

        code, msg = validate_sql.run(backend, self.args)
        self.assertEqual(code, 0)
        self.assertIn("1 skipped due to missing tables", msg)

    def test_disabled_query_with_syntax_error_still_fails(self) -> None:
        backend = _make_backend(
            statuses=self._statuses_for(
                {"My Disabled Query": ("failed", "SQL compilation error:\nsyntax error")}
            )
        )

        code, msg = validate_sql.run(backend, self.args)
        self.assertEqual(code, 1)
        self.assertIn("1 of 4", msg)

    def test_enabled_query_with_missing_table_fails_by_default(self) -> None:
        backend = _make_backend(
            statuses=self._statuses_for({"My Scheduled Query": ("failed", MISSING_TABLE_ERROR)})
        )

        code, msg = validate_sql.run(backend, self.args)
        self.assertEqual(code, 1)
        self.assertIn("1 of 4", msg)

    def test_polls_until_terminal_status(self) -> None:
        backend = _make_backend(
            statuses=[
                ("running", "still going"),
                ("succeeded", "done"),
            ]
        )

        with mock.patch.object(validate_sql.time, "sleep"):
            error = validate_sql._validate_target(
                backend,
                validate_sql.SqlValidationTarget(
                    analysis_id="My Query", file_name="a.yml", sql="SELECT 1"
                ),
            )

        self.assertIsNone(error)
        self.assertEqual(backend.get_data_lake_query.call_count, 2)

    def test_skip_missing_tables_flag_covers_enabled_queries(self) -> None:
        backend = _make_backend(
            statuses=self._statuses_for({"My Scheduled Query": ("failed", MISSING_TABLE_ERROR)})
        )

        args = validate_sql.ValidateSqlArgs(
            path=self.tmp_dir.name,
            ignore_files=[],
            filters=[],
            filters_inverted=[],
            skip_missing_tables=True,
        )
        code, msg = validate_sql.run(backend, args)
        self.assertEqual(code, 0)
        self.assertIn("1 skipped due to missing tables", msg)

    def test_cancelled_query_is_an_error(self) -> None:
        backend = _make_backend(statuses=[("cancelled", "")])

        error = validate_sql._validate_target(
            backend,
            validate_sql.SqlValidationTarget(
                analysis_id="My Query", file_name="a.yml", sql="SELECT 1"
            ),
        )

        self.assertEqual(error, "validation query cancelled")
