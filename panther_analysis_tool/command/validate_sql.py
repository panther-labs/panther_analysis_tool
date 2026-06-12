import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from panther_analysis_tool import cli_output
from panther_analysis_tool.analysis_utils import filter_analysis, load_analysis_specs
from panther_analysis_tool.backend.client import Client as BackendClient
from panther_analysis_tool.backend.client import (
    DataLakeQueryStatus,
    ExecuteDataLakeQueryParams,
    GetDataLakeQueryParams,
    UnsupportedEndpointError,
)
from panther_analysis_tool.constants import AnalysisTypes
from panther_analysis_tool.core.definitions import ClassifiedAnalysis
from panther_analysis_tool.core.parse import Filter

POLL_INTERVAL_SECONDS = 1
PER_QUERY_TIMEOUT_SECONDS = 60

_SQL_KEYS = ("Query", "SnowflakeQuery")
_MISSING_TABLE_ERROR = "does not exist or not authorized"

# Matches substitution markers like <ACTOR_ID> or <WINDOW> used by investigation
# template queries, which are meant to be filled in by a human before running.
_PLACEHOLDER_PATTERN = re.compile(r"<[A-Z][A-Z0-9_]*>")


@dataclass
class ValidateSqlArgs:
    path: str
    ignore_files: List[str]
    filters: List[Filter]
    filters_inverted: List[Filter]
    skip_missing_tables: bool = False


@dataclass(frozen=True)
class SqlValidationTarget:
    analysis_id: str
    file_name: str
    sql: str
    enabled: bool = True


def run(backend: BackendClient, args: ValidateSqlArgs) -> Tuple[int, str]:
    if backend is None or not backend.supports_data_lake_queries():
        return 1, "Invalid backend. `validate-sql` is only supported via API token"

    targets = _collect_targets(args)
    if not targets:
        return 0, "No SQL queries found to validate"

    failures: List[Tuple[SqlValidationTarget, str]] = []
    skipped = 0
    for target in targets:
        try:
            error = _validate_target(backend, target)
        except UnsupportedEndpointError as err:
            logging.debug(err)
            return 1, cli_output.warning("Your Panther instance does not support this feature")

        if error is None:
            print(f"  {cli_output.success('PASS')} {target.analysis_id}")
        elif _MISSING_TABLE_ERROR in error and (args.skip_missing_tables or not target.enabled):
            # Disabled queries don't need their log source onboarded; enabled queries
            # do, unless --skip-missing-tables loosens that requirement.
            skipped += 1
            print(
                f"  {cli_output.warning('SKIP')} {target.analysis_id}"
                " (table does not exist in this instance)"
            )
        else:
            failures.append((target, error))
            print(f"  {cli_output.failed('FAIL')} {target.analysis_id} ({target.file_name})")
            for line in error.splitlines():
                print(f"         {line}")

    skip_suffix = f" ({skipped} skipped due to missing tables)" if skipped else ""
    if failures:
        return 1, cli_output.failed(
            f"SQL validation failed for {len(failures)} of {len(targets)} queries{skip_suffix}"
        )

    return 0, cli_output.success(
        f"SQL validation succeeded for all {len(targets) - skipped} queries{skip_suffix}"
    )


def _collect_targets(args: ValidateSqlArgs) -> List[SqlValidationTarget]:
    analysis = []
    for file_name, dir_name, analysis_spec, error in load_analysis_specs(
        [args.path], args.ignore_files
    ):
        if error is not None:
            logging.warning("Skipping %s: %s", file_name, error)
            continue
        analysis.append(ClassifiedAnalysis(file_name, dir_name, analysis_spec))

    analysis = filter_analysis(analysis, args.filters, args.filters_inverted)

    targets = []
    for item in analysis:
        spec = item.analysis_spec
        analysis_type = spec.get("AnalysisType")
        if analysis_type in (AnalysisTypes.SCHEDULED_QUERY, AnalysisTypes.SAVED_QUERY):
            analysis_id = spec.get("QueryName", "")
        elif analysis_type == AnalysisTypes.LOOKUP_TABLE:
            analysis_id = spec.get("LookupName", "")
        else:
            continue

        sql = _lookup_sql(spec)
        if sql is None:
            if analysis_type != AnalysisTypes.LOOKUP_TABLE:
                logging.warning("Skipping %s: no Query or SnowflakeQuery field found", analysis_id)
            continue

        # Jinja macro library files (e.g. panther-analysis queries/macros) expand to
        # nothing on their own and only compile when included from another query.
        if "{% macro" in sql:
            logging.info("Skipping %s: query only defines jinja macros", analysis_id)
            continue

        placeholder = _PLACEHOLDER_PATTERN.search(sql)
        if placeholder:
            logging.info(
                "Skipping %s: query contains placeholder %s",
                analysis_id,
                placeholder.group(0),
            )
            continue

        targets.append(
            SqlValidationTarget(
                analysis_id=analysis_id,
                file_name=item.file_name,
                sql=sql,
                enabled=bool(spec.get("Enabled", True)),
            )
        )

    return targets


def _lookup_sql(analysis_spec: Dict[str, Any]) -> Optional[str]:
    for key in _SQL_KEYS:
        if isinstance(analysis_spec.get(key), str):
            return analysis_spec[key]
    return None


def _validate_target(backend: BackendClient, target: SqlValidationTarget) -> Optional[str]:
    """Compiles the target's SQL against the data lake via EXPLAIN.

    Returns None if the SQL is valid, otherwise the compilation error message.
    """
    # EXPLAIN compiles the query in the data lake without scanning any data,
    # which surfaces syntax errors and invalid table/column references.
    sql = re.sub(r"[;\s]+$", "", target.sql)
    explain_sql = f"EXPLAIN {sql}"

    try:
        execute_res = backend.execute_data_lake_query(ExecuteDataLakeQueryParams(sql=explain_sql))
    except UnsupportedEndpointError:
        raise
    except BaseException as err:  # pylint: disable=broad-except
        return str(err)

    deadline = time.time() + PER_QUERY_TIMEOUT_SECONDS
    while True:
        try:
            status_res = backend.get_data_lake_query(GetDataLakeQueryParams(id=execute_res.data.id))
        except BaseException as err:  # pylint: disable=broad-except
            return str(err)

        status = (status_res.data.status or "").lower()
        if status == DataLakeQueryStatus.SUCCEEDED:
            return None
        if status in (DataLakeQueryStatus.FAILED, DataLakeQueryStatus.CANCELLED):
            return status_res.data.message or f"validation query {status}"
        if time.time() >= deadline:
            return "timed out waiting for SQL validation to complete"

        time.sleep(POLL_INTERVAL_SECONDS)
