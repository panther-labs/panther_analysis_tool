import os
import tempfile
from typing import Dict, Final

from schema import Schema

from panther_analysis_tool.schemas import (
    CORRELATION_RULE_SCHEMA,
    DATA_MODEL_SCHEMA,
    DERIVED_SCHEMA,
    GLOBAL_SCHEMA,
    LOOKUP_TABLE_SCHEMA,
    PACK_SCHEMA,
    POLICY_SCHEMA,
    RULE_SCHEMA,
    SAVED_QUERY_SCHEMA,
    SCHEDULED_QUERY_SCHEMA,
)

PACKAGE_NAME: Final = "panther_analysis_tool"

VERSION_STRING: Final = "0.42.0"

CONFIG_FILE = ".panther_settings.yml"
DATA_MODEL_LOCATION = "./data_models"
HELPERS_LOCATION = "./global_helpers"
LUTS_LOCATION = "./lookup_tables"
DATA_MODEL_PATH_PATTERN = "*data_models*"
LUTS_PATH_PATTERN = "*lookup_tables*"
HELPERS_PATH_PATTERN = "*/global_helpers"
PACKS_PATH_PATTERN = "*/packs"
POLICIES_PATH_PATTERN = "*policies*"
QUERIES_PATH_PATTERN = "*queries*"
RULES_PATH_PATTERN = "*rules*"
TMP_HELPER_MODULE_LOCATION = os.path.join(tempfile.gettempdir(), "panther-path", "globals")


class AnalysisTypes:
    DATA_MODEL = "datamodel"
    DETECTION = "detection"
    GLOBAL = "global"
    LOOKUP_TABLE = "lookup_table"
    PACK = "pack"
    POLICY = "policy"
    SAVED_QUERY = "saved_query"
    SCHEDULED_QUERY = "scheduled_query"
    RULE = "rule"
    DERIVED = "derived"
    SCHEDULED_RULE = "scheduled_rule"
    SIMPLE_DETECTION = "simple_detection"
    CORRELATION_RULE = "correlation_rule"


# The UserID is required by Panther for some API calls, but we have no way of
# acquiring it, and it isn't used for anything. This is a valid UUID used by the
# Panther deployment tool to indicate this action was performed automatically.
PANTHER_USER_ID = "00000000-0000-4000-8000-000000000000"

RESERVED_FUNCTIONS = (
    "alert_context",
    "dedup",
    "description",
    "destinations",
    "reference",
    "runbook",
    "severity",
    "title",
)

VALID_SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

SCHEMAS: Dict[str, Schema] = {
    AnalysisTypes.DATA_MODEL: DATA_MODEL_SCHEMA,
    AnalysisTypes.GLOBAL: GLOBAL_SCHEMA,
    AnalysisTypes.LOOKUP_TABLE: LOOKUP_TABLE_SCHEMA,
    AnalysisTypes.PACK: PACK_SCHEMA,
    AnalysisTypes.POLICY: POLICY_SCHEMA,
    AnalysisTypes.SAVED_QUERY: SAVED_QUERY_SCHEMA,
    AnalysisTypes.SCHEDULED_QUERY: SCHEDULED_QUERY_SCHEMA,
    AnalysisTypes.RULE: RULE_SCHEMA,
    AnalysisTypes.DERIVED: DERIVED_SCHEMA,
    AnalysisTypes.SCHEDULED_RULE: RULE_SCHEMA,
    AnalysisTypes.CORRELATION_RULE: CORRELATION_RULE_SCHEMA,
}

SET_FIELDS = [
    "LogTypes",
    "PackIDs",
    "OutputIds",
    "SummaryAttributes",
    "Suppressions",
    "Tags",
]

BACKEND_FILTERS_ANALYSIS_SPEC_KEY = "_backend_filters"


class ReplayStatus:
    DONE = "DONE"
    CANCELED = "CANCELED"
    ERROR_EVALUATION = "ERROR_EVALUATION"
    ERROR_COMPUTATION = "ERROR_COMPUTATION"
    EVALUATION_IN_PROGRESS = "EVALUATION_IN_PROGRESS"
    COMPUTATION_IN_PROGRESS = "COMPUTATION_IN_PROGRESS"


ENABLE_CORRELATION_RULES_FLAG = "EnableCorrelationRules"
