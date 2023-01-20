import os
import tempfile
from typing import Dict, Final

from schema import Schema

from panther_analysis_tool.schemas import (
    DATA_MODEL_SCHEMA,
    GLOBAL_SCHEMA,
    LOOKUP_TABLE_SCHEMA,
    PACK_SCHEMA,
    POLICY_SCHEMA,
    RULE_SCHEMA,
    SCHEDULED_QUERY_SCHEMA,
)

VERSION_STRING: Final = "panther_analysis_tool 0.19.0"

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

DATAMODEL = "datamodel"
DETECTION = "detection"
GLOBAL = "global"
LOOKUP_TABLE = "lookup_table"
PACK = "pack"
POLICY = "policy"
QUERY = "scheduled_query"
RULE = "rule"
SCHEDULED_RULE = "scheduled_rule"

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
    DATAMODEL: DATA_MODEL_SCHEMA,
    GLOBAL: GLOBAL_SCHEMA,
    LOOKUP_TABLE: LOOKUP_TABLE_SCHEMA,
    PACK: PACK_SCHEMA,
    POLICY: POLICY_SCHEMA,
    QUERY: SCHEDULED_QUERY_SCHEMA,
    RULE: RULE_SCHEMA,
    SCHEDULED_RULE: RULE_SCHEMA,
}

SET_FIELDS = [
    "LogTypes",
    "PackIDs",
    "OutputIds",
    "SummaryAttributes",
    "Suppressions",
    "Tags",
]
