import logging
from typing import Any, List, Optional

from sql_metadata import Parser

from panther_analysis_tool.constants import SET_FIELDS


def contains_invalid_field_set(analysis_spec: Any) -> List[str]:
    """Checks if the fields that Panther expects as sets have duplicates, returns True if invalid.

    :param analysis_spec: Loaded YAML specification file
    :return: bool - whether or not the specifications file is valid where False denotes valid.
    """
    invalid_fields = []
    for field in SET_FIELDS:
        if field not in analysis_spec:
            continue
        # Handle special case where we need to test for lowercase tags
        if field == "Tags":
            if len(analysis_spec[field]) != len(set(x.lower() for x in analysis_spec[field])):
                invalid_fields.append("LowerTags")
        if len(analysis_spec[field]) != len(set(analysis_spec[field])):
            invalid_fields.append(field)
    return invalid_fields


def contains_invalid_table_names(analysis_spec: Any, analysis_id: str) -> List[str]:
    invalid_table_names = []
    query = lookup_snowflake_query(analysis_spec)
    if query is not None:
        tables = []
        try:
            tables = Parser(query).tables
        except Exception:  # pylint: disable=broad-except
            # Intentionally broad exception catch:
            # We want to fall back on original behavior if this third-party parser cannot tell us the table names
            logging.info("Failed to parse query for scheduled query %s", analysis_id)
        for table in tables:
            components = table.split(".")
            if len(components) != 3:
                invalid_table_names.append(table)
            else:
                is_public_table = components[1] == "public"
                is_snowflake_account_usage_table = (
                    components[0] == "snowflake" and components[1] == "account_usage"
                )
                if not is_public_table and not is_snowflake_account_usage_table:
                    invalid_table_names.append(table)
    else:
        logging.info("No query found for scheduled query %s", analysis_id)
    return invalid_table_names


def lookup_snowflake_query(analysis_spec: Any) -> Optional[str]:
    query_keys = ["Query", "SnowflakeQuery"]
    for key in query_keys:
        if key in analysis_spec:
            return analysis_spec[key]
    return None
