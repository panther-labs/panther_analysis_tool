import logging
import re
from typing import Any, List, Optional

from nested_lookup import nested_lookup
from sqlfluff import parse

from panther_analysis_tool.analysis_utils import ClassifiedAnalysisContainer
from panther_analysis_tool.constants import SET_FIELDS

# This file was generated in whole or in part by GitHub Copilot.


def contains_invalid_field_set(analysis_spec: Any) -> List[str]:
    """Checks if the fields that Panther expects as sets have duplicates, returns list of invalid.

    :param analysis_spec: Loaded YAML specification file
    :return: list of invalid fields, empty if all valid.
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


def contains_invalid_table_names(
    analysis_spec: Any, analysis_id: str, valid_table_names: List[str]
) -> List[str]:
    invalid_table_names = []
    query = lookup_snowflake_query(analysis_spec)
    if query is not None:
        parsed_query = dict()
        try:
            parsed_query = parse(query, "snowflake")
        except Exception:  # pylint: disable=broad-except
            # Intentionally broad exception catch:
            # We want to fall back on original behavior if this third-party parser cannot tell us the table names
            logging.info("Failed to parse query %s. Skipping table name validation", analysis_id)
            return []
        tables = nested_lookup("table_reference", parsed_query)
        aliases = [alias[0] for alias in nested_lookup("common_table_expression", parsed_query)]
        for table in tables:
            if table in aliases:
                continue
            table_name = ""
            if isinstance(table, dict):
                table = [table]
            try:
                for name_component in table:
                    table_name += list(name_component.values())[0].lower()
            except Exception:  # pylint: disable=broad-except
                # Intentionally broad exception catch:
                # We want to fall back on original behavior if this third-party parser cannot tell us the table names
                logging.info("Failed to retrieve table name for table %s", table)
            else:
                if matches_valid_table_name(table_name, valid_table_names):
                    continue
                components = table_name.split(".")
                if len(components) != 3:
                    invalid_table_names.append(table_name)
                else:
                    is_public_table = components[1] == "public"
                    is_snowflake_account_usage_table = (
                        components[0] == "snowflake" and components[1] == "account_usage"
                    )
                    if not is_public_table and not is_snowflake_account_usage_table:
                        invalid_table_names.append(table_name)
    else:
        logging.info("No query found for %s", analysis_id)
    return invalid_table_names


def lookup_snowflake_query(analysis_spec: Any) -> Optional[str]:
    query_keys = ["Query", "SnowflakeQuery"]
    for key in query_keys:
        if key in analysis_spec:
            return analysis_spec[key]
    return None


def matches_valid_table_name(table_name: str, valid_table_names: List[str]) -> bool:
    for valid_table_name in valid_table_names:
        if (
            re.match(valid_table_name.replace(".", "\\.").replace("*", ".*"), table_name)
            is not None
        ):
            return True
    return False


def validate_packs(analysis_specs: ClassifiedAnalysisContainer) -> List[Any]:
    invalid_specs = []
    # first, setup dictionary of id to detection item
    id_to_detection = {}
    for item in analysis_specs.items():
        analysis_spec = item.analysis_spec
        analysis_id = (
            analysis_spec.get("PolicyID")
            or analysis_spec.get("RuleID")
            or analysis_spec.get("DataModelID")
            or analysis_spec.get("GlobalID")
            or analysis_spec.get("PackID")
            or analysis_spec.get("QueryName")
            or analysis_spec["LookupName"]
        )
        id_to_detection[analysis_id] = analysis_spec
    for item in analysis_specs.packs:
        analysis_spec = item.analysis_spec
        analysis_spec_filename = item.file_name
        # validate each id in the pack def exists
        pack_invalid_ids = []
        for analysis_id in analysis_spec.get("PackDefinition", {}).get("IDs", []):
            if analysis_id not in id_to_detection:
                pack_invalid_ids.append(analysis_id)
        if pack_invalid_ids:
            invalid_specs.append(
                (
                    analysis_spec_filename,
                    f"pack ({analysis_spec['PackID']}) definition includes item(s)"
                    f" that do not exist ({', '.join(pack_invalid_ids)})",
                )
            )
    return invalid_specs
