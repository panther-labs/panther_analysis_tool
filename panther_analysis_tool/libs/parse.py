from typing import Any, Dict, List, Tuple
import logging
from schema import Optional

from panther_analysis_tool.constants import GLOBAL_SCHEMA, POLICY_SCHEMA, RULE_SCHEMA
from panther_analysis_tool.schemas import extract_keys_schema

# Parses the filters, expects a list of strings
def parse_filter(filters: List[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    parsed_filters: Dict[str, Any] = {}
    parsed_filters_inverted: Dict[str, Any] = {}
    for filt in filters:
        split = filt.split("=")
        if len(split) != 2 or split[0] == "" or split[1] == "":
            logging.error("Filter %s is not in format KEY=VALUE", filt)
            exit(1)
        # Check for "!="
        invert_filter = split[0].endswith("!")
        if invert_filter:
            split[0] = split[0][:-1]  # Remove the trailing "!"
        key = split[0]
        valid_keys = extract_keys_schema(GLOBAL_SCHEMA) | extract_keys_schema(POLICY_SCHEMA) | extract_keys_schema(RULE_SCHEMA)
        if key not in valid_keys:
            logging.error("Filter key %s is not a valid filter field", key)
            exit(1)
        if invert_filter:
            parsed_filters_inverted[key] = split[1].split(",")
        else:
            parsed_filters[key] = split[1].split(",")
        # Handle boolean fields
        if key == "Enabled":
            try:
                bool_value = bool(strtobool(split[1]))
            except ValueError:
                logging.error("Filter key %s should have either true or false", key)
                exit(1)
            if invert_filter:
                parsed_filters_inverted[key] = [bool_value]
            else:
                parsed_filters[key] = [bool_value]
    return parsed_filters, parsed_filters_inverted


def strtobool(value: str) -> bool:
    return value.lower() in ("y", "yes", "on", "1", "true", "t")